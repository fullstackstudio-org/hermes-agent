"""Per-request TTS voice and prosody for the dashboard audio routes.

``POST /api/audio/speak`` and the ``/api/audio/speak-stream`` text frame take an optional ``voice``
(and, for Edge, ``rate``/``pitch``). This module owns the rules shared by both routes and by
``GET /api/audio/voice-config``:

* a voice is a plain identifier (letters, digits, ``. _ : -``, at most 128 characters): it is never
  interpolated into a path, a command or SSML, but the charset keeps it that way for every provider;
* it is checked against the provider's own list where that list is cheap (Edge's, cached; ElevenLabs'
  for the account, cached) and passed through otherwise (OpenAI-compatible servers accept voices of
  their own);
* applying it is a shallow copy of the ``tts`` config with the provider's voice key replaced, the
  same way a per-call ``speed`` is applied, so no provider code changes and the cached config is
  never mutated.

Providers that read their voice from somewhere else (command and plugin providers, the local
engines) do not support a per-request voice: asking for one is an error, not a silent no-op.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

VOICE_MAX_LENGTH = 128
_VOICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")

# provider -> (tts config section, key that holds the voice). Every entry is what that provider's
# generator and streamer already read, so a per-request voice needs no provider change.
VOICE_CONFIG_KEYS: Dict[str, tuple] = {
    "edge": ("edge", "voice"),
    "elevenlabs": ("elevenlabs", "voice_id"),
    "openai": ("openai", "voice"),
    "deepinfra": ("deepinfra", "voice"),
    "gemini": ("gemini", "voice"),
    "xai": ("xai", "voice_id"),
    "mistral": ("mistral", "voice_id"),
    "minimax": ("minimax", "voice_id"),
}

# Edge accepts a prosody change as a signed percentage (rate) and a signed number of hertz (pitch).
# The bounds keep a hint inside what sounds like speech; outside them is an error, not a clamp.
EDGE_RATE_PERCENT_MIN, EDGE_RATE_PERCENT_MAX = -50, 100
EDGE_PITCH_HZ_MIN, EDGE_PITCH_HZ_MAX = -50, 50

_LIST_TTL_SECONDS = 6 * 3600
_LIST_FAILURE_TTL_SECONDS = 60
_ELEVENLABS_LIST_TTL_SECONDS = 300


class VoiceSelectionError(ValueError):
    """A voice or prosody request that cannot be honoured. ``code`` is stable for clients."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VoiceSelection:
    """A validated per-request override: apply it to the ``tts`` config of the same provider."""

    voice: Optional[str] = None
    rate: Optional[int] = None  # percent, Edge only
    pitch: Optional[int] = None  # hertz, Edge only

    def apply(self, tts_config: Dict[str, Any], provider: str) -> Dict[str, Any]:
        out = dict(tts_config or {})
        if self.voice is not None and provider in VOICE_CONFIG_KEYS:
            section, key = VOICE_CONFIG_KEYS[provider]
            out[section] = {**_section(out, section), key: self.voice}
        if provider == "edge" and (self.rate is not None or self.pitch is not None):
            edge = dict(_section(out, "edge"))
            if self.rate is not None:
                edge["_rate_percent"] = self.rate
            if self.pitch is not None:
                edge["_pitch_hz"] = self.pitch
            out["edge"] = edge
        return out


def _section(config: Any, name: str) -> Dict[str, Any]:
    value = config.get(name) if isinstance(config, dict) else None
    return value if isinstance(value, dict) else {}


# --- Edge voice list (cached, single-flight, never on the request path for long) ---
# The list comes from Microsoft's service, which can hang. Three guards: the fetch itself has a hard
# deadline; only one fetch runs at a time and every caller shares it; and a request that has to wait
# for a cold cache waits at most a little longer than that deadline (``GET voice-config`` does not wait).
EDGE_FETCH_DEADLINE_SECONDS = 5.0
EDGE_WAIT_SECONDS = EDGE_FETCH_DEADLINE_SECONDS + 0.5

_edge_lock = threading.Lock()
_edge_cache: Dict[str, Any] = {"at": 0.0, "voices": None, "failed_at": 0.0}
_edge_inflight: Optional[threading.Event] = None


def _fetch_edge_voices() -> List[Dict[str, Any]]:
    """The raw ``edge_tts.list_voices()`` result, within :data:`EDGE_FETCH_DEADLINE_SECONDS`.

    Runs in the refresh thread, so a loop of its own is fine. The loop is closed, not shut down:
    ``asyncio.run`` would wait up to five minutes for a resolver thread that is stuck on DNS.
    """
    from tools import tts_tool
    edge_tts = tts_tool._import_edge_tts()
    loop = asyncio.new_event_loop()
    try:
        return list(loop.run_until_complete(
            asyncio.wait_for(edge_tts.list_voices(), timeout=EDGE_FETCH_DEADLINE_SECONDS)))
    finally:
        loop.close()


def _refresh_edge_voices(done: threading.Event) -> None:
    global _edge_inflight
    try:
        fetched = [v for v in (_normalize_edge_voice(r) for r in _fetch_edge_voices()) if v]
        fetched.sort(key=lambda v: (v["language"].lower(), v["name"].lower(), v["id"]))
        with _edge_lock:
            _edge_cache.update(at=time.monotonic(), voices=fetched, failed_at=0.0)
    except Exception as exc:  # the finally below frees the single-flight slot whatever happens
        logger.warning("Edge voice list unavailable: %s", str(exc) or type(exc).__name__)
        with _edge_lock:
            _edge_cache["failed_at"] = time.monotonic()
    finally:
        with _edge_lock:
            _edge_inflight = None
        done.set()


_FRIENDLY_RE = re.compile(r"^Microsoft\s+(.+?)\s+Online\s+\(Natural\)", re.IGNORECASE)


def _normalize_edge_voice(raw: Any) -> Optional[Dict[str, str]]:
    if not isinstance(raw, dict):
        return None
    voice_id = str(raw.get("ShortName") or "").strip()
    if not voice_id:
        return None
    match = _FRIENDLY_RE.match(str(raw.get("FriendlyName") or ""))
    return {
        "id": voice_id,
        "name": match.group(1) if match else voice_id,
        "language": str(raw.get("Locale") or "").strip(),
    }


def edge_voice_list(wait: Optional[float] = None) -> tuple:
    """Edge's voices as ``([{id, name, language}], state)``; the list is ``None`` unless *state* is ``"ready"``.

    ``"ready"``: a list (fresh, or the last good one while a refresh runs in the background).
    ``"loading"``: nothing cached yet and a fetch is still running. ``"unavailable"``: nothing cached
    and the last fetch failed (remembered for a minute, so a dashboard polling ``voice-config`` does
    not hit the network on every request; the last good list outlives a later failure).

    There is one fetch at a time, in a background thread, with a hard deadline of its own. *wait* is
    how long this caller waits for a cold cache: ``None`` = :data:`EDGE_WAIT_SECONDS`, ``0`` = not at
    all (the fetch is started and the answer is ``"loading"``).
    """
    global _edge_inflight
    if wait is None:
        wait = EDGE_WAIT_SECONDS
    now = time.monotonic()
    with _edge_lock:
        voices = _edge_cache["voices"]
        if voices is not None and now - _edge_cache["at"] < _LIST_TTL_SECONDS:
            return voices, "ready"
        failed_at = _edge_cache["failed_at"]
        if failed_at > 0.0 and now - failed_at < _LIST_FAILURE_TTL_SECONDS:
            return (voices, "ready") if voices is not None else (None, "unavailable")
        if _edge_inflight is None:
            _edge_inflight = done = threading.Event()
            threading.Thread(target=_refresh_edge_voices, args=(done,), daemon=True, name="edge-voice-list").start()
        done = _edge_inflight
        if voices is not None:
            return voices, "ready"  # stale, served while the refresh runs
    if wait > 0:
        done.wait(wait)
    with _edge_lock:
        voices = _edge_cache["voices"]
        if voices is not None:
            return voices, "ready"
        failed_at = _edge_cache["failed_at"]
        failed = failed_at > 0.0 and time.monotonic() - failed_at < _LIST_FAILURE_TTL_SECONDS
        return None, ("unavailable" if failed else "loading")


def edge_voices(wait: Optional[float] = None) -> Optional[List[Dict[str, str]]]:
    """Edge's voices (see :func:`edge_voice_list`), or ``None`` when they are not available (yet)."""
    return edge_voice_list(wait)[0]


def filter_voices_by_language(voices: List[Dict[str, str]], language: Optional[str]) -> List[Dict[str, str]]:
    """``nl`` matches every ``nl-*`` locale, ``nl-NL`` that locale only (case-insensitive)."""
    wanted = (language or "").strip().lower()
    if not wanted:
        return list(voices)
    return [v for v in voices
            if v["language"].lower() == wanted or v["language"].lower().startswith(wanted + "-")]


# --- ElevenLabs voice list (cached per account) ---
_el_lock = threading.Lock()
_el_cache: Dict[str, tuple] = {}
_el_failed: Dict[str, float] = {}  # cache key -> when the last list attempt failed


def _elevenlabs_api_root(base_url: Optional[str]) -> str:
    """The REST root (ending in ``/v1``) for ``tts.elevenlabs.base_url``.

    The SDK path takes the origin (``https://proxy.example``) and adds ``/v1`` itself; a value that
    already ends in ``/v1`` is taken as the root. Both reach the same ``/v1/voices``.
    """
    base = str(base_url or "").strip().rstrip("/") or "https://api.elevenlabs.io"
    return base if base.lower().endswith("/v1") else f"{base}/v1"


def _elevenlabs_endpoint(tts_config: Dict[str, Any]) -> tuple:
    from tools import tts_tool
    api_key = tts_tool._resolve_provider_key("ELEVENLABS_API_KEY", "elevenlabs")
    return api_key, _elevenlabs_api_root(_section(tts_config, "elevenlabs").get("base_url"))


def _fetch_elevenlabs_voice_ids(api_key: str, base_url: str) -> Set[str]:
    request = urllib.request.Request(
        f"{base_url}/voices", headers={"Accept": "application/json", "xi-api-key": api_key})
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed https endpoint
        payload = json.loads(response.read().decode("utf-8"))
    voices = payload.get("voices") if isinstance(payload, dict) else None
    if not isinstance(voices, list):
        raise ValueError("ElevenLabs answered with something that is not a voice list")
    ids = {str(v.get("voice_id") or "").strip() for v in voices if isinstance(v, dict)}
    ids.discard("")
    return ids


def elevenlabs_voice_ids(tts_config: Dict[str, Any]) -> Optional[Set[str]]:
    """The account's voice ids (cached 5 minutes), or ``None`` when they cannot be listed.

    A failed listing is remembered for a minute (a rejected key or a down service is not asked again
    on every speak). Must run under the requesting profile's scope: the key is that profile's. The
    cache is keyed by a hash of the key, never the key itself, and holds ids only.
    """
    try:
        api_key, base_url = _elevenlabs_endpoint(tts_config)
    except Exception as exc:
        logger.debug("ElevenLabs key lookup failed: %s", exc)
        return None
    if not api_key:
        return None
    cache_key = hashlib.sha256(f"{base_url}\0{api_key}".encode()).hexdigest()
    now = time.monotonic()
    with _el_lock:
        hit = _el_cache.get(cache_key)
        if hit and now - hit[0] < _ELEVENLABS_LIST_TTL_SECONDS:
            return hit[1]
        failed_at = _el_failed.get(cache_key)
        if failed_at is not None and now - failed_at < _LIST_FAILURE_TTL_SECONDS:
            return None
    try:
        ids = _fetch_elevenlabs_voice_ids(api_key, base_url)
    except Exception as exc:
        logger.warning("ElevenLabs voice list unavailable: %s", exc)
        with _el_lock:
            _el_failed[cache_key] = time.monotonic()
        return None
    with _el_lock:
        _el_cache[cache_key] = (time.monotonic(), ids)
        _el_failed.pop(cache_key, None)
    return ids


# --- ElevenLabs voice previews (free samples, fetched server-side) ---
PREVIEW_MAX_BYTES = 5 * 1024 * 1024
PREVIEW_TIMEOUT_SECONDS = 10
PREVIEW_CACHE_TTL_SECONDS = 3600
PREVIEW_CACHE_MAX_ENTRIES = 50
PREVIEW_CACHE_MAX_BYTES = 50 * 1024 * 1024
# Where ElevenLabs keeps the sample files: ``preview_url`` points at storage.googleapis.com
# (``eleven-public-prod/...``) for the premade voices and at an ``elevenlabs.io`` host for others.
# A ``preview_url`` is data from a third party, so the fetch goes to these hosts and nowhere else.
_PREVIEW_HOSTS = ("storage.googleapis.com",)
_PREVIEW_HOST_SUFFIXES = (".elevenlabs.io",)


class PreviewError(Exception):
    """A preview that was refused or could not be fetched (the route answers 502)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None  # the 3xx surfaces as an HTTPError: a sample host has no business redirecting


def check_preview_url(url: str) -> None:
    """Raise :class:`PreviewError` unless *url* is https, on the allowlist, and has no userinfo."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise PreviewError("preview url is malformed") from exc
    if parts.scheme != "https":
        raise PreviewError("preview url is not https")
    if parts.username or parts.password or (port not in (None, 443)):
        raise PreviewError("preview url has credentials or a non-standard port")
    if host not in _PREVIEW_HOSTS and host != "elevenlabs.io" and not host.endswith(_PREVIEW_HOST_SUFFIXES):
        raise PreviewError(f"preview host {host!r} is not allowed")


def _response_socket(response: Any) -> Any:
    """The socket under an ``http.client`` response (``response.fp`` is a buffered reader over a
    ``SocketIO`` that holds it), or ``None`` for a response that is not backed by one."""
    return getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)


def fetch_preview(url: str, timeout: float = PREVIEW_TIMEOUT_SECONDS) -> tuple:
    """Download one preview → ``(bytes, content_type)``. Blocking (worker thread).

    https and the host allowlist are checked first, redirects are not followed, the body is read
    in chunks and refused past :data:`PREVIEW_MAX_BYTES`, and the body has to arrive within *timeout*
    seconds (default :data:`PREVIEW_TIMEOUT_SECONDS`) of the start, counted as a whole: each read
    returns what has arrived (``read1``) and the socket's timeout is cut to the time that is left
    before it, so a server that dribbles bytes or stalls cannot outlast the limit. (Connecting and
    the response headers are bounded by *timeout* per operation, not as a whole.) A non-audio content
    type is sent on as ``audio/mpeg``.
    """
    check_preview_url(url)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "audio/*"})
    deadline = time.monotonic() + timeout
    try:
        with opener.open(request, timeout=timeout) as response:
            content_type = response.headers.get_content_type() if response.headers else ""
            sock = _response_socket(response)
            body = bytearray()
            while not getattr(response, "isclosed", lambda: False)():  # closed = the body was complete
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PreviewError("preview download took too long")
                if sock is not None:
                    sock.settimeout(remaining)
                try:
                    chunk = response.read1(64 * 1024)
                except (TimeoutError, socket.timeout):  # the socket ran out of the time that was left
                    raise PreviewError("preview download took too long") from None
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > PREVIEW_MAX_BYTES:
                    raise PreviewError("preview is larger than the limit")
    except PreviewError:
        raise
    except Exception as exc:  # HTTPError (incl. a refused redirect), timeouts, DNS, TLS
        raise PreviewError(f"preview fetch failed: {exc}") from exc
    if not body:
        raise PreviewError("preview is empty")
    return bytes(body), content_type if content_type.startswith("audio/") else "audio/mpeg"


_preview_lock = threading.Lock()
_preview_cache: "OrderedDict[str, tuple]" = OrderedDict()


def _preview_key(api_key: str, voice_id: str) -> str:
    # Per account: another profile's key may not list the same voice. Hashed, the key is never stored.
    return hashlib.sha256(f"{api_key}\0{voice_id}".encode()).hexdigest()


def preview_cache_get(api_key: str, voice_id: str) -> Optional[tuple]:
    key = _preview_key(api_key, voice_id)
    with _preview_lock:
        hit = _preview_cache.get(key)
        if hit is None:
            return None
        if time.monotonic() - hit[0] > PREVIEW_CACHE_TTL_SECONDS:
            del _preview_cache[key]
            return None
        _preview_cache.move_to_end(key)
        return hit[1]


def preview_cache_put(api_key: str, voice_id: str, value: tuple) -> None:
    """Remember a preview; the oldest go first past :data:`PREVIEW_CACHE_MAX_ENTRIES` entries or
    :data:`PREVIEW_CACHE_MAX_BYTES` bytes in all (a body larger than the whole budget is not kept)."""
    size = len(value[0])
    if size > PREVIEW_CACHE_MAX_BYTES:
        return
    key = _preview_key(api_key, voice_id)
    with _preview_lock:
        _preview_cache.pop(key, None)
        _preview_cache[key] = (time.monotonic(), value)
        total = sum(len(entry[1][0]) for entry in _preview_cache.values())
        while len(_preview_cache) > PREVIEW_CACHE_MAX_ENTRIES or total > PREVIEW_CACHE_MAX_BYTES:
            _, (_, (evicted, _)) = _preview_cache.popitem(last=False)
            total -= len(evicted)


# --- Validation ---
def clean_voice_id(voice: Any) -> str:
    """A voice id as the routes take it (path segment or field): the charset and length rule, or
    :class:`VoiceSelectionError`. Blank is an error here; ``voice`` fields treat it as absent."""
    voice = _clean_voice(voice)
    if voice is None:
        raise VoiceSelectionError("invalid_voice", "voice is required")
    return voice


def _clean_voice(voice: Any) -> Optional[str]:
    if voice is None:
        return None
    if not isinstance(voice, str):
        raise VoiceSelectionError("invalid_voice", "voice must be a string")
    voice = voice.strip()
    if not voice:
        return None
    if len(voice) > VOICE_MAX_LENGTH:
        raise VoiceSelectionError("invalid_voice", f"voice must be at most {VOICE_MAX_LENGTH} characters")
    if not _VOICE_RE.fullmatch(voice):
        raise VoiceSelectionError(
            "invalid_voice", "voice may contain only letters, digits and . _ : - (and must start with one)")
    return voice


def _clean_prosody(name: str, value: Any, low: int, high: int, unit: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise VoiceSelectionError("invalid_prosody", f"{name} must be a number")
    if value < low or value > high:
        raise VoiceSelectionError("invalid_prosody", f"{name} must be between {low} and {high} {unit}")
    return int(round(value))


def supports_voice_selection(provider: str) -> bool:
    """Whether a per-request voice reaches the configured provider's synthesis."""
    if provider not in VOICE_CONFIG_KEYS:
        return False
    if provider == "edge":
        from tools import tts_tool
        return tts_tool._importable(tts_tool._import_edge_tts)
    return True


def supports_prosody(provider: str) -> bool:
    return provider == "edge" and supports_voice_selection("edge")


def _known_voice_ids(provider: str, tts_config: Dict[str, Any]) -> Optional[Set[str]]:
    """The provider's own voice ids where listing them is cheap; ``None`` = pass through."""
    if provider == "edge":
        voices = edge_voices()
        return {v["id"] for v in voices} if voices is not None else None
    if provider == "elevenlabs":
        return elevenlabs_voice_ids(tts_config)
    return None


def resolve_voice_selection(
    tts_config: Dict[str, Any], provider: str, voice: Any = None, rate: Any = None, pitch: Any = None,
) -> Optional[VoiceSelection]:
    """Validate a per-request ``voice``/``rate``/``pitch`` against *provider* → a selection or ``None``.

    ``rate``/``pitch`` are checked for type and bounds whatever the provider, and applied only where
    the provider has them (Edge). Raises :class:`VoiceSelectionError` (never anything else) for a bad
    value, a provider without per-request voices and a voice the provider does not know. Blocking
    (the voice lists are network calls): call it from a worker thread, under the requesting profile's
    config scope.
    """
    voice = _clean_voice(voice)
    rate = _clean_prosody("rate", rate, EDGE_RATE_PERCENT_MIN, EDGE_RATE_PERCENT_MAX, "percent")
    pitch = _clean_prosody("pitch", pitch, EDGE_PITCH_HZ_MIN, EDGE_PITCH_HZ_MAX, "Hz")
    if voice is not None:
        if not supports_voice_selection(provider):
            raise VoiceSelectionError(
                "voice_unsupported", f"the configured TTS provider ({provider}) does not support choosing a voice")
        known = _known_voice_ids(provider, tts_config)
        if known is not None and voice not in known:
            raise VoiceSelectionError("unknown_voice", f"{provider} has no voice {voice!r}")
    if not supports_prosody(provider):
        rate = pitch = None
    if voice is None and rate is None and pitch is None:
        return None
    return VoiceSelection(voice=voice, rate=rate, pitch=pitch)


def streamer_provider_name(streamer: Any, tts_config: Dict[str, Any], fallback: str) -> str:
    """The provider a streamer was registered under (``tts.streaming.provider`` may differ from
    ``tts.provider``); *fallback* when it is not a registered class."""
    from tools import tts_streaming
    for name, cls in tts_streaming._REGISTRY.items():
        if type(streamer) is cls:
            return name
    return fallback


# --- What voice-config advertises ---
def default_voice(tts_config: Dict[str, Any], provider: str) -> Optional[str]:
    """The voice the provider speaks with when a request names none."""
    entry = VOICE_CONFIG_KEYS.get(provider)
    if entry is None:
        return None
    configured = _section(tts_config, entry[0]).get(entry[1])
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    from tools import tts_tool_providers as providers
    defaults = {
        "edge": providers.DEFAULT_EDGE_VOICE, "elevenlabs": providers.DEFAULT_ELEVENLABS_VOICE_ID,
        "gemini": providers.DEFAULT_GEMINI_TTS_VOICE, "xai": providers.DEFAULT_XAI_VOICE_ID,
        "mistral": providers.DEFAULT_MISTRAL_TTS_VOICE_ID, "minimax": providers.DEFAULT_MINIMAX_VOICE_ID}
    if provider == "openai":
        from tools.tts_tool_openai import DEFAULT_OPENAI_VOICE
        return DEFAULT_OPENAI_VOICE
    if provider == "deepinfra":
        from tools.tts_tool_openai import DEFAULT_DEEPINFRA_TTS_VOICE
        return DEFAULT_DEEPINFRA_TTS_VOICE
    return defaults.get(provider)


def voice_capabilities(tts_config: Dict[str, Any], provider: str, language: Optional[str] = None) -> Dict[str, Any]:
    """The non-secret voice fields ``GET /api/audio/voice-config`` adds to ``tts``."""
    selectable = supports_voice_selection(provider)
    caps: Dict[str, Any] = {
        "provider": provider, "voice_selection": selectable, "prosody": supports_prosody(provider),
        "voice": default_voice(tts_config, provider) if selectable else None,
    }
    # How a client may let the person hear a voice before choosing it, without spending anything:
    # ElevenLabs keeps a free sample per voice; Edge is free to synthesize; the paid providers have
    # neither, so the key is absent for them.
    if selectable and provider == "elevenlabs":
        caps["voice_preview"] = "sample"
    elif selectable and provider == "edge":
        caps["voice_preview"] = "speak"
    if provider == "edge" and selectable:
        # Never waits: a cold cache starts the fetch and answers "loading" (the client asks again).
        voices, state = edge_voice_list(wait=0)
        if voices is None:
            caps["voices"] = []
            caps["voices_error"] = state
        else:
            caps["voices"] = filter_voices_by_language(voices, language)
    return caps
