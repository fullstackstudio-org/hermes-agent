"""Per-request TTS voice on the dashboard audio routes: POST /api/audio/speak, the speak-stream
text frame, GET /api/audio/voice-config and the ElevenLabs preview route.

Providers are mocked at the SDK seam and the voice lists/preview fetches at ``tools.tts_voice``'s
network functions, so what is asserted is what a provider receives and what a client can see.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from hermes_cli import web_server
from tools import tts_voice

_REAL_FETCH_ELEVENLABS_IDS = tts_voice._fetch_elevenlabs_voice_ids

EL_VOICE = "21m00Tcm4TlvDq8ikWAM"
EL_OTHER = "AZnzlk1XvdvUeBnXmlld"
KEY = "sk-el-SECRET"
PREVIEW_URL = "https://storage.googleapis.com/eleven-public-prod/premade/voices/21m00/sample.mp3"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", KEY)
    monkeypatch.setattr(tts_voice, "_el_cache", {})
    monkeypatch.setattr(tts_voice, "_preview_cache", tts_voice.OrderedDict())
    monkeypatch.setattr(tts_voice, "_el_failed", {})
    monkeypatch.setattr(tts_voice, "_edge_cache", {"at": 0.0, "voices": None, "failed_at": 0.0})
    monkeypatch.setattr(tts_voice, "_edge_inflight", None)
    monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda key, base: {EL_VOICE, EL_OTHER})
    yield
    _settle_edge()


def _settle_edge(timeout=3.0):
    import time
    end = time.monotonic() + timeout
    while tts_voice._edge_inflight is not None and time.monotonic() < end:
        time.sleep(0.01)


@pytest.fixture
def client(monkeypatch, _isolate_hermes_home):
    previous = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.auth_required = False
    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    try:
        yield c
    finally:
        c.close()
        if previous is None:
            if hasattr(web_server.app.state, "auth_required"):
                delattr(web_server.app.state, "auth_required")
        else:
            web_server.app.state.auth_required = previous


def _config(monkeypatch, config):
    monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: config)


def _elevenlabs_sdk():
    sdk = MagicMock()
    sdk.text_to_speech.convert.side_effect = lambda **kw: iter([b"ID3audio"])
    return sdk


def _speak(client, **body):
    return client.post("/api/audio/speak", json={"text": "Hello there", **body})


# ------------------------------------------------------------------ POST /api/audio/speak
class TestSpeak:
    def test_elevenlabs_voice_id_reaches_the_sdk(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "elevenlabs", "elevenlabs": {"voice_id": "configured"}})
        sdk = _elevenlabs_sdk()
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            resp = _speak(client, voice=EL_VOICE)
        assert resp.status_code == 200, resp.text
        assert resp.json()["data_url"].startswith("data:audio/")
        assert sdk.text_to_speech.convert.call_args.kwargs["voice_id"] == EL_VOICE

    def test_without_voice_the_configured_voice_is_used(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "elevenlabs", "elevenlabs": {"voice_id": "configured"}})
        sdk = _elevenlabs_sdk()
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            assert _speak(client).status_code == 200
        assert sdk.text_to_speech.convert.call_args.kwargs["voice_id"] == "configured"

    def test_unknown_elevenlabs_voice_is_a_400_and_nothing_is_synthesized(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "elevenlabs"})
        sdk = _elevenlabs_sdk()
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            resp = _speak(client, voice="NotOnThisAccount123")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "unknown_voice"
        sdk.text_to_speech.convert.assert_not_called()

    @pytest.mark.parametrize("voice", ["a" * 129, "al oy", "../x", "a;b", "<speak/>"])
    def test_bad_voice_is_a_400(self, client, monkeypatch, voice):
        _config(monkeypatch, {"provider": "openai"})
        resp = _speak(client, voice=voice)
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "invalid_voice"

    def test_provider_without_per_request_voice_is_a_400(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "piper"})
        resp = _speak(client, voice="en_US-lessac")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "voice_unsupported"

    def test_edge_voice_and_prosody_reach_communicate(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "edge"})
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: [
            {"ShortName": "nl-NL-FennaNeural", "Locale": "nl-NL", "FriendlyName": "Microsoft Fenna Online (Natural) - Dutch"}])
        comm = MagicMock()
        comm.save = AsyncMock(side_effect=lambda path: open(path, "wb").write(b"ID3audio"))
        edge = MagicMock()
        edge.Communicate = MagicMock(return_value=comm)
        with patch("tools.tts_tool._import_edge_tts", return_value=edge):
            resp = _speak(client, voice="nl-NL-FennaNeural", rate=15, pitch=-5)
        assert resp.status_code == 200, resp.text
        kwargs = edge.Communicate.call_args.kwargs
        assert kwargs["voice"] == "nl-NL-FennaNeural" and kwargs["rate"] == "+15%" and kwargs["pitch"] == "-5Hz"

    def test_unknown_edge_voice_is_a_400(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "edge"})
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: [
            {"ShortName": "nl-NL-FennaNeural", "Locale": "nl-NL"}])
        assert _speak(client, voice="nl-NL-NopeNeural").status_code == 400

    @pytest.mark.parametrize("field,value", [("rate", 101), ("rate", -51), ("pitch", 51), ("pitch", -51)])
    def test_prosody_out_of_bounds_is_a_400(self, client, monkeypatch, field, value):
        _config(monkeypatch, {"provider": "edge"})
        resp = _speak(client, **{field: value})
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "invalid_prosody"

    def test_prosody_is_ignored_where_unsupported(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "elevenlabs"})
        sdk = _elevenlabs_sdk()
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            assert _speak(client, rate=20, pitch=5).status_code == 200


# ------------------------------------------------------------------ GET /api/audio/voice-config
class TestVoiceConfig:
    def test_elevenlabs_advertises_selection_and_sample_and_never_the_key(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "elevenlabs"})
        resp = client.get("/api/audio/voice-config")
        assert resp.status_code == 200
        assert KEY not in resp.text and "api_key" not in resp.text
        tts = resp.json()["tts"]
        assert tts["voice_selection"] is True and tts["voice_preview"] == "sample" and tts["prosody"] is False
        assert tts["provider"] == "elevenlabs"

    def test_edge_lists_voices_and_previews_by_speaking(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "edge"})
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: [
            {"ShortName": "nl-NL-FennaNeural", "Locale": "nl-NL", "FriendlyName": "Microsoft Fenna Online (Natural) - Dutch"},
            {"ShortName": "en-US-AriaNeural", "Locale": "en-US", "FriendlyName": "Microsoft Aria Online (Natural) - English"}])
        assert tts_voice.edge_voices() is not None  # voice-config never waits for a cold list: warm it
        tts = client.get("/api/audio/voice-config?language=nl").json()["tts"]
        assert tts["mode"] == "relay" and tts["reason"] == "provider 'edge' has no client wire"
        assert tts["voices"] == [{"id": "nl-NL-FennaNeural", "name": "Fenna", "language": "nl-NL"}]
        assert tts["voice_selection"] is True and tts["voice_preview"] == "speak" and tts["prosody"] is True

    def test_a_cold_edge_list_is_loading_not_awaited(self, client, monkeypatch):
        import threading
        import time
        _config(monkeypatch, {"provider": "edge"})
        release = threading.Event()

        def fetch():
            release.wait(10)
            return [{"ShortName": "nl-NL-FennaNeural", "Locale": "nl-NL"}]
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", fetch)
        started = time.monotonic()
        tts = client.get("/api/audio/voice-config").json()["tts"]
        assert time.monotonic() - started < 2
        assert tts["voices"] == [] and tts["voices_error"] == "loading" and tts["voice_selection"] is True
        release.set()
        _settle_edge()
        tts = client.get("/api/audio/voice-config").json()["tts"]
        assert [v["id"] for v in tts["voices"]] == ["nl-NL-FennaNeural"] and "voices_error" not in tts

    @pytest.mark.parametrize("provider,preview", [
        ("elevenlabs", "sample"), ("edge", "speak"), ("openai", None), ("gemini", None), ("xai", None),
        ("mistral", None), ("minimax", None), ("deepinfra", None), ("piper", None), ("neutts", None),
    ])
    def test_voice_preview_per_provider(self, provider, preview):
        monkey = pytest.MonkeyPatch()
        try:
            monkey.setattr(tts_voice, "_fetch_edge_voices", lambda: [])
            tts_voice.edge_voices()  # warm: voice_capabilities never waits for a cold list
            caps = tts_voice.voice_capabilities({}, provider)
        finally:
            monkey.undo()
        assert caps.get("voice_preview") == preview
        assert ("voice_preview" in caps) is (preview is not None)

    def test_bad_language_filter_is_a_400(self, client, monkeypatch):
        _config(monkeypatch, {"provider": "edge"})
        assert client.get("/api/audio/voice-config?language=../x").status_code == 400


# ------------------------------------------------------------------ ElevenLabs preview
VOICES_BODY = {"voices": [
    {"voice_id": EL_VOICE, "name": "Rachel", "category": "premade", "preview_url": PREVIEW_URL},
    {"voice_id": EL_OTHER, "name": "Mine", "category": "cloned"},
]}


@pytest.fixture
def previews(monkeypatch):
    from hermes_cli.web_routers import audio

    calls = {"list": 0, "fetch": []}

    async def fake_list(api_key):
        calls["list"] += 1
        assert api_key == KEY
        return VOICES_BODY

    def fake_fetch(url):
        calls["fetch"].append(url)
        return b"ID3sample", "audio/mpeg"

    monkeypatch.setattr(audio, "_fetch_elevenlabs_voices", fake_list)
    monkeypatch.setattr(audio, "_elevenlabs_api_key", lambda profile: KEY)
    monkeypatch.setattr(tts_voice, "fetch_preview", fake_fetch)
    return calls


class TestPreviewRoute:
    def test_voices_say_preview_but_never_give_the_url_or_the_key(self, client, previews):
        resp = client.get("/api/audio/elevenlabs/voices")
        body = resp.json()
        assert [(v["voice_id"], v["preview"]) for v in body["voices"]] == [(EL_OTHER, False), (EL_VOICE, True)]
        assert PREVIEW_URL not in resp.text and "preview_url" not in resp.text and KEY not in resp.text

    def test_streams_the_sample_with_headers(self, client, previews):
        resp = client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview")
        assert resp.status_code == 200
        assert resp.content == b"ID3sample"
        assert resp.headers["content-type"] == "audio/mpeg"
        assert resp.headers["cache-control"] == "private, max-age=3600"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert previews["fetch"] == [PREVIEW_URL]
        assert KEY not in resp.text and PREVIEW_URL not in str(resp.headers)

    def test_second_request_is_served_from_the_cache(self, client, previews):
        for _ in range(3):
            assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview").status_code == 200
        assert previews["fetch"] == [PREVIEW_URL] and previews["list"] == 1

    def test_unknown_voice_is_404(self, client, previews):
        assert client.get("/api/audio/elevenlabs/voices/NoSuchVoice123/preview").status_code == 404
        assert previews["fetch"] == []

    def test_voice_without_a_sample_is_404(self, client, previews):
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_OTHER}/preview").status_code == 404

    def test_no_key_is_404(self, client, previews, monkeypatch):
        from hermes_cli.web_routers import audio
        monkeypatch.setattr(audio, "_elevenlabs_api_key", lambda profile: "")
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview").status_code == 404

    @pytest.mark.parametrize("voice_id", ["a" * 129, "a;b", "a%20b", "-x"])
    def test_malformed_voice_id_is_400(self, client, previews, voice_id):
        assert client.get(f"/api/audio/elevenlabs/voices/{voice_id}/preview").status_code == 400

    def test_upstream_failure_is_502_without_leaking_the_url(self, client, previews, monkeypatch):
        def boom(url):
            raise tts_voice.PreviewError(f"preview fetch failed: {url}")
        monkeypatch.setattr(tts_voice, "fetch_preview", boom)
        resp = client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview")
        assert resp.status_code == 502
        assert PREVIEW_URL not in resp.text and KEY not in resp.text

    def test_foreign_host_from_elevenlabs_is_502_through_the_real_fetch(self, client, monkeypatch):
        from hermes_cli.web_routers import audio

        async def fake_list(api_key):
            return {"voices": [{"voice_id": EL_VOICE, "preview_url": "https://evil.example/x.mp3"}]}

        monkeypatch.setattr(audio, "_fetch_elevenlabs_voices", fake_list)
        monkeypatch.setattr(audio, "_elevenlabs_api_key", lambda profile: KEY)
        with patch("urllib.request.build_opener", side_effect=AssertionError("must not connect")):
            resp = client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview")
        assert resp.status_code == 502
        assert "evil.example" not in resp.text


# ------------------------------------------------------------------ speak-stream
def _url() -> str:
    return f"/api/audio/speak-stream?{urlencode({'token': web_server._SESSION_TOKEN})}"


class _Streamer:
    sample_rate = 24000
    channels = 1

    def __init__(self, label: bytes):
        self.label = label
        self.requests: list[str] = []

    def stream(self, text):
        self.requests.append(text)
        yield self.label


@pytest.fixture
def stream_client(client):
    return client


def _patch_stream(monkeypatch, provider="elevenlabs"):
    made: dict[str, _Streamer] = {}

    def resolve(cfg):
        voice = ((cfg.get(provider) or {}).get("voice_id")) or "default"
        return made.setdefault(voice, _Streamer(voice.encode()))

    monkeypatch.setattr("tools.tts_streaming.resolve_streaming_provider", resolve)
    monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {"provider": provider})
    monkeypatch.setattr("tools.tts_tool._get_provider", lambda cfg: provider)
    monkeypatch.setattr("tools.tts_tool._resolve_max_text_length", lambda p, c: 4000)
    return made


def _drain(conn):
    frames = []
    while True:
        message = conn.receive()
        if message.get("bytes") is not None:
            frames.append(message["bytes"])
        else:
            frames.append(json.loads(message["text"]))
            if frames[-1].get("type") in ("end", "error"):
                return frames


class TestSpeakStreamVoice:
    def test_voice_on_the_first_frame_selects_the_elevenlabs_voice(self, stream_client, monkeypatch):
        made = _patch_stream(monkeypatch)
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": EL_VOICE, "done": True}))
            frames = _drain(conn)
        assert frames[0] == {"type": "start", "sample_rate": 24000, "channels": 1}
        assert frames[1] == EL_VOICE.encode() and frames[-1] == {"type": "end"}
        assert made[EL_VOICE].requests == ["Hello there."]
        assert made["default"].requests == []  # the configured voice spoke nothing

    def test_without_voice_the_configured_streamer_speaks(self, stream_client, monkeypatch):
        made = _patch_stream(monkeypatch)
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "done": True}))
            frames = _drain(conn)
        assert frames[1] == b"default" and list(made) == ["default"]

    def test_unknown_voice_is_an_error_frame_and_nothing_is_spoken(self, stream_client, monkeypatch):
        made = _patch_stream(monkeypatch)
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": "NotOnThisAccount123", "done": True}))
            frames = _drain(conn)
        assert frames == [{"type": "error", "code": "unknown_voice",
                           "message": "elevenlabs has no voice 'NotOnThisAccount123'"}]
        assert made["default"].requests == []

    @pytest.mark.parametrize("voice,code", [("a" * 129, "invalid_voice"), ("a b", "invalid_voice"), (7, "invalid_voice")])
    def test_bad_voice_is_an_error_frame(self, stream_client, monkeypatch, voice, code):
        _patch_stream(monkeypatch)
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": voice}))
            assert _drain(conn)[0]["code"] == code

    def test_provider_without_per_request_voice_is_an_error_frame(self, stream_client, monkeypatch):
        _patch_stream(monkeypatch, provider="piper")
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": "en_US-lessac"}))
            assert _drain(conn)[0]["code"] == "voice_unsupported"

    def test_blank_voice_is_no_voice(self, stream_client, monkeypatch):
        _patch_stream(monkeypatch)
        with stream_client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": "  ", "done": True}))
            assert _drain(conn)[1] == b"default"


# ------------------------------------------------------------------ the voice list that is not a list
class _Body:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._body).encode()


class TestMalformedElevenLabsBody:
    @pytest.mark.parametrize("body", [[], "text", 5, None, {"voices": "x"}, {"voices": {"a": 1}}])
    def test_voices_and_preview_answer_502(self, client, monkeypatch, body):
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _Body(body))
        assert client.get("/api/audio/elevenlabs/voices").status_code == 502
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview").status_code == 502


# ------------------------------------------------------------------ the streamer is not tts.provider's
class TestSpeakStreamFallbackForAnotherProvider:
    def _connect(self, client, voice, **extra):
        with client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", **({"voice": voice} if voice else {}), **extra,
                                       "done": True}))
            return _drain(conn)

    @pytest.mark.parametrize("streaming", [{"provider": "elevenlabs"}, {"provider": "auto"}])
    def test_a_voice_with_a_streamer_of_another_provider_answers_fallback(self, client, monkeypatch, streaming):
        # tts.provider is Edge (voice-config lists Edge's voices, POST /speak speaks with Edge) but the
        # streamer is ElevenLabs': the voice is not for the streamer, so the client is sent to /speak.
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {"provider": "edge", "streaming": streaming})
        sdk = MagicMock()
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            with client.websocket_connect(_url()) as conn:
                conn.send_text(json.dumps({"text": "Hello there.", "voice": "nl-NL-FennaNeural", "done": True}))
                message = conn.receive()
                assert json.loads(message["text"]) == {"type": "fallback"}
        sdk.text_to_speech.convert.assert_not_called()

    def test_without_a_voice_that_streamer_still_speaks(self, client, monkeypatch):
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {
            "provider": "edge", "streaming": {"provider": "elevenlabs"}})
        sdk = MagicMock()
        sdk.text_to_speech.convert.side_effect = lambda **kw: iter([b"\x01\x02"])
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            frames = self._connect(client, None)
        assert frames[0]["type"] == "start" and frames[1] == b"\x01\x02" and frames[-1] == {"type": "end"}

    def test_the_same_provider_keeps_working(self, client, monkeypatch):
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {
            "provider": "elevenlabs", "streaming": {"provider": "elevenlabs"}})
        sdk = MagicMock()
        sdk.text_to_speech.convert.side_effect = lambda **kw: iter([b"\x01\x02"])
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=sdk)):
            frames = self._connect(client, EL_VOICE)
        assert frames[-1] == {"type": "end"}
        assert sdk.text_to_speech.convert.call_args.kwargs["voice_id"] == EL_VOICE


class TestSpeakStreamProviderRefusesThePassedThroughVoice:
    def test_an_error_frame_instead_of_a_silent_start_and_end(self, client, monkeypatch):
        class Refusing(_Streamer):
            def stream(self, text):
                raise RuntimeError("400: no such voice")
                yield b""  # pragma: no cover - makes it a generator

        monkeypatch.setattr("tools.tts_streaming.resolve_streaming_provider", lambda cfg: (
            Refusing(b"x") if (cfg.get("openai") or {}).get("voice") else _Streamer(b"default")))
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {"provider": "openai"})
        monkeypatch.setattr("tools.tts_tool._get_provider", lambda cfg: "openai")
        monkeypatch.setattr("tools.tts_tool._resolve_max_text_length", lambda p, c: 4000)
        with client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": "my_cloned_voice-1", "done": True}))
            frames = _drain(conn)
        assert frames == [{"type": "error", "code": "voice_failed",
                           "message": "The provider could not speak that voice"}]

    def test_a_failure_without_a_named_voice_ends_as_it_always_did(self, client, monkeypatch):
        class Failing(_Streamer):
            def stream(self, text):
                raise RuntimeError("boom")
                yield b""  # pragma: no cover

        monkeypatch.setattr("tools.tts_streaming.resolve_streaming_provider", lambda cfg: Failing(b"x"))
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {"provider": "openai"})
        monkeypatch.setattr("tools.tts_tool._get_provider", lambda cfg: "openai")
        monkeypatch.setattr("tools.tts_tool._resolve_max_text_length", lambda p, c: 4000)
        with client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "done": True}))
            assert [f for f in _drain(conn) if isinstance(f, dict)] == [
                {"type": "start", "sample_rate": 24000, "channels": 1}, {"type": "end"}]


class TestSpeakStreamProducerThread:
    @staticmethod
    def _record_producers(monkeypatch):
        """Every producer thread the route starts (it may be gone again before a test looks)."""
        import threading
        started = []
        real_start = threading.Thread.start

        def start(self):
            if self.name == "speak-stream-producer":
                started.append(self)
            return real_start(self)

        monkeypatch.setattr(threading.Thread, "start", start)
        return started

    @staticmethod
    def _gone(threads, timeout=5.0):
        import time
        end = time.monotonic() + timeout
        while any(t.is_alive() for t in threads) and time.monotonic() < end:
            time.sleep(0.02)
        return not any(t.is_alive() for t in threads)

    def test_the_producer_exits_after_an_error_frame(self, client, monkeypatch):
        _patch_stream(monkeypatch)
        started = self._record_producers(monkeypatch)
        with client.websocket_connect(_url()) as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": "NotOnThisAccount123"}))
            assert _drain(conn)[0]["code"] == "unknown_voice"
        assert len(started) == 1 and self._gone(started)

    def test_the_producer_exits_after_a_fallback_frame(self, client, monkeypatch):
        monkeypatch.setattr("tools.tts_tool._load_tts_config", lambda: {
            "provider": "edge", "streaming": {"provider": "elevenlabs"}})
        started = self._record_producers(monkeypatch)
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock()):
            with client.websocket_connect(_url()) as conn:
                conn.send_text(json.dumps({"text": "Hello there.", "voice": "nl-NL-FennaNeural"}))
                assert json.loads(conn.receive()["text"]) == {"type": "fallback"}
        assert len(started) == 1 and self._gone(started)


# ------------------------------------------------------------------ two profiles, two ElevenLabs accounts
KEY_B = "sk-el-BETA-SECRET"
PREVIEW_B = "https://storage.googleapis.com/eleven-public-prod/premade/voices/beta/sample.mp3"
PREVIEW_B_SHARED = "https://storage.googleapis.com/eleven-public-prod/premade/voices/beta-rachel/sample.mp3"
B_VOICE = "BetaOnlyVoice0000001"
DEFAULT_ONLY = "DefaultOnlyVoice0001"
ACCOUNT_VOICES = {
    KEY: {"voices": [
        {"voice_id": EL_VOICE, "name": "Rachel", "category": "premade", "preview_url": PREVIEW_URL},
        {"voice_id": DEFAULT_ONLY, "name": "Dora", "category": "cloned", "preview_url": PREVIEW_URL},
    ]},
    KEY_B: {"voices": [
        {"voice_id": B_VOICE, "name": "Bea", "category": "cloned", "preview_url": PREVIEW_B},
        {"voice_id": EL_VOICE, "name": "Rachel (beta)", "category": "premade", "preview_url": PREVIEW_B_SHARED},
    ]},
}


@pytest.fixture
def two_profiles(tmp_path, monkeypatch, _isolate_hermes_home):
    """The default profile (key from the process env) and ``worker_beta`` (key in its own .env), each
    with its own ElevenLabs voice and its own account's voice list behind ``urllib``."""
    import yaml
    from hermes_constants import get_hermes_home
    from hermes_cli import profiles

    default_home = get_hermes_home()
    profiles_root = default_home / "profiles"
    beta_home = profiles_root / "worker_beta"
    for home, voice in ((default_home, "default-voice"), (beta_home, "beta-voice")):
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.yaml").write_text(yaml.safe_dump(
            {"tts": {"provider": "elevenlabs", "elevenlabs": {"voice_id": voice}}}), encoding="utf-8")
    (beta_home / ".env").write_text(f"ELEVENLABS_API_KEY={KEY_B}\n", encoding="utf-8")
    monkeypatch.setattr(profiles, "_get_default_hermes_home", lambda: default_home)
    monkeypatch.setattr(profiles, "_get_profiles_root", lambda: profiles_root)

    seen_keys: list[str] = []

    def urlopen(request, timeout=None):
        key = request.get_header("Xi-api-key")
        seen_keys.append(key)
        return _Body(ACCOUNT_VOICES[key])

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", _REAL_FETCH_ELEVENLABS_IDS)
    fetched: list[str] = []
    monkeypatch.setattr(tts_voice, "fetch_preview", lambda url: fetched.append(url) or (b"sample:" + url.encode(), "audio/mpeg"))
    return {"seen_keys": seen_keys, "fetched": fetched, "beta": "worker_beta"}


def _elevenlabs_sdk_recording():
    calls: list[dict] = []

    def make_client(api_key=None, **kwargs):
        client = MagicMock()

        def convert(**kw):
            calls.append({"api_key": api_key, **kw})
            return iter([b"\x01\x02"])

        client.text_to_speech.convert.side_effect = convert
        return client

    return calls, make_client


class TestProfileScoping:
    def test_voices_list_is_the_requested_profiles(self, client, two_profiles):
        beta = client.get("/api/audio/elevenlabs/voices?profile=worker_beta").json()
        assert [v["voice_id"] for v in beta["voices"]] == [B_VOICE, EL_VOICE]
        default = client.get("/api/audio/elevenlabs/voices").json()
        assert [v["voice_id"] for v in default["voices"]] == [DEFAULT_ONLY, EL_VOICE]
        assert two_profiles["seen_keys"] == [KEY_B, KEY]

    def test_preview_uses_profile_b_key_and_list(self, client, two_profiles):
        resp = client.get(f"/api/audio/elevenlabs/voices/{B_VOICE}/preview?profile=worker_beta")
        assert resp.status_code == 200 and resp.content == b"sample:" + PREVIEW_B.encode()
        assert two_profiles["seen_keys"] == [KEY_B]
        # The default profile's account has no such voice.
        assert client.get(f"/api/audio/elevenlabs/voices/{B_VOICE}/preview").status_code == 404
        assert two_profiles["seen_keys"] == [KEY_B, KEY]

    def test_preview_cache_is_not_shared_across_keys(self, client, two_profiles):
        # The same voice id, a different sample on each account.
        first = client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview")
        second = client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview?profile=worker_beta")
        assert first.content == b"sample:" + PREVIEW_URL.encode()
        assert second.content == b"sample:" + PREVIEW_B_SHARED.encode()
        # ... and each is a hit for its own key afterwards.
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview").content == first.content
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview?profile=worker_beta").content == second.content
        assert two_profiles["fetched"] == [PREVIEW_URL, PREVIEW_B_SHARED]

    def test_speak_with_voice_uses_profile_b_key_and_list(self, client, two_profiles):
        calls, make_client = _elevenlabs_sdk_recording()
        with patch("tools.tts_tool._import_elevenlabs", return_value=make_client):
            resp = client.post("/api/audio/speak?profile=worker_beta", json={"text": "Hello there", "voice": B_VOICE})
            assert resp.status_code == 200, resp.text
            assert calls[-1]["api_key"] == KEY_B and calls[-1]["voice_id"] == B_VOICE
            # B's voice is not on the default account, and the default's is not on B's.
            default = _speak(client, voice=B_VOICE)
            assert default.status_code == 400 and default.json()["detail"]["code"] == "unknown_voice"
            beta = client.post("/api/audio/speak?profile=worker_beta", json={"text": "Hi", "voice": DEFAULT_ONLY})
            assert beta.status_code == 400 and beta.json()["detail"]["code"] == "unknown_voice"
            assert len(calls) == 1
            ok = _speak(client, voice=DEFAULT_ONLY)
            assert ok.status_code == 200 and calls[-1]["api_key"] == KEY and calls[-1]["voice_id"] == DEFAULT_ONLY

    def test_speak_stream_voice_check_uses_profile_b_key_and_list(self, client, two_profiles):
        calls, make_client = _elevenlabs_sdk_recording()
        profile_url = _url() + "&profile=worker_beta"
        with patch("tools.tts_tool._import_elevenlabs", return_value=make_client):
            with client.websocket_connect(profile_url) as conn:
                conn.send_text(json.dumps({"text": "Hello there.", "voice": B_VOICE, "done": True}))
                frames = _drain(conn)
            assert frames[-1] == {"type": "end"}
            assert calls[-1]["api_key"] == KEY_B and calls[-1]["voice_id"] == B_VOICE
            with client.websocket_connect(profile_url) as conn:
                conn.send_text(json.dumps({"text": "Hello there.", "voice": DEFAULT_ONLY, "done": True}))
                assert _drain(conn)[0]["code"] == "unknown_voice"
            with client.websocket_connect(_url()) as conn:
                conn.send_text(json.dumps({"text": "Hello there.", "voice": B_VOICE, "done": True}))
                assert _drain(conn)[0]["code"] == "unknown_voice"
            assert len(calls) == 1

    def test_voice_config_follows_the_profile(self, client, two_profiles):
        beta = client.get("/api/audio/voice-config?profile=worker_beta")
        default = client.get("/api/audio/voice-config")
        assert beta.json()["tts"]["voice"] == "beta-voice" and default.json()["tts"]["voice"] == "default-voice"
        for resp in (beta, default):
            assert resp.json()["tts"]["voice_selection"] is True
            assert KEY not in resp.text and KEY_B not in resp.text and "api_key" not in resp.text

    def test_an_unknown_profile_is_a_404_on_every_rest_route(self, client, two_profiles):
        assert client.get("/api/audio/voice-config?profile=ghost").status_code == 404
        assert client.get("/api/audio/elevenlabs/voices?profile=ghost").status_code == 404
        assert client.get(f"/api/audio/elevenlabs/voices/{EL_VOICE}/preview?profile=ghost").status_code == 404
        assert client.post("/api/audio/speak?profile=ghost", json={"text": "x", "voice": EL_VOICE}).status_code == 404
        assert two_profiles["seen_keys"] == []  # nothing was asked of ElevenLabs

    def test_an_unknown_profile_on_the_socket_falls_back_and_speak_then_says_404(self, client, two_profiles):
        with client.websocket_connect(_url() + "&profile=ghost") as conn:
            conn.send_text(json.dumps({"text": "Hello there.", "voice": EL_VOICE}))
            assert json.loads(conn.receive()["text"]) == {"type": "fallback"}
        assert two_profiles["seen_keys"] == []
