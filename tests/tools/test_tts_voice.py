"""Per-request TTS voice and prosody (tools.tts_voice) and what voice-config advertises.

Providers are mocked at the SDK seam (Edge ``Communicate``, the ElevenLabs and OpenAI clients), so
what is asserted is the voice the provider code actually receives, not the config that was built.
"""

import asyncio
import json
import sys
import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from tools import tts_voice
from tools.tts_voice import VoiceSelection, VoiceSelectionError, resolve_voice_selection


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    for key in ("ELEVENLABS_API_KEY", "OPENAI_API_KEY", "HERMES_SESSION_PLATFORM"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(tts_voice, "_edge_cache", {"at": 0.0, "voices": None, "failed_at": 0.0})
    monkeypatch.setattr(tts_voice, "_el_cache", {})
    # Never reach the network from a unit test unless the test installs its own fetcher.
    monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: pytest.fail("edge list fetched"))
    monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda key, base: pytest.fail("el list fetched"))


EDGE_RAW = [
    {"ShortName": "nl-NL-FennaNeural", "Locale": "nl-NL", "Gender": "Female",
     "FriendlyName": "Microsoft Fenna Online (Natural) - Dutch (Netherlands)"},
    {"ShortName": "nl-BE-ArnaudNeural", "Locale": "nl-BE", "Gender": "Male",
     "FriendlyName": "Microsoft Arnaud Online (Natural) - Dutch (Belgium)"},
    {"ShortName": "en-US-AriaNeural", "Locale": "en-US", "Gender": "Female",
     "FriendlyName": "Microsoft Aria Online (Natural) - English (United States)"},
    {"ShortName": "xx-XX-NoFriendly", "Locale": "xx-XX"},
    {"nonsense": True},
]


def _edge_list(monkeypatch):
    monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: EDGE_RAW)


# --------------------------------------------------------------------------- validation
class TestValidation:
    @pytest.mark.parametrize("voice", ["a" * 129, "a" * 1000])
    def test_too_long(self, voice):
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "openai", voice)
        assert err.value.code == "invalid_voice"

    def test_exactly_128_is_fine(self):
        assert resolve_voice_selection({}, "openai", "a" * 128).voice == "a" * 128

    @pytest.mark.parametrize("voice", [
        "al oy", "../etc/passwd", "alloy;rm", "<speak>", "voi\nce", "-leading", ".leading", "café", "a/b", "a%20b",
    ])
    def test_bad_charset(self, voice):
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "openai", voice)
        assert err.value.code == "invalid_voice"

    def test_not_a_string(self):
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "openai", 5)
        assert err.value.code == "invalid_voice"

    def test_blank_voice_names_no_voice(self):
        assert resolve_voice_selection({}, "openai", "   ") is None
        assert resolve_voice_selection({}, "openai", None) is None

    @pytest.mark.parametrize("provider", ["piper", "neutts", "kittentts", "my-command-provider"])
    def test_provider_without_per_request_voice(self, provider):
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, provider, "alloy")
        assert err.value.code == "voice_unsupported"

    def test_openai_passes_unknown_names_through(self):
        # OpenAI-compatible servers have voices of their own: there is no list to check against.
        assert resolve_voice_selection({}, "openai", "my_cloned_voice-1").voice == "my_cloned_voice-1"


# --------------------------------------------------------------------------- apply (no mutation)
class TestApply:
    @pytest.mark.parametrize("provider,section,key", [
        ("edge", "edge", "voice"), ("elevenlabs", "elevenlabs", "voice_id"), ("openai", "openai", "voice"),
        ("deepinfra", "deepinfra", "voice"), ("gemini", "gemini", "voice"), ("xai", "xai", "voice_id"),
        ("mistral", "mistral", "voice_id"), ("minimax", "minimax", "voice_id"),
    ])
    def test_sets_the_providers_voice_key_on_a_copy(self, provider, section, key):
        original = {section: {key: "old", "model": "m"}}
        out = VoiceSelection(voice="new").apply(original, provider)
        assert out[section] == {key: "new", "model": "m"}
        assert original == {section: {key: "old", "model": "m"}}  # cached config untouched

    def test_no_section_yet(self):
        assert VoiceSelection(voice="x").apply({}, "openai") == {"openai": {"voice": "x"}}


# --------------------------------------------------------------------------- Edge
class TestEdge:
    def test_known_voice_accepted_unknown_rejected(self, monkeypatch):
        _edge_list(monkeypatch)
        assert resolve_voice_selection({}, "edge", "nl-NL-FennaNeural").voice == "nl-NL-FennaNeural"
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "edge", "nl-NL-NoSuchNeural")
        assert err.value.code == "unknown_voice"

    def test_unreachable_list_passes_through(self, monkeypatch):
        def boom():
            raise OSError("offline")
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", boom)
        assert resolve_voice_selection({}, "edge", "nl-NL-FennaNeural").voice == "nl-NL-FennaNeural"

    def test_list_is_cached_and_failure_not_retried_for_a_minute(self, monkeypatch):
        calls = []
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: calls.append(1) or EDGE_RAW)
        tts_voice.edge_voices()
        tts_voice.edge_voices()
        assert len(calls) == 1

        monkeypatch.setattr(tts_voice, "_edge_cache", {"at": 0.0, "voices": None, "failed_at": 0.0})
        failing = []

        def boom():
            failing.append(1)
            raise OSError("offline")
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", boom)
        assert tts_voice.edge_voices() is None
        assert tts_voice.edge_voices() is None
        assert len(failing) == 1

    def test_voices_shape_and_language_filter(self, monkeypatch):
        _edge_list(monkeypatch)
        everything = tts_voice.voice_capabilities({}, "edge")["voices"]
        assert {"id": "nl-NL-FennaNeural", "name": "Fenna", "language": "nl-NL"} in everything
        assert {"id": "xx-XX-NoFriendly", "name": "xx-XX-NoFriendly", "language": "xx-XX"} in everything
        assert all(set(v) == {"id", "name", "language"} for v in everything)
        assert len(everything) == 4  # the entry without a ShortName is dropped

        dutch = tts_voice.voice_capabilities({}, "edge", "nl")["voices"]
        assert [v["id"] for v in dutch] == ["nl-BE-ArnaudNeural", "nl-NL-FennaNeural"]
        only_nl = tts_voice.voice_capabilities({}, "edge", "NL-nl")["voices"]
        assert [v["id"] for v in only_nl] == ["nl-NL-FennaNeural"]
        assert tts_voice.voice_capabilities({}, "edge", "fr")["voices"] == []

    def test_list_failure_is_reported_not_hidden(self, monkeypatch):
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: (_ for _ in ()).throw(OSError("x")))
        caps = tts_voice.voice_capabilities({}, "edge")
        assert caps["voices"] == [] and caps["voices_error"] == "unavailable"

    def test_capabilities(self, monkeypatch):
        _edge_list(monkeypatch)
        caps = tts_voice.voice_capabilities({}, "edge")
        assert caps["voice_selection"] is True and caps["prosody"] is True
        assert caps["voice"] == "en-US-AriaNeural"
        assert tts_voice.voice_capabilities({"edge": {"voice": "nl-NL-FennaNeural"}}, "edge")["voice"] == "nl-NL-FennaNeural"

    def _synthesize(self, tmp_path, selection, config=None):
        comm = MagicMock()
        comm.save = AsyncMock(side_effect=lambda path: open(path, "wb").write(b"ID3audio"))
        edge = MagicMock()
        edge.Communicate = MagicMock(return_value=comm)
        out = tmp_path / "o.mp3"
        with patch("tools.tts_tool._import_edge_tts", return_value=edge), \
                patch("tools.tts_tool._load_tts_config", return_value=config or {"provider": "edge"}):
            from tools.tts_tool import text_to_speech_tool
            result = json.loads(text_to_speech_tool("Hello there", output_path=str(out), voice_selection=selection))
        assert result["success"], result
        return edge.Communicate.call_args

    def test_voice_reaches_communicate(self, tmp_path):
        call = self._synthesize(tmp_path, VoiceSelection(voice="nl-NL-FennaNeural"))
        assert call.kwargs["voice"] == "nl-NL-FennaNeural"
        assert "rate" not in call.kwargs and "pitch" not in call.kwargs

    def test_without_selection_behaviour_is_unchanged(self, tmp_path):
        call = self._synthesize(tmp_path, None, {"provider": "edge", "edge": {"voice": "en-GB-SoniaNeural"}})
        assert call.kwargs["voice"] == "en-GB-SoniaNeural"

    def test_prosody_reaches_communicate_and_adds_to_speed(self, tmp_path):
        call = self._synthesize(tmp_path, VoiceSelection(rate=20, pitch=-10))
        assert call.kwargs["rate"] == "+20%" and call.kwargs["pitch"] == "-10Hz"
        call = self._synthesize(tmp_path, VoiceSelection(rate=-10), {"provider": "edge", "speed": 1.5})
        assert call.kwargs["rate"] == "+40%"  # speed 1.5 = +50%, hint -10


class TestProsodyBounds:
    @pytest.mark.parametrize("rate,pitch", [
        (-50, -50), (100, 50), (0, 0), (12.4, -3.6),
    ])
    def test_inside_the_bounds(self, monkeypatch, rate, pitch):
        _edge_list(monkeypatch)
        sel = resolve_voice_selection({}, "edge", None, rate, pitch)
        assert (sel.rate, sel.pitch) == (round(rate), round(pitch)) or (rate, pitch) == (0, 0)

    @pytest.mark.parametrize("kwargs", [
        {"rate": -51}, {"rate": 101}, {"pitch": -51}, {"pitch": 51},
        {"rate": float("nan")}, {"rate": float("inf")}, {"pitch": True}, {"rate": "fast"},
    ])
    def test_outside_the_bounds_is_an_error(self, kwargs):
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "edge", None, **kwargs)
        assert err.value.code == "invalid_prosody"

    @pytest.mark.parametrize("provider", ["openai", "elevenlabs", "piper"])
    def test_ignored_by_providers_without_prosody(self, provider):
        assert resolve_voice_selection({}, provider, None, 20, 10) is None
        assert tts_voice.supports_prosody(provider) is False

    def test_still_checked_for_providers_that_ignore_it(self):
        with pytest.raises(VoiceSelectionError):
            resolve_voice_selection({}, "openai", None, 5000, None)


# --------------------------------------------------------------------------- ElevenLabs
EL_VOICE = "21m00Tcm4TlvDq8ikWAM"
EL_OTHER = "AZnzlk1XvdvUeBnXmlld"


class TestElevenLabs:
    def _ids(self, monkeypatch, ids=(EL_VOICE, EL_OTHER)):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")
        calls = []
        monkeypatch.setattr(
            tts_voice, "_fetch_elevenlabs_voice_ids", lambda key, base: calls.append((key, base)) or set(ids))
        return calls

    def test_known_voice_id_accepted(self, monkeypatch):
        self._ids(monkeypatch)
        assert resolve_voice_selection({}, "elevenlabs", EL_VOICE).voice == EL_VOICE

    def test_unknown_voice_id_rejected(self, monkeypatch):
        self._ids(monkeypatch)
        with pytest.raises(VoiceSelectionError) as err:
            resolve_voice_selection({}, "elevenlabs", "notAVoiceOnThisAccount1")
        assert err.value.code == "unknown_voice"

    def test_list_cached_per_account(self, monkeypatch):
        calls = self._ids(monkeypatch)
        resolve_voice_selection({}, "elevenlabs", EL_VOICE)
        resolve_voice_selection({}, "elevenlabs", EL_OTHER)
        assert len(calls) == 1
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-another-account")
        resolve_voice_selection({}, "elevenlabs", EL_VOICE)
        assert len(calls) == 2

    def test_cache_never_holds_the_key(self, monkeypatch):
        self._ids(monkeypatch)
        resolve_voice_selection({}, "elevenlabs", EL_VOICE)
        assert "sk-el-test" not in repr(tts_voice._el_cache)

    def test_list_failure_or_no_key_passes_through(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda k, b: (_ for _ in ()).throw(OSError("x")))
        assert resolve_voice_selection({}, "elevenlabs", "AnythingGoes123").voice == "AnythingGoes123"
        monkeypatch.delenv("ELEVENLABS_API_KEY")
        assert resolve_voice_selection({}, "elevenlabs", "AnythingGoes123").voice == "AnythingGoes123"

    def test_voice_selection_advertised_without_a_voice_list(self):
        caps = tts_voice.voice_capabilities({}, "elevenlabs")
        assert caps["voice_selection"] is True and caps["prosody"] is False
        assert caps["voice"] == "pNInz6obpgDQGcFmaJgB" and "voices" not in caps

    def test_voice_id_reaches_the_sdk(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")
        client = MagicMock()
        client.text_to_speech.convert.return_value = iter([b"ID3audio"])
        with patch("tools.tts_tool._import_elevenlabs", return_value=MagicMock(return_value=client)), \
                patch("tools.tts_tool._load_tts_config",
                      return_value={"provider": "elevenlabs", "elevenlabs": {"voice_id": "configured"}}):
            from tools.tts_tool import text_to_speech_tool
            result = json.loads(text_to_speech_tool(
                "Hello there", output_path=str(tmp_path / "o.mp3"), voice_selection=VoiceSelection(voice=EL_VOICE)))
        assert result["success"], result
        assert client.text_to_speech.convert.call_args.kwargs["voice_id"] == EL_VOICE

    def test_streamer_gets_the_voice_id(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")
        import tools.tts_streaming as ts
        cfg = VoiceSelection(voice=EL_VOICE).apply({"provider": "elevenlabs"}, "elevenlabs")
        streamer = ts.resolve_streaming_provider(cfg)
        assert isinstance(streamer, ts.ElevenLabsStreamer)
        assert streamer.section["voice_id"] == EL_VOICE
        assert tts_voice.streamer_provider_name(streamer, cfg, "x") == "elevenlabs"


# --------------------------------------------------------------------------- OpenAI
class TestOpenAI:
    def test_voice_reaches_the_sdk(self, tmp_path, monkeypatch):
        client = MagicMock()
        client.audio.speech.create.return_value.stream_to_file.side_effect = lambda p: open(p, "wb").write(b"ID3audio")
        with patch("tools.tts_tool._import_openai_client", return_value=MagicMock(return_value=client)), \
                patch("tools.tts_tool_openai._resolve_openai_audio_client_config", return_value=("k", None, False)), \
                patch("tools.tts_tool._load_tts_config", return_value={"provider": "openai"}):
            from tools.tts_tool import text_to_speech_tool
            result = json.loads(text_to_speech_tool(
                "Hello there", output_path=str(tmp_path / "o.mp3"), voice_selection=VoiceSelection(voice="coral")))
        assert result["success"], result
        assert client.audio.speech.create.call_args.kwargs["voice"] == "coral"

    def test_capabilities(self):
        caps = tts_voice.voice_capabilities({"openai": {"voice": "nova"}}, "openai")
        assert caps["voice_selection"] is True and caps["voice"] == "nova" and caps["prosody"] is False


def test_unsupported_provider_capabilities():
    caps = tts_voice.voice_capabilities({}, "piper")
    assert caps["voice_selection"] is False and caps["prosody"] is False and caps["voice"] is None
    assert "voices" not in caps


# --------------------------------------------------------------------------- voice-config carries no secrets
SECRETS = ("sk-el-SECRET", "sk-oai-SECRET", "di-SECRET", "gsk-SECRET", "mistral-SECRET", "xai-SECRET")


@pytest.fixture()
def voice_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    for var in ("GROQ_API_KEY", "OPENAI_API_KEY", "VOICE_TOOLS_OPENAI_KEY", "MISTRAL_API_KEY", "XAI_API_KEY",
                "ELEVENLABS_API_KEY", "DEEPINFRA_API_KEY", "HERMES_LOCAL_STT_LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-SECRET")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-SECRET")
    monkeypatch.setenv("DEEPINFRA_API_KEY", "di-SECRET")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-SECRET")
    monkeypatch.setenv("MISTRAL_API_KEY", "mistral-SECRET")
    monkeypatch.setenv("XAI_API_KEY", "xai-SECRET")

    def write(config: dict) -> None:
        (home / "config.yaml").write_text(yaml.safe_dump(config))
        for name in list(sys.modules):
            if name in {"hermes_cli.config", "tools.transcription_tools", "tools.tts_tool", "tools.voice_client_config"}:
                importlib.reload(sys.modules[name])
        # reloading tts_tool made fresh function objects; the voice module imports lazily so it follows

    yield write


def _public(language=None):
    from tools.voice_client_config import resolve_public_voice_config
    return resolve_public_voice_config(language)


class TestPublicVoiceConfig:
    @pytest.mark.parametrize("tts_provider,stt_provider", [
        ("elevenlabs", "elevenlabs"), ("openai", "openai"), ("deepinfra", "groq"), ("elevenlabs", "mistral"),
        ("edge", "groq"), ("xai", "xai"),
    ])
    def test_no_secret_anywhere(self, voice_home, monkeypatch, tts_provider, stt_provider):
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: EDGE_RAW)
        voice_home({"tts": {"provider": tts_provider}, "stt": {"provider": stt_provider}})
        # The internal resolver does hold the keys for the direct providers (that is what is being kept out).
        from tools.voice_client_config import resolve_client_voice_config
        internal = json.dumps(resolve_client_voice_config())
        out = json.dumps(_public("nl"))
        for secret in SECRETS:
            assert secret not in out, secret
        assert "api_key" not in out
        if tts_provider in ("elevenlabs", "openai", "deepinfra"):
            assert any(s in internal for s in SECRETS), "fixture should have exercised a keyed provider"

    def test_shape_the_app_parses_is_kept(self, voice_home):
        voice_home({"tts": {"provider": "elevenlabs", "elevenlabs": {"voice_id": "v1"}}})
        tts = _public()["tts"]
        assert tts["mode"] == "direct" and tts["provider"] == "elevenlabs" and tts["voice"] == "v1"
        assert tts["wire"] == "elevenlabs-tts" and "api_key" not in tts
        assert tts["voice_selection"] is True and tts["prosody"] is False

    def test_relay_reason_text_unchanged(self, voice_home, monkeypatch):
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: EDGE_RAW)
        voice_home({"tts": {"provider": "edge"}})
        tts = _public()["tts"]
        assert tts["mode"] == "relay" and tts["reason"] == "provider 'edge' has no client wire"
        assert tts["voice_selection"] is True and tts["prosody"] is True
        assert {"id": "nl-NL-FennaNeural", "name": "Fenna", "language": "nl-NL"} in tts["voices"]

    def test_language_filter(self, voice_home, monkeypatch):
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: EDGE_RAW)
        voice_home({"tts": {"provider": "edge"}})
        assert [v["id"] for v in _public("nl-BE")["tts"]["voices"]] == ["nl-BE-ArnaudNeural"]

    def test_command_provider_has_no_voice_selection(self, voice_home):
        voice_home({"tts": {"provider": "mine", "providers": {"mine": {"type": "command", "command": "true"}}}})
        tts = _public()["tts"]
        assert tts["voice_selection"] is False and tts["prosody"] is False and "voices" not in tts

    def test_client_direct_disabled_still_advertises(self, voice_home, monkeypatch):
        voice_home({"tts": {"provider": "elevenlabs"}, "voice": {"client_direct": False}})
        tts = _public()["tts"]
        assert tts["mode"] == "relay" and tts["voice_selection"] is True

    def test_url_credentials_and_nested_secrets_are_stripped(self):
        from tools.voice_client_config import _without_secrets
        out = _without_secrets({
            "base_url": "https://user:pw@host.example:8443/v1?key=abc#f",
            "api_key": "x", "extra_body": {"lang_code": "nl", "auth_token": "t", "headers": [{"Authorization": "b"}]},
            "voice": "v"})
        assert out == {"base_url": "https://host.example:8443/v1", "extra_body": {"lang_code": "nl", "headers": [{}]},
                       "voice": "v"}


# --------------------------------------------------------------------------- preview fetch guard
class _FakeResponse:
    def __init__(self, body=b"ID3sample", content_type="audio/mpeg"):
        import email.message
        self._body, self._pos = body, 0
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type

    def read(self, n=-1):
        chunk = self._body[self._pos:self._pos + (n if n and n > 0 else len(self._body))]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(monkeypatch, response=None, error=None):
    opened = []

    class Opener:
        def open(self, request, timeout=None):
            opened.append((request.full_url, timeout))
            if error:
                raise error
            return response or _FakeResponse()

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    return opened


class TestPreviewGuard:
    @pytest.mark.parametrize("url", [
        "https://storage.googleapis.com/eleven-public-prod/premade/voices/x/s.mp3",
        "https://api.elevenlabs.io/v1/voices/x/sample.mp3",
        "https://elevenlabs.io/s.mp3",
        "https://HOST.ELEVENLABS.IO/s.mp3",
    ])
    def test_allowed(self, monkeypatch, url):
        opened = _opener(monkeypatch)
        assert tts_voice.fetch_preview(url) == (b"ID3sample", "audio/mpeg")
        assert opened[0][1] == tts_voice.PREVIEW_TIMEOUT_SECONDS

    @pytest.mark.parametrize("url", [
        "http://storage.googleapis.com/x.mp3",  # not https
        "https://evil.example/x.mp3",
        "https://storage.googleapis.com.evil.example/x.mp3",
        "https://evilelevenlabs.io/x.mp3",
        "https://elevenlabs.io.evil.example/x.mp3",
        "https://user:pw@storage.googleapis.com/x.mp3",
        "https://storage.googleapis.com:8443/x.mp3",
        "https://127.0.0.1/x.mp3",
        "https://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "ftp://storage.googleapis.com/x.mp3",
        "//storage.googleapis.com/x.mp3",
        "",
    ])
    def test_refused_before_any_connection(self, monkeypatch, url):
        monkeypatch.setattr("urllib.request.build_opener", lambda *h: pytest.fail("connected"))
        with pytest.raises(tts_voice.PreviewError):
            tts_voice.fetch_preview(url)

    def test_redirects_are_not_followed(self):
        handler = tts_voice._NoRedirect()
        assert handler.redirect_request(MagicMock(), None, 302, "Found", {}, "https://evil.example/x") is None

    def test_a_redirect_is_a_failure(self, monkeypatch):
        import urllib.error
        _opener(monkeypatch, error=urllib.error.HTTPError(
            "https://storage.googleapis.com/x.mp3", 302, "Found", {"Location": "https://evil.example/x"}, None))
        with pytest.raises(tts_voice.PreviewError):
            tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")

    def test_size_cap(self, monkeypatch):
        _opener(monkeypatch, _FakeResponse(b"x" * (tts_voice.PREVIEW_MAX_BYTES + 1)))
        with pytest.raises(tts_voice.PreviewError, match="larger"):
            tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")
        _opener(monkeypatch, _FakeResponse(b"x" * tts_voice.PREVIEW_MAX_BYTES))
        assert len(tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")[0]) == tts_voice.PREVIEW_MAX_BYTES

    def test_slow_download_is_cut_off(self, monkeypatch):
        _opener(monkeypatch)
        ticks = iter([0.0, 11.0, 11.0, 11.0])
        monkeypatch.setattr(tts_voice.time, "monotonic", lambda: next(ticks, 11.0))
        with pytest.raises(tts_voice.PreviewError, match="too long"):
            tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")

    def test_non_audio_content_type_is_sent_as_mpeg(self, monkeypatch):
        _opener(monkeypatch, _FakeResponse(content_type="text/html"))
        assert tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")[1] == "audio/mpeg"
        _opener(monkeypatch, _FakeResponse(content_type="audio/ogg"))
        assert tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")[1] == "audio/ogg"

    def test_empty_body_and_network_error(self, monkeypatch):
        _opener(monkeypatch, _FakeResponse(b""))
        with pytest.raises(tts_voice.PreviewError):
            tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")
        _opener(monkeypatch, error=TimeoutError("slow"))
        with pytest.raises(tts_voice.PreviewError):
            tts_voice.fetch_preview("https://storage.googleapis.com/x.mp3")


class TestPreviewCache:
    @pytest.fixture(autouse=True)
    def _empty(self, monkeypatch):
        monkeypatch.setattr(tts_voice, "_preview_cache", tts_voice.OrderedDict())

    def test_hit_miss_and_per_account(self):
        tts_voice.preview_cache_put("key-a", "v1", (b"a", "audio/mpeg"))
        assert tts_voice.preview_cache_get("key-a", "v1") == (b"a", "audio/mpeg")
        assert tts_voice.preview_cache_get("key-b", "v1") is None
        assert tts_voice.preview_cache_get("key-a", "v2") is None
        assert "key-a" not in repr(tts_voice._preview_cache)

    def test_expires_after_an_hour(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(tts_voice.time, "monotonic", lambda: now[0])
        tts_voice.preview_cache_put("k", "v", (b"a", "audio/mpeg"))
        now[0] += tts_voice.PREVIEW_CACHE_TTL_SECONDS - 1
        assert tts_voice.preview_cache_get("k", "v") is not None
        now[0] += 2
        assert tts_voice.preview_cache_get("k", "v") is None

    def test_lru_of_fifty(self):
        for i in range(50):
            tts_voice.preview_cache_put("k", f"v{i}", (b"x", "audio/mpeg"))
        tts_voice.preview_cache_get("k", "v0")  # v0 is now the most recently used
        tts_voice.preview_cache_put("k", "v50", (b"x", "audio/mpeg"))
        assert len(tts_voice._preview_cache) == 50
        assert tts_voice.preview_cache_get("k", "v0") is not None
        assert tts_voice.preview_cache_get("k", "v1") is None  # the least recently used went
