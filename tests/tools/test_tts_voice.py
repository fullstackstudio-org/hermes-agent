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

_REAL_FETCH_EDGE_VOICES = tts_voice._fetch_edge_voices
_REAL_FETCH_ELEVENLABS_IDS = tts_voice._fetch_elevenlabs_voice_ids


def _settle(timeout=3.0):
    """Wait for the Edge list's background refresh to finish (it holds the single-flight slot)."""
    import time
    end = time.monotonic() + timeout
    while tts_voice._edge_inflight is not None and time.monotonic() < end:
        time.sleep(0.01)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    for key in ("ELEVENLABS_API_KEY", "OPENAI_API_KEY", "HERMES_SESSION_PLATFORM"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(tts_voice, "_edge_cache", {"at": 0.0, "voices": None, "failed_at": 0.0})
    monkeypatch.setattr(tts_voice, "_edge_inflight", None)
    monkeypatch.setattr(tts_voice, "_el_cache", {})
    monkeypatch.setattr(tts_voice, "_el_failed", {})
    # Never reach the network from a unit test unless the test installs its own fetcher.
    monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: pytest.fail("edge list fetched"))
    monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda key, base: pytest.fail("el list fetched"))
    yield
    _settle()


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
    """Edge's list is served by a fetch; ``voice-config`` never waits for a cold one, so warm it."""
    monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: EDGE_RAW)
    assert tts_voice.edge_voices() is not None


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
        assert tts_voice.edge_voices() is None
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


class TestEdgeListResilience:
    """The Edge list sits on GET voice-config and POST speak: it must never hold either for long."""

    def _hung_fetcher(self, monkeypatch):
        import threading
        release, calls = threading.Event(), []

        def fetch():
            calls.append(1)
            release.wait(10)
            return EDGE_RAW
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", fetch)
        return release, calls

    def test_the_fetch_has_a_hard_deadline_of_its_own(self, monkeypatch):
        import time

        async def hang():
            await asyncio.sleep(30)

        edge = MagicMock()
        edge.list_voices = hang
        monkeypatch.setattr("tools.tts_tool._import_edge_tts", lambda: edge)
        monkeypatch.setattr(tts_voice, "EDGE_FETCH_DEADLINE_SECONDS", 0.2)
        started = time.monotonic()
        with pytest.raises(asyncio.TimeoutError):
            _REAL_FETCH_EDGE_VOICES()
        assert time.monotonic() - started < 2

    def test_a_timed_out_fetch_is_a_negative_answer_and_not_retried_for_a_minute(self, monkeypatch):
        import time
        calls = []

        async def hang():
            calls.append(1)
            await asyncio.sleep(30)

        edge = MagicMock()
        edge.list_voices = hang
        monkeypatch.setattr("tools.tts_tool._import_edge_tts", lambda: edge)
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", _REAL_FETCH_EDGE_VOICES)
        monkeypatch.setattr(tts_voice, "EDGE_FETCH_DEADLINE_SECONDS", 0.2)
        monkeypatch.setattr(tts_voice, "EDGE_WAIT_SECONDS", 3.0)
        started = time.monotonic()
        assert tts_voice.edge_voice_list() == (None, "unavailable")
        assert time.monotonic() - started < 2.5
        assert tts_voice.edge_voice_list() == (None, "unavailable")
        assert tts_voice.edge_voice_list(wait=0) == (None, "unavailable")
        assert len(calls) == 1

    def test_voice_config_does_not_wait_for_a_cold_cache(self, monkeypatch):
        import time
        release, calls = self._hung_fetcher(monkeypatch)
        started = time.monotonic()
        caps = tts_voice.voice_capabilities({}, "edge")
        again = tts_voice.voice_capabilities({}, "edge")
        assert time.monotonic() - started < 1
        assert caps["voices"] == [] and caps["voices_error"] == "loading"
        assert again["voices_error"] == "loading"
        release.set()
        _settle()
        assert len(calls) == 1  # both answers shared one fetch
        ready = tts_voice.voice_capabilities({}, "edge")
        assert len(ready["voices"]) == 4 and "voices_error" not in ready

    def test_speak_waits_up_to_the_deadline_then_passes_the_voice_through(self, monkeypatch):
        import time
        release, _ = self._hung_fetcher(monkeypatch)
        monkeypatch.setattr(tts_voice, "EDGE_WAIT_SECONDS", 0.3)
        started = time.monotonic()
        selection = resolve_voice_selection({}, "edge", "nl-NL-NoSuchNeural")
        assert selection.voice == "nl-NL-NoSuchNeural"  # not validated: the list never arrived
        assert time.monotonic() - started < 2
        release.set()

    def test_one_fetch_at_a_time_and_every_caller_gets_the_list(self, monkeypatch):
        import threading
        import time
        calls = []

        def slow():
            calls.append(1)
            time.sleep(0.3)
            return EDGE_RAW
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", slow)
        results = []
        threads = [threading.Thread(target=lambda: results.append(tts_voice.edge_voices())) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert len(calls) == 1
        assert len(results) == 8 and all(r is not None and len(r) == 4 for r in results)

    def test_an_expired_list_is_served_while_it_refreshes(self, monkeypatch):
        _edge_list(monkeypatch)
        monkeypatch.setitem(tts_voice._edge_cache, "at", tts_voice._edge_cache["at"] - tts_voice._LIST_TTL_SECONDS - 1)
        release, calls = self._hung_fetcher(monkeypatch)
        voices, state = tts_voice.edge_voice_list()  # does not wait for the refresh
        assert state == "ready" and len(voices) == 4
        release.set()
        _settle()
        assert len(calls) == 1

    def test_a_failed_refresh_keeps_the_last_good_list(self, monkeypatch):
        _edge_list(monkeypatch)
        monkeypatch.setitem(tts_voice._edge_cache, "at", tts_voice._edge_cache["at"] - tts_voice._LIST_TTL_SECONDS - 1)
        monkeypatch.setattr(tts_voice, "_fetch_edge_voices", lambda: (_ for _ in ()).throw(OSError("down")))
        assert tts_voice.edge_voice_list()[1] == "ready"
        _settle()
        voices, state = tts_voice.edge_voice_list()
        assert state == "ready" and len(voices) == 4


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

    @pytest.mark.parametrize("configured,root", [
        (None, "https://api.elevenlabs.io/v1"),
        ("", "https://api.elevenlabs.io/v1"),
        ("https://proxy.example", "https://proxy.example/v1"),
        ("https://proxy.example/", "https://proxy.example/v1"),
        ("https://proxy.example/v1", "https://proxy.example/v1"),
        ("https://proxy.example/v1/", "https://proxy.example/v1"),
        ("https://proxy.example/eleven", "https://proxy.example/eleven/v1"),
    ])
    def test_list_url_follows_base_url_with_or_without_v1(self, monkeypatch, configured, root):
        calls = self._ids(monkeypatch)
        config = {"elevenlabs": {"base_url": configured}} if configured is not None else {}
        assert tts_voice.elevenlabs_voice_ids(config) == {EL_VOICE, EL_OTHER}
        assert calls == [("sk-el-test", root)]

    def test_list_url_is_voices_under_the_root(self, monkeypatch):
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", _REAL_FETCH_ELEVENLABS_IDS)
        seen = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps({"voices": [{"voice_id": EL_VOICE}]}).encode()

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: seen.append(req.full_url) or Resp())
        assert tts_voice._fetch_elevenlabs_voice_ids("k", tts_voice._elevenlabs_api_root("https://proxy.example")) == {EL_VOICE}
        assert seen == ["https://proxy.example/v1/voices"]

    def test_failed_list_is_remembered_for_a_minute(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")
        calls = []
        now = [1000.0]
        monkeypatch.setattr(tts_voice.time, "monotonic", lambda: now[0])

        def boom(key, base):
            calls.append(1)
            raise OSError("down")
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", boom)
        assert tts_voice.elevenlabs_voice_ids({}) is None
        assert tts_voice.elevenlabs_voice_ids({}) is None
        assert resolve_voice_selection({}, "elevenlabs", "AnythingGoes123").voice == "AnythingGoes123"
        assert len(calls) == 1
        now[0] += tts_voice._LIST_FAILURE_TTL_SECONDS + 1
        assert tts_voice.elevenlabs_voice_ids({}) is None
        assert len(calls) == 2
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda k, b: {EL_VOICE})
        now[0] += tts_voice._LIST_FAILURE_TTL_SECONDS + 1
        assert tts_voice.elevenlabs_voice_ids({}) == {EL_VOICE}
        assert tts_voice._el_failed == {}

    def test_another_accounts_failure_does_not_block_this_one(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-broken")

        def fetch(key, base):
            if key == "sk-el-broken":
                raise OSError("down")
            return {EL_VOICE}
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", fetch)
        assert tts_voice.elevenlabs_voice_ids({}) is None
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-fine")
        assert tts_voice.elevenlabs_voice_ids({}) == {EL_VOICE}

    @pytest.mark.parametrize("body", [[], "text", 5, {"voices": "x"}, {"voices": {"a": 1}}, {}])
    def test_a_body_that_is_not_a_voice_list_is_a_failure_not_a_crash(self, monkeypatch, body):
        monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", _REAL_FETCH_ELEVENLABS_IDS)
        monkeypatch.setenv("ELEVENLABS_API_KEY", "sk-el-test")

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps(body).encode()

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: Resp())
        assert tts_voice.elevenlabs_voice_ids({}) is None
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
        _edge_list(monkeypatch)
        voice_home({"tts": {"provider": "edge"}})
        tts = _public()["tts"]
        assert tts["mode"] == "relay" and tts["reason"] == "provider 'edge' has no client wire"
        assert tts["voice_selection"] is True and tts["prosody"] is True
        assert {"id": "nl-NL-FennaNeural", "name": "Fenna", "language": "nl-NL"} in tts["voices"]

    def test_language_filter(self, voice_home, monkeypatch):
        _edge_list(monkeypatch)
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


    @pytest.mark.parametrize("url,expected", [
        ("https://user:pw@[2001:db8::1]:8443/v1?key=abc#f", "https://[2001:db8::1]:8443/v1"),
        ("https://[::1]/v1?x=1", "https://[::1]/v1"),
        ("https://u@host.example/v1", "https://host.example/v1"),
        ("https://host.example:0/v1?x=1", "https://host.example:0/v1"),
        ("https://host.example/v1", "https://host.example/v1"),  # nothing to strip: unchanged
        ("https://host.example:notaport/v1?x=1", ""),  # unparseable: dropped, not passed on
    ])
    def test_url_secrets_keep_ipv6_brackets(self, url, expected):
        from tools.voice_client_config import _strip_url_secrets
        assert _strip_url_secrets(url) == expected

    def test_every_url_field_is_scrubbed_whatever_its_name_or_case(self):
        from tools.voice_client_config import _without_secrets
        dirty = "https://user:pw@host.example/v1?sig=abc"
        out = _without_secrets({
            "base_url": dirty, "wss_url": dirty, "BaseURL": dirty, "Proxy_Url": dirty, "url": dirty,
            "nested": {"endpoint_url": dirty}, "model": "m", "note": "not a url field?x=1"})
        clean = "https://host.example/v1"
        assert out == {"base_url": clean, "wss_url": clean, "BaseURL": clean, "Proxy_Url": clean, "url": clean,
                       "nested": {"endpoint_url": clean}, "model": "m", "note": "not a url field?x=1"}


# --------------------------------------------------------------------------- preview fetch guard
class _FakeResponse:
    def __init__(self, body=b"ID3sample", content_type="audio/mpeg"):
        import email.message
        self._body, self._pos = body, 0
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type

    def read1(self, n=-1):
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


class TestPreviewDeadline:
    """The limit is on the whole download: a real server that dribbles bytes or stalls cannot outlast it."""

    @pytest.fixture()
    def slow_server(self, monkeypatch):
        import http.server
        import threading
        import time

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "audio/mpeg")
                self.end_headers()
                self.wfile.flush()
                try:
                    if self.path == "/stall":
                        time.sleep(8)
                        return
                    for _ in range(80):  # 16 bytes every 100 ms: eight seconds of a slow trickle
                        self.wfile.write(b"ID3audio-bytes-16")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # The host allowlist is https-only and never lets a loopback address through; this test is
        # about the clock, so it steps over that one check and nothing else.
        monkeypatch.setattr(tts_voice, "check_preview_url", lambda url: None)
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()

    def test_a_trickling_server_is_cut_off_at_the_limit(self, slow_server):
        import time
        started = time.monotonic()
        with pytest.raises(tts_voice.PreviewError, match="too long"):
            tts_voice.fetch_preview(f"{slow_server}/trickle", timeout=1)
        assert 0.8 < time.monotonic() - started < 6

    def test_a_stalled_server_is_cut_off_at_the_limit(self, slow_server):
        import time
        started = time.monotonic()
        with pytest.raises(tts_voice.PreviewError):
            tts_voice.fetch_preview(f"{slow_server}/stall", timeout=1)
        assert time.monotonic() - started < 6

    def test_a_fast_server_still_works(self, slow_server, monkeypatch):
        import http.server
        import threading

        class Fast(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "audio/mpeg")
                self.send_header("Content-Length", "9")
                self.end_headers()
                self.wfile.write(b"ID3sample")

        server = http.server.HTTPServer(("127.0.0.1", 0), Fast)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            body = tts_voice.fetch_preview(f"http://127.0.0.1:{server.server_address[1]}/x", timeout=2)
        finally:
            server.shutdown()
            server.server_close()
        assert body == (b"ID3sample", "audio/mpeg")


class TestPreviewCacheBudget:
    @pytest.fixture(autouse=True)
    def _empty(self, monkeypatch):
        monkeypatch.setattr(tts_voice, "_preview_cache", tts_voice.OrderedDict())
        monkeypatch.setattr(tts_voice, "PREVIEW_CACHE_MAX_BYTES", 100)

    def test_oldest_go_first_past_the_byte_budget(self):
        for i in range(3):
            tts_voice.preview_cache_put("k", f"v{i}", (b"x" * 40, "audio/mpeg"))
        assert tts_voice.preview_cache_get("k", "v0") is None
        assert tts_voice.preview_cache_get("k", "v1") is not None and tts_voice.preview_cache_get("k", "v2") is not None
        assert sum(len(e[1][0]) for e in tts_voice._preview_cache.values()) <= 100

    def test_a_body_over_the_whole_budget_is_not_kept_and_evicts_nothing(self):
        tts_voice.preview_cache_put("k", "v0", (b"x" * 40, "audio/mpeg"))
        tts_voice.preview_cache_put("k", "big", (b"x" * 101, "audio/mpeg"))
        assert tts_voice.preview_cache_get("k", "big") is None
        assert tts_voice.preview_cache_get("k", "v0") is not None

    def test_replacing_an_entry_does_not_double_count_it(self):
        for _ in range(5):
            tts_voice.preview_cache_put("k", "v0", (b"x" * 60, "audio/mpeg"))
        assert tts_voice.preview_cache_get("k", "v0") is not None and len(tts_voice._preview_cache) == 1

    def test_the_real_budget_is_fifty_megabytes(self, monkeypatch):
        monkeypatch.undo()
        assert tts_voice.PREVIEW_CACHE_MAX_BYTES == 50 * 1024 * 1024
