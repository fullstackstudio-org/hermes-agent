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

EL_VOICE = "21m00Tcm4TlvDq8ikWAM"
EL_OTHER = "AZnzlk1XvdvUeBnXmlld"
KEY = "sk-el-SECRET"
PREVIEW_URL = "https://storage.googleapis.com/eleven-public-prod/premade/voices/21m00/sample.mp3"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setenv("ELEVENLABS_API_KEY", KEY)
    monkeypatch.setattr(tts_voice, "_el_cache", {})
    monkeypatch.setattr(tts_voice, "_preview_cache", tts_voice.OrderedDict())
    monkeypatch.setattr(tts_voice, "_edge_cache", {"at": 0.0, "voices": None, "failed_at": 0.0})
    monkeypatch.setattr(tts_voice, "_fetch_elevenlabs_voice_ids", lambda key, base: {EL_VOICE, EL_OTHER})


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
        tts = client.get("/api/audio/voice-config?language=nl").json()["tts"]
        assert tts["mode"] == "relay" and tts["reason"] == "provider 'edge' has no client wire"
        assert tts["voices"] == [{"id": "nl-NL-FennaNeural", "name": "Fenna", "language": "nl-NL"}]
        assert tts["voice_selection"] is True and tts["voice_preview"] == "speak" and tts["prosody"] is True

    @pytest.mark.parametrize("provider,preview", [
        ("elevenlabs", "sample"), ("edge", "speak"), ("openai", None), ("gemini", None), ("xai", None),
        ("mistral", None), ("minimax", None), ("deepinfra", None), ("piper", None), ("neutts", None),
    ])
    def test_voice_preview_per_provider(self, provider, preview):
        monkey = pytest.MonkeyPatch()
        try:
            monkey.setattr(tts_voice, "_fetch_edge_voices", lambda: [])
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
