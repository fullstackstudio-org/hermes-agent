"""GET /api/files/outbox/{token}/{name}: a client fetches a file a bot shared, and nothing else.

Exactly the recorded copy of the profile asked for, only with the session header (never ``?token=``), only to a
caller the conversation belonged to, never as active content, with byte ranges so audio and video can seek.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.web_routers import files as files_router
from tui_gateway import outbox, upload_dirs

pytestmark = pytest.mark.skipif(not upload_dirs.supported(), reason="needs O_NOFOLLOW and dir_fd")

_MP3 = b"ID3\x03\x00\x00\x00\x00\x00\x00" + bytes(range(256)) * 4  # 1034 bytes
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
_SVG = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
_HTML = b"<!doctype html><script>alert(1)</script>"


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A default home and a profile ``lloyd``, a work folder with files, and a client with the session header."""
    home = tmp_path / ".hermes"
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(home))
    lloyd = home / "profiles" / "lloyd"
    for h in (home, lloyd):
        h.mkdir(parents=True, exist_ok=True)
        (h / "config.yaml").write_text("{}", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()

    def share(name: str, data: bytes, *, into: Path = home, logins=("oidc:a",), session_id="s1"):
        source = work / name
        source.write_bytes(data)
        return outbox.share_file(str(source), home=into, session_id=session_id, logins=list(logins))

    prev = (getattr(web_server.app.state, "auth_required", None), getattr(web_server.app.state, "bound_host", None))
    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = None
    client = TestClient(web_server.app)
    client.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    try:
        yield SimpleNamespace(client=client, home=home, lloyd=lloyd, share=share)
    finally:
        client.close()
        web_server.app.state.auth_required, web_server.app.state.bound_host = prev


def _url(record) -> str:
    return outbox.attachment_of(record)["url"]


def test_serves_the_shared_copy_with_safe_headers(world):
    record = world.share("tts_20261004_225730_989324.mp3", _MP3)
    response = world.client.get(_url(record))
    assert response.status_code == 200, response.text
    assert response.content == _MP3
    headers = response.headers
    assert headers["content-type"] == "audio/mpeg"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert headers["content-disposition"].startswith('inline; filename="tts_20261004_225730_989324.mp3"')
    assert headers["accept-ranges"] == "bytes"
    assert headers["content-length"] == str(len(_MP3))
    assert headers["etag"] == f'"{record["sha256"][:40]}"'
    assert headers["cache-control"].startswith("private")


@pytest.mark.parametrize(("name", "data", "content_type", "disposition"), [
    ("a.png", _PNG, "image/png", "inline"),
    ("a.pdf", b"%PDF-1.7\n", "application/pdf", "inline"),
    ("a.mp4", b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16, "video/mp4", "inline"),
    ("a.svg", _SVG, "application/octet-stream", "attachment"),
    ("a.html", _HTML, "application/octet-stream", "attachment"),
    ("a.png", _HTML, "application/octet-stream", "attachment"),  # the bytes contradict the name
    ("a.zip", b"PK\x03\x04", "application/zip", "attachment"),
    ("run.sh", b"#!/bin/sh\necho hi\n", "application/octet-stream", "attachment"),
    ("notes.txt", b"hello", "text/plain", "attachment"),
])
def test_only_checked_images_video_audio_and_pdf_are_inline(world, name, data, content_type, disposition):
    response = world.client.get(_url(world.share(name, data)))
    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == content_type
    assert response.headers["content-disposition"].split(";")[0] == disposition
    assert response.headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_a_non_ascii_name_is_quoted_in_the_disposition(world):
    record = world.share("café \"quoted\".pdf", b"%PDF-1.7\n")
    response = world.client.get(_url(record))
    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert 'filename="caf_ _quoted_.pdf"' in disposition
    assert "filename*=UTF-8''caf%C3%A9%20%22quoted%22.pdf" in disposition


@pytest.mark.parametrize(("header", "status", "body", "content_range"), [
    ("bytes=0-9", 206, _MP3[0:10], "bytes 0-9/1034"),
    ("bytes=1000-", 206, _MP3[1000:], "bytes 1000-1033/1034"),
    ("bytes=-34", 206, _MP3[-34:], "bytes 1000-1033/1034"),
    ("bytes=1030-5000", 206, _MP3[1030:], "bytes 1030-1033/1034"),
    ("bytes=1034-", 416, b"", "bytes */1034"),
    ("bytes=9-3", 416, b"", "bytes */1034"),
    ("bytes=abc", 416, b"", "bytes */1034"),
    ("bytes=-0", 416, b"", "bytes */1034"),
    ("bytes=-", 416, b"", "bytes */1034"),
    ("items=0-9", 200, _MP3, None),  # another unit: the whole file
    ("bytes=0-1,4-5", 200, _MP3, None),  # several ranges: the whole file
])
def test_range_requests(world, header, status, body, content_range):
    response = world.client.get(_url(world.share("clip.mp3", _MP3)), headers={"Range": header})
    assert response.status_code == status
    assert response.content == body
    assert response.headers.get("content-range") == content_range
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'; sandbox"


def test_if_range_and_if_none_match_use_the_etag(world):
    url = _url(world.share("clip.mp3", _MP3))
    etag = world.client.get(url).headers["etag"]
    assert world.client.get(url, headers={"Range": "bytes=0-1", "If-Range": etag}).status_code == 206
    stale = world.client.get(url, headers={"Range": "bytes=0-1", "If-Range": '"other"'})
    assert stale.status_code == 200 and stale.content == _MP3
    assert world.client.get(url, headers={"If-None-Match": etag}).status_code == 304


def test_head_answers_without_a_body(world):
    url = _url(world.share("clip.mp3", _MP3))
    response = world.client.head(url)
    assert response.status_code == 200 and response.content == b""
    assert response.headers["content-length"] == str(len(_MP3))
    ranged = world.client.head(url, headers={"Range": "bytes=0-9"})
    assert ranged.status_code == 206 and ranged.headers["content-range"] == "bytes 0-9/1034"


def test_needs_the_session_header_and_never_takes_the_query_token(world):
    url = _url(world.share("clip.mp3", _MP3))
    bare = TestClient(web_server.app)
    try:
        assert bare.get(url).status_code == 401
        assert bare.get(url, params={"token": web_server._SESSION_TOKEN}).status_code == 401
    finally:
        bare.close()


def test_scoped_to_the_profile_asked_for(world):
    mine = world.share("mine.txt", b"default")
    theirs = world.share("theirs.txt", b"lloyd", into=world.lloyd)
    assert world.client.get(_url(mine)).content == b"default"
    assert world.client.get(_url(theirs)).status_code == 404
    assert world.client.get(_url(theirs), params={"profile": "lloyd"}).content == b"lloyd"
    assert world.client.get(_url(mine), params={"profile": "lloyd"}).status_code == 404
    assert world.client.get(_url(mine), params={"profile": "nobody"}).status_code == 404


def test_a_wrong_name_or_token_is_404(world):
    record = world.share("clip.mp3", _MP3)
    base = f"/api/files/outbox/{record['id']}"
    assert world.client.get(f"{base}/other.mp3").status_code == 404
    assert world.client.get(f"/api/files/outbox/{'Z' * 32}/clip.mp3").status_code == 404
    assert world.client.get("/api/files/outbox/short/clip.mp3").status_code == 404
    assert world.client.get(f"{base}/..%2F..%2Fconfig.yaml").status_code == 404


def test_only_the_people_of_the_conversation_may_fetch(world, monkeypatch):
    url = _url(world.share("clip.mp3", _MP3, logins=("oidc:a",)))
    login = {"value": "oidc:a"}
    monkeypatch.setattr(files_router, "_outbox_request_login", lambda _request: login["value"])
    assert world.client.get(url).status_code == 200
    login["value"] = "oidc:b"
    assert world.client.get(url).status_code == 404
    # Someone who joined the live conversation after the file was shared may fetch it too.
    monkeypatch.setattr(files_router, "_outbox_live_logins", lambda session_id: {"oidc:b"} if session_id == "s1"
                        else set())
    assert world.client.get(url).status_code == 200


def test_a_gated_caller_without_a_person_is_refused(world, monkeypatch):
    url = _url(world.share("clip.mp3", _MP3))
    monkeypatch.setattr(files_router, "_outbox_request_login", lambda _request: None)
    world.client.app.state.auth_required = True
    monkeypatch.setattr("hermes_cli.dashboard_auth.middleware.gated_auth_middleware",
                        lambda request, call_next: call_next(request))
    try:
        assert world.client.get(url).status_code == 404
    finally:
        world.client.app.state.auth_required = False


def test_the_login_is_read_from_the_verified_session():
    request = SimpleNamespace(state=SimpleNamespace(session=SimpleNamespace(provider="oidc", user_id="u-1")))
    assert files_router._outbox_request_login(request) == "oidc:u-1"
    assert files_router._outbox_request_login(SimpleNamespace(state=SimpleNamespace())) is None


def test_live_logins_come_from_the_conversation_that_shared(monkeypatch):
    import sys
    import threading

    session = {"session_key": "s1", "auth_user_id": "oidc:a", "attached_logins": {"oidc:b"},
               "stored_owner": "oidc:c"}
    fake = SimpleNamespace(
        _sessions={"x": session, "y": {"session_key": "s2", "auth_user_id": "oidc:z"}},
        _sessions_lock=threading.Lock(), _session_auth_user_id=lambda record: record.get("auth_user_id"))
    monkeypatch.setitem(sys.modules, "tui_gateway.server", fake)
    assert files_router._outbox_live_logins("s1") == {"oidc:a", "oidc:b", "oidc:c"}
    assert files_router._outbox_live_logins("") == set()
    monkeypatch.delitem(sys.modules, "tui_gateway.server")
    assert files_router._outbox_live_logins("s1") == set()  # no gateway in this process: nobody live


def test_a_replaced_blob_is_not_served(world):
    record = world.share("a.txt", b"hello world!")
    secret = world.home / ".env"
    secret.write_text("SECRET=1234\n")  # 12 bytes, like the copy
    blob = world.home / "outbox" / record["id"] / "blob"
    blob.unlink()
    os.link(secret, blob)
    assert world.client.get(_url(record)).status_code == 404


@pytest.mark.parametrize("header", ["bytes=0-9999999999999999999999", "bytes=99999999999999999999-",
                                    "bytes=-99999999999999999999"])
def test_a_huge_range_number_is_416_not_500(world, header):
    response = world.client.get(_url(world.share("clip.mp3", _MP3)), headers={"Range": header})
    assert response.status_code == 416 and response.headers["content-range"] == "bytes */1034"


@pytest.mark.parametrize(("dest", "disposition"), [
    (None, "inline"), ("empty", "inline"), ("document", "attachment"), ("iframe", "attachment"),
    ("embed", "attachment"),
])
def test_a_pdf_opened_as_a_page_is_a_download(world, dest, disposition):
    """Chromium's PDF viewer does not run under the sandbox CSP: a page navigation gets a download instead,
    an app's fetch keeps it inline. The CSP is never relaxed."""
    headers = {"Sec-Fetch-Dest": dest} if dest else {}
    response = world.client.get(_url(world.share("a.pdf", b"%PDF-1.7\n")), headers=headers)
    assert response.headers["content-disposition"].split(";")[0] == disposition
    assert response.headers["content-security-policy"] == "default-src 'none'; sandbox"


def test_the_body_closes_its_file_when_never_iterated(world):
    """A client that goes before the body is iterated: the generator never runs its ``finally``, but the
    descriptor is held by a file object, which closes it when the response is dropped."""
    import gc

    record = world.share("clip.mp3", _MP3)
    shared = outbox.open_shared(world.home, record["id"], record["name"])
    fd = shared.fd
    body = files_router._outbox_body(os.fdopen(fd, "rb", buffering=0), 0, 10)
    os.fstat(fd)  # open while the body exists
    del body
    gc.collect()
    with pytest.raises(OSError):
        os.fstat(fd)
