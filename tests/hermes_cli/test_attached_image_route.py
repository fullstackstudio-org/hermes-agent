"""GET /api/files/images/{name}: a client shows an attached image from the path the conversation names.

Confined to ``<profile home>/images/``: one plain file, by name, of the profile asked for; no traversal,
no link, no other directory, no other profile, and only for an authenticated client.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from hermes_cli import web_server
from tui_gateway import upload_dirs

_PNG = b"\x89PNG\r\n\x1a\n" + b"pixels"


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """A default home and a profile ``lloyd``, each with an attached image; the managed-files root is
    locked elsewhere (the route must not depend on it)."""
    home = tmp_path / ".hermes"
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(tmp_path / "workspace"))
    lloyd = home / "profiles" / "lloyd"
    for h in (home, lloyd):
        (h / "images").mkdir(parents=True)
        (h / "config.yaml").write_text("{}", encoding="utf-8")
    (home / "images" / "upload_20261004_120000_1.png").write_bytes(_PNG)
    (lloyd / "images" / "upload_20261004_130000_1.png").write_bytes(_PNG + b"-lloyd")
    (home / ".env").write_text("SECRET=1", encoding="utf-8")
    (home / "config.yaml").write_text("model: x", encoding="utf-8")

    prev = (getattr(web_server.app.state, "auth_required", None), getattr(web_server.app.state, "bound_host", None))
    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = None
    client = TestClient(web_server.app)
    client.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    try:
        yield client, home, lloyd
    finally:
        client.close()
        web_server.app.state.auth_required, web_server.app.state.bound_host = prev


def test_serves_an_attached_image_of_the_default_and_a_named_profile(homes):
    client, home, lloyd = homes
    own = client.get("/api/files/images/upload_20261004_120000_1.png")
    assert own.status_code == 200, own.text
    assert own.content == _PNG
    assert own.headers["content-type"] == "image/png"
    assert own.headers["x-content-type-options"] == "nosniff"

    theirs = client.get("/api/files/images/upload_20261004_130000_1.png", params={"profile": "lloyd"})
    assert theirs.status_code == 200 and theirs.content == _PNG + b"-lloyd"


def test_an_image_of_another_profile_is_not_served(homes):
    client, _home, _lloyd = homes
    assert client.get("/api/files/images/upload_20261004_130000_1.png").status_code == 404
    assert client.get("/api/files/images/upload_20261004_120000_1.png",
                      params={"profile": "lloyd"}).status_code == 404
    assert client.get("/api/files/images/upload_20261004_120000_1.png",
                      params={"profile": "missing"}).status_code == 404
    assert client.get("/api/files/images/upload_20261004_120000_1.png",
                      params={"profile": "../.."}).status_code in (400, 404)


@pytest.mark.parametrize("name", [
    "..%2Fconfig.yaml", "..%2F.env", "%2E%2E%2Fconfig.yaml", "%2E%2E", ".env", "config.yaml",
    "upload.svg", "upload_1.png%00.txt", ".hidden.png", "a..b.png",
])
def test_nothing_outside_the_images_dir_or_of_another_type(homes, name):
    client, _home, _lloyd = homes
    response = client.get(f"/api/files/images/{name}")
    assert response.status_code == 404, (name, response.status_code)
    assert b"SECRET" not in response.content and b"model:" not in response.content


def test_a_nested_path_does_not_reach_the_route(homes):
    client, home, _lloyd = homes
    (home / "images" / "sub").mkdir()
    (home / "images" / "sub" / "x.png").write_bytes(_PNG)
    assert client.get("/api/files/images/sub/x.png").status_code == 404
    assert client.get("/api/files/images/../config.yaml").status_code == 404


@pytest.mark.skipif(not upload_dirs.supported(), reason="needs O_NOFOLLOW and dir_fd")
def test_links_are_never_followed(homes, tmp_path):
    client, home, lloyd = homes
    secret = tmp_path / "secret.png"
    secret.write_bytes(b"not yours")
    os.symlink(secret, home / "images" / "link.png")
    assert client.get("/api/files/images/link.png").status_code == 404

    # The images dir itself replaced by a link to somewhere else.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "upload_x.png").write_bytes(b"not yours either")
    for child in (lloyd / "images").iterdir():
        child.unlink()
    (lloyd / "images").rmdir()
    os.symlink(elsewhere, lloyd / "images")
    assert client.get("/api/files/images/upload_x.png", params={"profile": "lloyd"}).status_code == 404


def test_an_unauthenticated_client_gets_nothing(homes):
    client, _home, _lloyd = homes
    del client.headers[web_server._SESSION_HEADER_NAME]
    response = client.get("/api/files/images/upload_20261004_120000_1.png")
    assert response.status_code == 401
    assert client.get("/api/files/images/upload_20261004_120000_1.png",
                      params={"token": web_server._SESSION_TOKEN}).status_code == 401


def test_an_uppercase_suffix_is_an_image_too(homes):
    client, home, _lloyd = homes
    (home / "images" / "upload_X.PNG").write_bytes(_PNG)
    response = client.get("/api/files/images/upload_X.PNG")
    assert response.status_code == 200 and response.headers["content-type"] == "image/png"


def test_a_name_with_a_trailing_newline_is_refused(homes):
    client, _home, _lloyd = homes
    assert client.get("/api/files/images/upload_20261004_120000_1.png%0A").status_code == 404


def test_an_image_over_the_cap_is_refused(homes, monkeypatch):
    import hermes_cli.web_routers.files as files

    client, _home, _lloyd = homes
    monkeypatch.setattr(files, "_ATTACHED_IMAGE_MAX_BYTES", 4)
    assert client.get("/api/files/images/upload_20261004_120000_1.png").status_code == 413


def test_a_directory_or_fifo_named_like_an_image_is_not_served(homes):
    client, home, _lloyd = homes
    (home / "images" / "folder.png").mkdir()
    assert client.get("/api/files/images/folder.png").status_code == 404
    if hasattr(os, "mkfifo"):
        os.mkfifo(home / "images" / "pipe.png")  # must not hang the request
        assert client.get("/api/files/images/pipe.png").status_code == 404


def test_without_nofollow_support_links_and_odd_files_are_still_refused(homes, monkeypatch, tmp_path):
    """The Windows path (no dir_fd / O_NOFOLLOW) checks with lstat instead."""
    client, home, _lloyd = homes
    monkeypatch.setattr(upload_dirs, "supported", lambda: False)
    assert client.get("/api/files/images/upload_20261004_120000_1.png").content == _PNG
    secret = tmp_path / "secret.png"
    secret.write_bytes(b"not yours")
    os.symlink(secret, home / "images" / "link.png")
    (home / "images" / "folder.png").mkdir()
    for name in ("link.png", "folder.png", "missing.png"):
        assert client.get(f"/api/files/images/{name}").status_code == 404, name


def test_a_signed_in_browser_session_may_read_it_and_a_gated_dashboard_refuses_without_one(homes):
    """Gated dashboard (OAuth): the session cookie authenticates the route, nothing else does."""
    from hermes_cli.dashboard_auth import clear_providers, register_provider
    from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider

    _client, _home, _lloyd = homes
    clear_providers()
    register_provider(StubAuthProvider())
    prev = (web_server.app.state.bound_host, getattr(web_server.app.state, "bound_port", None))
    web_server.app.state.bound_host, web_server.app.state.bound_port = "fly-app.fly.dev", 443
    web_server.app.state.auth_required = True
    try:
        client = TestClient(web_server.app, base_url="https://fly-app.fly.dev")
        url = "/api/files/images/upload_20261004_120000_1.png"
        assert client.get(url).status_code == 401
        assert client.get(url, headers={web_server._SESSION_HEADER_NAME: web_server._SESSION_TOKEN}).status_code == 401

        start = client.get("/auth/login?provider=stub", follow_redirects=False)
        pkce = next(c for c in start.headers.get_list("set-cookie") if "hermes_session_pkce" in c).split(";", 1)[0]
        state = start.headers["location"].split("state=")[1]
        done = client.get(f"/auth/callback?code=stub_code&state={state}", headers={"cookie": pkce},
                          follow_redirects=False)
        assert done.status_code == 302
        signed_in = client.get(url)
        assert signed_in.status_code == 200 and signed_in.content == _PNG
    finally:
        clear_providers()
        web_server.app.state.bound_host, web_server.app.state.bound_port = prev
