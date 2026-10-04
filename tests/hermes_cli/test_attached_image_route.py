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
