"""Tests for the dashboard-managed file browser API."""

import base64
import os
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from hermes_cli import web_server
import hermes_cli.web_routers.files as _rt_files


def _client_with_app_state():
    prev_auth_required = getattr(web_server.app.state, "auth_required", None)
    prev_bound_host = getattr(web_server.app.state, "bound_host", None)
    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = None

    client = TestClient(web_server.app)
    client.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    return client, prev_auth_required, prev_bound_host


def _restore_app_state(prev_auth_required, prev_bound_host):
    if prev_auth_required is None:
        delattr(web_server.app.state, "auth_required")
    else:
        web_server.app.state.auth_required = prev_auth_required
    if prev_bound_host is None:
        if hasattr(web_server.app.state, "bound_host"):
            delattr(web_server.app.state, "bound_host")
    else:
        web_server.app.state.bound_host = prev_bound_host


def _close_client(client):
    close = getattr(client, "close", None)
    if close is not None:
        close()


@pytest.fixture
def forced_files_client(monkeypatch, tmp_path):
    root = tmp_path / "data"
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(root))

    client, prev_auth_required, prev_bound_host = _client_with_app_state()
    try:
        yield client, root
    finally:
        _close_client(client)
        _restore_app_state(prev_auth_required, prev_bound_host)


@pytest.fixture
def local_files_client(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.delenv("HERMES_DASHBOARD_FILES_ROOT", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(home))

    client, prev_auth_required, prev_bound_host = _client_with_app_state()
    try:
        yield client, home
    finally:
        _close_client(client)
        _restore_app_state(prev_auth_required, prev_bound_host)














def _seed_file(client, root, name="out/hello.txt"):
    file_path = root / name
    created = client.post(
        "/api/files/upload",
        json={"path": str(file_path), "data_url": "data:text/plain;base64,aGVsbG8="},
    )
    assert created.status_code == 200
    return file_path




@pytest.mark.parametrize("client_fixture", ["local_files_client", "forced_files_client"])
def test_mkdir_creates_a_folder_the_picker_can_list_and_enter(client_fixture, request):
    """The desktop remote folder picker's New folder: mkdir an absolute child of
    the folder it is browsing, then list the parent and navigate into the result."""
    client, root = request.getfixturevalue(client_fixture)
    root.mkdir(exist_ok=True)
    listed = client.get("/api/fs/list", params={"path": str(root)}).json()
    assert "error" not in listed

    created = client.post("/api/files/mkdir", json={"path": str(root / "fresh project")})

    assert created.status_code == 200
    new_dir = created.json()["path"]
    assert (root / "fresh project").is_dir()
    after = client.get("/api/fs/list", params={"path": str(root)}).json()["entries"]
    assert {"name": "fresh project", "path": new_dir, "isDirectory": True} in after
    assert client.get("/api/fs/list", params={"path": new_dir}).json() == {"entries": []}


def test_download_authenticates_via_query_token(forced_files_client):
    client, root = forced_files_client
    file_path = _seed_file(client, root, name="out/demo.mp4")
    active_content = _seed_file(client, root, name="out/page.html")

    # Drop the session header so only the ?token= query param authenticates —
    # mirrors a browser/shell-opened download that can't set the session header.
    del client.headers[web_server._SESSION_HEADER_NAME]

    ok = client.get(
        "/api/files/download",
        params={"path": str(file_path), "token": web_server._SESSION_TOKEN},
    )
    assert ok.status_code == 200
    assert ok.content == b"hello"
    assert ok.headers["content-disposition"].startswith("attachment;")

    playback = client.get(
        "/api/files/download",
        params={"path": str(file_path), "token": web_server._SESSION_TOKEN},
        headers={"Sec-Fetch-Dest": "video", "Range": "bytes=1-3"},
    )
    assert playback.status_code == 206
    assert playback.content == b"ell"
    assert playback.headers["content-disposition"].startswith("inline;")
    assert playback.headers["x-content-type-options"] == "nosniff"

    rejected = client.get(
        "/api/files/download",
        params={"path": str(active_content), "token": web_server._SESSION_TOKEN},
        headers={"Sec-Fetch-Dest": "video"},
    )
    assert rejected.status_code == 415

    assert client.get(
        "/api/files/download", params={"path": str(file_path), "token": "nope"}
    ).status_code == 401
    assert client.get(
        "/api/files/download", params={"path": str(file_path)}
    ).status_code == 401


def test_download_resolves_paths_in_the_originating_profile_session(local_files_client, monkeypatch):
    from pathlib import Path
    from hermes_state import SessionDB

    client, home = local_files_client
    monkeypatch.setattr(Path, "home", lambda: home)
    hermes_home = home / "isolated-hermes"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    session_cwd = home / "project"
    session_cwd.mkdir()
    gateway_cwd = home / "gateway"
    gateway_cwd.mkdir()
    monkeypatch.chdir(gateway_cwd)
    artifact = session_cwd / "report.txt"
    artifact.write_bytes(b"session artifact")
    (gateway_cwd / artifact.name).write_bytes(b"wrong gateway artifact")
    for profile, sid, cwd in [("default", "origin-session", str(session_cwd)),
                              ("other", "other-session", str(gateway_cwd))]:
        db_home = hermes_home if profile == "default" else hermes_home / "profiles" / profile
        db_home.mkdir(parents=True, exist_ok=True)
        (db_home / "config.yaml").write_text("{}", encoding="utf-8")
        db = SessionDB(db_path=db_home / "state.db")
        try:
            db.create_session(sid, source="gui", cwd=cwd)
        finally:
            db.close()
    for route in ("/api/fs/download", "/api/fs/read-data-url"):
        for path in ("./report.txt", "../project/report.txt", str(artifact), artifact.as_uri()):
            response = client.get(route, params={
                "path": path, "profile": "default", "session_id": "origin-session",
            })
            assert response.status_code == 200, response.text
            data = (base64.b64decode(response.json()["dataUrl"].split(",", 1)[1])
                    if route.endswith("read-data-url") else response.content)
            assert data == artifact.read_bytes()
        for profile, session_id in (("other", "origin-session"), ("missing", "origin-session"),
                                    ("default", "missing-session"), ("default", "")):
            response = client.get(route, params={
                "path": str(artifact), "profile": profile, "session_id": session_id,
            })
            assert response.status_code == 404, response.text


def test_stream_requires_header_auth_and_supports_ranges(forced_files_client):
    client, root = forced_files_client
    file_path = _seed_file(client, root, name="out/demo.mp4")

    # Electron's main-process proxy supplies the connection credential as a
    # header. Unlike browser-visible download links, the stream endpoint must
    # not accept credentials in its URL.
    params = {"path": str(file_path)}

    full = client.get("/api/files/stream", params=params)
    assert full.status_code == 200
    assert full.content == b"hello"
    assert full.headers["content-type"] == "video/mp4"
    assert full.headers["content-disposition"].startswith("inline;")
    assert full.headers["accept-ranges"] == "bytes"
    assert full.headers["x-content-type-options"] == "nosniff"

    partial = client.get(
        "/api/files/stream",
        params=params,
        headers={"Range": "bytes=1-3"},
    )
    assert partial.status_code == 206
    assert partial.content == b"ell"
    assert partial.headers["content-range"] == "bytes 1-3/5"
    assert partial.headers["content-disposition"].startswith("inline;")
    assert partial.headers["x-content-type-options"] == "nosniff"

    head = client.head("/api/files/stream", params=params)
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == "5"
    assert head.headers["x-content-type-options"] == "nosniff"

    del client.headers[web_server._SESSION_HEADER_NAME]
    assert client.get(
        "/api/files/stream",
        params={"path": str(file_path), "token": web_server._SESSION_TOKEN},
    ).status_code == 401
    assert client.get("/api/files/stream", params=params).status_code == 401


def test_stream_rejects_non_media_active_content(forced_files_client):
    client, root = forced_files_client

    for name in ("out/page.html", "out/image.svg"):
        file_path = _seed_file(client, root, name=name)
        response = client.get("/api/files/stream", params={"path": str(file_path)})
        assert response.status_code == 415


def test_query_token_does_not_authenticate_other_endpoints(forced_files_client):
    client, root = forced_files_client
    file_path = _seed_file(client, root)

    del client.headers[web_server._SESSION_HEADER_NAME]

    # The query-token escape hatch is scoped to downloads only; it must not
    # unlock the rest of the API surface.
    leaked = client.get(
        "/api/files/read",
        params={"path": str(file_path), "token": web_server._SESSION_TOKEN},
    )
    assert leaked.status_code == 401




# ---------------------------------------------------------------------------
# Streaming multipart upload (/api/files/upload-stream) — NS-501
# ---------------------------------------------------------------------------








def test_stream_upload_cleans_temp_on_cancellation(forced_files_client):
    """A client disconnect mid-stream (asyncio.CancelledError) must not leak a temp file.

    CancelledError is a BaseException, not an Exception, so it bypasses the
    endpoint's ``except`` clauses entirely. The cleanup therefore lives in a
    ``finally`` keyed on a success flag — without it, every aborted large
    upload (the exact NS-501 scenario) would orphan a partial ``.upload`` temp
    file in the target directory. We invoke the endpoint coroutine directly so
    the BaseException propagates instead of being swallowed by the test client.
    """
    import asyncio

    _client, root = forced_files_client
    target = root / "out" / "aborted.bin"
    target.parent.mkdir(parents=True, exist_ok=True)

    class _AbortingUpload:
        """UploadFile stand-in that yields one chunk then aborts like a dropped client."""

        filename = "aborted.bin"

        def __init__(self):
            self._calls = 0

        async def read(self, _size):
            self._calls += 1
            if self._calls == 1:
                return b"partial chunk before the client vanished"
            raise asyncio.CancelledError()

        async def close(self):
            return None

    request = SimpleNamespace()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            _rt_files.upload_managed_file_stream(
                request=request,
                file=_AbortingUpload(),
                path=str(target),
                overwrite=True,
            )
        )

    # No partial data was promoted into place ...
    assert not target.exists()
    # ... and no .upload temp file was left behind.
    leftovers = [p.name for p in target.parent.iterdir() if ".upload" in p.name]
    assert leftovers == [], f"temp upload files leaked on cancellation: {leftovers}"


def test_sensitive_env_files_hidden_from_listing(forced_files_client):
    """Regression test for #57505: .env files must not appear in directory listings."""
    client, root = forced_files_client

    # Create a regular file and .env variants including shorthand suffixes.
    root.mkdir(parents=True, exist_ok=True)
    regular = root / "config.txt"
    regular.write_text("safe content")
    env_file = root / ".env"
    env_file.write_text("SECRET_KEY=abc123")
    env_local = root / ".env.local"
    env_local.write_text("LOCAL_SECRET=def456")
    env_prod = root / ".env.prod"
    env_prod.write_text("PROD_SECRET=ghi789")

    listing = client.get("/api/files", params={"path": str(root)})
    assert listing.status_code == 200
    names = [e["name"] for e in listing.json()["entries"]]
    assert "config.txt" in names
    assert ".env" not in names
    assert ".env.local" not in names
    assert ".env.prod" not in names












def test_other_credential_store_basenames_blocked(forced_files_client):
    """Regression: the managed-files guard must cover the same credential
    basenames as gateway.platforms.base._ROOT_CREDENTIAL_FILES and
    agent.file_safety.get_read_block_error, not just .env — an operator can
    point the managed root at HERMES_HOME itself (#57505), which contains
    all of these live secret stores."""
    client, root = forced_files_client
    root.mkdir(parents=True, exist_ok=True)

    for name in (
        "auth.json",
        "auth.lock",
        "credentials",
        "config.yaml",
        ".anthropic_oauth.json",
        "google_token.json",
        "google_oauth_pending.json",
        "google_oauth.json",
        "webhook_subscriptions.json",
        "bws_cache.json",
        "bws_cache.enc.json",
    ):
        p = root / name
        p.write_text("SECRET=abc123")
        assert client.get("/api/files/read", params={"path": str(p)}).status_code == 403, name
        assert client.get("/api/files/download", params={"path": str(p)}).status_code == 403, name
        assert client.get("/api/files/stream", params={"path": str(p)}).status_code == 403, name

    listing = client.get("/api/files", params={"path": str(root)})
    names = [e["name"] for e in listing.json()["entries"]]
    assert names == []




def test_credential_dir_trees_blocked_on_subdir_descent(forced_files_client):
    """Regression: mcp-tokens/ (live MCP OAuth tokens) and pairing/ are denied
    as whole directory trees by both canonical guards
    (gateway.platforms.base._ROOT_CREDENTIAL_DIRS and
    agent.file_safety). A basename-only check would still expose their
    per-server files (e.g. ``mcp-tokens/github.json``) once the browser
    descends into the subdir. The managed-files guard must block any path with
    a credential-directory component, not just leaf basenames."""
    client, root = forced_files_client
    root.mkdir(parents=True, exist_ok=True)

    # A per-server MCP token file with a NON-canonical basename that the
    # basename denylist alone would not catch.
    mcp_dir = root / "mcp-tokens"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    mcp_file = mcp_dir / "github.json"
    mcp_file.write_text('{"access_token": "SECRET"}\n')

    pairing_dir = root / "pairing"
    pairing_dir.mkdir(parents=True, exist_ok=True)
    pairing_file = pairing_dir / "device-abc"
    pairing_file.write_text("PAIRING-SECRET\n")

    # The token dirs themselves must not appear in the root listing.
    root_names = [e["name"] for e in client.get(
        "/api/files", params={"path": str(root)}).json()["entries"]]
    assert "mcp-tokens" not in root_names
    assert "pairing" not in root_names

    # Read/download of the per-server files must be denied even though their
    # basenames aren't in _SENSITIVE_MANAGED_FILE_BASENAMES.
    for p in (mcp_file, pairing_file):
        assert client.get("/api/files/read", params={"path": str(p)}).status_code == 403, str(p)
        assert client.get("/api/files/download", params={"path": str(p)}).status_code == 403, str(p)
        assert client.get("/api/files/stream", params={"path": str(p)}).status_code == 403, str(p)

    # Listing the credential dir itself yields nothing exploitable: every child
    # is filtered because the parent component is a credential dir.
    mcp_listing = client.get("/api/files", params={"path": str(mcp_dir)})
    assert [e["name"] for e in mcp_listing.json()["entries"]] == []




def test_git_branch_decodes_utf8_under_a_gbk_default_codec(tmp_path, monkeypatch):
    """#83851: the Desktop polls ``/api/fs/default-cwd``; on zh-CN Windows the serve process's default
    subprocess codec is cp936, and git's UTF-8 output (branch names, localized stderr) raised
    UnicodeDecodeError in communicate()'s reader threads on every poll. The branch must round-trip."""
    import shutil
    import subprocess

    git = shutil.which("git")
    if git is None:
        pytest.skip("git not installed")
    branch = "功能/✅-修复"  # UTF-8 bytes that are illegal multibyte sequences in GBK
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    subprocess.run([git, "-C", str(tmp_path), "symbolic-ref", "HEAD", f"refs/heads/{branch}"], check=True)
    # subprocess resolves an unspecified text-mode codec through _text_encoding() → locale.getencoding()
    # (cp936 on zh-CN Windows); patch that seam since run_tests.sh's PYTHONUTF8=1 short-circuits locale.
    monkeypatch.setattr(subprocess, "_text_encoding", lambda: "gbk")

    assert _rt_files._fs_git_branch(str(tmp_path)) == branch


# ---------------------------------------------------------------------------
# Uploads below uploads/hermie never follow a symbolic link (the Hermie apps' attachments and the upload.dir of
# an input.file request: <session cwd>/uploads/hermie/<date>/<16 hex>-<name>; the cwd is the agent's).
# ---------------------------------------------------------------------------

_DAY = "2026-10-04"


def _upload_json(client, path, *, overwrite=False):
    return client.post("/api/files/upload", json={
        "path": str(path), "data_url": "data:text/plain;base64,TUFSS0VS", "overwrite": overwrite})


def _upload_stream(client, path, *, overwrite=False):
    return client.post("/api/files/upload-stream", data={"path": str(path), "overwrite": str(overwrite).lower()},
                       files={"file": ("x.txt", b"MARKER", "text/plain")})


_UPLOADS = {"json": _upload_json, "stream": _upload_stream}


@pytest.mark.parametrize("route", sorted(_UPLOADS))
@pytest.mark.parametrize("link", ["uploads", "uploads/hermie", f"uploads/hermie/{_DAY}"])
def test_an_upload_below_uploads_hermie_never_follows_a_symlink(local_files_client, route, link):
    """An agent links a component of its workspace's uploads/hermie/<date> to a folder elsewhere (an autostart
    folder, say): the person's upload is refused instead of landing there, and nothing is created through it."""
    client, home = local_files_client
    workspace, elsewhere = home / "work", home / "elsewhere"
    workspace.mkdir()
    elsewhere.mkdir()
    linked = workspace / link
    linked.parent.mkdir(parents=True, exist_ok=True)
    linked.symlink_to(elsewhere, target_is_directory=True)
    response = _UPLOADS[route](client, workspace / "uploads" / "hermie" / _DAY / "0123456789abcdef-x.txt")
    assert response.status_code == 400, response.text
    assert list(elsewhere.rglob("*")) == []


@pytest.mark.parametrize("route", sorted(_UPLOADS))
def test_an_upload_below_uploads_hermie_never_writes_through_a_symlinked_file(local_files_client, route):
    client, home = local_files_client
    folder = home / "work" / "uploads" / "hermie" / _DAY
    folder.mkdir(parents=True)
    victim = home / "victim.txt"
    victim.write_bytes(b"untouched")
    (folder / "0123456789abcdef-x.txt").symlink_to(victim)
    response = _UPLOADS[route](client, folder / "0123456789abcdef-x.txt", overwrite=True)
    assert response.status_code == 400, response.text
    assert victim.read_bytes() == b"untouched"
    assert (folder / "0123456789abcdef-x.txt").is_symlink()


@pytest.mark.parametrize("route", sorted(_UPLOADS))
def test_an_upload_below_uploads_hermie_creates_private_folders_and_the_file(local_files_client, route):
    """The ordinary case still works: missing folders are created (0700), a symlink ABOVE uploads (a workspace
    reached through a link, /tmp on macOS) is fine, and the response names the stored file."""
    client, home = local_files_client
    real_workspace = home / "real-work"
    real_workspace.mkdir()
    (home / "work").symlink_to(real_workspace, target_is_directory=True)
    target = home / "work" / "uploads" / "hermie" / _DAY / "0123456789abcdef-x.txt"
    response = _UPLOADS[route](client, target)
    assert response.status_code == 200, response.text
    stored = real_workspace / "uploads" / "hermie" / _DAY / "0123456789abcdef-x.txt"
    assert stored.read_bytes() == b"MARKER" and not stored.is_symlink()
    assert response.json()["path"] == str(stored.resolve())
    for folder in (stored.parent, stored.parent.parent, stored.parent.parent.parent):
        assert folder.stat().st_mode & 0o777 == 0o700
    assert [p.name for p in stored.parent.iterdir()] == [stored.name], "no temp file left behind"
    # overwrite rules are unchanged
    assert _UPLOADS[route](client, target).status_code == 409
    assert _UPLOADS[route](client, target, overwrite=True).status_code == 200


def test_an_upload_into_an_existing_private_upload_dir_works(local_files_client):
    """The directory the gateway made for an input.file request (``interactive._upload_dir``) takes the upload."""
    client, home = local_files_client
    folder = home / "work" / "uploads" / "hermie" / _DAY
    folder.mkdir(parents=True, mode=0o700)
    response = _upload_stream(client, folder / "0123456789abcdef-receipt.txt")
    assert response.status_code == 200, response.text
    assert (folder / "0123456789abcdef-receipt.txt").read_bytes() == b"MARKER"


def test_an_upload_elsewhere_keeps_following_links_as_before(local_files_client):
    """Only the uploads/hermie part of a path is held to no-follow: the file browser's other writes are as before."""
    client, home = local_files_client
    real = home / "real"
    real.mkdir()
    (home / "alias").symlink_to(real, target_is_directory=True)
    assert _upload_json(client, home / "alias" / "notes.txt").status_code == 200
    assert (real / "notes.txt").read_bytes() == b"MARKER"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
@pytest.mark.parametrize("route", sorted(_UPLOADS))
def test_an_upload_below_uploads_hermie_under_a_search_only_ancestor_works(local_files_client, route):
    """An ancestor the gateway may search but not list (``/home`` at 0711): only the folder holding ``uploads`` is
    opened, never its ancestors."""
    client, home = local_files_client
    locked = home / "locked"
    folder = locked / "work" / "uploads" / "hermie" / _DAY
    (locked / "work").mkdir(parents=True)
    locked.chmod(0o100)
    try:
        response = _UPLOADS[route](client, folder / "0123456789abcdef-x.txt")
        assert response.status_code == 200, response.text
        assert (folder / "0123456789abcdef-x.txt").read_bytes() == b"MARKER"
    finally:
        locked.chmod(0o700)
