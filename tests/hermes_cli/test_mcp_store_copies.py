"""The MCP grant registry (``dashboard_auth/mcp.db``) never travels, exactly like ``passkeys.db``: backups
leave it out, imports skip it, profile clones and exports do not copy it, a profile import drops it, and the
file manager neither shows, writes nor deletes a folder holding it. A copy on another host would accept this
gateway's MCP tokens there; an imported one would carry grants nobody consented to here."""

from __future__ import annotations

import tarfile
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest

STORE_FILES = ("mcp.db", "mcp.db-wal", "mcp.db-shm")


def _plant_store(home: Path, *, real: bool = False) -> Path:
    store_dir = home / "dashboard_auth"
    store_dir.mkdir(parents=True, exist_ok=True)
    if real:  # a real database: a backup snapshots .db files rather than copying them
        from hermes_cli.dashboard_auth.mcp.store import MCPStore
        MCPStore(store_dir / "mcp.db").counts()
    else:
        for name in STORE_FILES:
            (store_dir / name).write_bytes(b"grant rows")
    (store_dir / "pictures").mkdir(exist_ok=True)
    (store_dir / "pictures" / "abc").write_bytes(b"picture")
    return store_dir


@pytest.fixture(autouse=True)
def _no_real_gateway_service(monkeypatch):
    import hermes_cli.gateway as gateway_mod
    monkeypatch.setattr(gateway_mod, "ensure_gateway_service", lambda **kw: False)
    monkeypatch.setattr(gateway_mod, "_is_service_running", lambda: False)


def test_backup_and_import_rules_cover_the_registry_in_any_case():
    from hermes_cli.backup import _should_exclude
    from hermes_cli.profiles import _non_exportable_entries
    for rel in ("dashboard_auth/mcp.db", "profiles/coder/dashboard_auth/mcp.db-wal", "Dashboard_Auth/MCP.db"):
        assert _should_exclude(Path(rel)), rel
    for rel in ("notes/mcp.db", "mcp.db", "dashboard_auth2/mcp.db", "dashboard_auth/pictures/abc"):
        assert not _should_exclude(Path(rel)), rel
    assert _non_exportable_entries("/h/Dashboard_Auth", ["MCP.db-shm"]) == {"MCP.db-shm"}


def test_a_backup_leaves_the_registry_out(tmp_path, monkeypatch):
    from hermes_cli.backup import run_backup
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: x\n")
    _plant_store(home, real=True)
    _plant_store(home / "profiles" / "coder", real=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    out = tmp_path / "b.zip"
    run_backup(Namespace(output=str(out)))
    names = zipfile.ZipFile(out).namelist()
    assert not [n for n in names if "mcp.db" in n]
    assert any(n.endswith("dashboard_auth/pictures/abc") for n in names)


def test_an_import_neither_installs_nor_replaces_the_registry(tmp_path, monkeypatch):
    from hermes_cli.backup import run_import
    archive = tmp_path / "hand-built.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config.yaml", "model: x\n")
        zf.writestr("dashboard_auth/mcp.db", b"foreign rows")
        zf.writestr("profiles/coder/config.yaml", "model: y\n")
        zf.writestr("profiles/coder/Dashboard_Auth/MCP.db", b"foreign rows")
    home = tmp_path / "dest" / ".hermes"
    store_dir = _plant_store(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "dest")
    run_import(Namespace(zipfile=str(archive), force=True))
    assert (home / "config.yaml").exists()
    assert (store_dir / "mcp.db").read_bytes() == b"grant rows"
    coder = home / "profiles" / "coder"
    assert not [p for p in coder.rglob("*") if p.name.casefold().startswith("mcp.db")]


@pytest.fixture
def profile_env(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    default_home = tmp_path / ".hermes"
    default_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(default_home))
    (default_home / "config.yaml").write_text("model: test\n")
    return default_home


def test_profile_clones_exports_and_imports_do_not_carry_the_registry(profile_env, tmp_path):
    from hermes_cli.profiles import create_profile, export_profile, get_profile_dir, import_profile
    _plant_store(profile_env)
    clone = create_profile("coder", clone_all=True, no_alias=True)
    assert (clone / "dashboard_auth" / "pictures" / "abc").exists()
    assert not list((clone / "dashboard_auth").glob("mcp.db*"))

    _plant_store(clone)
    for name in ("coder", "default"):
        out = tmp_path / f"{name}.tar.gz"
        export_profile(name, str(out))
        with tarfile.open(out) as tf:
            assert not [n for n in tf.getnames() if "mcp.db" in n], name

    staging = tmp_path / "staging" / "imported"
    (staging / "Dashboard_Auth").mkdir(parents=True)
    (staging / "config.yaml").write_text("model: x\n")
    (staging / "Dashboard_Auth" / "MCP.db").write_bytes(b"foreign rows")
    archive = tmp_path / "imported.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(staging, arcname="imported")
    import_profile(str(archive))
    assert not (get_profile_dir("imported") / "Dashboard_Auth" / "MCP.db").exists()


@pytest.fixture
def files_client(tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    from hermes_cli import web_server

    home = tmp_path / "home" / ".hermes"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(tmp_path / "home"))
    prev = (getattr(web_server.app.state, "auth_required", None), getattr(web_server.app.state, "bound_host", None))
    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = None
    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    try:
        yield c, home
    finally:
        c.close()
        web_server.app.state.auth_required, web_server.app.state.bound_host = prev


def test_the_file_manager_neither_deletes_nor_writes_the_registry(files_client):
    client, home = files_client
    store_dir = _plant_store(home)
    _plant_store(home / "profiles" / "coder")
    for target in (store_dir, home, home / "profiles", store_dir / "mcp.db"):
        resp = client.request("DELETE", "/api/files", json={"path": str(target), "recursive": True})
        assert resp.status_code == 403, target
    assert (store_dir / "mcp.db").exists()
    write = client.post("/api/fs/write-text", json={"path": str(store_dir / "MCP.db-journal"), "content": "x"})
    assert write.status_code == 403, write.text
    listing = client.get("/api/files", params={"path": str(store_dir)})
    assert listing.status_code == 200, listing.text
    assert [e["name"] for e in listing.json()["entries"]] == ["pictures"]
    # A folder inside dashboard_auth that does not hold a store goes as before.
    assert client.request("DELETE", "/api/files",
                          json={"path": str(store_dir / "pictures"), "recursive": True}).status_code == 200
