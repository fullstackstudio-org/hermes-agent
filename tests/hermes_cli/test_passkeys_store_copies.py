"""The passkey store never travels: backups leave it out, imports skip it, a backup is never written beside
it, profile clones and exports do not copy it, a profile import drops it, and the file manager will not
delete a folder that holds it. A copy would give two gateways one ``gateway_id`` and ``handle_key``; an
imported store would carry credentials nobody enrolled on this gateway."""

from __future__ import annotations

import tarfile
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest

STORE_FILES = ("passkeys.db", "passkeys.db-wal", "passkeys.db-shm")


def _plant_store(home: Path) -> Path:
    store_dir = home / "dashboard_auth"
    store_dir.mkdir(parents=True, exist_ok=True)
    for name in STORE_FILES:
        (store_dir / name).write_bytes(b"store rows")
    (store_dir / "pictures").mkdir(exist_ok=True)
    (store_dir / "pictures" / "abc").write_bytes(b"picture")
    return store_dir


@pytest.fixture(autouse=True)
def _no_real_gateway_service(monkeypatch):
    import hermes_cli.gateway as gateway_mod
    monkeypatch.setattr(gateway_mod, "ensure_gateway_service", lambda **kw: False)
    monkeypatch.setattr(gateway_mod, "_is_service_running", lambda: False)


# ── hermes backup / hermes import (also what /api/ops/import-upload runs) ────────────────────────


def test_should_exclude_the_store_at_the_root_and_in_profiles():
    from hermes_cli.backup import _should_exclude
    for rel in ("dashboard_auth/passkeys.db", "profiles/coder/dashboard_auth/passkeys.db",
                "dashboard_auth/passkeys.db-journal"):
        assert _should_exclude(Path(rel)), rel
    for rel in ("dashboard_auth/pictures/abc", "notes/passkeys.db", "passkeys.db"):
        assert not _should_exclude(Path(rel)), rel


def test_a_backup_leaves_the_store_out(tmp_path, monkeypatch):
    from hermes_cli.backup import run_backup
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: x\n")
    _plant_store(home)
    _plant_store(home / "profiles" / "coder")
    from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
    for where in (home, home / "profiles" / "coder"):  # real databases: the backup snapshots those
        (where / "dashboard_auth" / "passkeys.db").unlink()
        PasskeyStore(where / "dashboard_auth" / "passkeys.db").identity()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    out = tmp_path / "b.zip"
    run_backup(Namespace(output=str(out)))
    names = zipfile.ZipFile(out).namelist()
    assert not [n for n in names if "passkeys.db" in n]
    assert any(n.endswith("dashboard_auth/pictures/abc") for n in names)


def test_an_import_skips_a_store_in_the_archive(tmp_path, monkeypatch):
    from hermes_cli.backup import run_import
    archive = tmp_path / "hand-built.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config.yaml", "model: x\n")
        zf.writestr("dashboard_auth/passkeys.db", b"foreign rows")
        zf.writestr("profiles/coder/config.yaml", "model: y\n")
        zf.writestr("profiles/coder/dashboard_auth/passkeys.db", b"foreign rows")
    home = tmp_path / "dest" / ".hermes"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "dest")
    run_import(Namespace(zipfile=str(archive), force=True))
    assert (home / "config.yaml").exists()
    assert not (home / "dashboard_auth" / "passkeys.db").exists()
    assert not (home / "profiles" / "coder" / "dashboard_auth" / "passkeys.db").exists()


def test_an_import_does_not_replace_the_store_already_here(tmp_path, monkeypatch):
    from hermes_cli.backup import run_import
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config.yaml", "model: x\n")
        zf.writestr("dashboard_auth/passkeys.db", b"foreign rows")
    home = tmp_path / "dest" / ".hermes"
    store_dir = _plant_store(home)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "dest")
    run_import(Namespace(zipfile=str(archive), force=True))
    assert (store_dir / "passkeys.db").read_bytes() == b"store rows"


# ── /api/ops/backup ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def ops_client(_isolate_hermes_home, monkeypatch):
    from starlette.testclient import TestClient
    from hermes_cli import web_server, web_server_gateway

    spawned: list = []
    class _Proc:
        pid = 4242

    monkeypatch.setattr(web_server_gateway, "_spawn_hermes_action",
                        lambda argv, name: spawned.append(list(argv)) or _Proc())
    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    return c, spawned


def test_a_backup_is_never_written_into_dashboard_auth(ops_client, tmp_path):
    client, spawned = ops_client
    from hermes_constants import get_hermes_home
    store_dir = _plant_store(get_hermes_home())
    for output in (str(store_dir / "passkeys.db"), str(store_dir), str(store_dir / "x.zip"),
                   str(store_dir / ".." / "dashboard_auth" / "y")):
        resp = client.post("/api/ops/backup", json={"output": output})
        assert resp.status_code == 403, output
    assert spawned == []
    assert client.post("/api/ops/backup", json={"output": str(tmp_path / "fine.zip")}).status_code == 200
    assert len(spawned) == 1


# ── profiles ─────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def profile_env(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    default_home = tmp_path / ".hermes"
    default_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(default_home))
    (default_home / "config.yaml").write_text("model: test\n")
    return default_home


def test_clone_all_does_not_copy_the_store(profile_env):
    from hermes_cli.profiles import create_profile
    _plant_store(profile_env)
    clone = create_profile("coder", clone_all=True, no_alias=True)
    assert (clone / "dashboard_auth" / "pictures" / "abc").exists()
    assert not list((clone / "dashboard_auth").glob("passkeys.db*"))


def test_exports_do_not_carry_the_store(profile_env, tmp_path):
    from hermes_cli.profiles import create_profile, export_profile
    named = create_profile("coder", no_alias=True)
    _plant_store(named)
    _plant_store(profile_env)
    for name in ("coder", "default"):
        out = tmp_path / f"{name}.tar.gz"
        export_profile(name, str(out))
        with tarfile.open(out) as tf:
            assert not [n for n in tf.getnames() if "passkeys.db" in n], name


def test_a_profile_import_drops_a_store_in_the_archive(profile_env, tmp_path):
    from hermes_cli.profiles import get_profile_dir, import_profile
    staging = tmp_path / "staging" / "imported"
    staging.mkdir(parents=True)
    (staging / "config.yaml").write_text("model: x\n")
    _plant_store(staging)
    archive = tmp_path / "imported.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(staging, arcname="imported")
    import_profile(str(archive))
    imported = get_profile_dir("imported")
    assert (imported / "config.yaml").exists()
    assert not list((imported / "dashboard_auth").glob("passkeys.db*"))
    assert (imported / "dashboard_auth" / "pictures" / "abc").exists()


# ── file manager ─────────────────────────────────────────────────────────────────────────────────


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


def test_the_file_manager_will_not_delete_a_folder_holding_the_store(files_client):
    client, home = files_client
    store_dir = _plant_store(home)
    profile_store = _plant_store(home / "profiles" / "coder")
    for target in (store_dir, home, home.parent, profile_store, home / "profiles"):
        resp = client.request("DELETE", "/api/files", json={"path": str(target), "recursive": True})
        assert resp.status_code == 403, target
    assert (store_dir / "passkeys.db").exists() and (profile_store / "passkeys.db").exists()
    # A folder beside it, or inside dashboard_auth but not holding the store, goes as before.
    assert client.request("DELETE", "/api/files",
                          json={"path": str(store_dir / "pictures"), "recursive": True}).status_code == 200
    other = home / "notes"
    other.mkdir()
    assert client.request("DELETE", "/api/files", json={"path": str(other), "recursive": True}).status_code == 200


# ── case variants and links (macOS APFS and Windows ignore case) ─────────────────────────────────


def _case_insensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe"
    probe.mkdir()
    try:
        return (directory / "caseprobe").exists()
    finally:
        probe.rmdir()


def test_store_names_are_compared_case_folded():
    from hermes_cli.backup import _should_exclude
    from hermes_cli.profiles import _non_exportable_entries
    for rel in ("Dashboard_Auth/Passkeys.db", "profiles/x/DASHBOARD_AUTH/PASSKEYS.DB-wal"):
        assert _should_exclude(Path(rel)), rel
    assert _non_exportable_entries("/h/Dashboard_Auth", ["Passkeys.DB"]) == {"Passkeys.DB"}
    assert not _should_exclude(Path("dashboard_auth2/passkeys.db"))


def test_an_import_with_a_case_variant_member_leaves_the_live_store_alone(tmp_path, monkeypatch):
    """The reproduction: ``Dashboard_Auth/Passkeys.db`` is the live store on a case-insensitive disk."""
    from hermes_cli.backup import run_import
    from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
    home = tmp_path / "dest" / ".hermes"
    home.mkdir(parents=True)
    live = PasskeyStore(home / "dashboard_auth" / "passkeys.db")
    before = live.identity()
    foreign = PasskeyStore(tmp_path / "foreign" / "passkeys.db")
    foreign.identity()
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config.yaml", "model: x\n")
        zf.writestr("Dashboard_Auth/Passkeys.db", foreign.path.read_bytes())
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "dest")
    run_import(Namespace(zipfile=str(archive), force=True))
    assert PasskeyStore(live.path).identity() == before
    assert not (home / "Dashboard_Auth" / "Passkeys.db").exists() or _case_insensitive(home)


def test_a_profile_import_drops_a_case_variant_store(profile_env, tmp_path):
    from hermes_cli.profiles import get_profile_dir, import_profile
    staging = tmp_path / "staging" / "variant"
    (staging / "Dashboard_Auth").mkdir(parents=True)
    (staging / "config.yaml").write_text("model: x\n")
    (staging / "Dashboard_Auth" / "Passkeys.db").write_bytes(b"foreign rows")
    archive = tmp_path / "variant.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(staging, arcname="variant")
    import_profile(str(archive))
    assert not (get_profile_dir("variant") / "Dashboard_Auth" / "Passkeys.db").exists()


def test_the_file_manager_refuses_case_variants_and_links_of_the_store_folders(files_client, tmp_path):
    client, home = files_client
    store_dir = _plant_store(home)

    def delete(path):
        return client.request("DELETE", "/api/files", json={"path": str(path), "recursive": True}).status_code

    if _case_insensitive(home.parent):
        assert delete(home / "Dashboard_Auth") == 403
        assert delete(home.parent / ".HERMES") == 403
    link = tmp_path / "home" / "innocent"
    link.symlink_to(store_dir, target_is_directory=True)
    assert delete(link) == 403
    assert (store_dir / "passkeys.db").exists()
    sibling = home / "dashboard_auth2"
    sibling.mkdir()
    (sibling / "passkeys.db").write_bytes(b"not a store location")
    assert delete(sibling) == 200


def test_a_backup_output_is_refused_in_any_case_and_through_a_link(ops_client, tmp_path):
    client, spawned = ops_client
    from hermes_constants import get_hermes_home
    store_dir = _plant_store(get_hermes_home())
    link = tmp_path / "linked"
    link.symlink_to(store_dir, target_is_directory=True)
    for output in (str(get_hermes_home() / "Dashboard_Auth" / "passkeys.db"), str(link / "x.zip"), str(link)):
        assert client.post("/api/ops/backup", json={"output": output}).status_code == 403, output
    assert spawned == []
    sibling = tmp_path / "dashboard_auth2"
    sibling.mkdir()
    assert client.post("/api/ops/backup", json={"output": str(sibling / "b.zip")}).status_code == 200
