"""``confirm.passkey`` and the passkey store are out of a dashboard session's reach: the config writers
(REST, raw YAML, ``config.set``) refuse a change to the section and change nothing, and the file manager
neither shows nor writes the store. Also the settings reader the guards and the gateway share."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
import yaml

from hermes_cli.dashboard_auth.passkeys import settings as ps


# ── the settings reader ──────────────────────────────────────────────────────────────────────────


def test_defaults_are_off_with_the_official_native_rp():
    s = ps.settings_from_config({})
    assert (s.enabled, s.user_invites, s.receipts_days, s.allow_private_base_urls) == (False, True, 90, False)
    assert dict(s.native_rps) == {"confirm.hermie.dev": ("https://confirm.hermie.dev",)}
    assert s.require == ps.Require() and s.problems == ()


def test_self_enrolment_is_on_by_default_without_cooling_off():
    s = ps.settings_from_config({})
    assert s.self_enrol == ps.SelfEnrol(enabled=True, accept_missing_auth_time=False, cooling_off_s=0)
    s = ps.settings_from_config({"confirm": {"passkey": {"self_enrol": {"cooling_off_s": 600}}}})
    assert s.self_enrol == ps.SelfEnrol(enabled=True, accept_missing_auth_time=False, cooling_off_s=600)
    assert s.problems == ()


@pytest.mark.parametrize(("section", "expected", "problems"), [
    ({"enabled": "no"}, ps.SelfEnrol(enabled=False), 1),
    ({"accept_missing_auth_time": 1}, ps.SelfEnrol(accept_missing_auth_time=False), 1),
    # An unreadable cooling-off must not become none: self-enrolment is off until it is fixed.
    ({"cooling_off_s": "10m"}, ps.SelfEnrol(enabled=False), 1),
    ({"cooling_off_s": -1}, ps.SelfEnrol(enabled=False), 1),
    ({"cooling_off_s": True}, ps.SelfEnrol(enabled=False), 1),
    ({"cooling_off_s": 7 * 24 * 3600 + 1}, ps.SelfEnrol(enabled=False), 1),
    ({"enabled": False, "accept_missing_auth_time": True}, ps.SelfEnrol(enabled=False, accept_missing_auth_time=True),
     0),
])
def test_unusable_self_enrolment_entries_take_the_safe_value(section, expected, problems):
    s = ps.settings_from_config({"confirm": {"passkey": {"self_enrol": section}}})
    assert s.self_enrol == expected and len(s.problems) == problems
    assert all("self_enrol" in p for p in s.problems)


def test_a_self_enrol_that_is_not_a_mapping_switches_it_off():
    s = ps.settings_from_config({"confirm": {"passkey": {"self_enrol": True}}})
    assert s.self_enrol.enabled is False and s.problems == ("self_enrol is not a mapping; self-enrolment is off",)


def test_unusable_entries_are_dropped_and_named():
    s = ps.settings_from_config({"confirm": {"passkey": {
        "enabled": "yes", "receipts_days": 0, "allow_private_base_urls": True,
        "native_rps": {"Confirm.Example": ["https://a.example"], "ok.example": ["https://ok.example",
                                                                                  "http://ok.example",
                                                                                  "https://ok.example/path"]},
        "require": {"commands": ["git push*", 3, ""], "approvals": "true", "tools": "x"}}}})
    assert s.enabled is False and s.receipts_days == 90 and s.allow_private_base_urls is True
    assert dict(s.native_rps) == {"confirm.hermie.dev": ("https://confirm.hermie.dev",),
                                  "ok.example": ("https://ok.example",)}
    assert s.require == ps.Require(commands=("git push*",))
    # Five for the other keys, three for the operator rules (commands entries, tools, approvals).
    assert len(s.problems) == 8


def test_an_empty_origin_list_removes_a_native_rp_even_the_default_one():
    s = ps.settings_from_config({"confirm": {"passkey": {"native_rps": {
        "confirm.hermie.dev": [], "confirm.example.org": ["https://confirm.example.org"]}}}})
    assert dict(s.native_rps) == {"confirm.example.org": ("https://confirm.example.org",)} and s.problems == ()


@pytest.mark.parametrize("cfg", [None, {"confirm": 5}, {"confirm": {"passkey": None}}, {"confirm": {}}])
def test_a_missing_or_malformed_section_reads_as_the_defaults(cfg):
    assert ps.effective_section(cfg) == ps.effective_section({})


@pytest.mark.parametrize(("before", "after", "changed"), [
    ({}, {"model": "x"}, False),
    ({}, {"confirm": {"passkey": {"enabled": False}}}, False),  # an explicit default reads the same
    ({}, {"confirm": {"passkey": {"enabled": True}}}, True),
    ({"confirm": {"passkey": {"enabled": True}}}, {}, True),  # dropping the section is a change
    ({"confirm": {"passkey": {"enabled": True}}}, {"confirm": 5}, True),
    ({}, {"confirm": {"passkey": {"native_rps": {"evil.example": ["https://evil.example"]}}}}, True),
    ({}, {"confirm": {"passkey": {"require": {"tools": []}}}}, False),
    ({}, {"confirm": {"passkey": {"new_key": 1}}}, True),
    ({}, {"confirm": {"other": 1}}, False),
    ({}, {"confirm": {"passkey": {"base_urls": ["https://evil.example"]}}}, True),
    ({"confirm": {"passkey": {"base_urls": ["https://gw.example"]}}}, {"confirm": {"passkey": {"base_urls": []}}}, True),
    ({}, {"dashboard": {"public_url": "https://evil.example"}}, False),  # not the level's list; see the CLI hint
    ({}, {"confirm": {"passkey": {"self_enrol": {"enabled": True}}}}, False),  # the default, written out
    ({}, {"confirm": {"passkey": {"self_enrol": {"enabled": False}}}}, True),
    ({}, {"confirm": {"passkey": {"self_enrol": {"accept_missing_auth_time": True}}}}, True),
    ({}, {"confirm": {"passkey": {"self_enrol": {"cooling_off_s": 600}}}}, True),
])
def test_changes_protected(before, after, changed):
    assert ps.changes_protected(before, after) is changed


@pytest.mark.parametrize(("key", "protected"), [
    ("confirm", True), ("confirm.passkey", True), ("confirm.passkey.enabled", True), (" confirm.passkey.x", True),
    ("confirm.other", False), ("confirmation", False), ("approvals.mode", False), ("", False)])
def test_is_protected_key(key, protected):
    assert ps.is_protected_key(key) is protected


def test_the_gateway_context_takes_only_the_levels_own_base_urls():
    s = ps.settings_from_config({"dashboard": {"public_url": "https://dashboard.example"},
                                "confirm": {"passkey": {"base_urls": ["https://GW.example.com/", "ftp://x",
                                                                      "http://10.0.0.2:9119", 7]}}})
    assert s.base_urls == ("https://gw.example.com", "http://10.0.0.2:9119")
    assert [p for p in s.problems if p.startswith("base_urls")] == [
        "base_urls: 'ftp://x' is not an http(s) base URL", "base_urls: '7' is not an http(s) base URL"]
    ctx = ps.gateway_context((b"g" * 16, b"h" * 32), s)
    assert ctx.base_urls == ("https://gw.example.com", "http://10.0.0.2:9119")
    assert ctx.accepted_base_urls == ("https://gw.example.com",)
    assert ctx.capability_reason() == ""
    assert ps.gateway_context((b"g" * 16, b"h" * 32), ps.settings_from_config({})).capability_reason() == "no_base_url"
    assert ps.serialise_base_urls(["ftp://x", "https://a.example/", "https://A.example"]) == (
        ("https://a.example",), ("ftp://x",))


# ── REST config writers ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def client(_isolate_hermes_home):
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")
    from hermes_cli import web_server

    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    return c


@pytest.fixture
def config_file():
    from hermes_cli.config import get_config_path
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("model: some-model\nconfirm:\n  passkey:\n    enabled: true\n", encoding="utf-8")
    return path


def _audit_events() -> list[dict]:
    from hermes_constants import get_hermes_home
    log = get_hermes_home() / "logs" / "dashboard-auth.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.mark.parametrize("change", [
    {"enabled": False},
    {"base_urls": ["https://evil.example"]},
    {"native_rps": {"evil.example": ["https://evil.example"]}},
    {"allow_private_base_urls": True},
    {"require": {"approvals": True}},
    {"self_enrol": {"enabled": False}},
    {"self_enrol": {"accept_missing_auth_time": True}},
    {"self_enrol": {"cooling_off_s": 0, "enabled": True, "accept_missing_auth_time": False, "extra": 1}},
])
def test_a_config_put_changing_the_section_is_refused_and_the_file_is_byte_identical(client, config_file, change):
    before = config_file.read_bytes()
    resp = client.put("/api/config", json={"config": {"display": {"skin": "mono"},
                                                      "confirm": {"passkey": change}}})
    assert resp.status_code == 403
    assert resp.json()["detail"].startswith("protected_setting")
    assert config_file.read_bytes() == before
    line = _audit_events()[-1]
    assert (line["event"], line["surface"], line["path"]) == ("protected_setting_refused", "config_put", "/api/config")
    assert line["user_id"] == "" and line["ip"]  # session-token mode names no user; the address is there


def test_a_refused_put_names_the_signed_in_user(client, config_file, monkeypatch):
    """In gated mode the gate's verified session says who tried it."""
    from types import SimpleNamespace
    from hermes_cli.dashboard_auth.passkeys import settings as settings_mod

    seen = {}
    real = settings_mod.audit_refusal_for_request

    def capture(surface, request):
        request.state.session = SimpleNamespace(provider="self_hosted", user_id="abc")
        seen["surface"] = surface
        real(surface, request)

    monkeypatch.setattr(settings_mod, "audit_refusal_for_request", capture)
    resp = client.put("/api/config", json={"config": {"confirm": {"passkey": {"enabled": False}}}})
    assert resp.status_code == 403 and seen["surface"] == "config_put"
    assert _audit_events()[-1]["user_id"] == "self_hosted:abc"


def test_the_settings_page_round_trip_is_not_refused(client, config_file):
    """The page PUTs the whole defaulted GET record back: the section rides along unchanged."""
    record = client.get("/api/config").json()
    assert record["confirm"]["passkey"]["enabled"] is True
    resp = client.put("/api/config", json={"config": {**record, "display": {**record["display"], "skin": "mono"}}})
    assert resp.status_code == 200
    saved = yaml.safe_load(config_file.read_text())
    assert saved["display"]["skin"] == "mono" and saved["confirm"]["passkey"]["enabled"] is True


def test_the_settings_form_does_not_offer_the_section(client):
    fields = client.get("/api/config/schema").json()["fields"]
    assert not [k for k in fields if k.startswith("confirm.passkey")]


def test_a_raw_put_changing_the_section_is_refused_and_the_file_is_byte_identical(client, config_file):
    before = config_file.read_bytes()
    for text in ("model: some-model\n",  # section dropped
                 "model: some-model\nconfirm:\n  passkey:\n    enabled: true\n    receipts_days: 1\n",
                 "model: some-model\nconfirm: 1\n"):
        resp = client.put("/api/config/raw", json={"yaml_text": text})
        assert resp.status_code == 403, text
        assert config_file.read_bytes() == before


def test_a_raw_put_keeping_the_section_goes_through(client, config_file):
    text = config_file.read_text() + "display:\n  skin: mono\n"
    assert client.put("/api/config/raw", json={"yaml_text": text}).status_code == 200
    assert yaml.safe_load(config_file.read_text())["display"]["skin"] == "mono"


# ── config.set RPC ───────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("key", ["confirm", "confirm.passkey", "confirm.passkey.enabled", "confirm.passkey.native_rps",
                                 "confirm.passkey.self_enrol", "confirm.passkey.self_enrol.enabled",
                                 "confirm.passkey.self_enrol.cooling_off_s"])
def test_config_set_refuses_the_section(_isolate_hermes_home, key):
    from hermes_cli.config import get_config_path
    from tui_gateway import server

    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("model: m\n", encoding="utf-8")
    before = path.read_bytes()
    resp = server._methods["config.set"]("rid", {"key": key, "value": "true", "session_id": "s-1"})
    assert resp["error"]["code"] == 4030 and resp["error"]["data"] == {"reason": "protected_setting"}
    assert path.read_bytes() == before
    line = _audit_events()[-1]
    assert (line["surface"], line["session_id"], line["user_id"]) == ("config_set", "s-1", "")
    assert "connection" in line and "ip" in line


def test_config_set_audit_names_the_connections_login(_isolate_hermes_home):
    from types import SimpleNamespace
    from tui_gateway import server
    from tui_gateway.transport import bind_transport, reset_transport

    conn = SimpleNamespace(auth_identity={"provider": "basic", "user_id": "admin", "authenticated": True},
                           _peer="203.0.113.9", write=lambda obj: True)
    token = bind_transport(cast(Any, conn))
    try:
        resp = server._methods["config.set"]("rid", {"key": "confirm.passkey.enabled", "value": "true"})
    finally:
        reset_transport(token)
    assert resp["error"]["code"] == 4030
    line = _audit_events()[-1]
    assert (line["user_id"], line["ip"], line["connection"]) == ("basic:admin", "203.0.113.9", "SimpleNamespace")


# ── file manager ─────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def files_client(monkeypatch, tmp_path):
    from starlette.testclient import TestClient
    from hermes_cli import web_server

    root = tmp_path / "data"
    store_dir = root / "dashboard_auth"
    store_dir.mkdir(parents=True)
    for name in ("passkeys.db", "passkeys.db-wal", "PASSKEYS.DB-shm"):
        (store_dir / name).write_bytes(b"secret rows")
    (store_dir / "notes.txt").write_text("fine")
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(root))
    prev = (getattr(web_server.app.state, "auth_required", None), getattr(web_server.app.state, "bound_host", None))
    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = None
    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    try:
        yield c, store_dir
    finally:
        c.close()
        web_server.app.state.auth_required, web_server.app.state.bound_host = prev


def test_the_file_manager_does_not_list_or_read_the_store(files_client):
    client, store_dir = files_client
    names = [e["name"] for e in client.get("/api/files", params={"path": str(store_dir)}).json()["entries"]]
    assert names == ["notes.txt"]
    fs_names = [e["name"] for e in client.get("/api/fs/list", params={"path": str(store_dir)}).json()["entries"]]
    assert fs_names == ["notes.txt"]
    for route in ("/api/files/read", "/api/files/download", "/api/fs/read-text"):
        assert client.get(route, params={"path": str(store_dir / "passkeys.db")}).status_code == 403, route


def test_the_file_manager_does_not_write_or_delete_the_store(files_client):
    client, store_dir = files_client
    target = store_dir / "passkeys.db"
    planted = store_dir / "passkeys.db-journal"
    assert client.post("/api/files/upload", json={"path": str(target), "overwrite": True,
                                                  "data_url": "data:text/plain;base64,aGVsbG8="}).status_code == 403
    assert client.post("/api/files/upload", json={"path": str(planted),
                                                  "data_url": "data:text/plain;base64,aGVsbG8="}).status_code == 403
    assert client.post("/api/files/upload-stream", data={"path": str(target)},
                       files={"file": ("x", b"hello")}).status_code == 403
    assert client.post("/api/fs/write-text", json={"path": str(target), "content": "x"}).status_code == 403
    assert client.request("DELETE", "/api/files", json={"path": str(target)}).status_code == 403
    assert client.post("/api/files/mkdir", json={"path": str(store_dir / "passkeys.db-x")}).status_code == 403
    assert target.read_bytes() == b"secret rows" and not planted.exists()
    # A symbolic link pointing at the store resolves to it and is refused the same way.
    link = store_dir / "innocent.txt"
    link.symlink_to(target)
    assert client.post("/api/fs/write-text", json={"path": str(link), "content": "x"}).status_code == 403
    assert target.read_bytes() == b"secret rows"
