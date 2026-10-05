"""``approval.grants`` / ``approval.revoke``: what a person has allowed, per profile and per live session, and
taking it back.

Real config files in temporary profile homes (launch + ``work``): the standing list is read from the profile's
own ``command_allowlist`` and a revoke rewrites that file, never the other profile's.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import yaml

import tools.approval as approval
import tui_gateway.server as server
from tools.approval_detection import _approval_key_aliases
from tui_gateway.transport import bind_transport, reset_transport

ALICE, BOB = "self_hosted:alice", "self_hosted:bob"
CANONICAL = "script execution via heredoc"
LEGACY = next(alias for alias in _approval_key_aliases(CANONICAL) if alias != CANONICAL)
SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
WITH_SECRET = f"OPENAI_API_KEY={SECRET} make deploy"


class _WS:
    def __init__(self, login: str | None, agent: dict | None = None):
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id, **({"agent": agent} if agent else {})}

    def write(self, obj):
        return True

    def close(self):
        pass


def _write_allowlist(home: Path, entries, mode: str = "manual", **extra) -> None:
    config = {"approvals": {"mode": mode}, "command_allowlist": list(entries), **extra}
    (home / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")


def _allowlist(home: Path) -> list:
    return (yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")) or {}).get("command_allowlist") or []


@pytest.fixture
def homes(tmp_path, monkeypatch):
    launch, work = tmp_path / "launch", tmp_path / "launch" / "profiles" / "work"
    work.mkdir(parents=True)
    _write_allowlist(launch, [CANONICAL, LEGACY, "podman *", WITH_SECRET])
    _write_allowlist(work, ["cargo *"], mode="off")
    monkeypatch.setenv("HERMES_HOME", str(launch))
    monkeypatch.setattr(server, "_hermes_home", launch)

    def profile_home(name):
        name = (name or "").strip()
        if not name:
            return None
        if name == "work":
            return work
        raise server.ProfileUnavailableError(f"Profile '{name}' does not exist.")

    monkeypatch.setattr(server, "_profile_home", profile_home)
    emitted = []
    monkeypatch.setattr(server, "_emit_all_session_info", lambda: emitted.append("session.info"))
    saved = (set(approval._permanent_approved), dict(approval._permanent_approved_by_home),
             dict(approval._permanent_baseline_by_home), {k: set(v) for k, v in approval._session_approved.items()},
             set(approval._session_yolo))
    approval._permanent_approved_by_home.clear()
    approval._session_approved.clear()
    approval._session_yolo.clear()
    approval.load_permanent_allowlist()                   # the launch profile as the process started
    yield launch, work, emitted
    for sid in list(server._sessions):
        server._sessions.pop(sid, None)
    approval._permanent_approved.clear()
    approval._permanent_approved.update(saved[0])
    for target, value in zip((approval._permanent_approved_by_home, approval._permanent_baseline_by_home,
                              approval._session_approved), saved[1:4]):
        target.clear()
        target.update(value)
    approval._session_yolo.clear()
    approval._session_yolo.update(saved[4])


def _session(sid, *, creator=ALICE, home=None):
    session = {"session_key": f"key-{sid}", "transport": None, "history": [], "history_lock": threading.Lock(),
               "agent": None, "auth_user_id": creator, "auth_user_name": "", "running": False,
               "profile_home": str(home) if home else None, "source": "hermie"}
    server._sessions[sid] = session
    return session


def _call(method, params, transport=None):
    token = bind_transport(transport if transport is not None else _WS(ALICE))
    try:
        return server.handle_request({"id": 1, "method": method, "params": params})
    finally:
        reset_transport(token)


def _result(response):
    assert "error" not in response, response
    return response["result"]


def _perm(result, label):
    return next(row for row in result["permanent"] if row["label"] == label)


# ── listing ─────────────────────────────────────────────────────────────────────────────────────


def test_lists_standing_and_session_grants_redacted_for_the_callers_sessions(homes):
    _session("mine")
    _session("bobs", creator=BOB)
    approval.approve_session("key-mine", "tirith:homograph_url")
    approval.approve_session("key-mine", LEGACY)
    approval.approve_session("key-bobs", "execute_code")
    approval.enable_session_yolo("key-bobs")

    result = _result(_call("approval.grants", {}))

    assert result["mode"] == "manual"
    rows = {row["label"]: row for row in result["permanent"]}
    assert set(rows) == {CANONICAL, "podman *", "OPENAI_API_KEY=*** make deploy"}   # alias folded into its rule
    assert SECRET not in repr(result)
    assert {label: row["kind"] for label, row in rows.items()} == {
        CANONICAL: "pattern", "podman *": "glob", "OPENAI_API_KEY=*** make deploy": "command"}
    assert all(row["id"].startswith("perm:") and len(row["id"]) == 5 + 16 for row in rows.values())
    assert result["sessions"] == [{
        "session_id": "mine", "session_key": "key-mine", "yolo": False,
        "grants": [{"id": rows[CANONICAL]["id"].replace("perm:", "sess:"), "kind": "pattern", "label": CANONICAL,
                    "tirith": False},
                   {"id": result["sessions"][0]["grants"][1]["id"], "kind": "pattern",
                    "label": "tirith:homograph_url", "tirith": True}]}]   # Bob's chat is not Alice's to see


def test_a_hand_edit_of_config_yaml_shows_up_at_once(homes):
    launch, _work, _ = homes
    _write_allowlist(launch, ["podman *", "make test"])
    labels = {row["label"] for row in _result(_call("approval.grants", {}))["permanent"]}
    assert "make test" in labels


def test_a_named_session_is_listed_even_when_it_holds_nothing(homes):
    _session("mine")
    result = _result(_call("approval.grants", {"session_id": "mine"}))
    assert result["sessions"] == [{"session_id": "mine", "session_key": "key-mine", "yolo": False, "grants": []}]


# ── revoking ────────────────────────────────────────────────────────────────────────────────────


def test_revoking_a_standing_grant_is_immediate_and_survives_the_next_always(homes, caplog):
    launch, work, emitted = homes
    _session("mine")
    grant = _perm(_result(_call("approval.grants", {})), CANONICAL)

    with caplog.at_level("INFO"):
        assert _result(_call("approval.revoke", {"scope": "permanent", "id": grant["id"]})) == {"revoked": 2}
    assert "alice" in caplog.text and "scope=permanent" in caplog.text and "revoked=2" in caplog.text

    assert sorted(_allowlist(launch)) == sorted(["podman *", WITH_SECRET])
    assert not approval.is_approved("key-mine", CANONICAL)
    assert not {CANONICAL, LEGACY} & approval._permanent_baseline_by_home[""]
    assert emitted == ["session.info"]                     # every open chat's indicator is refreshed
    approval._persist_choice("key-mine", "always", [("make deploy", None, False)])
    assert CANONICAL not in _allowlist(launch) and LEGACY not in _allowlist(launch)
    assert _allowlist(work) == ["cargo *"]
    # Revoking the same id again is a no-op, not an error.
    assert _result(_call("approval.revoke", {"scope": "permanent", "id": grant["id"]})) == {"revoked": 0}


def test_revoking_in_a_second_profile_touches_only_that_profile(homes):
    launch, work, _ = homes
    before = sorted(_allowlist(launch))
    result = _result(_call("approval.grants", {"profile": "work"}))
    assert result["mode"] == "off" and [row["label"] for row in result["permanent"]] == ["cargo *"]
    assert _result(_call("approval.revoke", {"scope": "permanent", "all": True, "profile": "work"})) == {"revoked": 1}
    assert _allowlist(work) == []
    assert sorted(_allowlist(launch)) == before
    assert {row["label"] for row in _result(_call("approval.grants", {}))["permanent"]} == {
        CANONICAL, "podman *", "OPENAI_API_KEY=*** make deploy"}


def test_revoking_all_standing_grants(homes):
    launch, _work, _ = homes
    assert _result(_call("approval.revoke", {"scope": "permanent", "all": True})) == {"revoked": 4}
    assert _allowlist(launch) == []
    assert _result(_call("approval.grants", {}))["permanent"] == []


def test_revoking_session_grants_one_and_all_leaves_yolo_alone(homes):
    _session("mine")
    approval.approve_session("key-mine", "execute_code")
    approval.approve_session("key-mine", "tirith:homograph_url")
    approval.enable_session_yolo("key-mine")
    row = _result(_call("approval.grants", {"session_id": "mine"}))["sessions"][0]
    code = next(grant for grant in row["grants"] if grant["label"] == "execute_code")

    assert _result(_call("approval.revoke", {"scope": "session", "session_id": "mine", "id": code["id"]})) == {
        "revoked": 1}
    assert approval.session_grants("key-mine") == ["tirith:homograph_url"]
    assert _result(_call("approval.revoke", {"scope": "session", "session_id": "mine", "all": True})) == {
        "revoked": 1}
    assert approval.session_grants("key-mine") == []
    assert approval.is_session_yolo_enabled("key-mine")


GIT_D_OLD, GIT_D_NEW = r"git\s+branch\s+-D", r"git\s+branch\s+(?-i:-D)"
SUDO_RULES = ("sudo with combined-flag privilege escalation", "sudo with privilege flag (stdin/askpass/shell/list)")
PUSH_RULES = ("git force push (rewrites remote history)", "git force push short flag (rewrites remote history)")


def _restart_with(home, entries, **extra):
    _write_allowlist(home, entries, **extra)
    approval.load_permanent_allowlist()


@pytest.mark.parametrize("revoke", ["id", "all"])
def test_every_spelling_of_a_rule_goes_with_its_grant(homes, revoke):
    """Two legacy spellings approve one rule. Revoking it must remove both, or the other keeps it approved."""
    launch, _work, _ = homes
    _restart_with(launch, [GIT_D_OLD, GIT_D_NEW])
    rows = _result(_call("approval.grants", {}))["permanent"]
    assert [row["label"] for row in rows] == ["git branch force delete"]
    params = {"id": rows[0]["id"]} if revoke == "id" else {"all": True}

    assert _result(_call("approval.revoke", {"scope": "permanent", **params})) == {"revoked": 2}
    assert _allowlist(launch) == []
    assert not approval.is_approved("any-session", "git branch force delete")


def test_a_shared_legacy_key_is_one_row_naming_every_rule_and_revokes_only_those(homes):
    launch, _work, _ = homes
    _restart_with(launch, ["sudo", SUDO_RULES[0], r"git\s+push", "find -delete"])
    rows = {row["label"]: row for row in _result(_call("approval.grants", {}))["permanent"]}
    assert set(rows) == {"; ".join(SUDO_RULES), "; ".join(PUSH_RULES), "find -delete"}

    sudo = rows["; ".join(SUDO_RULES)]
    assert _result(_call("approval.revoke", {"scope": "permanent", "id": sudo["id"]})) == {"revoked": 2}
    assert sorted(_allowlist(launch)) == sorted([r"git\s+push", "find -delete"])
    assert not any(approval.is_approved("s", rule) for rule in SUDO_RULES)
    assert all(approval.is_approved("s", rule) for rule in (*PUSH_RULES, "find -delete"))


def test_a_shared_legacy_key_in_a_session_is_one_grant_too(homes):
    _session("mine")
    approval.approve_session("key-mine", "sudo")
    approval.approve_session("key-mine", "tee")
    grants = _result(_call("approval.grants", {"session_id": "mine"}))["sessions"][0]["grants"]
    sudo = next(grant for grant in grants if grant["label"] == "; ".join(SUDO_RULES))
    assert _result(_call("approval.revoke", {"scope": "session", "session_id": "mine", "id": sudo["id"]})) == {
        "revoked": 1}
    assert approval.session_grants("key-mine") == ["tee"]


def test_labels_hide_url_credentials_and_passwords_even_with_redaction_off(homes):
    _launch, work, _ = homes
    secrets = ("abc123def456ghi", "hunter2pass", "S3cretPassw0rd", "an0therSecret")
    _write_allowlist(work, [f"curl https://api.example.test/v1?token={secrets[0]}",
                            f"git clone https://alice:{secrets[1]}@git.example.test/r.git",
                            f"mysql -uroot -p{secrets[2]} shop", f"mysql --password {secrets[3]} shop"],
                     security={"redact_secrets": False})
    result = _result(_call("approval.grants", {"profile": "work"}))
    assert len(result["permanent"]) == 4
    assert not any(secret in repr(result) for secret in secrets)


def test_a_work_profile_revoke_then_an_always_answer_keeps_it_gone(homes):
    """A routed profile's allowlist is loaded lazily, with no baseline: the revoke and the next save must
    still agree."""
    launch, work, _ = homes
    launch_before = sorted(_allowlist(launch))
    assert _result(_call("approval.revoke", {"scope": "permanent", "all": True, "profile": "work"})) == {"revoked": 1}
    with server._session_profile_runtime_scope({"profile_home": str(work)}):
        approval._persist_choice("key-work", "always", [("make deploy", None, False)])
        assert not approval._command_matches_permanent_allowlist("cargo build")
    assert _allowlist(work) == ["make deploy"]
    assert sorted(_allowlist(launch)) == launch_before


# ── who may ─────────────────────────────────────────────────────────────────────────────────────


def test_an_agent_connection_is_refused_both_at_dispatch_and_in_the_handler(homes):
    agent = _WS(ALICE, agent={"grant": "g1"})
    for method, params in (("approval.grants", {}), ("approval.revoke", {"scope": "permanent", "all": True})):
        assert _call(method, params, agent)["error"]["code"] == 4033
        token = bind_transport(agent)
        try:
            assert server._methods[method](1, params)["error"]["code"] == 4033   # past the dispatcher too
        finally:
            reset_transport(token)
    assert len(_allowlist(homes[0])) == 4


def test_a_session_the_caller_may_not_access_answers_session_not_found(homes):
    _session("bobs", creator=BOB)
    approval.approve_session("key-bobs", "execute_code")
    for method, params in (("approval.grants", {"session_id": "bobs"}),
                           ("approval.revoke", {"scope": "session", "session_id": "bobs", "all": True}),
                           ("approval.revoke", {"scope": "session", "session_id": "gone", "all": True})):
        error = _call(method, params)["error"]
        assert (error["code"], error["message"]) == (4001, "session not found")
    assert approval.session_grants("key-bobs") == ["execute_code"]


def test_an_unknown_profile_and_malformed_requests_are_refused(homes):
    assert _call("approval.grants", {"profile": "nope"})["error"]["code"] == 4064
    assert _call("approval.revoke", {"scope": "permanent", "all": True, "profile": "nope"})["error"]["code"] == 4064
    for params in ({"scope": "permanent"}, {"scope": "permanent", "id": "perm:x", "all": True},
                   {"scope": "session", "all": True}):
        assert _call("approval.revoke", params)["error"]["code"] == 4006
    assert len(_allowlist(homes[0])) == 4


# ── session lifetime ────────────────────────────────────────────────────────────────────────────


def test_session_grants_follow_a_compression_rotation(homes, monkeypatch):
    from types import SimpleNamespace
    session = _session("mine")
    session["agent"] = SimpleNamespace(session_id="key-mine-continued")
    monkeypatch.setattr(server, "_transfer_active_session_slot", lambda *a, **k: True)
    monkeypatch.setattr(server, "_restart_slash_worker", lambda *a, **k: None)
    approval.approve_session("key-mine", "execute_code")

    server._sync_session_key_after_compress("mine", session)

    assert approval.session_grants("key-mine-continued") == ["execute_code"]
    assert approval.session_grants("key-mine") == []


def test_closing_a_chat_ends_its_session_grants_but_a_reclaim_keeps_them(homes):
    closed, reclaimed, twin = _session("closed"), _session("reclaimed"), _session("twin")
    twin["session_key"] = "key-shared"
    for key in ("key-closed", "key-reclaimed", "key-shared"):
        approval.approve_session(key, "execute_code")
    approval.enable_session_yolo("key-closed")

    assert _result(_call("session.close", {"session_id": "closed"})) == {"closed": True}
    assert approval.session_grants("key-closed") == [] and not approval.is_session_yolo_enabled("key-closed")

    server._sessions.pop("reclaimed")
    server._teardown_session(reclaimed, end_reason="idle_timeout")       # the backend reclaimed it; chat goes on
    assert approval.session_grants("key-reclaimed") == ["execute_code"]

    other = _session("other-window")
    other["session_key"] = "key-shared"                                  # the same chat, still open elsewhere
    server._sessions.pop("twin")
    server._teardown_session(twin, end_reason="tui_close")
    assert approval.session_grants("key-shared") == ["execute_code"]
    assert closed["_finalized"]


def test_pending_approval_rows_still_carry_their_pattern_keys(homes):
    _session("mine")
    entry = SimpleEntry({"request_id": "r1", "command": "make deploy", "pattern_key": "execute_code",
                         "pattern_keys": ["execute_code"]})
    approval._gateway_queues["key-mine"] = [entry]
    try:
        rows = _result(_call("approval.pending", {"session_id": "mine"}))["approvals"]
    finally:
        approval._gateway_queues.pop("key-mine", None)
    assert rows[0]["pattern_key"] == "execute_code" and rows[0]["pattern_keys"] == ["execute_code"]


class SimpleEntry:
    def __init__(self, data):
        self.data = data
