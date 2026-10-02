"""``hermes dashboard passkey``: parser wiring and every command against a store in a temporary home."""

from __future__ import annotations

import argparse
import io
import json

import pytest

from hermes_cli.dashboard_auth.passkeys import cli
from hermes_cli.dashboard_auth.passkeys.settings import settings_from_config
from hermes_cli.dashboard_auth.passkeys.store import OPERATOR, PasskeyStore
from hermes_cli.dashboard_auth.passkeys.webauthn import AssertionOk, RegistrationOk
from hermes_cli.subcommands.dashboard import build_dashboard_parser

U = "self_hosted:alice"


def _parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command")
    build_dashboard_parser(subparsers, cmd_dashboard=lambda a: None, cmd_dashboard_register=lambda a: None)
    return root


@pytest.fixture
def store(tmp_path):
    return PasskeyStore(tmp_path / "dashboard_auth" / "passkeys.db")


LISTED = {"confirm": {"passkey": {"base_urls": ["https://gw.example.com"]}}}


def _run(store, argv, *, cfg=None, urls=("https://gw.example.com",), tty=True, providers=("basic",)):
    out, err = io.StringIO(), io.StringIO()
    args = _parser().parse_args(["dashboard", "passkey", *argv])
    code = cli.run(args, out=out, err=err, store=store, settings=settings_from_config(cfg or {}),
                   public_urls=list(urls), isatty=lambda: tty, sign_in_providers=list(providers))
    return code, out.getvalue(), err.getvalue()


def _enabled(**passkey):
    return {"confirm": {"passkey": {"enabled": True, "base_urls": ["https://gw.example.com"], **passkey}}}


def _enrol(store, credential_id: bytes, user=U, name="Phone"):
    p = store.open_pending("register", user_id=user, rp_id="confirm.hermie.dev", base_url="https://gw.example.com",
                           subject=name)
    reg = RegistrationOk(credential_id=credential_id, rp_id="confirm.hermie.dev", alg=-7, public_x=b"x" * 32,
                         public_y=b"y" * 32, sign_count=0, backup_eligible=True, backed_up=True, aaguid=b"\0" * 16,
                         transports=(), registration_id=p.id, user_id=user, nonce=p.nonce)
    return store.add_credential(user_id=user, code=store.mint_code(user_id=user).code, registration=reg)


def test_the_parser_keeps_bare_dashboard_and_register_working():
    p = _parser()
    assert p.parse_args(["dashboard"]).dashboard_subcommand is None
    assert p.parse_args(["dashboard", "register"]).dashboard_subcommand == "register"
    args = p.parse_args(["dashboard", "passkey", "invite", "--user", U, "--ttl", "2h", "--print"])
    assert (args.func, args.passkey_command, args.user, args.ttl, args.print_code) == (
        cli.cmd_dashboard_passkey, "invite", U, 7200, True)
    with pytest.raises(SystemExit):
        p.parse_args(["dashboard", "passkey", "invite", "--ttl", "soon"])


@pytest.mark.parametrize(("text", "seconds"), [("15m", 900), ("900", 900), ("2h", 7200), ("1d", 86400), (" 30S ", 30)])
def test_parse_duration(text, seconds):
    assert cli.parse_duration(text) == seconds


def test_status_explains_a_missing_base_url_without_creating_the_store(store):
    code, out, _ = _run(store, ["status"], cfg={"confirm": {"passkey": {"enabled": True}}})
    assert code == 0
    assert "Unavailable (no_base_url)" in out and "passkey base-url add" in out
    assert "not created yet" in out and not store.exists()


def test_status_does_not_take_base_urls_from_the_dashboard(store):
    """The dashboard's public URL is a hint, never a base URL a challenge may name."""
    _, out, _ = _run(store, ["status"], cfg={"confirm": {"passkey": {"enabled": True}}},
                     urls=("https://GW.example.com/",))
    assert "Accepted base URLs: none" in out
    assert "Hint: the dashboard is served on https://gw.example.com, which is not a passkey base URL" in out


def test_status_hints_at_a_base_url_the_dashboard_does_not_serve(store):
    _, out, _ = _run(store, ["status"], cfg=_enabled(base_urls=["https://gw.example.com", "https://other.example"]))
    assert "Hint: https://other.example is a passkey base URL but not one of the dashboard's public URLs" in out
    assert "Hint: the dashboard is served on" not in out


def test_status_names_every_reason_and_the_private_origin_remedy(store):
    _, out, _ = _run(store, ["status"], cfg={"confirm": {"passkey": {"base_urls": ["http://192.168.1.5:9119"]}}},
                     providers=())
    assert "Unavailable (disabled)" in out and "Unavailable (private_origin)" in out
    assert "allow_private_base_urls" in out
    assert "Unavailable (no_identity)" in out and "Sign-in providers: none" in out


def test_status_when_available(store):
    store.mint_code()
    _, out, _ = _run(store, ["status"], cfg=_enabled())
    assert "Available to signed-in users" in out and "Unavailable" not in out and "Hint" not in out
    assert "Web RPs: gw.example.com" in out and "Native RPs: confirm.hermie.dev" in out
    assert "open codes: 1" in out and "Sign-in providers: basic" in out


def test_sign_in_providers_follow_the_config(_isolate_hermes_home, monkeypatch):
    for name in ("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
                 "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH"):
        monkeypatch.delenv(name, raising=False)
    assert "basic" not in cli.configured_sign_in_providers()
    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", "admin")
    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "correct horse battery staple")
    assert "basic" in cli.configured_sign_in_providers()


def test_base_url_keeps_entries_it_cannot_read_and_names_them(store, _isolate_hermes_home):
    from hermes_cli.config import get_config_path, load_config
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("confirm:\n  passkey:\n    base_urls: ['ftp://typo.example', 'HTTPS://GW.example.com/']\n")
    code, out, err = _run(store, ["base-url", "add", "https://two.example"])
    assert code == 0 and "'ftp://typo.example'" in err
    assert load_config()["confirm"]["passkey"]["base_urls"] == [
        "ftp://typo.example", "HTTPS://GW.example.com/", "https://two.example"]
    code, out, err = _run(store, ["base-url", "remove", "https://gw.example.com"])
    assert code == 0 and load_config()["confirm"]["passkey"]["base_urls"] == ["ftp://typo.example",
                                                                               "https://two.example"]
    code, out, err = _run(store, ["base-url", "list"])
    assert out.split() == ["https://two.example"] and "'ftp://typo.example'" in err


def test_base_url_add_list_remove_writes_the_protected_list(store, _isolate_hermes_home):
    from hermes_cli.config import load_config
    from hermes_constants import get_hermes_home

    def base_urls():
        return load_config()["confirm"]["passkey"]["base_urls"]

    assert _run(store, ["base-url", "list"])[1].strip() == "No base URLs listed."
    code, out, _ = _run(store, ["base-url", "add", "HTTPS://GW.Example.com:443/"])
    assert code == 0 and "Added https://gw.example.com" in out and base_urls() == ["https://gw.example.com"]
    assert "Already listed" in _run(store, ["base-url", "add", "https://gw.example.com"])[1]
    _run(store, ["base-url", "add", "https://shared.example/alice/"])
    assert _run(store, ["base-url", "list"])[1].split() == ["https://gw.example.com", "https://shared.example/alice"]
    assert _run(store, ["base-url", "add", "ftp://x"])[0] == 2
    assert _run(store, ["base-url", "remove", "https://nope.example"])[0] == 1
    code, out, _ = _run(store, ["base-url", "remove", "https://gw.example.com/"])
    assert code == 0 and base_urls() == ["https://shared.example/alice"]
    events = [json.loads(line) for line in (get_hermes_home() / "logs" / "dashboard-auth.log").read_text().splitlines()]
    assert [e["action"] for e in events if e["event"] == "passkey_base_urls_changed"] == ["add", "add", "remove"]


def test_invite_refuses_a_non_terminal_unless_print(store, _isolate_hermes_home):
    code, out, err = _run(store, ["invite", "--user", U], tty=False)
    assert code == 2 and "--print" in err and out == "" and not store.exists()
    code, out, _ = _run(store, ["invite", "--user", U, "--print"], tty=False)
    assert code == 0 and "Enrolment code: " in out and f"only {U!r} can redeem it" in out
    assert store.open_codes() == 1


def test_invite_audits_without_the_code(store, _isolate_hermes_home):
    from hermes_constants import get_hermes_home
    _, out, _ = _run(store, ["invite", "--ttl", "1h"])
    printed = out.split("Enrolment code: ")[1].split()[0]
    assert "pass --user to bind it" in out
    line = (get_hermes_home() / "logs" / "dashboard-auth.log").read_text().splitlines()[-1]
    entry = json.loads(line)
    assert entry["event"] == "passkey_invite_minted" and entry["by"] == OPERATOR and entry["user_id"] == ""
    assert printed not in line and printed.replace("-", "") not in line


def test_invite_rejects_a_ttl_over_a_day(store, _isolate_hermes_home):
    code, _, err = _run(store, ["invite", "--ttl", "25h"])
    assert code == 2 and "ttl" in err


def test_list_and_revoke_by_prefix(store, _isolate_hermes_home):
    a = _enrol(store, b"\xaa" * 32)
    b = _enrol(store, b"\xab" * 32, user="self_hosted:bob", name="Laptop")
    code, out, _ = _run(store, ["list"])
    assert code == 0 and a.id_b64u[:16] in out and b.id_b64u[:16] in out and "'Laptop'" in out
    _, out, _ = _run(store, ["list", "--user", U])
    assert b.id_b64u[:16] not in out
    code, _, err = _run(store, ["revoke", a.id_b64u[:1]])  # both start with "q"
    assert code == 1 and "matches 2" in err
    code, out, _ = _run(store, ["revoke", a.id_b64u[:12]])
    assert code == 0 and "Revoked" in out and not store.credential(a.credential_id).active
    assert store.credential(a.credential_id).revoked_by == OPERATOR
    _, out, _ = _run(store, ["list"])
    assert a.id_b64u[:16] not in out
    _, out, _ = _run(store, ["list", "--all"])
    assert "revoked" in out
    code, _, err = _run(store, ["revoke", a.id_b64u[:12]])
    assert code == 1 and "No active credential" in err


def test_revoke_all_of_a_user(store, _isolate_hermes_home):
    _enrol(store, b"\x01" * 32)
    _enrol(store, b"\x02" * 32)
    keep = _enrol(store, b"\x03" * 32, user="self_hosted:bob")
    assert _run(store, ["revoke", "--all"])[0] == 2
    code, out, _ = _run(store, ["revoke", "--user", U, "--all"])
    assert code == 0 and out.count("Revoked") == 2
    assert [c.credential_id for c in store.credentials()] == [keep.credential_id]


def test_receipts_list_and_prune(store, _isolate_hermes_home):
    cred = _enrol(store, b"\x05" * 32)
    ok = AssertionOk(credential_id=cred.credential_id, rp_id=cred.rp_id, base_url="https://gw.example.com",
                     sign_count=0, backup_eligible=True, backed_up=True, counter_warning=False, challenge=b"c" * 32,
                     text_digest=b"\x11" * 32, authenticator_data=b"a" * 37, client_data_json=b"{}", signature=b"s",
                     user_id=U, purpose="confirm", session_id="sess", request_id="9", nonce=b"n" * 32)
    store.commit_assertion(ok, user_id=U, snapshot=cred.stored())
    code, out, _ = _run(store, ["receipts", "--user", U])
    assert code == 0 and "confirm" in out and "request='9'" in out and repr(U) in out and cred.id_b64u[:16] in out
    assert "No receipts." in _run(store, ["receipts", "--since", "2999-01-01"])[1]
    assert "No receipts." in _run(store, ["receipts", "--user", "self_hosted:nobody"])[1]


def test_no_subcommand_prints_usage(store):
    code, _, err = _run(store, [])
    assert code == 2 and "usage" in err
