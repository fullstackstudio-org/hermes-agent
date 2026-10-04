"""Passkeys are the gateway's: settings, store, operator rules and the CLI read the gateway's own home.

A gateway that multiplexes profiles runs a profile's turns with that profile's home as the context-local
``HERMES_HOME`` override, and ``hermes -p <name> ...`` runs a command with ``HERMES_HOME`` set to it. Pinned
here (``passkeys.paths.gateway_home``): ``load_settings`` and the store path ignore a profile override; the
operator rules a profile turn gets are the gateway's plus the profile's own; ``hermes dashboard passkey``
inside a served profile reports and changes the gateway's settings and store and says so, and a
standalone profile or the default home keeps its own; confirm_action's memoized definitions follow an edit
of the gateway's config from inside a profile scope.
"""

from __future__ import annotations

import argparse
import io

import pytest
import yaml

from hermes_cli.dashboard_auth.passkeys import cli
from hermes_cli.dashboard_auth.passkeys.challenge import b64u
from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
from hermes_cli.subcommands.dashboard import build_dashboard_parser

BASE = "https://gw.example.com"


def _write(path, cfg):
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A default home whose gateway multiplexes, with the passkey level configured and a store, and a
    profile ``techsupport`` under it with a stale section of its own and no store."""
    from hermes_constants import reset_hermes_home_key_cache
    root = tmp_path / ".hermes"
    profile = root / "profiles" / "techsupport"
    profile.mkdir(parents=True)
    _write(root / "config.yaml", {"gateway": {"multiplex_profiles": True}, "confirm": {"passkey": {
        "enabled": True, "base_urls": [BASE], "require": {"commands": ["deploy-prod*"]}}}})
    _write(profile / "config.yaml", {"confirm": {"passkey": {"enabled": True, "require": {
        "tools": ["publish_site"]}}}})
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.delenv("GATEWAY_MULTIPLEX_PROFILES", raising=False)
    reset_hermes_home_key_cache()
    store = PasskeyStore(root / "dashboard_auth" / "passkeys.db")
    store.identity()
    yield root, profile, store
    reset_hermes_home_key_cache()


def _in_home(home, fn, *args, **kwargs):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    token = set_hermes_home_override(str(home))
    try:
        return fn(*args, **kwargs)
    finally:
        reset_hermes_home_override(token)


# ── in the gateway process ────────────────────────────────────────────────────────────────────


def test_settings_and_store_ignore_a_profile_override(host):
    from hermes_cli.dashboard_auth.passkeys.settings import load_settings
    from hermes_cli.dashboard_auth.passkeys.store import default_path
    root, profile, _store = host
    for scoped in (lambda f: f(), lambda f: _in_home(profile, f)):
        settings = scoped(load_settings)
        assert settings.enabled is True and settings.base_urls == (BASE,)
        assert scoped(default_path) == root / "dashboard_auth" / "passkeys.db"


def test_a_profile_turn_gets_the_gateways_rules_and_its_own(host):
    from tools import passkey_policy
    _root, profile, _store = host
    at_gateway = passkey_policy.require()
    assert at_gateway.commands == ("deploy-prod*",) and at_gateway.tools == ()
    in_profile = _in_home(profile, passkey_policy.require)
    assert in_profile.commands == ("deploy-prod*",) and in_profile.tools == ("publish_site",)
    assert _in_home(profile, passkey_policy.match_command, "deploy-prod --now") is not None


def test_a_broken_profile_config_keeps_the_gateways_rules(host):
    from tools import passkey_policy
    _root, profile, _store = host
    (profile / "config.yaml").write_text("confirm: [unclosed\n", encoding="utf-8")
    assert _in_home(profile, passkey_policy.require).commands == ("deploy-prod*",)


def test_tool_definitions_follow_the_gateways_config_from_a_profile(host):
    import model_tools
    root, profile, _store = host
    assert model_tools._gateway_config_signature(root / "config.yaml") is None
    before = _in_home(profile, model_tools._gateway_config_signature, profile / "config.yaml")
    assert before is not None
    _write(root / "config.yaml", {"confirm": {"passkey": {"enabled": False, "base_urls": [BASE, BASE + "/x"]}}})
    assert _in_home(profile, model_tools._gateway_config_signature, profile / "config.yaml") != before


# ── the operator CLI inside a profile ─────────────────────────────────────────────────────────


def _parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command")
    build_dashboard_parser(subparsers, cmd_dashboard=lambda a: None, cmd_dashboard_register=lambda a: None)
    return root


def _cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    args = _parser().parse_args(["dashboard", "passkey", *argv])
    code = cli.run(args, out=out, err=err, public_urls=[BASE], isatty=lambda: True, sign_in_providers=["basic"])
    return code, out.getvalue(), err.getvalue()


def test_status_in_a_served_profile_reports_the_gateways(host, monkeypatch):
    root, profile, store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    code, out, _err = _cli("status")
    assert code == 0
    assert f"Profile 'techsupport' is served by the gateway at {root}" in out
    assert f"Store: {root / 'dashboard_auth' / 'passkeys.db'}" in out
    assert f"Gateway id: {b64u(store.gateway_id)}" in out
    assert f"Base URLs (confirm.passkey.base_urls): {BASE}" in out
    assert "Unavailable" not in out
    assert not (profile / "dashboard_auth").exists()


def test_base_url_add_in_a_served_profile_writes_the_gateways_config(host, monkeypatch):
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    code, _out, err = _cli("base-url", "add", "https://other.example.com")
    assert code == 0 and "served by the gateway" in err
    gateway = yaml.safe_load((root / "config.yaml").read_text(encoding="utf-8"))
    assert gateway["confirm"]["passkey"]["base_urls"] == [BASE, "https://other.example.com"]
    own = yaml.safe_load((profile / "config.yaml").read_text(encoding="utf-8"))
    assert "base_urls" not in own["confirm"]["passkey"]


def test_a_standalone_profile_keeps_its_own(host, monkeypatch):
    _root, profile, _store = host
    _write(profile / "config.yaml", {"gateway": {"standalone": True}})
    monkeypatch.setenv("HERMES_HOME", str(profile))
    code, out, _err = _cli("status")
    assert code == 0 and "served by the gateway" not in out
    assert f"Store: {profile / 'dashboard_auth' / 'passkeys.db'}" in out
    assert "Base URLs (confirm.passkey.base_urls): none" in out


def test_status_in_the_default_home_is_unchanged(host):
    root, _profile, store = host
    code, out, _err = _cli("status")
    assert code == 0 and "served by the gateway" not in out
    assert f"Store: {root / 'dashboard_auth' / 'passkeys.db'}" in out
    assert f"Gateway id: {b64u(store.gateway_id)}" in out
