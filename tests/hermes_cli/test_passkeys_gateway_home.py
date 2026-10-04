"""Passkeys are the gateway's: settings, store, operator rules and the CLI read the gateway's own home.

A gateway that multiplexes profiles runs a profile's turns with that profile's home as the context-local
``HERMES_HOME`` override, and ``hermes -p <name> ...`` runs a command with ``HERMES_HOME`` set to it. Pinned
here (``passkeys.paths.gateway_home``): ``load_settings`` and the store path ignore a profile override; the
operator rules a profile turn gets are the gateway's plus the profile's own; ``hermes dashboard passkey``
inside a served profile reports and changes the gateway's settings and store and says so, and a
standalone profile or the default home keeps its own; confirm_action's memoized definitions follow an edit
of the gateway's config from inside a profile scope. A separate process of a served profile (``HERMES_HOME``
on the profile, no override) still gets the gateway's rules; a host gateway started from a named profile
(pinned home) is the gateway for a turn in another profile; the file tools cannot write the gateway's
config.yaml or a ``dashboard_auth`` directory from any turn; the passkey routes and the re-sign-in policy
read the gateway's settings and store under a dashboard request scoped to a profile.
"""

from __future__ import annotations

import argparse
import io

import pytest
import yaml

from hermes_cli.dashboard_auth.passkeys import cli, serving
from hermes_cli.dashboard_auth.passkeys.challenge import b64u
from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
from hermes_cli.subcommands.dashboard import build_dashboard_parser
from hermes_constants import pin_process_hermes_home

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
    serving.reset_for_tests()
    store = PasskeyStore(root / "dashboard_auth" / "passkeys.db")
    store.identity()
    yield root, profile, store
    reset_hermes_home_key_cache()
    serving.reset_for_tests()
    pin_process_hermes_home(None)


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


# ── a separate process of a served profile ────────────────────────────────────────────────────


def test_a_separate_profile_process_gets_the_gateways_rules(host, monkeypatch):
    """``hermes -p techsupport chat`` or a kanban worker: HERMES_HOME is the profile, there is no override."""
    from tools import passkey_policy
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    rules = passkey_policy.require()
    assert rules.commands == ("deploy-prod*",) and rules.tools == ("publish_site",)
    assert passkey_policy.match_command("deploy-prod --now") is not None


def test_a_standalone_profile_process_keeps_only_its_own_rules(host, monkeypatch):
    from tools import passkey_policy
    _root, profile, _store = host
    _write(profile / "config.yaml", {"gateway": {"standalone": True}, "confirm": {"passkey": {"require": {
        "tools": ["publish_site"]}}}})
    monkeypatch.setenv("HERMES_HOME", str(profile))
    rules = passkey_policy.require()
    assert rules.commands == () and rules.tools == ("publish_site",)


# ── a host gateway started from a named profile ───────────────────────────────────────────────


def test_a_pinned_launch_home_is_the_gateway_for_a_turn_in_another_profile(host, monkeypatch):
    """The embedding host pins its launch profile and mirrors the turn's profile into HERMES_HOME."""
    from hermes_cli.dashboard_auth.passkeys.settings import load_settings
    from hermes_cli.dashboard_auth.passkeys.store import default_path
    from tools import passkey_policy
    root, profile, _store = host
    launch = root / "profiles" / "ops"
    launch.mkdir()
    _write(launch / "config.yaml", {"confirm": {"passkey": {"enabled": True, "base_urls": ["https://ops.example.com"],
                                                            "require": {"commands": ["rotate-keys*"]}}}})
    pin_process_hermes_home(launch)
    monkeypatch.setenv("HERMES_HOME", str(profile))  # the host's mirror of the turn's profile
    for scoped in (lambda f: f(), lambda f: _in_home(profile, f)):
        assert scoped(load_settings).base_urls == ("https://ops.example.com",)
        assert scoped(default_path) == launch / "dashboard_auth" / "passkeys.db"
    rules = _in_home(profile, passkey_policy.require)
    assert "rotate-keys*" in rules.commands and rules.tools == ("publish_site",)


# ── the file tools ────────────────────────────────────────────────────────────────────────────


def _write_refused(path) -> str | None:
    from tools.file_tools_write_guards import _check_sensitive_path
    return _check_sensitive_path(str(path))


def test_a_profile_turn_cannot_write_the_gateways_config_or_store(host, tmp_path):
    root, profile, _store = host
    for target in (root / "config.yaml", root / "dashboard_auth" / "passkeys.db",
                   root / "dashboard_auth" / "passkeys.db-wal", root / "Dashboard_Auth" / "mcp.db",
                   root / "dashboard_auth" / "new.txt", profile / "dashboard_auth" / "passkeys.db"):
        assert _in_home(profile, _write_refused, target), target
        assert _write_refused(target), target
    # The profile's own config stays refused by the existing guard; other files are not this guard's.
    assert "Hermes config file" in _in_home(profile, _write_refused, profile / "config.yaml")
    project = tmp_path / "project" / "hermes_cli" / "dashboard_auth"
    project.mkdir(parents=True)
    for allowed in (root / "notes.md", profile / "notes.md", project / "routes.py", tmp_path / "config.yaml"):
        assert _in_home(profile, _write_refused, allowed) is None, allowed


def test_a_symlink_into_the_gateways_store_is_refused(host, tmp_path):
    root, profile, _store = host
    link = tmp_path / "innocent"
    link.symlink_to(root / "dashboard_auth")
    assert _in_home(profile, _write_refused, link / "passkeys.db")
    config_link = tmp_path / "settings.yaml"
    config_link.symlink_to(root / "config.yaml")
    assert _in_home(profile, _write_refused, config_link)


def test_a_separate_profile_process_cannot_write_the_gateways_config(host, monkeypatch):
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    assert _write_refused(root / "config.yaml")
    assert _write_refused(root / "dashboard_auth" / "passkeys.db")


# ── the dashboard under a request scoped to a profile ─────────────────────────────────────────


def test_passkey_routes_and_reauth_policy_read_the_gateways_under_a_profile_scope(host):
    from hermes_cli.dashboard_auth.passkeys import reauth, routes
    root, profile, store = host
    _write(profile / "config.yaml", {"confirm": {"passkey": {"enabled": False, "base_urls": ["https://evil.example"]}}})
    routes._stores.clear()
    try:
        settings = _in_home(profile, routes._settings)
        assert settings.enabled is True and settings.base_urls == (BASE,)
        assert _in_home(profile, routes._store).path == store.path
        assert _in_home(profile, reauth.policy).level_enabled is True
    finally:
        routes._stores.clear()


# ── the CLI ───────────────────────────────────────────────────────────────────────────────────


def test_status_in_a_served_profile_names_the_gateways_config_when_disabled(host, monkeypatch):
    root, profile, _store = host
    _write(root / "config.yaml", {"gateway": {"multiplex_profiles": True}, "confirm": {"passkey": {
        "base_urls": [BASE]}}})
    monkeypatch.setenv("HERMES_HOME", str(profile))
    _code, out, _err = _cli("status")
    assert f"in the gateway's config ({root / 'config.yaml'})" in out and "WITHOUT -p" in out


def test_a_running_dashboard_of_the_default_home_serves_the_profile(host, monkeypatch):
    root, profile, _store = host
    _write(root / "config.yaml", {"confirm": {"passkey": {"enabled": True, "base_urls": [BASE]}}})
    monkeypatch.setenv("HERMES_HOME", str(profile))
    assert cli.serving_gateway_home() is None
    seen = []

    def dashboards(*, exclude_pids=None, scope_home=None):
        seen.append(scope_home)
        return [4242] if scope_home == str(root) else []

    monkeypatch.setattr("hermes_cli.main_dashboard._find_stale_dashboard_pids", dashboards)
    assert cli.serving_gateway_home() == root and seen == [str(profile), str(root)]
    # The per-call policy path never scans processes.
    serving.reset_for_tests()
    assert serving.serving_gateway_home() is None


# ── forged runtime records and linked homes ───────────────────────────────────────────────────


def _forge_records(monkeypatch, root, profile):
    """What a turn could write if the records were writable: its profile's ``gateway_state.json`` saying a
    gateway runs there, the root's saying it serves nothing. The detection is made to believe them."""
    import json
    (profile / "gateway_state.json").write_text(json.dumps({"pid": 4242, "gateway_state": "running"}))
    (root / "gateway_state.json").write_text(json.dumps({"pid": 4343, "served_profiles": []}))
    monkeypatch.setattr("gateway.status.live_gateway_pid_for_home",
                        lambda home: 4242 if str(home) == str(profile) else None)
    monkeypatch.setattr("hermes_cli.gateway_multiplex_mode.default_gateway_multiplexes", lambda root=None: False)
    serving.reset_for_tests()
    assert serving.serving_gateway_home() is None  # the records now say nobody serves the profile


def test_forged_records_do_not_drop_the_roots_rules(host, monkeypatch):
    from tools import passkey_policy
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    _forge_records(monkeypatch, root, profile)
    rules = passkey_policy.require()
    assert rules.commands == ("deploy-prod*",) and rules.tools == ("publish_site",)


def test_forged_records_do_not_lift_the_write_block(host, monkeypatch):
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    _forge_records(monkeypatch, root, profile)
    for target in (root / "config.yaml", root / "dashboard_auth" / "passkeys.db"):
        assert _write_refused(target), target


def test_runtime_records_of_every_home_are_refused(host):
    root, profile, _store = host
    other = root / "profiles" / "billing"
    other.mkdir()
    for home in (root, profile, other):
        for name in ("gateway_state.json", "gateway.pid", "gateway.lock", "config.yaml", "Gateway_State.json"):
            assert _in_home(profile, _write_refused, home / name), home / name
        assert _in_home(profile, _write_refused, home / "dashboard_auth" / "mcp.db")


def test_a_linked_config_and_store_are_refused_at_their_targets(host, tmp_path):
    """Dotfiles setups: the root's config.yaml and dashboard_auth are links to files elsewhere."""
    root, profile, _store = host
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    (root / "config.yaml").rename(dotfiles / "hermes.yaml")
    (root / "config.yaml").symlink_to(dotfiles / "hermes.yaml")
    (root / "dashboard_auth").rename(dotfiles / "auth")
    (root / "dashboard_auth").symlink_to(dotfiles / "auth")
    for target in (dotfiles / "hermes.yaml", dotfiles / "auth" / "passkeys.db", dotfiles / "auth" / "new.db",
                   root / "config.yaml", root / "dashboard_auth" / "passkeys.db"):
        assert _in_home(profile, _write_refused, target), target
        assert _write_refused(target), target
    assert _in_home(profile, _write_refused, dotfiles / "zshrc") is None


def test_the_guard_fails_closed_when_no_home_can_be_named(host, tmp_path, monkeypatch):
    from tools import file_tools_write_guards as guards
    monkeypatch.setattr(guards, "_guarded_homes", lambda: [])
    elsewhere = tmp_path / "x"
    assert guards._gateway_owned_path_error("p", (str(elsewhere / "config.yaml"),))
    assert guards._gateway_owned_path_error("p", (str(elsewhere / "Dashboard_Auth" / "a.db"),))
    assert guards._gateway_owned_path_error("p", (str(elsewhere / "notes.md"),)) is None


def test_the_cli_keeps_a_profile_that_runs_its_own_dashboard(host, monkeypatch):
    root, profile, _store = host
    monkeypatch.setenv("HERMES_HOME", str(profile))
    monkeypatch.setattr("hermes_cli.main_dashboard._find_stale_dashboard_pids",
                        lambda *, exclude_pids=None, scope_home=None: [7] if scope_home == str(profile) else [])
    assert cli.serving_gateway_home() is None


# ── file identity, not path strings ───────────────────────────────────────────────────────────

NFC_CAFE, NFD_CAFE = "Café", "Café"


def _linked_dotfiles(root, tmp_path):
    dotfiles = tmp_path / "dotfiles" / NFC_CAFE
    dotfiles.mkdir(parents=True)
    (root / "config.yaml").rename(dotfiles / "hermes.yaml")
    (root / "config.yaml").symlink_to(dotfiles / "hermes.yaml")
    (root / "dashboard_auth").rename(dotfiles / "auth")
    (root / "dashboard_auth").symlink_to(dotfiles / "auth")
    return dotfiles


def test_case_and_unicode_variants_of_a_linked_target_are_refused(host, tmp_path):
    import os
    root, profile, _store = host
    dotfiles = _linked_dotfiles(root, tmp_path)
    variant = tmp_path / "DOTFILES" / NFD_CAFE
    if not os.path.exists(variant / "HERMES.yaml"):
        pytest.skip("this file system tells case and Unicode-normalisation variants apart")
    for target in (variant / "HERMES.yaml", variant / "hermes.YAML", variant / "AUTH" / "passkeys.db",
                   variant / "Auth" / "brand-new.db", variant / "auth" / "sub" / "new.db"):
        assert _in_home(profile, _write_refused, target), target
        assert _write_refused(target), target
    assert _in_home(profile, _write_refused, variant / "zshrc") is None
    assert (dotfiles / "hermes.yaml").exists()


def test_a_hard_link_to_the_gateways_config_is_refused(host, tmp_path):
    import os
    root, profile, _store = host
    link = tmp_path / "elsewhere.yaml"
    os.link(root / "config.yaml", link)
    assert _in_home(profile, _write_refused, link)


def test_a_profile_that_does_not_exist_yet_is_guarded_by_name(host):
    root, profile, _store = host
    newbie = root / "profiles" / "newbie"
    assert not newbie.exists()
    for target in (newbie / "config.yaml", newbie / "gateway.pid", newbie / "gateway_state.json",
                   newbie / "dashboard_auth" / "passkeys.db", newbie / "Dashboard_Auth" / "sub" / "x.db"):
        assert _in_home(profile, _write_refused, target), target
    assert _in_home(profile, _write_refused, newbie / "notes.md") is None
    assert _in_home(profile, _write_refused, root / "profiles" / ".trash" / "config.yaml") is None
