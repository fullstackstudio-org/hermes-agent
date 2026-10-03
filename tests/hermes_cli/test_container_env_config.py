"""Tests for hermes_cli.container_env_config — the image's environment-driven config step
(/etc/cont-init.d/018-env-config)."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from hermes_cli import container_env_config as cec
from plugins.dashboard_auth.basic import _verify_password, hash_password

SHA_A = "a" * 40
SHA_B = "b" * 40
PASSWORD = "correct-horse-battery-staple-7f3a"


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _cfg(home: Path) -> dict:
    return yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")) or {}


def _run(home: Path, env: dict, **kw) -> list[str]:
    # The default (baked) plugin mode finds no baked plugin in a test environment; tests that
    # exercise the plugin pass their own ``hermie``.
    kw.setdefault("hermie", lambda plan, default_home, profiles: [])
    kw.setdefault("profile_homes", [])
    return cec.run(env, home, **kw)


def _all_bytes(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file())


# ---------------------------------------------------------------------------------------------
# Each variable
# ---------------------------------------------------------------------------------------------


class TestVariables:
    def test_public_url(self, home):
        _run(home, {cec.PUBLIC_URL: "https://hermes.example.com/app/"})
        assert _cfg(home)["dashboard"]["public_url"] == "https://hermes.example.com/app"

    def test_trusted_proxies_are_normalized(self, home):
        _run(home, {cec.TRUSTED_PROXIES: " 10.0.0.7 , 10.42.0.0/16,10.42.1.9/16, ::1 "})
        assert _cfg(home)["dashboard"]["trusted_proxies"] == ["10.0.0.7", "10.42.0.0/16", "::1"]

    def test_profiles_max(self, home):
        _run(home, {cec.PROFILES_MAX: "5"})
        assert _cfg(home)["profiles"]["max"] == 5

    def test_basic_auth_username_and_password(self, home):
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
        basic = _cfg(home)["dashboard"]["basic_auth"]
        assert basic["username"] == "admin"
        assert _verify_password(PASSWORD, basic["password_hash"])
        assert "password" not in basic
        # A signing secret is generated once so sessions survive restarts.
        assert len(cec._secret_bytes(basic["secret"])) >= 16

    def test_password_hash_env(self, home):
        pw_hash = hash_password(PASSWORD)
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD_HASH: pw_hash})
        assert _cfg(home)["dashboard"]["basic_auth"]["password_hash"] == pw_hash

    def test_hash_wins_over_plaintext(self, home):
        pw_hash = hash_password("the-hashed-one")
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD_HASH: pw_hash, cec.BASIC_PASSWORD: PASSWORD})
        stored = _cfg(home)["dashboard"]["basic_auth"]["password_hash"]
        assert stored == pw_hash
        assert not _verify_password(PASSWORD, stored)

    def test_env_session_secret_is_not_written(self, home):
        secret = "s" * 48
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD, cec.BASIC_SECRET: secret})
        assert "secret" not in _cfg(home)["dashboard"]["basic_auth"]
        assert secret.encode() not in _all_bytes(home)

    def test_generated_secret_is_kept_across_starts(self, home):
        env = {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD}
        _run(home, env)
        first = _cfg(home)["dashboard"]["basic_auth"]["secret"]
        _run(home, env)
        assert _cfg(home)["dashboard"]["basic_auth"]["secret"] == first

    def test_oidc(self, home):
        _run(home, {
            cec.OIDC_ISSUER: "https://id.example.com/application/o/hermes/",
            cec.OIDC_CLIENT_ID: "hermes-dashboard",
            cec.OIDC_CLIENT_SECRET: "oidc-client-secret-value-123",
            cec.OIDC_SCOPES: "openid  profile email",
        })
        oidc = _cfg(home)["dashboard"]["oauth"]["self_hosted"]
        assert oidc == {"issuer": "https://id.example.com/application/o/hermes",
                        "client_id": "hermes-dashboard", "scopes": "openid profile email"}
        assert b"oidc-client-secret-value-123" not in _all_bytes(home)

    def test_oidc_public_client_without_secret(self, home):
        _run(home, {cec.OIDC_ISSUER: "https://id.example.com", cec.OIDC_CLIENT_ID: "hermes"})
        assert _cfg(home)["dashboard"]["oauth"]["self_hosted"]["client_id"] == "hermes"

    def test_blank_variable_counts_as_unset(self, home):
        (home / "config.yaml").write_text("dashboard:\n  public_url: https://kept.example.com\n", encoding="utf-8")
        _run(home, {cec.PUBLIC_URL: "   "})
        assert _cfg(home)["dashboard"]["public_url"] == "https://kept.example.com"

    def test_basic_auth_reenables_disabled_plugin(self, home):
        (home / "config.yaml").write_text("plugins:\n  disabled: [basic, other]\n", encoding="utf-8")
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
        assert _cfg(home)["plugins"]["disabled"] == ["other"]

    def test_plaintext_config_password_is_removed(self, home):
        (home / "config.yaml").write_text(
            "dashboard:\n  basic_auth:\n    username: admin\n    password: old-plaintext-pw\n", encoding="utf-8")
        _run(home, {cec.BASIC_PASSWORD: PASSWORD})
        assert b"old-plaintext-pw" not in (home / "config.yaml").read_bytes()
        assert _verify_password(PASSWORD, _cfg(home)["dashboard"]["basic_auth"]["password_hash"])


# ---------------------------------------------------------------------------------------------
# Source-of-truth semantics
# ---------------------------------------------------------------------------------------------


USER_CONFIG = """\
# my own notes about this deployment
model:
  default: some/model  # picked in the dashboard
dashboard:
  public_url: https://edited-in-dashboard.example.com
  theme: dark
profiles:
  max: 9
"""


class TestSemantics:
    def test_env_reasserts_its_keys_and_leaves_the_rest(self, home):
        (home / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
        _run(home, {cec.PUBLIC_URL: "https://hermes.example.com"})
        text = (home / "config.yaml").read_text(encoding="utf-8")
        cfg = yaml.safe_load(text)
        assert cfg["dashboard"]["public_url"] == "https://hermes.example.com"
        # Untouched keys and the user's comments survive.
        assert cfg["dashboard"]["theme"] == "dark"
        assert cfg["profiles"]["max"] == 9
        assert cfg["model"]["default"] == "some/model"
        assert "# my own notes about this deployment" in text
        assert "# picked in the dashboard" in text

    def test_unsetting_a_variable_keeps_the_last_value(self, home):
        _run(home, {cec.PUBLIC_URL: "https://hermes.example.com", cec.PROFILES_MAX: "3"})
        _run(home, {})
        cfg = _cfg(home)
        assert cfg["dashboard"]["public_url"] == "https://hermes.example.com"
        assert cfg["profiles"]["max"] == 3

    def test_no_variables_no_write(self, home):
        (home / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
        before = os.stat(home / "config.yaml")
        assert _run(home, {}) == []
        after = os.stat(home / "config.yaml")
        assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


FULL_ENV = {
    cec.PUBLIC_URL: "https://hermes.example.com",
    cec.TRUSTED_PROXIES: "10.42.0.0/16",
    cec.PROFILES_MAX: "4",
    cec.BASIC_USERNAME: "admin",
    cec.BASIC_PASSWORD: PASSWORD,
    cec.OIDC_ISSUER: "https://id.example.com",
    cec.OIDC_CLIENT_ID: "hermes",
}


class TestIdempotencyAndSafety:
    def test_second_start_is_byte_identical(self, home):
        (home / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
        _run(home, FULL_ENV)
        first = (home / "config.yaml").read_bytes()
        st1 = os.stat(home / "config.yaml")
        assert _run(home, FULL_ENV) == []
        assert (home / "config.yaml").read_bytes() == first
        st2 = os.stat(home / "config.yaml")
        # Not even rewritten with the same bytes.
        assert (st1.st_ino, st1.st_mtime_ns) == (st2.st_ino, st2.st_mtime_ns)

    def test_password_changes_rehash(self, home):
        _run(home, FULL_ENV)
        _run(home, {**FULL_ENV, cec.BASIC_PASSWORD: "a-new-password-4411"})
        stored = _cfg(home)["dashboard"]["basic_auth"]["password_hash"]
        assert _verify_password("a-new-password-4411", stored)
        assert not _verify_password(PASSWORD, stored)

    def test_plaintext_password_never_on_disk(self, home):
        _run(home, FULL_ENV)
        _run(home, FULL_ENV)
        assert PASSWORD.encode() not in _all_bytes(home)

    def test_mode_is_kept_and_write_is_atomic(self, home):
        path = home / "config.yaml"
        path.write_text(USER_CONFIG, encoding="utf-8")
        path.chmod(0o640)
        _run(home, FULL_ENV)
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
        # No temp files left behind next to config.yaml.
        assert sorted(p.name for p in home.iterdir()) == ["config.yaml"]

    def test_secrets_never_logged(self, home, capsys):
        secret = "S" * 40
        env = {**FULL_ENV, cec.BASIC_SECRET: secret, cec.OIDC_CLIENT_SECRET: "client-secret-xyz-987"}
        changed = _run(home, env)
        for key in changed:
            cec._log(f"set {key}")
        out = capsys.readouterr()
        logged = out.out + out.err + "\n".join(changed)
        for value in (PASSWORD, secret, "client-secret-xyz-987", "hermes.example.com", "admin"):
            assert value not in logged
        assert "dashboard.public_url" in logged

    def test_main_logs_keys_only(self, home, monkeypatch, capsys):
        for name, value in FULL_ENV.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr(cec, "_named_profile_homes", lambda: [])
        monkeypatch.setattr(cec, "apply_hermie_plugin", lambda plan, default_home, profiles: [])
        assert cec.main([]) == 0
        out = capsys.readouterr().out
        assert "set dashboard.public_url" in out
        assert PASSWORD not in out and "hermes.example.com" not in out


# ---------------------------------------------------------------------------------------------
# Invalid values fail closed
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("env, needle", [
    ({cec.PUBLIC_URL: "dash.internal.test"}, cec.PUBLIC_URL),
    ({cec.PUBLIC_URL: "ftp://hermes.example.com"}, cec.PUBLIC_URL),
    ({cec.PUBLIC_URL: "https://"}, cec.PUBLIC_URL),
    ({cec.PROFILES_MAX: "three"}, cec.PROFILES_MAX),
    ({cec.PROFILES_MAX: "2.5"}, cec.PROFILES_MAX),
    ({cec.PROFILES_MAX: "-1"}, cec.PROFILES_MAX),
    ({cec.TRUSTED_PROXIES: "0.0.0.0/0"}, cec.TRUSTED_PROXIES),
    ({cec.TRUSTED_PROXIES: "*"}, cec.TRUSTED_PROXIES),
    ({cec.TRUSTED_PROXIES: "10.0.0.1, not-an-ip"}, cec.TRUSTED_PROXIES),
    ({cec.TRUSTED_PROXIES: " , "}, cec.TRUSTED_PROXIES),
    ({cec.OIDC_ISSUER: "https://id.example.com"}, cec.OIDC_CLIENT_ID),
    ({cec.OIDC_CLIENT_ID: "hermes"}, cec.OIDC_ISSUER),
    ({cec.OIDC_CLIENT_SECRET: "only-the-secret"}, "incomplete self-hosted OIDC"),
    ({cec.OIDC_ISSUER: "http://id.example.com", cec.OIDC_CLIENT_ID: "x"}, cec.OIDC_ISSUER),
    ({cec.OIDC_ISSUER: "https://id.example.com", cec.OIDC_CLIENT_ID: "x", cec.OIDC_SCOPES: "profile"},
     cec.OIDC_SCOPES),
    ({cec.BASIC_USERNAME: "admin"}, "incomplete basic auth"),
    ({cec.BASIC_PASSWORD: PASSWORD}, "incomplete basic auth"),
    ({cec.BASIC_USERNAME: "ad min", cec.BASIC_PASSWORD: PASSWORD}, cec.BASIC_USERNAME),
    ({cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD_HASH: "not-a-hash"}, cec.BASIC_PASSWORD_HASH),
    ({cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD_HASH: "scrypt$3$8$1$c2FsdA==$ZGs="}, cec.BASIC_PASSWORD_HASH),
    ({cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD, cec.BASIC_SECRET: "short"}, cec.BASIC_SECRET),
    ({cec.DASHBOARD_PORT: "http"}, cec.DASHBOARD_PORT),
    ({cec.DASHBOARD_PORT: "70000"}, cec.DASHBOARD_PORT),
    ({cec.HERMIE_PLUGIN: "--upload-pack=touch /tmp/x"}, cec.HERMIE_PLUGIN),
])
def test_invalid_values_fail_without_writing(home, env, needle):
    (home / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
    before = (home / "config.yaml").read_bytes()
    with pytest.raises(cec.EnvConfigError) as exc:
        _run(home, {**env, cec.PROFILES_MAX: env.get(cec.PROFILES_MAX, "7")})
    assert needle in str(exc.value)
    # Nothing applied — not even the valid PROFILES_MAX that came with the bad value.
    assert (home / "config.yaml").read_bytes() == before
    # Values are not echoed (the trusted-proxies message names the refused wildcards itself).
    if needle != cec.TRUSTED_PROXIES:
        for value in env.values():
            if len(value) > 8:
                assert value not in str(exc.value)


def test_all_problems_reported_at_once(home):
    with pytest.raises(cec.EnvConfigError) as exc:
        _run(home, {cec.PUBLIC_URL: "nope", cec.PROFILES_MAX: "x", cec.OIDC_ISSUER: "https://id.example.com"})
    message = str(exc.value)
    assert cec.PUBLIC_URL in message and cec.PROFILES_MAX in message and cec.OIDC_CLIENT_ID in message


def test_username_with_existing_config_hash_is_complete(home):
    (home / "config.yaml").write_text(
        f"dashboard:\n  basic_auth:\n    password_hash: '{hash_password(PASSWORD)}'\n", encoding="utf-8")
    _run(home, {cec.BASIC_USERNAME: "admin"})
    assert _cfg(home)["dashboard"]["basic_auth"]["username"] == "admin"


def test_main_returns_1_and_names_the_problem(home, monkeypatch, capsys):
    monkeypatch.setenv(cec.PUBLIC_URL, "no-scheme.example.com")
    assert cec.main([]) == 1
    err = capsys.readouterr().err
    assert "config.yaml was not changed" in err and cec.PUBLIC_URL in err
    assert not (home / "config.yaml").exists()


def test_malformed_config_is_not_overwritten(home):
    (home / "config.yaml").write_text("dashboard: [unclosed\n", encoding="utf-8")
    before = (home / "config.yaml").read_bytes()
    with pytest.raises(Exception):
        _run(home, {cec.PROFILES_MAX: "2"})
    assert (home / "config.yaml").read_bytes() == before


# ---------------------------------------------------------------------------------------------
# HERMIE_PLUGIN
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    ("", ("baked", None, False)),
    ("true", ("baked", None, True)), ("True", ("baked", None, True)), ("1", ("baked", None, True)),
    ("yes", ("baked", None, True)),
    ("false", ("off", None, False)), ("FALSE", ("off", None, False)), ("0", ("off", None, False)),
    ("no", ("off", None, False)),
    (SHA_A.upper(), ("ref", SHA_A, True)), ("main", ("ref", "main", True)), ("v1.2.0", ("ref", "v1.2.0", True)),
    ("release/2026-09", ("ref", "release/2026-09", True)), ("refs/tags/v1", ("ref", "refs/tags/v1", True)),
])
def test_hermie_parsing(raw, expected):
    plan = cec.parse_environment({cec.HERMIE_PLUGIN: raw})
    assert (plan.hermie_mode, plan.hermie_ref, plan.hermie_required) == expected


@pytest.mark.parametrize("raw", ["-x", "a..b", "foo bar", "main.lock", "feature/", "a//b", "x@{1}", "~1"])
def test_hermie_ref_rejects_invalid(raw):
    with pytest.raises(cec.EnvConfigError):
        cec.parse_environment({cec.HERMIE_PLUGIN: raw})


def _hermie(mode):
    return lambda plan, default_home, profiles: [(default_home, "hermie", mode)]


def test_hermie_reassert_enables_and_undisables(home):
    (home / "config.yaml").write_text("plugins:\n  enabled: [other]\n  disabled: [hermie]\n", encoding="utf-8")
    seen = []

    def hermie(plan, default_home, profiles):
        seen.append(plan.hermie_mode)
        return [(default_home, "hermie", "reassert")]

    _run(home, {cec.HERMIE_PLUGIN: "true"}, hermie=hermie)
    assert seen == ["baked"]
    plugins = _cfg(home)["plugins"]
    assert plugins["enabled"] == ["other", "hermie"]
    assert plugins["disabled"] == []
    # Not rewritten when nothing changed ...
    before = (home / "config.yaml").read_bytes()
    _run(home, {cec.HERMIE_PLUGIN: "true"}, hermie=_hermie("reassert"))
    assert (home / "config.yaml").read_bytes() == before
    # ... and reasserted when a user disabled it in between.
    (home / "config.yaml").write_text("plugins:\n  enabled: [other]\n  disabled: [hermie]\n", encoding="utf-8")
    _run(home, {cec.HERMIE_PLUGIN: "true"}, hermie=_hermie("reassert"))
    assert "hermie" in _cfg(home)["plugins"]["enabled"]
    assert "hermie" not in _cfg(home)["plugins"]["disabled"]


def test_first_install_enables_but_respects_explicit_disable(home):
    _run(home, {}, hermie=_hermie("first"))
    assert _cfg(home)["plugins"]["enabled"] == ["hermie"]
    (home / "config.yaml").write_text("plugins:\n  disabled: [hermie]\n", encoding="utf-8")
    _run(home, {}, hermie=_hermie("first"))
    assert _cfg(home)["plugins"] == {"disabled": ["hermie"]}


def test_unset_after_first_install_leaves_the_user_choice(home):
    (home / "config.yaml").write_text("plugins:\n  enabled: [other]\n", encoding="utf-8")
    before = (home / "config.yaml").read_bytes()
    _run(home, {}, hermie=_hermie("none"))
    assert (home / "config.yaml").read_bytes() == before


@pytest.mark.parametrize("raw, first, expected", [
    ("", True, "first"), ("", False, "none"), ("true", False, "reassert"), ("true", True, "reassert"),
    ("v1.0.0", False, "reassert"),
])
def test_enable_mode(raw, first, expected):
    assert cec._enable_mode(cec.parse_environment({cec.HERMIE_PLUGIN: raw}), first) == expected


def test_hermie_false_leaves_plugins_alone(home):
    config = "plugins:\n  enabled: [hermie]\n"
    (home / "config.yaml").write_text(config, encoding="utf-8")
    (home / "plugins" / "hermie").mkdir(parents=True)
    (home / "plugins" / "hermie" / "plugin.yaml").write_text("name: hermie  # user-installed\n", encoding="utf-8")
    plan = cec.parse_environment({cec.HERMIE_PLUGIN: "false"})
    assert cec.apply_hermie_plugin(plan, home, []) == []
    cec.run({cec.HERMIE_PLUGIN: "false"}, home)
    assert (home / "config.yaml").read_text(encoding="utf-8") == config
    assert "user-installed" in (home / "plugins" / "hermie" / "plugin.yaml").read_text(encoding="utf-8")


def test_hermie_false_does_not_enable(home):
    cec.run({cec.HERMIE_PLUGIN: "false", cec.PROFILES_MAX: "1"}, home)
    assert "plugins" not in _cfg(home)


def test_hermie_install_failure_fails_before_config(home):
    (home / "config.yaml").write_text(USER_CONFIG, encoding="utf-8")
    before = (home / "config.yaml").read_bytes()

    def boom(plan, default_home, profiles):
        raise cec.PluginInstallError("Security scan blocked plugin install: dangerous")

    with pytest.raises(cec.EnvConfigError) as exc:
        _run(home, {cec.HERMIE_PLUGIN: "v1.0.0", cec.PROFILES_MAX: "2"}, hermie=boom)
    assert "Security scan blocked" in str(exc.value)
    assert (home / "config.yaml").read_bytes() == before


def test_invalid_auth_fails_before_the_plugin_step(home):
    called = []
    with pytest.raises(cec.EnvConfigError, match="incomplete basic auth"):
        _run(home, {cec.BASIC_USERNAME: "admin"}, hermie=lambda *a: called.append(1) or [])
    assert called == []


def test_ref_mode_dispatches_to_runtime_fetch(home, monkeypatch):
    calls = []

    def fake_ensure(ref):
        calls.append(ref)
        tree = home / "plugins" / "hermie"
        tree.mkdir(parents=True)
        (tree / "plugin.yaml").write_text("name: hermie\n", encoding="utf-8")
        (home / "plugins" / ".install-metadata.json").write_text(
            '{"hermie": {"pinned": true, "revision": "%s", "source": "x"}}' % SHA_A, encoding="utf-8")
        return "hermie"

    monkeypatch.setattr(cec, "ensure_hermie_plugin", fake_ensure)
    monkeypatch.setattr(cec, "baked_copy", lambda **kw: pytest.fail("baked sync not expected"))
    result = cec.apply_hermie_plugin(cec.parse_environment({cec.HERMIE_PLUGIN: "main"}), home, [])
    assert result == [(home, "hermie", "reassert")]
    assert calls == ["main"]


class _FakePlugins:
    """Stand-in for the bits of hermes_cli.plugins_cmd the installer touches."""

    def __init__(self, home: Path, metadata: dict, ls_remote: str = "", ls_rc: int = 0):
        self.plugins_dir = home / "plugins"
        self.plugins_dir.mkdir(exist_ok=True)
        self.metadata = metadata
        for name in metadata:
            (self.plugins_dir / name).mkdir(exist_ok=True)
        self.ls_remote = ls_remote
        self.ls_rc = ls_rc
        self.installs: list[dict] = []

    def patch(self, monkeypatch):
        from hermes_cli import plugins_cmd, plugins_cmd_catalog

        monkeypatch.setattr(plugins_cmd, "_read_install_metadata", lambda: self.metadata)
        monkeypatch.setattr(plugins_cmd, "_plugins_dir", lambda: self.plugins_dir)
        monkeypatch.setattr(plugins_cmd, "_resolve_git_executable", lambda: "git")
        monkeypatch.setattr(plugins_cmd, "_run_plugin_git", self._git)
        monkeypatch.setattr(plugins_cmd, "_install_plugin_core", self._install)
        monkeypatch.setattr(plugins_cmd, "_install_python_dependencies_quietly", lambda target, warnings: [])
        monkeypatch.setattr(plugins_cmd_catalog, "raise_if_removed", lambda *a: None)

    def _git(self, git_exe, cwd, *args, **kw):
        assert args[0] == "ls-remote"
        return SimpleNamespace(returncode=self.ls_rc, stdout=self.ls_remote, stderr="fatal: unable to access")

    def _install(self, identifier, *, force, ref, before_swap=None, **kw):
        self.installs.append({"identifier": identifier, "force": force, "ref": ref})
        tree = self.plugins_dir / "hermie"
        tree.mkdir(exist_ok=True)
        (tree / "plugin.yaml").write_text("name: hermie\n", encoding="utf-8")
        if before_swap is not None:
            before_swap({"name": "hermie"}, tree)
        return tree, {"name": "hermie"}, "hermie"


LS_REMOTE = (
    f"{SHA_A}\tHEAD\n"
    f"{SHA_A}\trefs/heads/main\n"
    f"{SHA_B}\trefs/heads/next\n"
    f"{'c' * 40}\trefs/tags/v1.0.0\n"
    f"{'d' * 40}\trefs/tags/v1.0.0^{{}}\n"
    f"{'e' * 40}\trefs/tags/next\n"
)
SOURCE = "https://github.com/fullstackstudio-org/hermie-plugin.git"


@pytest.mark.parametrize("ref, sha", [
    ("HEAD", SHA_A), ("main", SHA_A), ("v1.0.0", "d" * 40), ("next", "e" * 40),
    ("refs/heads/next", SHA_B), (SHA_B.upper(), SHA_B),
])
def test_resolve_remote_ref(home, monkeypatch, ref, sha):
    _FakePlugins(home, {}, LS_REMOTE).patch(monkeypatch)
    assert cec.resolve_remote_ref(SOURCE, ref) == sha


def test_resolve_remote_ref_unknown(home, monkeypatch):
    _FakePlugins(home, {}, LS_REMOTE).patch(monkeypatch)
    with pytest.raises(cec.PluginInstallError, match="does not name a branch or tag"):
        cec.resolve_remote_ref(SOURCE, "abc1234")


def test_install_when_missing(home, monkeypatch, capsys):
    fake = _FakePlugins(home, {}, LS_REMOTE)
    fake.patch(monkeypatch)
    monkeypatch.setattr(cec, "_print_scan_report", lambda tree, ident: cec._log("plugin security scan report: SAFE"))
    assert cec.ensure_hermie_plugin("HEAD") == "hermie"
    assert fake.installs == [{"identifier": SOURCE, "force": True, "ref": SHA_A}]
    assert "plugin security scan report" in capsys.readouterr().out


def test_skip_when_installed_ref_matches(home, monkeypatch):
    fake = _FakePlugins(home, {"hermie": {"source": SOURCE, "revision": SHA_A, "pinned": True}}, LS_REMOTE)
    fake.patch(monkeypatch)
    assert cec.ensure_hermie_plugin("main") == "hermie"
    assert fake.installs == []


def test_full_sha_skips_without_network(home, monkeypatch):
    fake = _FakePlugins(home, {"hermie": {"source": SOURCE, "revision": SHA_B, "pinned": True}}, ls_rc=128)
    fake.patch(monkeypatch)
    assert cec.ensure_hermie_plugin(SHA_B) == "hermie"
    assert fake.installs == []


def test_reinstall_when_ref_moves(home, monkeypatch):
    fake = _FakePlugins(home, {"hermie": {"source": SOURCE, "revision": SHA_A, "pinned": True}}, LS_REMOTE)
    fake.patch(monkeypatch)
    monkeypatch.setattr(cec, "_print_scan_report", lambda tree, ident: None)
    cec.ensure_hermie_plugin("next")
    assert fake.installs == [{"identifier": SOURCE, "force": True, "ref": "e" * 40}]


def test_offline_keeps_existing_install(home, monkeypatch, capsys):
    fake = _FakePlugins(home, {"hermie": {"source": SOURCE, "revision": SHA_A, "pinned": True}}, ls_rc=128)
    fake.patch(monkeypatch)
    assert cec.ensure_hermie_plugin("HEAD") == "hermie"
    assert fake.installs == []
    assert "keeping the installed hermie" in capsys.readouterr().out


def test_offline_without_install_fails(home, monkeypatch):
    _FakePlugins(home, {}, ls_rc=128).patch(monkeypatch)
    with pytest.raises(cec.PluginInstallError, match="could not list refs"):
        cec.ensure_hermie_plugin("HEAD")


def test_other_source_is_not_mistaken_for_hermie(home, monkeypatch):
    fake = _FakePlugins(home, {"hermie": {"source": "https://example.com/fork.git", "revision": SHA_A}}, LS_REMOTE)
    fake.patch(monkeypatch)
    monkeypatch.setattr(cec, "_print_scan_report", lambda tree, ident: None)
    cec.ensure_hermie_plugin("HEAD")
    assert len(fake.installs) == 1


def test_scan_block_becomes_install_error(home, monkeypatch):
    from hermes_cli import plugins_cmd

    fake = _FakePlugins(home, {}, LS_REMOTE)
    fake.patch(monkeypatch)

    def blocked(*a, **kw):
        raise plugins_cmd.PluginScanBlocked("Security scan blocked plugin install: dangerous\n\nREPORT")

    monkeypatch.setattr(plugins_cmd, "_install_plugin_core", blocked)
    with pytest.raises(cec.PluginInstallError, match="REPORT"):
        cec.ensure_hermie_plugin("HEAD")


# ---------------------------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------------------------


def test_ungated_dashboard_warning(home, capsys):
    _run(home, {"HERMES_DASHBOARD": "1"})
    assert "no auth provider is configured" in capsys.readouterr().out
    _run(home, {"HERMES_DASHBOARD": "1", cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
    assert "no auth provider" not in capsys.readouterr().out
    _run(home, {"HERMES_DASHBOARD": "1", cec.DASHBOARD_HOST: "127.0.0.1"})
    assert "no auth provider" not in capsys.readouterr().out


def test_cont_init_script_is_valid_sh():
    script = Path(__file__).resolve().parents[2] / "docker" / "cont-init.d" / "018-env-config"
    assert os.access(script, os.X_OK)
    subprocess.run(["sh", "-n", str(script)], check=True)
    text = script.read_text(encoding="utf-8")
    assert "hermes_cli.container_env_config" in text and "s6-setuidgid hermes" in text
    assert "S6_BEHAVIOUR_IF_STAGE2_FAILS" in text and "/run/hermes/env-config-failed" in text


@pytest.mark.parametrize("script", ["docker/cont-init.d/02-reconcile-profiles", "docker/main-wrapper.sh"])
def test_failure_marker_is_honoured(script):
    text = (Path(__file__).resolve().parents[2] / script).read_text(encoding="utf-8")
    assert "/run/hermes/env-config-failed" in text


# ---------------------------------------------------------------------------------------------
# Baked plugin: build-time bake + runtime sync
# ---------------------------------------------------------------------------------------------


def _git(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def plugin_repo(tmp_path) -> Path:
    """A local git repo standing in for the plugin's GitHub repository, tagged v1.0.0."""
    repo = tmp_path / "hermie-plugin-src"
    repo.mkdir()
    (repo / "plugin.yaml").write_text("name: hermie\nversion: 1.0.0\nkind: standalone\n", encoding="utf-8")
    (repo / "__init__.py").write_text("def register(ctx):\n    return None\n", encoding="utf-8")
    (repo / "push").mkdir()
    (repo / "push" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git("init", "--quiet", "-b", "main", cwd=repo)
    _git("add", ".", cwd=repo)
    _git("commit", "--quiet", "-m", "v1", cwd=repo)
    _git("tag", "-a", "v1.0.0", "-m", "v1.0.0", cwd=repo)
    return repo


@pytest.fixture
def baked(tmp_path, plugin_repo, capsys):
    dest, meta = tmp_path / "opt-hermie-plugin", tmp_path / "etc" / "hermie-plugin.json"
    assert cec.bake_plugin(str(plugin_repo), "v1.0.0", dest, meta) == 0
    out = capsys.readouterr().out
    assert "security scan report" in out and "baked hermie v1.0.0" in out
    return dest, meta


def test_bake_records_the_build(baked, plugin_repo):
    dest, meta_path = baked
    meta = cec.read_baked_plugin(meta_path, dest)
    head = subprocess.run(["git", "rev-parse", "v1.0.0^{commit}"], cwd=plugin_repo, capture_output=True,
                          text=True, encoding="utf-8", check=True).stdout.strip()
    assert meta["name"] == "hermie" and meta["ref"] == "v1.0.0" and meta["commit"] == head
    assert meta["digest"] == cec.tree_digest(dest)
    # The plugin reads its own build from .git/HEAD (a detached tag checkout names the commit).
    assert (dest / ".git" / "HEAD").read_text(encoding="utf-8").strip() == head
    assert stat.S_IMODE(meta_path.stat().st_mode) == 0o444


def test_bake_by_full_sha(tmp_path, plugin_repo):
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=plugin_repo, capture_output=True,
                         text=True, encoding="utf-8", check=True).stdout.strip()
    dest, meta = tmp_path / "by-sha", tmp_path / "by-sha.json"
    assert cec.bake_plugin(f"file://{plugin_repo}", sha, dest, meta, expect_commit=sha) == 0
    assert cec.read_baked_plugin(meta, dest)["commit"] == sha


def test_bake_empty_ref_ships_without_plugin(tmp_path):
    assert cec.bake_plugin("unused", "", tmp_path / "d", tmp_path / "m.json") == 0
    assert not (tmp_path / "m.json").exists()


def test_bake_fails_on_blocked_scan(tmp_path, plugin_repo, monkeypatch):
    import tools.plugin_guard as guard

    monkeypatch.setattr(guard, "should_allow_plugin_install", lambda result, force=False: (False, "dangerous"))
    assert cec.bake_plugin(str(plugin_repo), "v1.0.0", tmp_path / "d", tmp_path / "m.json") == 1
    assert not (tmp_path / "m.json").exists()


def test_bake_rejects_bad_ref(tmp_path, plugin_repo):
    assert cec.bake_plugin(str(plugin_repo), "--upload-pack=x", tmp_path / "d", tmp_path / "m.json") == 1


def test_bake_checks_the_expected_commit(tmp_path, plugin_repo):
    assert cec.bake_plugin(str(plugin_repo), "v1.0.0", tmp_path / "d", tmp_path / "m.json",
                           expect_commit=SHA_A) == 1
    assert not (tmp_path / "m.json").exists()


@pytest.mark.parametrize("repo", ["https://user:tok@github.com/x/y.git", "https://tok@github.com/x/y.git",
                                  "-uhttps://github.com/x/y.git", "https://github.com/x/y.git?a=b"])
def test_bake_refuses_unsafe_repo_urls(tmp_path, repo, capsys):
    assert cec.bake_plugin(repo, "v1.0.0", tmp_path / "d", tmp_path / "m.json") == 1
    assert "tok" not in capsys.readouterr().err


def test_sync_baked_plugin_is_idempotent(home, baked):
    from hermes_cli import plugins_cmd

    dest, meta_path = baked
    meta = cec.read_baked_plugin(meta_path, dest)
    assert cec.sync_baked_plugin(required=False, meta_path=meta_path, tree=dest) == "hermie"
    target = home / "plugins" / "hermie"
    assert cec.tree_digest(target) == meta["digest"]
    record = plugins_cmd._read_install_metadata()["hermie"]
    assert record == {"pinned": True, "revision": meta["commit"], "source": meta["source"], "image_ref": "v1.0.0"}

    before = {p: os.stat(p).st_mtime_ns for p in [target, *target.rglob("*")]}
    metadata_before = (home / "plugins" / ".install-metadata.json").read_bytes()
    assert cec.sync_baked_plugin(required=False, meta_path=meta_path, tree=dest) == "hermie"
    assert {p: os.stat(p).st_mtime_ns for p in [target, *target.rglob("*")]} == before
    assert (home / "plugins" / ".install-metadata.json").read_bytes() == metadata_before
    # No staging directories left behind.
    assert not [p.name for p in (home / "plugins").iterdir() if p.name.startswith(".hermie-sync-")]


def test_sync_restores_a_modified_copy(home, baked):
    dest, meta_path = baked
    cec.sync_baked_plugin(required=False, meta_path=meta_path, tree=dest)
    target = home / "plugins" / "hermie"
    (target / "stray.py").write_text("x = 1\n", encoding="utf-8")
    (target / "push" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    cec.sync_baked_plugin(required=False, meta_path=meta_path, tree=dest)
    assert not (target / "stray.py").exists()
    assert (target / "push" / "__init__.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_sync_replaces_a_ref_override_install(home, baked):
    from hermes_cli import plugins_cmd

    dest, meta_path = baked
    target = home / "plugins" / "hermie"
    target.mkdir(parents=True)
    (target / "plugin.yaml").write_text("name: hermie\nversion: 9.9.9-dev\n", encoding="utf-8")
    plugins_cmd._update_install_record("hermie", lambda _r: {"pinned": True, "revision": SHA_B,
                                                            "source": cec.read_baked_plugin(meta_path, dest)["source"]})
    cec.sync_baked_plugin(required=False, meta_path=meta_path, tree=dest)
    assert "9.9.9-dev" not in (target / "plugin.yaml").read_text(encoding="utf-8")


def test_no_baked_plugin(home, tmp_path):
    missing = tmp_path / "nope.json"
    assert cec.sync_baked_plugin(required=False, meta_path=missing, tree=tmp_path) is None
    with pytest.raises(cec.PluginInstallError, match="no baked Hermie plugin"):
        cec.sync_baked_plugin(required=True, meta_path=missing, tree=tmp_path)


@pytest.fixture
def image_plugin(baked, monkeypatch):
    """Point the module at the baked test plugin, as if running inside the image."""
    dest, meta_path = baked
    monkeypatch.setattr(cec, "BAKED_PLUGIN_DIR", dest)
    monkeypatch.setattr(cec, "BAKED_PLUGIN_META", meta_path)
    return dest, meta_path


def test_default_start_syncs_and_enables_once(home, image_plugin):
    from hermes_cli import plugins_cmd

    cec.run({}, home, profile_homes=[])
    assert _cfg(home)["plugins"]["enabled"] == ["hermie"]
    first = (home / "config.yaml").read_bytes()
    cec.run({}, home, profile_homes=[])
    assert (home / "config.yaml").read_bytes() == first
    # A user who disables it keeps it disabled while HERMIE_PLUGIN is unset ...
    (home / "config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [hermie]\n", encoding="utf-8")
    cec.run({}, home, profile_homes=[])
    assert _cfg(home)["plugins"] == {"enabled": [], "disabled": ["hermie"]}
    # ... the tree is still kept in sync ...
    (home / "plugins" / "hermie" / "stray.py").write_text("x = 1\n", encoding="utf-8")
    cec.run({}, home, profile_homes=[])
    assert not (home / "plugins" / "hermie" / "stray.py").exists()
    assert plugins_cmd._read_install_metadata()["hermie"]["image_ref"] == "v1.0.0"
    # ... and HERMIE_PLUGIN=true takes it back.
    cec.run({cec.HERMIE_PLUGIN: "true"}, home, profile_homes=[])
    assert _cfg(home)["plugins"] == {"enabled": ["hermie"], "disabled": []}


def _make_profile(home: Path, name: str, config: str = "model:\n  default: x\n") -> Path:
    from hermes_constants import named_profile_has_identity

    profile = home / "profiles" / name
    profile.mkdir(parents=True)
    (profile / "config.yaml").write_text(config, encoding="utf-8")
    (profile / ".env").write_text("", encoding="utf-8")
    (profile / "SOUL.md").write_text("x\n", encoding="utf-8")
    if not named_profile_has_identity(profile):
        pytest.skip("profile identity marker layout differs")
    return profile


def test_every_named_profile_gets_the_plugin(home, image_plugin):
    bot = _make_profile(home, "bot1")
    broken = _make_profile(home, "bot2", config="plugins: [unclosed\n")
    assert [p.name for p in cec._named_profile_homes()] == ["bot1", "bot2"]
    changed = cec.run({}, home)
    for profile in (bot, broken):
        assert (profile / "plugins" / "hermie" / "plugin.yaml").is_file()
    assert yaml.safe_load((bot / "config.yaml").read_text(encoding="utf-8"))["plugins"]["enabled"] == ["hermie"]
    assert (broken / "config.yaml").read_text(encoding="utf-8") == "plugins: [unclosed\n"  # skipped, not fatal
    assert any("in profile bot1" in c for c in changed)
    before = (bot / "config.yaml").read_bytes()
    cec.run({}, home)
    assert (bot / "config.yaml").read_bytes() == before


def test_profile_created_later_gets_the_plugin(home, image_plugin, monkeypatch):
    from hermes_cli import profiles

    monkeypatch.delenv(cec.HERMIE_PLUGIN, raising=False)
    cec.run({}, home, profile_homes=[])
    monkeypatch.setattr(profiles, "_maybe_register_gateway_service", lambda name: None)
    monkeypatch.setattr(profiles, "_notify_multiplexer", lambda name: None)
    created = profiles.create_profile("latebot", no_alias=True)
    assert (created / "plugins" / "hermie" / "plugin.yaml").is_file()
    assert "hermie" in yaml.safe_load((created / "config.yaml").read_text(encoding="utf-8"))["plugins"]["enabled"]


def test_new_profile_seed_respects_false(home, image_plugin, monkeypatch):
    staging = home / "staging"
    (staging / "plugins").mkdir(parents=True)
    monkeypatch.setenv(cec.HERMIE_PLUGIN, "false")
    cec.seed_new_profile(staging)
    assert not (staging / "plugins" / "hermie").exists()


def test_new_profile_seed_is_a_noop_outside_the_image(home, tmp_path, monkeypatch):
    monkeypatch.setattr(cec, "BAKED_PLUGIN_META", tmp_path / "absent.json")
    staging = home / "staging"
    staging.mkdir()
    cec.seed_new_profile(staging)
    assert not (staging / "plugins").exists()


def test_sync_refuses_a_symlinked_target(home, image_plugin, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / "plugins").mkdir()
    (home / "plugins" / "hermie").symlink_to(elsewhere)
    with pytest.raises(cec.PluginInstallError, match="symlink"):
        cec.sync_baked_plugin(required=False)


def test_tree_digest_does_not_open_a_fifo(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.py").write_text("x\n", encoding="utf-8")
    clean = cec.tree_digest(tree)
    os.mkfifo(tree / "pipe")
    assert cec.tree_digest(tree) != clean  # returns (does not block) and differs


# ---------------------------------------------------------------------------------------------
# Round 2: public_urls, write_origin_check, .env shadowing, session revocation, plaintext migration
# ---------------------------------------------------------------------------------------------


def test_public_urls(home):
    _run(home, {cec.PUBLIC_URLS: "https://hermes.example.com, https://app.example.com:8443/,"
                                 "https://hermes.example.com, https://example.com/prefix"})
    assert _cfg(home)["dashboard"]["public_urls"] == [
        "https://hermes.example.com", "https://app.example.com:8443", "https://example.com/prefix"]


@pytest.mark.parametrize("raw", ["app.example.com", "ftp://x.example.com", "https://", "https://a.example.com:99999",
                                 "https://user:pw@a.example.com", "https://a.example.com/?q=1"])
def test_public_urls_invalid(home, raw):
    with pytest.raises(cec.EnvConfigError, match=cec.PUBLIC_URLS):
        _run(home, {cec.PUBLIC_URLS: f"https://ok.example.com,{raw}"})


def test_public_urls_are_what_the_gateway_reads(home, monkeypatch):
    from hermes_cli.dashboard_auth import prefix

    _run(home, {cec.PUBLIC_URL: "https://primary.example.com", cec.PUBLIC_URLS: "https://app.example.com/x"})
    monkeypatch.delenv(cec.PUBLIC_URL, raising=False)
    monkeypatch.setattr(prefix, "_load_dashboard_section", lambda: _cfg(home)["dashboard"])
    assert prefix.resolve_public_urls() == ["https://primary.example.com", "https://app.example.com/x"]


@pytest.mark.parametrize("raw, stored", [("auto", "auto"), ("ON", True), ("off", False)])
def test_write_origin_check(home, raw, stored):
    _run(home, {cec.WRITE_ORIGIN_CHECK: raw})
    assert _cfg(home)["dashboard"]["write_origin_check"] == stored
    before = (home / "config.yaml").read_bytes()
    assert _run(home, {cec.WRITE_ORIGIN_CHECK: raw}) == []
    assert (home / "config.yaml").read_bytes() == before


def test_write_origin_check_invalid(home):
    with pytest.raises(cec.EnvConfigError, match=cec.WRITE_ORIGIN_CHECK):
        _run(home, {cec.WRITE_ORIGIN_CHECK: "sometimes"})


@pytest.mark.parametrize("raw, stored", [("true", True), ("1", True), ("FALSE", False)])
def test_mcp_enabled_is_what_the_mcp_settings_read(home, raw, stored):
    from hermes_cli.dashboard_auth.mcp.settings import parse

    _run(home, {cec.MCP_ENABLED: raw})
    settings, problems = parse(_cfg(home))
    assert (settings.enabled, problems) == (stored, [])
    before = (home / "config.yaml").read_bytes()
    assert _run(home, {cec.MCP_ENABLED: raw}) == []
    assert (home / "config.yaml").read_bytes() == before


def test_mcp_enabled_invalid(home):
    with pytest.raises(cec.EnvConfigError, match=cec.MCP_ENABLED):
        _run(home, {cec.MCP_ENABLED: "sometimes"})


class TestMessagingGatewaySwitch:
    """HERM-131: HERMES_MESSAGING_GATEWAY is validated here but never written to config.yaml — it is
    a live container switch read by hermes_cli.container_boot and `hermes gateway start`."""

    def test_default_is_enabled(self):
        assert cec.parse_environment({}).messaging_gateway_enabled is True

    @pytest.mark.parametrize("raw", ["on", "ON", "1", "true", "True", "yes"])
    def test_truthy_values_enable(self, raw):
        assert cec.parse_environment({cec.MESSAGING_GATEWAY: raw}).messaging_gateway_enabled is True

    @pytest.mark.parametrize("raw", ["off", "OFF", "0", "false", "False", "no"])
    def test_falsy_values_disable(self, raw):
        assert cec.parse_environment({cec.MESSAGING_GATEWAY: raw}).messaging_gateway_enabled is False

    def test_invalid_value_fails_closed(self, home):
        with pytest.raises(cec.EnvConfigError, match=cec.MESSAGING_GATEWAY):
            _run(home, {cec.MESSAGING_GATEWAY: "sometimes", cec.PROFILES_MAX: "3"})
        # Nothing else from the same (otherwise valid) environment was applied either.
        assert not (home / "config.yaml").exists()

    def test_off_does_not_touch_config_yaml(self, home):
        # A fresh home has no config.yaml at all; HERMES_MESSAGING_GATEWAY alone must not create one.
        changed = _run(home, {cec.MESSAGING_GATEWAY: "off"})
        assert changed == []
        assert not (home / "config.yaml").exists()

    def test_off_alongside_a_real_setting_leaves_no_gateway_key_in_config(self, home):
        _run(home, {cec.MESSAGING_GATEWAY: "off", cec.PROFILES_MAX: "3"})
        cfg = _cfg(home)
        assert cfg == {"profiles": {"max": 3}}

    def test_messaging_gateway_enabled_helper_default(self, monkeypatch):
        monkeypatch.delenv(cec.MESSAGING_GATEWAY, raising=False)
        assert cec.messaging_gateway_enabled() is True

    def test_messaging_gateway_enabled_helper_reads_live_environ(self, monkeypatch):
        monkeypatch.setenv(cec.MESSAGING_GATEWAY, "off")
        assert cec.messaging_gateway_enabled() is False
        monkeypatch.setenv(cec.MESSAGING_GATEWAY, "on")
        assert cec.messaging_gateway_enabled() is True

    def test_messaging_gateway_enabled_helper_takes_explicit_mapping(self):
        assert cec.messaging_gateway_enabled({cec.MESSAGING_GATEWAY: "off"}) is False
        assert cec.messaging_gateway_enabled({}) is True

    def test_messaging_gateway_is_a_managed_env_name(self):
        # Consistency with the other container-level switches (e.g. HERMES_DASHBOARD_HOST): a copy
        # left in $HERMES_HOME/.env must not shadow the container environment.
        assert cec.MESSAGING_GATEWAY in cec.MANAGED_ENV_NAMES


def test_env_file_copies_of_managed_variables_are_removed(home, capsys):
    env_file = home / ".env"
    env_file.write_text("OPENROUTER_API_KEY=sk-keep\n"
                        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=old-password-from-api\n"
                        "export HERMES_DASHBOARD_PUBLIC_URL=https://stale.example.com\n"
                        "HERMES_DASHBOARD_OIDC_CLIENT_SECRET=not-set-in-env-so-kept\n", encoding="utf-8")
    env_file.chmod(0o600)
    _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD,
                cec.PUBLIC_URL: "https://hermes.example.com"})
    text = env_file.read_text(encoding="utf-8")
    assert "old-password-from-api" not in text and "stale.example.com" not in text
    assert "OPENROUTER_API_KEY=sk-keep" in text and "not-set-in-env-so-kept" in text
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert f"removed {cec.BASIC_PASSWORD}" in out and "old-password-from-api" not in out
    # Nothing left to remove on the next start.
    before = env_file.read_bytes()
    _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
    assert env_file.read_bytes() == before


def test_remove_keeps_process_environment(home, monkeypatch):
    (home / ".env").write_text(f"{cec.PROFILES_MAX}=9\n", encoding="utf-8")
    monkeypatch.setenv(cec.PROFILES_MAX, "3")
    assert cec.remove_shadowing_env_lines({cec.PROFILES_MAX: "3"}, home) == [cec.PROFILES_MAX]
    assert os.environ[cec.PROFILES_MAX] == "3"


@pytest.mark.parametrize("key", ["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "HERMES_DASHBOARD_BASIC_AUTH_SECRET",
                                 "HERMES_DASHBOARD_BASIC_AUTH_USERNAME", "HERMES_DASHBOARD_OIDC_CLIENT_SECRET",
                                 "HERMES_DASHBOARD_OIDC_ISSUER"])
def test_env_writer_refuses_dashboard_credentials(home, key):
    from hermes_cli.config import save_env_value

    with pytest.raises(ValueError, match="denylist"):
        save_env_value(key, "x")
    assert not (home / ".env").exists() or key not in (home / ".env").read_text(encoding="utf-8")


def test_api_env_put_refuses_dashboard_credentials(home):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from hermes_cli.web_routers import config_env

    app = FastAPI()
    app.include_router(config_env.router)
    resp = TestClient(app).put("/api/env", json={"key": "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "value": "x"})
    assert resp.status_code == 400 and "denylist" in resp.text


def _provider_from(home, monkeypatch):
    import plugins.dashboard_auth.basic as basic

    for name in (cec.BASIC_USERNAME, cec.BASIC_PASSWORD, cec.BASIC_PASSWORD_HASH, cec.BASIC_SECRET):
        monkeypatch.delenv(name, raising=False)
    section = _cfg(home)["dashboard"]["basic_auth"]
    monkeypatch.setattr(basic, "_load_config_basic_auth_section", lambda: section)
    return basic.BasicAuthProvider(**basic._settings())


def test_password_change_ends_existing_sessions(home, monkeypatch):
    _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
    old = _provider_from(home, monkeypatch).complete_password_login(username="admin", password=PASSWORD)
    # A plain restart keeps sessions.
    _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
    assert _provider_from(home, monkeypatch).verify_session(access_token=old.access_token) is not None
    # A new password refuses the old access AND refresh token.
    changed = _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: "a-rotated-password-99"})
    assert any("secret (rotated" in c for c in changed)
    provider = _provider_from(home, monkeypatch)
    assert provider.verify_session(access_token=old.access_token) is None
    from hermes_cli.dashboard_auth import RefreshExpiredError
    with pytest.raises(RefreshExpiredError):
        provider.refresh_session(refresh_token=old.refresh_token)


def test_env_secret_is_not_rotated(home):
    env = {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD, cec.BASIC_SECRET: "k" * 40}
    _run(home, env)
    changed = _run(home, {**env, cec.BASIC_PASSWORD: "a-rotated-password-99"})
    assert "secret" not in _cfg(home)["dashboard"]["basic_auth"]
    assert not any("secret" in c for c in changed)


def test_env_username_with_config_plaintext_is_migrated(home):
    (home / "config.yaml").write_text(
        "dashboard:\n  basic_auth:\n    password: legacy-plain-pw-55\n", encoding="utf-8")
    _run(home, {cec.BASIC_USERNAME: "admin"})
    basic = _cfg(home)["dashboard"]["basic_auth"]
    assert "password" not in basic and _verify_password("legacy-plain-pw-55", basic["password_hash"])
    assert b"legacy-plain-pw-55" not in (home / "config.yaml").read_bytes()


def test_yaml_error_is_described_without_content(home, monkeypatch, capsys):
    (home / "config.yaml").write_text("model: ok\nsecret_line: 'sk-live-XYZ\n", encoding="utf-8")
    monkeypatch.setenv(cec.PROFILES_MAX, "2")
    assert cec.main([]) == 1
    err = capsys.readouterr().err
    assert "line" in err and "sk-live-XYZ" not in err


@pytest.mark.parametrize("key", ["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH",
                                 "HERMES_DASHBOARD_BASIC_AUTH_SECRET", "HERMES_DASHBOARD_OIDC_CLIENT_SECRET"])
def test_dashboard_secrets_never_reach_agent_subprocesses(monkeypatch, key):
    from tools.environments import local

    monkeypatch.setenv(key, "probe-secret-value")
    for env in (local.hermes_subprocess_env(), local.hermes_subprocess_env(inherit_credentials=True),
                local._sanitize_subprocess_env(dict(os.environ)), local.build_subprocess_env()):
        assert key not in env
        assert "probe-secret-value" not in env.values()


# ---------------------------------------------------------------------------------------------
# Final round: failure ordering and per-profile isolation
# ---------------------------------------------------------------------------------------------


def test_failed_start_leaves_env_file_untouched(home):
    env_file = home / ".env"
    env_file.write_text("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=copy-in-env-file\n", encoding="utf-8")
    before = env_file.read_bytes()

    def boom(plan, default_home, profiles):
        raise cec.PluginInstallError("scan blocked")

    with pytest.raises(cec.EnvConfigError):
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD}, hermie=boom)
    assert env_file.read_bytes() == before
    # A malformed config.yaml fails the start too, and .env stays as it was.
    (home / "config.yaml").write_text("dashboard: [unclosed\n", encoding="utf-8")
    with pytest.raises(Exception):
        _run(home, {cec.BASIC_USERNAME: "admin", cec.BASIC_PASSWORD: PASSWORD})
    assert env_file.read_bytes() == before


def test_corrupt_install_record_in_one_profile_does_not_stop_the_start(home, image_plugin, capsys):
    bad = _make_profile(home, "badbot")
    good = _make_profile(home, "goodbot")
    (bad / "plugins").mkdir()
    (bad / "plugins" / ".install-metadata.json").write_text("[not an object]", encoding="utf-8")
    cec.run({}, home)
    assert (good / "plugins" / "hermie" / "plugin.yaml").is_file()
    assert yaml.safe_load((good / "config.yaml").read_text(encoding="utf-8"))["plugins"]["enabled"] == ["hermie"]
    assert _cfg(home)["plugins"]["enabled"] == ["hermie"]
    out = capsys.readouterr().out
    assert "could not sync hermie into profile badbot: PluginInstallError" in out
    assert "not an object" not in out


def test_unexpected_error_in_one_profile_does_not_stop_the_start(home, image_plugin, monkeypatch, capsys):
    bad = _make_profile(home, "badbot")
    good = _make_profile(home, "goodbot")
    real = cec.sync_plugin_copy

    def flaky(src):
        from hermes_constants import get_hermes_home

        if get_hermes_home() == bad:
            raise KeyError("secret-looking-detail")
        return real(src)

    monkeypatch.setattr(cec, "sync_plugin_copy", flaky)
    cec.run({}, home)
    assert (good / "plugins" / "hermie" / "plugin.yaml").is_file()
    assert not (bad / "plugins" / "hermie").exists()
    out = capsys.readouterr().out
    assert "could not sync hermie into profile badbot: KeyError" in out
    assert "secret-looking-detail" not in out
