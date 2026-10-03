"""Every path that changes a plugin tree scans the new tree before it goes live, and fails closed
(HERM-192 review).

A git update fetches, scans the fetched commit written out OUTSIDE the plugins dir, and applies it
(``merge --ff-only`` to exactly that commit, then dependencies) only when it passes. A refused
update changes nothing: the live tree stays at the old, accepted commit, keeps its enabled state and
the loader still loads the old version. An unchanged plugin is never rescanned. Installs scan a
temporary clone, so a verdict short of safe leaves nothing installed. Real git repositories, real
scanner, the loader's own gate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

DANGEROUS = 'import os\nos.system("rm -rf /")\n'                                   # destructive_root_rm: critical
CAUTION = 'import subprocess\nsubprocess.run("sudo apt install x", shell=True)\n'   # sudo_usage: high


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _loader(target: Path):
    """The loader's own answer for the plugin in *target*: (gate action, manifest version)."""
    from hermes_cli.plugins_discovery import (
        _get_disabled_plugins, _get_enabled_plugins, collect_directory_manifests, gate_manifest)

    for manifest in collect_directory_manifests():
        if manifest.path and Path(manifest.path).resolve() == target.resolve():
            verdict = gate_manifest(manifest, _get_disabled_plugins(), _get_enabled_plugins())
            return verdict.action, manifest.version
    raise AssertionError(f"the loader does not see {target}")


class _Plugin:
    def __init__(self, pc, repo: Path, target: Path, deps: list):
        self.pc, self.repo, self.target, self.deps = pc, repo, target, deps

    @property
    def name(self) -> str:
        return self.target.name

    def push(self, filename: str, content: str, version: str = "2.0.0") -> str:
        (self.repo / filename).write_text(content, encoding="utf-8")
        (self.repo / "plugin.yaml").write_text(yaml.safe_dump({"name": "demo", "version": version}), encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", f"add {filename}")
        return _git(self.repo, "rev-parse", "HEAD")

    def head(self) -> str:
        return _git(self.target, "rev-parse", "HEAD")


@pytest.fixture(params=["same", "renamed"])
def plugin(request, tmp_path, monkeypatch):
    """An installed, enabled, unpinned plugin whose manifest name is ``demo``. ``renamed``: its
    folder is ``demo-folder`` (folder name != manifest name)."""
    import hermes_cli.plugins_cmd as pc
    from hermes_cli.plugins_manifest import manifest_key

    if not pc._resolve_git_executable():
        pytest.skip("git not available")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "plugin.yaml").write_text(yaml.safe_dump({"name": "demo", "version": "1.0.0"}), encoding="utf-8")
    (repo / "__init__.py").write_text("def register(ctx):\n    pass\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "first")
    target, _manifest, _name = pc._install_plugin_core(repo.as_uri(), force=False)
    if request.param == "renamed":
        renamed = target.parent / "demo-folder"
        target.rename(renamed)
        target = renamed
    from hermes_cli.plugins_discovery import collect_directory_manifests
    key = next(manifest_key(m) for m in collect_directory_manifests()
               if m.path and Path(m.path).resolve() == target.resolve())
    pc._activate_key(key, enable=True)
    assert _loader(target) == ("load", "1.0.0")
    deps: list = []
    monkeypatch.setattr(pc, "_install_python_dependencies", lambda path, *_a, **_k: deps.append(Path(path)))
    monkeypatch.setattr(pc, "_install_python_dependencies_quietly",
                        lambda path, *_a, **_k: deps.append(Path(path)) or [])
    return _Plugin(pc, repo, target, deps)


def _refused_and_untouched(plugin: _Plugin, old_head: str) -> None:
    assert plugin.head() == old_head                       # nothing applied
    assert not (plugin.target / "evil.py").exists() and not (plugin.target / "run.py").exists()
    assert _loader(plugin.target) == ("load", "1.0.0")     # still enabled, still the old version
    assert plugin.deps == []


# ── hermes plugins update ────────────────────────────────────────────────────────────────


class TestCliUpdate:
    def test_dangerous_is_refused_and_the_live_tree_is_untouched(self, plugin, capsys):
        old = plugin.head()
        plugin.push("evil.py", DANGEROUS)
        with pytest.raises(SystemExit) as exc:
            plugin.pc.cmd_update(plugin.name)
        assert exc.value.code == 1                          # the timer does not restart
        assert "not applied" in capsys.readouterr().out
        _refused_and_untouched(plugin, old)

    def test_caution_without_a_terminal_is_refused(self, plugin, monkeypatch):
        monkeypatch.setattr(plugin.pc, "_is_tty", lambda: False)
        old = plugin.head()
        plugin.push("run.py", CAUTION)
        with pytest.raises(SystemExit) as exc:
            plugin.pc.cmd_update(plugin.name)
        assert exc.value.code == 1
        _refused_and_untouched(plugin, old)

    def test_caution_declined_on_a_terminal_is_refused(self, plugin, monkeypatch):
        monkeypatch.setattr(plugin.pc, "_is_tty", lambda: True)
        monkeypatch.setattr(plugin.pc, "_ask_yes", lambda *_a, **_k: False)
        old = plugin.head()
        plugin.push("run.py", CAUTION)
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)

    def test_caution_accepted_on_a_terminal_is_applied(self, plugin, monkeypatch):
        monkeypatch.setattr(plugin.pc, "_is_tty", lambda: True)
        monkeypatch.setattr(plugin.pc, "_ask_yes", lambda *_a, **_k: True)
        new = plugin.push("run.py", CAUTION)
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == new and plugin.deps == [plugin.target]
        assert _loader(plugin.target) == ("load", "2.0.0")  # nothing was disabled, nothing to re-enable

    def test_safe_is_applied(self, plugin):
        new = plugin.push("notes.txt", "nothing to see\n")
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == new and plugin.deps == [plugin.target]
        assert _loader(plugin.target) == ("load", "2.0.0")

    def test_a_scan_that_raises_is_refused(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        old = plugin.head()
        plugin.push("notes.txt", "nothing to see\n")
        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: 1 / 0)
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == old and _loader(plugin.target) == ("load", "1.0.0") and plugin.deps == []

    def test_a_scan_killed_half_way_leaves_the_tree_untouched(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        def killed(*_a, **_k):
            raise KeyboardInterrupt    # SIGINT, a timer stopped mid-scan

        old = plugin.head()
        plugin.push("evil.py", DANGEROUS)
        monkeypatch.setattr(guard, "scan_plugin", killed)
        with pytest.raises(KeyboardInterrupt):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)
        assert _git(plugin.target, "status", "--porcelain") == ""

    def test_the_scan_never_sees_the_live_tree_or_the_plugins_dir(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        seen: list = []
        real = guard.scan_plugin
        monkeypatch.setattr(guard, "scan_plugin", lambda tree, **kw: seen.append(Path(tree)) or real(tree, **kw))
        plugin.push("notes.txt", "x\n")
        plugin.pc.cmd_update(plugin.name)
        plugins_dir = plugin.pc._plugins_dir().resolve()
        assert len(seen) == 1 and plugins_dir not in seen[0].resolve().parents
        assert not seen[0].exists()                         # the export is gone afterwards

    def test_an_unchanged_plugin_is_left_alone_by_a_newer_scanner(self, plugin, monkeypatch):
        """Nothing fetched: no scan, no change, even when today's scanner would refuse the tree."""
        import tools.plugin_guard as guard

        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: pytest.fail("an unchanged plugin was scanned"))
        old = plugin.head()
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == old and _loader(plugin.target) == ("load", "1.0.0")

    def test_export_ignore_cannot_hide_a_file_from_the_scan(self, plugin):
        old = plugin.head()
        (plugin.repo / ".gitattributes").write_text("evil.py export-ignore\n", encoding="utf-8")
        plugin.push("evil.py", DANGEROUS)
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)

    def test_a_config_write_error_during_the_update_leaves_the_old_tree_live(self, plugin, monkeypatch):
        """Nothing in the gate writes config; a failing config write cannot leave a changed tree live."""
        old = plugin.head()
        plugin.push("evil.py", DANGEROUS)
        monkeypatch.setattr(plugin.pc, "_write_config_value", lambda *_a, **_k: (_ for _ in ()).throw(OSError("ro")))
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)


# ── the dashboard's update ───────────────────────────────────────────────────────────────


class TestDashboardUpdate:
    def test_dangerous_is_refused_with_its_findings(self, plugin):
        old = plugin.head()
        new = plugin.push("evil.py", DANGEROUS)
        result = plugin.pc.dashboard_update_user_plugin(plugin.name)
        assert result["ok"] is False and result["update_refused"] is True and result["scan_verdict"] == "dangerous"
        assert result["caution_consent_required"] is False and result["revision"] == new
        assert any(f["severity"] == "critical" for f in result["scan_findings"])
        _refused_and_untouched(plugin, old)

    def test_caution_without_consent_asks_for_it(self, plugin):
        old = plugin.head()
        plugin.push("run.py", CAUTION)
        result = plugin.pc.dashboard_update_user_plugin(plugin.name)
        assert result["ok"] is False and result["caution_consent_required"] is True
        assert result["scan_verdict"] == "caution" and result["scan_findings"]
        _refused_and_untouched(plugin, old)

    def test_caution_with_explicit_consent_is_applied(self, plugin):
        new = plugin.push("run.py", CAUTION)
        result = plugin.pc.dashboard_update_user_plugin(plugin.name, accept_caution=True)
        assert result["ok"] is True and plugin.head() == new and plugin.deps == [plugin.target]
        assert _loader(plugin.target) == ("load", "2.0.0")

    def test_a_scan_that_raises_is_refused(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        old = plugin.head()
        plugin.push("notes.txt", "nothing to see\n")
        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: 1 / 0)
        result = plugin.pc.dashboard_update_user_plugin(plugin.name)
        assert result["ok"] is False and result["scan_verdict"] == "error" and "ZeroDivisionError" in result["error"]
        assert plugin.head() == old and _loader(plugin.target) == ("load", "1.0.0") and plugin.deps == []

    def test_safe_is_applied(self, plugin):
        new = plugin.push("notes.txt", "nothing to see\n")
        result = plugin.pc.dashboard_update_user_plugin(plugin.name)
        assert result["ok"] is True and plugin.head() == new and plugin.deps == [plugin.target]


# ── installs scan a temporary clone: nothing lands when the scan does not pass ───────────


class TestInstall:
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        import hermes_cli.plugins_cmd as pc

        if not pc._resolve_git_executable():
            pytest.skip("git not available")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        repo = tmp_path / "repo2"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "fixture@example.com")
        _git(repo, "config", "user.name", "Fixture")
        (repo / "plugin.yaml").write_text(yaml.safe_dump({"name": "fresh", "version": "1.0.0"}), encoding="utf-8")
        return pc, repo

    def _commit(self, repo, filename, content):
        (repo / filename).write_text(content, encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", filename)

    def test_a_scan_that_raises_installs_nothing(self, repo, monkeypatch):
        import tools.plugin_guard as guard

        pc, origin = repo
        self._commit(origin, "notes.txt", "x\n")
        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: 1 / 0)
        with pytest.raises(ZeroDivisionError):
            pc._install_plugin_core(origin.as_uri(), force=False)
        assert not (pc._plugins_dir() / "fresh").exists()
        assert "fresh" not in pc._read_install_metadata()

    @pytest.mark.parametrize("content", [DANGEROUS, CAUTION])
    def test_a_verdict_short_of_safe_installs_nothing_without_consent(self, repo, content):
        pc, origin = repo
        self._commit(origin, "code.py", content)
        with pytest.raises(pc.PluginScanBlocked):
            pc._install_plugin_core(origin.as_uri(), force=False)
        assert not (pc._plugins_dir() / "fresh").exists()
        result = pc.dashboard_install_plugin(origin.as_uri(), force=False, enable=True)
        assert result["ok"] is False and result["scan_blocked"] is True
        assert not (pc._plugins_dir() / "fresh").exists()
