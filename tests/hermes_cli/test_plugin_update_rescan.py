"""Every path that changes a plugin tree scans it before dependencies are installed or the
plugin can load, and fails closed (HERM-192 review).

The update paths run ``git pull`` first, so the tree on disk is already the new one when the
scan runs: a verdict that does not pass, or a scan that cannot finish, must leave the plugin
disabled with its new dependencies uninstalled. Installs scan a temporary clone, so there the
same verdicts leave nothing installed. Real git repositories, real scanner.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

DANGEROUS = 'import os\nos.system("rm -rf /")\n'                         # destructive_root_rm: critical
CAUTION = 'import subprocess\nsubprocess.run("sudo apt install x", shell=True)\n'   # sudo_usage: high


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return done.stdout.strip()


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    """An installed, enabled, unpinned plugin ``demo`` whose origin can take a new commit."""
    import hermes_cli.plugins_cmd as pc

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
    target, _manifest, name = pc._install_plugin_core(repo.as_uri(), force=False)
    assert name == "demo"
    pc._set_plugin_enabled("demo", enable=True)
    deps: list = []
    monkeypatch.setattr(pc, "_install_python_dependencies", lambda path, *_a, **_k: deps.append(Path(path)))
    monkeypatch.setattr(pc, "_install_python_dependencies_quietly", lambda path, *_a, **_k: deps.append(Path(path)) or [])

    def push(filename: str, content: str) -> None:
        (repo / filename).write_text(content, encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", f"add {filename}")

    return pc, target, push, deps


def _enabled(pc) -> bool:
    return "demo" in pc._get_enabled_set() and "demo" not in pc._get_disabled_set()


# ── hermes plugins update ────────────────────────────────────────────────────────────────


class TestCliUpdate:
    def test_dangerous_disables_and_installs_no_dependency(self, plugin):
        pc, target, push, deps = plugin
        push("evil.py", DANGEROUS)
        with pytest.raises(SystemExit) as exc:
            pc.cmd_update("demo")
        assert exc.value.code == 1
        assert (target / "evil.py").exists()          # the pull happened …
        assert not _enabled(pc) and deps == []        # … and the tree can neither load nor install

    def test_caution_without_a_terminal_disables_pending_consent(self, plugin, monkeypatch):
        pc, _target, push, deps = plugin
        monkeypatch.setattr(pc, "_is_tty", lambda: False)
        push("run.py", CAUTION)
        with pytest.raises(SystemExit) as exc:
            pc.cmd_update("demo")
        assert exc.value.code == 1
        assert not _enabled(pc) and deps == []

    def test_caution_declined_on_a_terminal_disables(self, plugin, monkeypatch):
        pc, _target, push, deps = plugin
        monkeypatch.setattr(pc, "_is_tty", lambda: True)
        monkeypatch.setattr(pc, "_ask_yes", lambda *_a, **_k: False)
        push("run.py", CAUTION)
        with pytest.raises(SystemExit):
            pc.cmd_update("demo")
        assert not _enabled(pc) and deps == []

    def test_caution_accepted_on_a_terminal_goes_on(self, plugin, monkeypatch):
        pc, target, push, deps = plugin
        monkeypatch.setattr(pc, "_is_tty", lambda: True)
        monkeypatch.setattr(pc, "_ask_yes", lambda *_a, **_k: True)
        push("run.py", CAUTION)
        pc.cmd_update("demo")
        assert _enabled(pc) and deps == [target]

    def test_safe_goes_on(self, plugin):
        pc, target, push, deps = plugin
        push("notes.txt", "nothing to see\n")
        pc.cmd_update("demo")
        assert _enabled(pc) and deps == [target]

    def test_a_scan_that_raises_disables(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        pc, _target, push, deps = plugin
        push("notes.txt", "nothing to see\n")
        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: 1 / 0)
        with pytest.raises(SystemExit):
            pc.cmd_update("demo")
        assert not _enabled(pc) and deps == []


# ── the dashboard's update ───────────────────────────────────────────────────────────────


class TestDashboardUpdate:
    def test_dangerous_disables_and_reports(self, plugin):
        pc, target, push, deps = plugin
        push("evil.py", DANGEROUS)
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is False and result["scan_blocked"] is True and result["disabled"] is True
        assert result["scan_verdict"] == "dangerous"
        assert any(f["severity"] == "critical" for f in result["scan_findings"])
        assert "disabled" in result["error"]
        assert (target / "evil.py").exists() and not _enabled(pc) and deps == []

    def test_caution_without_consent_disables_pending_consent(self, plugin):
        pc, _target, push, deps = plugin
        push("run.py", CAUTION)
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is False and result["caution_consent_required"] is True
        assert result["scan_verdict"] == "caution" and "accept_caution" in result["error"]
        assert not _enabled(pc) and deps == []

    def test_caution_with_explicit_consent_goes_on(self, plugin):
        pc, target, push, deps = plugin
        push("run.py", CAUTION)
        result = pc.dashboard_update_user_plugin("demo", accept_caution=True)
        assert result["ok"] is True and result["scan_verdict"] == "caution"
        assert _enabled(pc) and deps == [target]

    def test_a_scan_that_raises_disables(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        pc, _target, push, deps = plugin
        push("notes.txt", "nothing to see\n")
        monkeypatch.setattr(guard, "scan_plugin", lambda *_a, **_k: 1 / 0)
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is False and result["scan_verdict"] == "error" and result["disabled"] is True
        assert "ZeroDivisionError" in result["error"]
        assert not _enabled(pc) and deps == []

    def test_safe_goes_on(self, plugin):
        pc, target, push, deps = plugin
        push("notes.txt", "nothing to see\n")
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is True and result["scan_verdict"] == "safe"
        assert _enabled(pc) and deps == [target]


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
