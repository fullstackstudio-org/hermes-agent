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

    def push_tree(self, extra: list, version: str = "2.0.0") -> str:
        """Commit, with git plumbing, the current files plus *extra* entries: ``(path, mode, bytes)``
        (``mode`` 100644/100755/120000) or ``(path, "dup", [(mode, bytes), ...])`` for a name listed
        twice. Trees are written with ``--literally`` so a tree git fsck would refuse can be made."""
        (self.repo / "plugin.yaml").write_text(yaml.safe_dump({"name": "demo", "version": version}), encoding="utf-8")
        entries = [("plugin.yaml", "100644", (self.repo / "plugin.yaml").read_bytes()),
                   ("__init__.py", "100644", (self.repo / "__init__.py").read_bytes())] + list(extra)
        tree = _write_tree(self.repo, entries)
        parent = _git(self.repo, "rev-parse", "HEAD")
        commit = _git(self.repo, "commit-tree", tree, "-p", parent, "-m", "plumbing")
        _git(self.repo, "update-ref", _git(self.repo, "symbolic-ref", "HEAD"), commit)
        _git(self.repo, "reset", "--quiet", "--soft", commit)
        return commit


def _hash(repo: Path, data: bytes, kind: str = "blob", literally: bool = False) -> str:
    args = ["hash-object", "-w", "-t", kind, "--stdin"] + (["--literally"] if literally else [])
    done = subprocess.run(["git", *args], cwd=repo, input=data, check=True, capture_output=True)
    return done.stdout.decode().strip()


def _write_tree(repo: Path, entries: list) -> str:
    """A tree object from ``(path, mode, bytes)`` entries (nested paths make subtrees)."""
    top: dict = {}
    order: list = []
    for path, mode, data in entries:
        head, _, rest = path.partition("/")
        if rest:
            top.setdefault(head, ("tree", []))[1].append((rest, mode, data))
            if head not in order:
                order.append(head)
        elif mode == "dup":
            for dup_mode, dup_data in data:
                order.append((head, dup_mode, dup_data))
        else:
            order.append((head, mode, data))
    raw = []
    for item in order:
        if isinstance(item, str):
            sub = _write_tree(repo, top[item][1])
            raw.append((item + "/", b"40000 " + item.encode() + b"\0" + bytes.fromhex(sub)))
        else:
            name, mode, data = item
            sha = _hash(repo, data)
            raw.append((name, mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)))
    raw.sort(key=lambda pair: pair[0].encode())
    return _hash(repo, b"".join(r for _, r in raw), kind="tree", literally=True)


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


# ── the checkout that is scanned is the tree that is applied (review round 3) ─────────────


class TestScannedCheckout:
    """The new commit is checked out by git into a temporary clone and scanned there; a tree no
    platform can check out unambiguously is refused before anything is written, and the files the
    merge writes must be the files that were scanned."""

    def _refused(self, plugin, old, outside: Path) -> None:
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)
        assert not (outside / "owned.txt").exists()

    def test_a_symlink_prefix_with_a_case_variant_is_refused(self, plugin, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        old = plugin.head()
        plugin.push_tree([("Link", "120000", str(outside).encode()), ("link/owned.txt", "100644", b"pwned\n")])
        self._refused(plugin, old, outside)

    def test_a_duplicate_tree_entry_is_refused(self, plugin, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        old = plugin.head()
        plugin.push_tree([("lnk", "dup", [("120000", str(outside).encode()), ("100644", b"x\n")])])
        self._refused(plugin, old, outside)

    def test_a_case_collision_is_refused(self, plugin, tmp_path):
        old = plugin.head()
        plugin.push_tree([("Run.py", "100644", b"x = 1\n"), ("run.py", "100644", b"x = 2\n")])
        self._refused(plugin, old, tmp_path / "nowhere")

    @pytest.mark.parametrize("name", ["C:x", "C:\\x", "a\\..\\b"])
    def test_a_drive_relative_or_backslash_path_is_refused(self, plugin, tmp_path, name):
        old = plugin.head()
        plugin.push_tree([(name, "100644", b"x = 1\n")])
        self._refused(plugin, old, tmp_path / "nowhere")

    def test_eol_and_ident_conversions_are_what_was_scanned(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        seen: dict = {}
        real = guard.scan_plugin

        def spy(tree, **kw):
            seen["notes"] = (Path(tree) / "notes.txt").read_bytes()
            seen["mod"] = (Path(tree) / "mod.py").read_bytes()
            return real(tree, **kw)

        monkeypatch.setattr(guard, "scan_plugin", spy)
        (plugin.repo / ".gitattributes").write_text("notes.txt eol=crlf\nmod.py ident\n", encoding="utf-8")
        (plugin.repo / "mod.py").write_text("# $Id$\nVALUE = 1\n", encoding="utf-8")
        new = plugin.push("notes.txt", "one\ntwo\n")
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == new
        assert seen["notes"] == b"one\r\ntwo\r\n" == (plugin.target / "notes.txt").read_bytes()
        assert b"$Id: " in seen["mod"] and seen["mod"] == (plugin.target / "mod.py").read_bytes()

    def test_working_tree_encoding_is_scanned_as_written(self, plugin, tmp_path):
        """IBM037: the blob is harmless-looking, the file git writes is ``os.system(...)``."""
        payload = b'import os\nos.system("rm -rf /")\n'
        probe = tmp_path / "probe"
        probe.mkdir()
        _git(probe, "init", "-q")
        (probe / ".gitattributes").write_text("e.py text working-tree-encoding=IBM037\n", encoding="utf-8")
        _git(probe, "add", ".gitattributes")
        blob = _hash(probe, payload.decode("cp037").encode("utf-8"))
        _git(probe, "update-index", "--add", "--cacheinfo", f"100644,{blob},e.py")
        _git(probe, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "probe")
        subprocess.run(["git", "checkout", "--", "e.py"], cwd=probe, capture_output=True)
        if not (probe / "e.py").exists() or (probe / "e.py").read_bytes() != payload:
            pytest.skip("this git/iconv does not convert IBM037")
        old = plugin.head()
        plugin.push_tree([(".gitattributes", "100644", b"evil.py text working-tree-encoding=IBM037\n"),
                          ("evil.py", "100644", payload.decode("cp037").encode("utf-8"))])
        with pytest.raises(SystemExit):
            plugin.pc.cmd_update(plugin.name)
        _refused_and_untouched(plugin, old)

    @pytest.mark.parametrize("tamper", ["autocrlf", "filter"])
    def test_a_conversion_changed_between_scan_and_apply_is_refused(self, plugin, monkeypatch, tamper):
        """Whatever makes the merge write other bytes than the scanned checkout (a line-ending
        setting, a repo-level filter driver) puts the plugin back on its old commit."""
        pc = plugin.pc
        real = pc._judge_scanned_tree

        def judge_then_tamper(*a, **kw):
            real(*a, **kw)
            if tamper == "autocrlf":
                _git(plugin.target, "config", "core.autocrlf", "true")
            else:
                _git(plugin.target, "config", "filter.shout.smudge", "tr a-z A-Z")

        monkeypatch.setattr(pc, "_judge_scanned_tree", judge_then_tamper)
        if tamper == "filter":
            (plugin.repo / ".gitattributes").write_text("notes.txt filter=shout\n", encoding="utf-8")
        old = plugin.head()
        plugin.push("notes.txt", "one\ntwo\n")
        with pytest.raises(SystemExit):
            pc.cmd_update(plugin.name)
        assert plugin.head() == old and _git(plugin.target, "status", "--porcelain") == ""
        assert _loader(plugin.target) == ("load", "1.0.0") and plugin.deps == []


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
        result = plugin.pc.dashboard_update_user_plugin(plugin.name, accept_caution_revision=new)
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

    def test_consent_is_bound_to_the_revision_shown(self, plugin):
        """A force-push between the two clicks: the consent for the first revision does not apply
        the second; the answer asks again, with the second revision and its findings."""
        old = plugin.head()
        first = plugin.push("run.py", CAUTION)
        asked = plugin.pc.dashboard_update_user_plugin(plugin.name)
        assert asked["caution_consent_required"] is True and asked["revision"] == first
        _git(plugin.repo, "reset", "--quiet", "--hard", "HEAD~1")
        second = plugin.push("run2.py", CAUTION.replace("apt install x", "apt install y"))
        assert second != first
        again = plugin.pc.dashboard_update_user_plugin(plugin.name, accept_caution_revision=first)
        assert again["ok"] is False and again["caution_consent_required"] is True and again["revision"] == second
        assert plugin.head() == old and plugin.deps == []
        applied = plugin.pc.dashboard_update_user_plugin(plugin.name, accept_caution_revision=second)
        assert applied["ok"] is True and plugin.head() == second

    def test_a_malformed_consent_applies_nothing(self, plugin):
        old = plugin.head()
        plugin.push("run.py", CAUTION)
        result = plugin.pc.dashboard_update_user_plugin(plugin.name, accept_caution_revision="yes")
        assert result["caution_consent_required"] is True and plugin.head() == old


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


# ── a subdirectory install has no .git: the reclone path ─────────────────────────────────


class TestRecloneUpdate:
    """A subdirectory install is updated by a fresh clone the installer scans before the swap.
    ``force`` there only replaces the directory: a caution verdict needs the same consent."""

    @pytest.fixture
    def sub(self, tmp_path, monkeypatch):
        import hermes_cli.plugins_cmd as pc

        if not pc._resolve_git_executable():
            pytest.skip("git not available")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        repo = tmp_path / "mono"
        (repo / "plugins" / "demo").mkdir(parents=True)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "fixture@example.com")
        _git(repo, "config", "user.name", "Fixture")
        (repo / "plugins/demo/plugin.yaml").write_text(yaml.safe_dump({"name": "demo", "version": "1.0.0"}),
                                                      encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", "first")
        target, _m, _n = pc._install_plugin_core(f"{repo.as_uri()}#plugins/demo", force=False)
        assert not (target / ".git").exists()
        deps: list = []
        monkeypatch.setattr(pc, "_install_python_dependencies", lambda path, *_a, **_k: deps.append(Path(path)))
        monkeypatch.setattr(pc, "_install_python_dependencies_quietly",
                            lambda path, *_a, **_k: deps.append(Path(path)) or [])

        def push(content: str) -> str:
            (repo / "plugins/demo/run.py").write_text(content, encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "run")
            return _git(repo, "rev-parse", "HEAD")

        return pc, target, push, deps

    def test_caution_without_consent_is_refused_with_findings(self, sub):
        pc, target, push, deps = sub
        push(CAUTION)
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is False and result["update_refused"] is True
        assert result["caution_consent_required"] is True and result["scan_findings"]
        assert not (target / "run.py").exists() and deps == []

    def test_caution_with_consent_for_that_revision_is_applied(self, sub):
        pc, target, push, deps = sub
        new = push(CAUTION)
        result = pc.dashboard_update_user_plugin("demo", accept_caution_revision=new)
        assert result["ok"] is True and (target / "run.py").exists() and deps == [target]

    def test_the_cli_without_a_terminal_refuses_caution(self, sub, monkeypatch):
        pc, target, push, deps = sub
        monkeypatch.setattr(pc, "_is_tty", lambda: False)
        push(CAUTION)
        with pytest.raises(SystemExit):
            pc.cmd_update("demo")
        assert not (target / "run.py").exists() and deps == []

    def test_dangerous_is_refused(self, sub):
        pc, target, push, deps = sub
        push(DANGEROUS)
        result = pc.dashboard_update_user_plugin("demo")
        assert result["ok"] is False and result["scan_verdict"] == "dangerous"
        assert not (target / "run.py").exists() and deps == []


# ── review round 5: a forced rewrite before refusing, a rollback that must take, one update at a time ──


class TestRewriteRollbackAndLock:
    def test_a_new_attribute_for_an_unchanged_file_is_accepted(self, plugin):
        """A fast-forward does not rewrite ``tool.ps1``; ``*.ps1 eol=crlf`` arrives later. The
        written tree is forced onto the merged commit once before anything is refused."""
        plugin.push("tool.ps1", "Write-Host one\nWrite-Host two\n")
        plugin.pc.cmd_update(plugin.name)
        (plugin.repo / ".gitattributes").write_text("*.ps1 text eol=crlf\n", encoding="utf-8")
        new = plugin.push("notes.txt", "x\n", version="3.0.0")
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == new
        assert (plugin.target / "tool.ps1").read_bytes() == b"Write-Host one\r\nWrite-Host two\r\n"
        assert _loader(plugin.target) == ("load", "3.0.0")

    def test_info_attributes_of_the_plugin_repo_are_scanned_as_written(self, plugin, monkeypatch):
        import tools.plugin_guard as guard

        seen: dict = {}
        real = guard.scan_plugin
        monkeypatch.setattr(guard, "scan_plugin",
                            lambda tree, **kw: seen.setdefault("n", (Path(tree) / "notes.txt").read_bytes())
                            and real(tree, **kw))
        info = plugin.target / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("notes.txt eol=crlf\n", encoding="utf-8")
        new = plugin.push("notes.txt", "a\nb\n")
        plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == new
        assert seen["n"] == b"a\r\nb\r\n" == (plugin.target / "notes.txt").read_bytes()

    def test_a_dirty_tree_with_a_mismatch_is_rolled_back_with_the_edit_kept(self, plugin, monkeypatch):
        pc = plugin.pc
        real = pc._judge_scanned_tree

        def judge_then_tamper(*a, **kw):
            real(*a, **kw)
            _git(plugin.target, "config", "core.autocrlf", "true")

        monkeypatch.setattr(pc, "_judge_scanned_tree", judge_then_tamper)
        edited = (plugin.target / "__init__.py").read_text(encoding="utf-8") + "# a local tweak\n"
        (plugin.target / "__init__.py").write_text(edited, encoding="utf-8")
        old = plugin.head()
        plugin.push("notes.txt", "one\ntwo\n")
        with pytest.raises(SystemExit):
            pc.cmd_update(plugin.name)
        assert plugin.head() == old
        assert "# a local tweak" in (plugin.target / "__init__.py").read_text(encoding="utf-8")
        assert not (plugin.target / "notes.txt").exists() and plugin.deps == []

    def test_a_rollback_blocked_by_index_lock_deactivates_the_plugin(self, plugin, monkeypatch):
        """The written tree differs, and ``reset --hard`` cannot run (a held ``index.lock``): the
        plugin is deactivated under its manifest keys, the loader refuses it, and the error says so."""
        pc = plugin.pc
        lock = plugin.target / ".git" / "index.lock"

        def differs_and_lock(*_a, **_k):
            lock.write_text("", encoding="utf-8")
            return False

        monkeypatch.setattr(pc, "_same_tracked_files", differs_and_lock)
        new = plugin.push("notes.txt", "x\n")
        try:
            with pytest.raises(pc.PluginUpdateRollbackFailed) as exc:
                pc._git_update_plugin_dir(plugin.target, name=plugin.name, accept_caution=lambda *_a: False)
        finally:
            lock.unlink(missing_ok=True)
        assert exc.value.deactivated is True and exc.value.head == new
        assert "deactivated" in str(exc.value) and new[:8] in str(exc.value)
        action, _version = _loader(plugin.target)
        assert action not in ("load", "load_now")

    def test_a_rollback_that_times_out_fails_closed(self, plugin, monkeypatch):
        pc = plugin.pc
        real_run = pc._run_plugin_git

        def run(git_exe, target, *args, **kwargs):
            if args[:2] == ("reset", "--hard") and kwargs.get("timeout") is None and args[-1] != "HEAD":
                if getattr(run, "rewritten", False):
                    raise subprocess.TimeoutExpired(args, 60)
                run.rewritten = True
            return real_run(git_exe, target, *args, **kwargs)

        monkeypatch.setattr(pc, "_run_plugin_git", run)
        monkeypatch.setattr(pc, "_same_tracked_files", lambda *_a, **_k: False)
        plugin.push("notes.txt", "x\n")
        with pytest.raises(pc.PluginUpdateRollbackFailed) as exc:
            pc._git_update_plugin_dir(plugin.target, name=plugin.name, accept_caution=lambda *_a: False)
        assert exc.value.deactivated is True
        assert _loader(plugin.target)[0] not in ("load", "load_now")

    def test_a_concurrent_update_is_refused_by_the_lock(self, plugin):
        old = plugin.head()
        plugin.push("notes.txt", "x\n")
        with plugin.pc._plugin_update_lock(plugin.target):
            result = plugin.pc.dashboard_update_user_plugin(plugin.name)
            assert result["ok"] is False and "Another update" in result["error"]
            with pytest.raises(SystemExit):
                plugin.pc.cmd_update(plugin.name)
        assert plugin.head() == old
        plugin.pc.cmd_update(plugin.name)              # released: the next update runs
        assert plugin.head() != old


def test_install_refuses_the_names_an_update_refuses(tmp_path, monkeypatch):
    import hermes_cli.plugins_cmd as pc

    if not pc._resolve_git_executable():
        pytest.skip("git not available")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    repo = tmp_path / "colon"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "plugin.yaml").write_text(yaml.safe_dump({"name": "colon", "version": "1.0.0"}), encoding="utf-8")
    _git(repo, "add", "plugin.yaml")
    blob = _hash(repo, b"x = 1\n")
    _git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},a:b.py")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "colon")
    with pytest.raises(pc.PluginOperationError, match="Refusing to install"):
        pc._install_plugin_core(repo.as_uri(), force=False)
    assert not (pc._plugins_dir() / "colon").exists()


def test_git_redirection_variables_are_not_inherited():
    from hermes_cli._subprocess_compat import noninteractive_git_env

    env = noninteractive_git_env({"GIT_DIR": "/x", "GIT_WORK_TREE": "/y", "GIT_INDEX_FILE": "/z",
                                  "GIT_OBJECT_DIRECTORY": "/o", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/a",
                                  "PATH": "/usr/bin"})
    assert not {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES"} & set(env)
