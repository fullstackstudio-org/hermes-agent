"""Two ``profiles.configure`` calls on one profile must not drop each other's changes.

Configure runs on the RPC thread pool, so two saves of the same bot editor (Desktop and the
phone, or two quick saves in a row) can run at once. Each section is a read-modify-write of a
whole file: ``disabled_skills`` / ``enabled_toolsets`` / ``enabled_mcp_servers`` rewrite
``config.yaml``, ``description`` and ``ui_meta`` rewrite ``profile.yaml``. Without one lock across
the read and the write, both calls read the old file and the second write puts back what the
first one changed.

The tests force the bad interleaving instead of hoping for it: a barrier holds every thread
right after its first read until the other thread has read too. When the lock is held across
the read-modify-write, the second thread cannot read until the first has written, the barrier
times out, and both changes land.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import yaml

import tui_gateway.server as server

_BARRIER_TIMEOUT = 1.0


@pytest.fixture
def profile_dir(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "hermes_home"
    path = root / "profiles" / "bot"
    path.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(root))
    return path


class _HoldAfterFirstRead:
    """Wraps readers so each thread parks once, right after its first read through ANY of them,
    until the other thread has read too (or the barrier times out)."""

    def __init__(self):
        self._barrier = threading.Barrier(2)
        self._seen = threading.local()

    def wrap(self, read):
        def wrapped(*args, **kwargs):
            result = read(*args, **kwargs)
            if not getattr(self._seen, "done", False):
                self._seen.done = True
                try:
                    self._barrier.wait(timeout=_BARRIER_TIMEOUT)
                except threading.BrokenBarrierError:
                    pass
            return result

        return wrapped


def _configure_concurrently(*param_sets: dict) -> list[dict]:
    results: list[dict] = [{} for _ in param_sets]

    def run(i, params):
        results[i] = server._methods["profiles.configure"](i, {"name": "bot", **params})

    threads = [threading.Thread(target=run, args=(i, p)) for i, p in enumerate(param_sets)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "configure deadlocked"
    for resp in results:
        assert resp.get("result", {}).get("ok") is True, resp
    return results


def test_concurrent_config_sections_both_persist(profile_dir, monkeypatch):
    import hermes_cli.config as config_mod

    (profile_dir / "config.yaml").write_text(yaml.safe_dump({"skills": {"disabled": []}}), encoding="utf-8")
    monkeypatch.setattr(config_mod, "load_config", _HoldAfterFirstRead().wrap(config_mod.load_config))

    _configure_concurrently({"disabled_skills": ["harmless-example-skill"]}, {"enabled_toolsets": ["web"]})

    on_disk = yaml.safe_load((profile_dir / "config.yaml").read_text(encoding="utf-8"))
    assert on_disk["skills"]["disabled"] == ["harmless-example-skill"]
    assert on_disk["platform_toolsets"]["cli"] == ["web"]


def test_concurrent_description_and_ui_meta_both_persist(profile_dir, monkeypatch):
    import hermes_cli.profiles as profiles_mod

    (profile_dir / "profile.yaml").write_text(yaml.safe_dump({"description": "before"}), encoding="utf-8")
    hold = _HoldAfterFirstRead()
    monkeypatch.setattr(server, "_read_profile_yaml", hold.wrap(server._read_profile_yaml))
    monkeypatch.setattr(profiles_mod, "_load_yaml_dict", hold.wrap(profiles_mod._load_yaml_dict))

    _configure_concurrently({"description": "after"}, {"ui_meta": {"accent": "teal"}})

    on_disk = yaml.safe_load((profile_dir / "profile.yaml").read_text(encoding="utf-8"))
    assert on_disk["description"] == "after"
    assert on_disk["ui_meta"] == {"accent": "teal"}
