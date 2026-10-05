"""Revoking a standing or a session approval (``tools.approval.revoke_permanent`` / ``revoke_session``).

A revoke must take effect at once and for good: the entry leaves ``command_allowlist``, the governing
in-memory set and this process's baseline. The baseline is what ``save_permanent_allowlist`` subtracts to
find "what this process approved itself"; an entry left in it would be written back by the next ``always``.
"""

from __future__ import annotations

import threading
import time

import pytest

import tools.approval as approval
from tools.approval_detection import _approval_key_aliases

CANONICAL = "script execution via heredoc"
LEGACY = next(alias for alias in _approval_key_aliases(CANONICAL) if alias != CANONICAL)


@pytest.fixture
def fake_config(monkeypatch):
    store = {"command_allowlist": []}
    monkeypatch.setattr("hermes_cli.config.load_config",
                        lambda: {"command_allowlist": list(store["command_allowlist"])}, raising=False)
    monkeypatch.setattr("hermes_cli.config.save_config",
                        lambda config: store.__setitem__("command_allowlist", list(config["command_allowlist"])),
                        raising=False)
    monkeypatch.setattr("hermes_cli.config.load_config_readonly",
                        lambda: {"command_allowlist": list(store["command_allowlist"])}, raising=False)
    saved = (set(approval._permanent_approved), dict(approval._permanent_baseline_by_home),
             {k: set(v) for k, v in approval._session_approved.items()})
    approval._permanent_approved.clear()
    approval._permanent_baseline_by_home.clear()
    approval._session_approved.clear()
    try:
        yield store
    finally:
        approval._permanent_approved.clear()
        approval._permanent_approved.update(saved[0])
        approval._permanent_baseline_by_home.clear()
        approval._permanent_baseline_by_home.update(saved[1])
        approval._session_approved.clear()
        approval._session_approved.update(saved[2])


def _start_with(store, entries):
    store["command_allowlist"] = list(entries)
    approval.load_permanent_allowlist()


def test_revoke_removes_the_entry_and_its_alias_everywhere_and_a_later_save_keeps_it_out(fake_config):
    _start_with(fake_config, [CANONICAL, LEGACY, "podman *"])

    assert approval.revoke_permanent(LEGACY) == 2

    assert fake_config["command_allowlist"] == ["podman *"]
    assert not {CANONICAL, LEGACY} & approval._permanent_approved
    assert not {CANONICAL, LEGACY} & approval._permanent_baseline_by_home[""]
    assert not approval.is_approved("other-session", CANONICAL)

    # The next "always" answer writes the file again; the revoked entry must not come back.
    approval._persist_choice("s1", "always", [("make deploy", None, False)])
    assert sorted(fake_config["command_allowlist"]) == ["make deploy", "podman *"]

    # Approving it again later is a new grant of this process, so it is written (the baseline forgot it).
    approval._persist_choice("s1", "always", [(CANONICAL, None, False)])
    assert sorted(fake_config["command_allowlist"]) == sorted([CANONICAL, "make deploy", "podman *"])


def test_an_entry_held_only_in_memory_is_revoked_without_rewriting_the_file(fake_config, monkeypatch):
    _start_with(fake_config, ["podman *"])
    approval.approve_permanent("make deploy")             # approved here, write not done (yet)
    writes = []
    monkeypatch.setattr("hermes_cli.config.save_config", writes.append, raising=False)

    assert approval.revoke_permanent("make deploy") == 1
    assert approval.revoke_permanent("make deploy") == 0  # idempotent
    assert writes == [] and "make deploy" not in approval._permanent_approved


def test_a_revoke_during_an_always_answer_is_not_written_back(fake_config, monkeypatch):
    """``_persist_choice`` snapshots the set, then saves it. A revoke landing in between used to be undone by
    that save (the snapshot still held the key, the baseline no longer did)."""
    _start_with(fake_config, ["podman *"])
    real_save = approval.save_permanent_allowlist
    revoker = threading.Thread(target=approval.revoke_permanent, args=("podman *",))

    def save_while_revoking(snapshot):
        revoker.start()
        time.sleep(0.2)                                   # unserialised, the revoke would finish here
        real_save(snapshot)

    monkeypatch.setattr(approval, "save_permanent_allowlist", save_while_revoking)
    approval._persist_choice("s1", "always", [("make deploy", None, False)])
    revoker.join(timeout=5)

    assert fake_config["command_allowlist"] == ["make deploy"]
    assert "podman *" not in approval._permanent_approved


def test_revoke_session_by_key_and_all_and_transfer_on_rotation(fake_config):
    approval.approve_session("old", LEGACY)
    approval.approve_session("old", "tirith:homograph_url")
    approval.approve_session("old", "execute_code")

    approval.transfer_session_grants("old", "new")
    assert approval.session_grants("old") == []
    assert approval.session_grants("new") == sorted([LEGACY, "tirith:homograph_url", "execute_code"])

    assert approval.revoke_session("new", CANONICAL) == 1  # an alias names the same grant
    assert not approval.is_approved("new", CANONICAL)
    assert approval.revoke_session("new", None) == 2
    assert approval.session_grants("new") == [] and "new" not in approval._session_approved
