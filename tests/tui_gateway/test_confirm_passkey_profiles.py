"""``confirm`` at level ``passkey`` for a turn that runs in a profile the gateway multiplexes.

The owner's passkey belongs to the dashboard sign-in, which is the gateway's: one ``confirm.passkey``
section, one ``dashboard_auth/passkeys.db`` (one gateway id) per gateway, read from the gateway's own home.
A turn in profile ``techsupport`` runs with that profile's home as the context-local ``HERMES_HOME``
override; before the fix the level read the profile's config (no base URL) and opened the profile's own
store (another gateway id, no credentials), so every passkey confirmation there was ``unavailable
(no_base_url)``. Pinned here: the request uses the gateway's settings and store from a profile turn, the
challenge names the gateway's id and base URL, the bound user is still the turn's submitter (another
signed-in person cannot answer it), a profile's own ``confirm.passkey`` section cannot widen the level,
and nothing changes outside a profile.
"""

from __future__ import annotations

import threading

import pytest
import yaml

from hermes_cli.dashboard_auth.passkeys.challenge import b64u
from hermes_cli.dashboard_auth.passkeys.store import PasskeyStore
from tests.tui_gateway.test_confirm_passkey import (
    ALICE, BASE, BOB, NATIVE_RP, TEXT, Passkeys, _advertise_passkey, _answer_rpc, _frame, _turn, native)
from tests.tui_gateway.test_confirm_request import _Peer, _advertise, _as, _session, server  # noqa: F401

GATEWAY_CONFIG = {"confirm": {"passkey": {"enabled": True, "base_urls": [BASE]}}}


@pytest.fixture
def homes(tmp_path, monkeypatch, server):
    """A gateway home with the passkey level configured and a store, and a profile home under it that has
    a stale ``confirm.passkey`` of its own (enabled, no base URL) and no store."""
    from hermes_constants import reset_hermes_home_key_cache
    from tui_gateway import confirm_passkey
    gateway = tmp_path / ".hermes"
    profile = gateway / "profiles" / "techsupport"
    profile.mkdir(parents=True)
    (gateway / "config.yaml").write_text(yaml.safe_dump(GATEWAY_CONFIG), encoding="utf-8")
    (profile / "config.yaml").write_text(yaml.safe_dump({"confirm": {"passkey": {"enabled": True}}}),
                                         encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(gateway))
    reset_hermes_home_key_cache()
    confirm_passkey.reset_for_tests()
    store = PasskeyStore(gateway / "dashboard_auth" / "passkeys.db")
    yield gateway, profile, Passkeys(store, GATEWAY_CONFIG)
    confirm_passkey.reset_for_tests()


def _in_home(home, fn, *args, **kwargs):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    token = set_hermes_home_override(str(home))
    try:
        return fn(*args, **kwargs)
    finally:
        reset_hermes_home_override(token)


def _ask(server, sid, home, submitter=(ALICE, "Alice")):
    """``confirm.request`` on a tool thread of a turn submitted by *submitter*, scoped to *home*."""
    from tui_gateway import confirm
    params = confirm.build_params(level="passkey", **TEXT)
    box: dict = {}

    def run():
        token = _turn(server, submitter)
        try:
            box["r"] = _in_home(home, confirm.request, sid, params, timeout=5) if home else \
                confirm.request(sid, params, timeout=5)
        finally:
            server._turn_auth_user.reset(token)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def _phone_in_session(server, passkeys):
    auth = native()
    passkeys.enrol(auth)
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, creator=ALICE)
    assert _advertise_passkey(server, phone)["result"]["confirm"] == ["passkey", "plain"]
    return phone, auth


def test_a_profile_turn_confirms_with_the_gateways_settings_and_store(server, homes):
    _gateway, profile, passkeys = homes
    phone, auth = _phone_in_session(server, passkeys)
    thread, box = _ask(server, "s1", profile)
    frame = _frame(server, phone)
    passkey = frame["params"]["passkey"]
    assert passkey["gateway_id"] == b64u(passkeys.store.gateway_id) and passkey["base_url"] == BASE
    assert passkey["user"]["id"] == ALICE
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].as_dict() == {"outcome": "confirmed", "method": "passkey", "verified": True}
    assert [r.request_id for r in passkeys.store.receipts(user_id=ALICE)] == [frame["id"]]
    # No store was made in the profile.
    assert not (profile / "dashboard_auth").exists()


def test_the_capability_inside_a_profile_scope_names_the_gateway(server, homes):
    _gateway, profile, passkeys = homes
    phone = _Peer("phone", ALICE)
    cap = _in_home(profile, _advertise, server, phone)["result"]["confirm_passkey"]
    assert cap["enabled"] is True and cap["gateway_id"] == b64u(passkeys.store.gateway_id)


def test_a_profile_turn_is_still_bound_to_its_submitter(server, homes):
    _gateway, profile, passkeys = homes
    phone, auth = _phone_in_session(server, passkeys)
    bob_phone = _Peer("bob-phone", BOB)
    bob = native()
    passkeys.enrol(bob, user=BOB)
    assert _advertise_passkey(server, bob_phone)["result"]["confirm"] == ["passkey", "plain"]
    thread, box = _ask(server, "s1", profile)
    frame = _frame(server, phone)
    assert bob_phone.requests() == []
    # Bob signs the same request with his own credential: refused, the request stays Alice's.
    refused = _answer_rpc(server, bob_phone, frame["id"], passkeys.answer(bob, frame, user_id=BOB,
                                                                           with_user_handle=False))
    assert "error" in refused
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].verified is True


def test_a_profile_section_cannot_change_the_level(server, homes):
    """The profile lists another base URL and switches the level off: neither counts, the gateway's does."""
    _gateway, profile, passkeys = homes
    (profile / "config.yaml").write_text(yaml.safe_dump({"confirm": {"passkey": {
        "enabled": False, "base_urls": ["https://evil.example"]}}}), encoding="utf-8")
    phone, auth = _phone_in_session(server, passkeys)
    thread, box = _ask(server, "s1", profile)
    frame = _frame(server, phone)
    assert frame["params"]["passkey"]["base_url"] == BASE
    refused = _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame, base_url="https://evil.example"))
    assert refused["error"]["data"] == {"reason": "base_url_not_accepted"}
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame), n=10)["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].verified is True


def test_without_a_profile_nothing_changes(server, homes):
    _gateway, _profile, passkeys = homes
    phone, auth = _phone_in_session(server, passkeys)
    thread, box = _ask(server, "s1", None)
    frame = _frame(server, phone)
    assert frame["params"]["passkey"]["gateway_id"] == b64u(passkeys.store.gateway_id)
    assert _answer_rpc(server, phone, frame["id"], passkeys.answer(auth, frame))["result"] == {"status": "ok"}
    thread.join(5)
    assert box["r"].verified is True


def test_the_plain_level_in_a_profile_turn_is_unaffected(server, homes):
    from tui_gateway import confirm
    _gateway, profile, _passkeys = homes
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, creator=ALICE)
    _advertise(server, phone, confirm=["plain"])
    params = confirm.build_params(level="plain", summary="Pay 10 EUR to the plumber.")
    box: dict = {}
    thread = threading.Thread(target=lambda: box.setdefault("r", _in_home(
        profile, confirm.request, "s1", params, timeout=5)), daemon=True)
    thread.start()
    frame = _frame(server, phone)
    _answer_rpc(server, phone, frame["id"], {"decision": "confirmed", "method": "tap"})
    thread.join(5)
    assert box["r"].outcome == "confirmed"
