"""``client.capabilities {markup}`` (plan rich-answers T1): which Hermie blocks a connection draws.

Pinned here: only the names this gateway has a guide for are kept (``chart``, ``cards``, ``alerts``), at most
16 names of at most 32 characters ``[a-z][a-z-]*``; anything malformed counts as none and never fails the call
(the other keys' answers stay); every call replaces the last one and a call without the key clears it; the
result always carries ``markup`` (sorted, ``[]`` when none) so a client knows it may send the key; a
disconnect forgets it; it is independent of ``server_requests``; an agent's connection cannot send it.
"""

from __future__ import annotations

import pytest

from tests.tui_gateway.test_confirm_request import _as, _Peer, server  # noqa: F401 - fixtures are used by name


def _caps(server, peer, **params):
    return _as(peer, server.handle_request, {"id": 1, "method": "client.capabilities", "params": params})


@pytest.fixture(autouse=True)
def _fresh():
    from tui_gateway import client_markup
    with client_markup._lock:
        client_markup._accepted.clear()
    yield
    with client_markup._lock:
        client_markup._accepted.clear()


def test_the_result_always_carries_the_key_even_when_it_was_not_sent(server):
    from tui_gateway.contracts import registry
    app = _Peer("app")
    result = _caps(server, app, server_requests=True)["result"]
    assert result["markup"] == []
    registry.METHODS["client.capabilities"].result.model_validate(result)


def test_accepts_known_names_drops_unknown_ones_and_echoes_them_sorted(server):
    from tui_gateway import client_markup
    app = _Peer("app")
    result = _caps(server, app, server_requests=True, markup=["cards", "alerts", "chart", "timeline", "facts"])
    assert result["result"]["markup"] == ["alerts", "cards", "chart"]
    assert client_markup.accepted(app) == frozenset({"alerts", "cards", "chart"})


def test_independent_of_server_requests(server):
    from tui_gateway import client_markup
    viewer = _Peer("viewer")
    assert _caps(server, viewer, markup=["chart"])["result"]["markup"] == ["chart"]
    assert client_markup.accepted(viewer) == frozenset({"chart"})


def test_each_call_replaces_the_last_and_a_call_without_the_key_clears_it(server):
    from tui_gateway import client_markup
    app = _Peer("app")
    _caps(server, app, server_requests=True, markup=["chart", "cards"])
    assert _caps(server, app, server_requests=True, markup=["alerts"])["result"]["markup"] == ["alerts"]
    assert client_markup.accepted(app) == frozenset({"alerts"})
    assert _caps(server, app, server_requests=True)["result"]["markup"] == []
    assert client_markup.accepted(app) == frozenset()


@pytest.mark.parametrize("odd", [
    "cards", {"cards": True}, ["cards"] * 17, ["car ds"], ["Cards"], ["cards", 1], ["cards", None],
    ["x" * 33], [""], ["-cards"], True, 3,
], ids=repr)
def test_a_malformed_value_is_none_and_never_fails_the_call(server, odd):
    from tui_gateway import client_markup
    app = _Peer("app")
    _caps(server, app, server_requests=True, confirm=["plain"], markup=["chart"])
    response = _caps(server, app, server_requests=True, confirm=["plain"], markup=odd)
    assert "error" not in response, response
    assert response["result"]["markup"] == [] and response["result"]["confirm"] == ["plain"]
    assert client_markup.accepted(app) == frozenset()


def test_sixteen_well_formed_names_are_still_read():
    from tui_gateway import client_markup
    names = ["cards", *(f"later-{chr(97 + i)}" for i in range(15))]
    assert client_markup.accepted_names(names) == frozenset({"cards"})
    assert client_markup.accepted_names([*names, "chart"]) == frozenset()  # 17


def test_a_disconnect_forgets_it(server):
    from tui_gateway import client_markup
    app, other = _Peer("app"), _Peer("other")
    _caps(server, app, markup=["chart"])
    _caps(server, other, markup=["cards"])
    server.register_live_transport(app)
    server.unregister_live_transport(app)
    assert client_markup.accepted(app) == frozenset()
    assert client_markup.accepted(other) == frozenset({"cards"})


def test_per_connection_never_shared(server):
    from tui_gateway import client_markup
    phone, laptop = _Peer("phone"), _Peer("laptop")
    _caps(server, phone, markup=["cards"])
    assert client_markup.accepted(laptop) == frozenset()
    assert client_markup.accepted(None) == frozenset()


def test_an_agents_connection_cannot_advertise_it():
    """Decision (T1): an agent connected through MCP reads a reply as text, where a block is raw JSON; its
    allowlist (``agent_guard.AGENT_PARAMS``) keeps ``server_requests`` only, so ``markup`` is refused (4033)."""
    from tui_gateway import agent_guard
    from tui_gateway.transport import bind_transport, reset_transport

    agent = _Peer("agent", "oidc:user-a")
    agent.auth_identity["agent"] = {"kind": "mcp", "client": "Marker agent", "grant": "grant-g1"}
    token = bind_transport(agent)
    try:
        refused = agent_guard.dispatch_refusal(1, "client.capabilities", {"server_requests": True, "markup": ["cards"]})
        assert refused["error"]["code"] == 4033
        assert agent_guard.dispatch_refusal(1, "client.capabilities", {"server_requests": True}) is None
    finally:
        reset_transport(token)


def test_wire_form_is_sorted_and_rechecked():
    from tui_gateway import client_markup
    assert client_markup.wire({"chart", "alerts"}) == ["alerts", "chart"]
    assert client_markup.wire(["chart", "bogus"]) == ["chart"]
    assert client_markup.accepted_names(("cards",)) == frozenset({"cards"})
