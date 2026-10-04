"""The app's MCP routes (``hermes_cli/dashboard_auth/mcp/api_routes.py``) on the real gated dashboard app: a
stub sign-in provider for two people, the real store, the real consent and token flow to make grants, and a
fake WebSocket connection to see ``mcp.changed``.

Pinned here, against ``contract/gateway/mcp.md``: the page's shape (every key, ``config_json`` a JSON string,
times in whole seconds, nullable fields ``null``, the label the ``whoami`` tool uses too); only the caller's
live grants, newest first, never a token or the person; 404 for GET and 405 for the rest while the endpoint is
off, exactly as for an unknown path; nothing public; 403 ``no_identity``; the Origin rule for a cookie write
(bearer exempt); the 16 KiB JSON-object body; one 404 ``not_found`` for every grant that is not the caller's
live one (so there is no oracle); that a revoke ends the tokens, is audited and is announced to that person's
live connections only; and ``mcp.changed`` ``granted`` at the token exchange.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from hermes_cli import web_server
from hermes_cli.dashboard_auth.mcp import api_routes, mount
from hermes_cli.dashboard_auth.mcp import store as store_mod
from hermes_cli.dashboard_auth.mcp.settings import MCPSettings, server_label, slug
from hermes_cli.dashboard_auth.mcp.store import StoreError
from tests.hermes_cli.dashboard_auth.mcp.test_routes import (  # noqa: F401 - the fixture is used by name
    ALICE, BASE, BOB, ISSUER, audit_lines, cookie, idp_bearer, make_gateway)

ALICE_ID, BOB_ID = f"stub:{ALICE}", f"stub:{BOB}"  # the key the gateway files a person's grants and connections under

PAGE = api_routes.PREFIX
OTHER_ORIGIN = "https://other.gw.example.invalid"
GRANT_KEYS = {"id", "client_name", "client_id", "scopes", "created_at", "created_ip", "created_user_agent",
              "last_used_at", "last_used_ip", "expires_at"}
NOT_FOUND = {"error": "not_found", "detail": "No such grant."}


def revoke_path(grant_id: str) -> str:
    return f"{PAGE}/grants/{grant_id}/revoke"


class FakeTransport:
    """A live WebSocket connection as ``tui_gateway.server`` tracks it: the minted login and the frames."""

    def __init__(self, user: str | None):
        provider, _, login = (user or "").partition(":")
        self.auth_identity = None if user is None else {"provider": provider, "user_id": login}
        self.frames: list[dict] = []

    def write(self, frame: dict) -> bool:
        self.frames.append(frame)
        return True

    def changes(self) -> list[dict]:
        return [f["params"]["payload"] for f in self.frames if f["params"]["type"] == "mcp.changed"]


@pytest.fixture
def transports():
    from tui_gateway import server

    made: list[FakeTransport] = []

    def connect(user: str | None) -> FakeTransport:
        transport = FakeTransport(user)
        server.register_live_transport(transport)
        made.append(transport)
        return transport

    yield connect
    for transport in made:
        server.unregister_live_transport(transport)


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock(gw):
    clock = Clock()
    gw.store._clock = clock
    return clock


@pytest.fixture
def gw(make_gateway):
    return make_gateway()


def get_page(gw, user: str = ALICE):
    return gw.client.get(PAGE, headers=idp_bearer(user))


def grants_of(gw, user: str = ALICE) -> list[dict]:
    r = get_page(gw, user)
    assert r.status_code == 200, r.text
    return r.json()["grants"]


def revoke(gw, grant_id: str, user: str = ALICE, *, headers: dict | None = None, **kw):
    return gw.client.post(revoke_path(grant_id), headers=headers if headers is not None else idp_bearer(user),
                          **({"json": {}} | kw))


# ── the page ─────────────────────────────────────────────────────────────────────────────────────


def test_the_page_names_the_endpoint_the_command_and_the_config(gw):
    r = get_page(gw)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == {"v", "enabled", "endpoint_url", "issuer", "label", "claude_command", "config_json",
                         "instructions", "grants"}
    assert (body["v"], body["enabled"], body["grants"]) == (1, True, [])
    assert body["endpoint_url"] == body["issuer"] == ISSUER
    assert body["label"] == "hermie-gw-example-invalid"
    assert body["claude_command"] == f"claude mcp add --transport http hermie-gw-example-invalid {ISSUER}"
    assert isinstance(body["config_json"], str)
    assert json.loads(body["config_json"]) == {"mcpServers": {"hermie-gw-example-invalid":
                                                              {"type": "http", "url": ISSUER}}}
    assert body["config_json"] == json.dumps(json.loads(body["config_json"]), indent=2)  # pretty-printed text
    assert "Claude Code" in body["instructions"] and "90 days" in body["instructions"]
    assert "5 clients" in body["instructions"] and "example.invalid" not in body["instructions"]


def test_the_label_is_the_slug_of_the_operators_label_and_whoami_uses_the_same(make_gateway, monkeypatch):
    from tui_gateway.mcp_bridge import tools

    seen: list[str] = []
    real = tools.Bridge

    def capture(**kwargs):
        seen.append(kwargs["label"])
        return real(**kwargs)

    monkeypatch.setattr(tools, "Bridge", capture)
    gw = make_gateway({"label": "  Robin's Home Gateway! "})
    body = get_page(gw).json()
    assert body["label"] == "robin-s-home-gateway" and seen and set(seen) == {"robin-s-home-gateway"}
    assert body["claude_command"].startswith("claude mcp add --transport http robin-s-home-gateway ")
    assert list(json.loads(body["config_json"])["mcpServers"]) == ["robin-s-home-gateway"]
    seen.clear()
    gw = make_gateway()
    assert get_page(gw).json()["label"] == seen[-1] == "hermie-gw-example-invalid"


@pytest.mark.parametrize("text, expected", [
    ("My Gateway", "my-gateway"), ("  --Hermie_01--  ", "hermie-01"), ("Zürich Büro", "zurich-buro"),
    ("a" * 80, "a" * 48), ("-" * 5, ""), ("", ""), (None, ""), (12, "")])
def test_slug(text, expected):
    assert slug(text) == expected


def test_server_label_falls_back_to_the_host_and_then_to_hermie():
    assert server_label(MCPSettings(), "gw.example.invalid") == "hermie-gw-example-invalid"
    assert server_label(MCPSettings(label="Home"), "gw.example.invalid") == "home"
    assert server_label(MCPSettings(label="!!!"), "gw.example.invalid") == "hermie-gw-example-invalid"
    assert server_label(MCPSettings(), "") == "hermie"
    assert server_label(MCPSettings(), "::1") == "hermie-1"


def test_the_instructions_follow_the_settings(make_gateway):
    gw = make_gateway({"grant_max_age": 86400, "max_grants_per_user": 1})
    text = get_page(gw).json()["instructions"]
    assert "lasts 1 day," in text and "up to 1 clients" in text


# ── the grants ───────────────────────────────────────────────────────────────────────────────────


def test_only_the_callers_live_grants_newest_first_without_secrets(gw, clock):
    first = gw.connect(ALICE)
    clock.advance(30)
    bobs = gw.connect(BOB)
    clock.advance(30)
    second = gw.connect(ALICE)
    stored = {g.id: g for g in gw.store.grants(include_inactive=True)}

    r = get_page(gw)
    ids = [g["id"] for g in r.json()["grants"]]
    assert len(ids) == 2 and ids == sorted(ids, key=lambda i: -stored[i].created_at)
    assert [stored[i].client_id for i in ids] == [second.client_id, first.client_id]
    [bob] = grants_of(gw, BOB)
    assert stored[bob["id"]].client_id == bobs.client_id

    newest = r.json()["grants"][0]
    assert set(newest) == GRANT_KEYS
    assert newest["client_name"] == "Claude Code" and newest["client_id"] == second.client_id
    assert newest["scopes"] == ["bots:read", "bots:prompt", "requests:read", "requests:clarify"]
    assert all(isinstance(newest[k], int) for k in ("created_at", "expires_at"))
    assert newest["expires_at"] == newest["created_at"] + 90 * 86400
    assert isinstance(newest["created_ip"], str) and newest["last_used_at"] is None and newest["last_used_ip"] is None
    text = r.text
    for secret in (first.tokens["access_token"], first.tokens["refresh_token"], second.tokens["access_token"],
                   second.client_secret or "\0"):
        assert secret not in text
    for private in ("alice", "Alice", "stub:", "user_id", "revoked", "resource"):
        assert private not in text


def test_the_page_carries_what_the_gateway_recorded_about_a_use(gw, clock):
    flow = gw.connect(ALICE)
    clock.advance(120)
    gw.call(flow.tokens["access_token"])  # a token check records the use
    [grant] = grants_of(gw)
    assert isinstance(grant["last_used_at"], int) and grant["last_used_at"] >= grant["created_at"] + 120
    assert isinstance(grant["last_used_ip"], str) and grant["last_used_ip"]


def test_an_unrecorded_address_or_user_agent_is_null_not_empty(gw):
    from hermes_cli.dashboard_auth.mcp.store import Grant

    gw.connect(ALICE)
    [base] = gw.store.grants()
    blank = Grant(**{**base.__dict__, "created_ip": "", "created_user_agent": "", "last_used_ip": "",
                     "last_used_at": None})
    view = api_routes.grant_view(blank)
    assert (view["created_ip"], view["created_user_agent"], view["last_used_ip"], view["last_used_at"]) == \
        (None, None, None, None)
    long_agent = Grant(**{**base.__dict__, "created_user_agent": "x" * 5000})
    assert len(api_routes.grant_view(long_agent)["created_user_agent"]) == api_routes.USER_AGENT_LIMIT


def test_revoked_and_ended_grants_are_not_listed(gw, clock):
    flow = gw.connect(ALICE)
    gw.connect(ALICE)
    [one, other] = grants_of(gw)
    assert revoke(gw, one["id"]).status_code == 200
    assert [g["id"] for g in grants_of(gw)] == [other["id"]]
    clock.advance(91 * 86400)  # past the grant's absolute lifetime
    assert grants_of(gw) == []
    assert flow.client_id  # the flow existed; nothing of it remains on the page


def test_a_store_that_cannot_be_read_is_503_not_a_500(gw, monkeypatch):
    def broken(_user_id):
        raise StoreError("mcp store: disk I/O error")

    monkeypatch.setattr(gw.store, "grants_for", broken)
    r = get_page(gw)
    assert r.status_code == 503 and r.json()["error"] == "unavailable"


# ── availability ─────────────────────────────────────────────────────────────────────────────────


def answer(gw, method: str, path: str, headers: dict):
    r = gw.client.request(method, path, headers=headers, json={} if method == "POST" else None)
    return r.status_code, r.json(), r.headers.get("allow")


@pytest.mark.parametrize("how", ["disabled", "ungated"])
def test_every_route_answers_like_an_unknown_path_while_the_endpoint_is_off(make_gateway, how):
    gw = make_gateway({"enabled": False}) if how == "disabled" else make_gateway(gated=False)
    assert mount.current() is None
    headers = idp_bearer(ALICE) if how == "disabled" else {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}
    unknown = {"GET": answer(gw, "GET", "/api/auth/nothing-here", headers),
               "POST": answer(gw, "POST", "/api/auth/nothing-here", headers)}
    assert unknown["GET"][0] == 404 and unknown["POST"][0] == 405  # what a gateway without the feature says

    page = answer(gw, "GET", PAGE, headers)
    assert page == (404, {"detail": f"No such API endpoint: {PAGE}"}, None)
    path = revoke_path("anything")
    assert answer(gw, "GET", path, headers) == (404, {"detail": f"No such API endpoint: {path}"}, None)
    assert answer(gw, "POST", PAGE, headers)[::2] == (405, "GET") == unknown["POST"][::2]
    assert answer(gw, "POST", path, headers)[::2] == (405, "GET")
    for method in ("PUT", "PATCH", "DELETE"):
        r = gw.client.request(method, path, headers=headers)
        assert (r.status_code, r.headers.get("allow")) == (405, "GET"), method


def test_nothing_is_public(gw):
    for method, path in (("GET", PAGE), ("POST", revoke_path("abc"))):
        r = gw.client.request(method, path, json={} if method == "POST" else None)
        assert r.status_code == 401, (method, path)


def test_a_connection_without_a_signed_in_person_has_none(gw):
    web_server.app.state.auth_required = False  # loopback / session-token mode: the token names nobody
    headers = {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}
    r = gw.client.get(PAGE, headers=headers)
    assert (r.status_code, r.json()["error"]) == (403, "no_identity")
    assert "detail" in r.json()
    r = gw.client.post(revoke_path("abc"), headers=headers, json={})
    assert (r.status_code, r.json()["error"]) == (403, "no_identity")


def test_the_wrong_method_on_a_live_route_is_405_with_allow(gw):
    r = gw.client.post(PAGE, headers=idp_bearer(), json={})
    assert (r.status_code, r.json(), r.headers["allow"]) == (405, {"detail": "Method Not Allowed"}, "GET")
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        r = gw.client.request(method, revoke_path("abc"), headers=idp_bearer())
        assert (r.status_code, r.json(), r.headers["allow"]) == (405, {"detail": "Method Not Allowed"}, "POST"), method


# ── revoking ─────────────────────────────────────────────────────────────────────────────────────


def test_a_revoke_ends_every_token_is_audited_and_is_announced_to_that_person_only(gw, transports, clock):
    # clock: the store's time stands still, so revoked_at == now() holds across a second boundary.
    mine, other_tab, bobs, nobody = (transports(ALICE_ID), transports(ALICE_ID), transports(BOB_ID), transports(None))
    alices, bob_flow = gw.connect(ALICE), gw.connect(BOB)
    [grant] = grants_of(gw)
    assert gw.call(alices.tokens["access_token"]).status_code == 503  # admitted (the bridge is not running here)
    for transport in (mine, other_tab, bobs, nobody):  # the grants above announced themselves: start clean
        transport.frames.clear()

    r = revoke(gw, grant["id"])
    assert r.status_code == 200 and r.json() == {"ok": True} and r.headers["cache-control"] == "no-store"

    assert grants_of(gw) == [] and len(grants_of(gw, BOB)) == 1
    assert gw.call(alices.tokens["access_token"]).status_code == 401
    assert gw.refresh(alices).status_code == 400
    assert gw.call(bob_flow.tokens["access_token"]).status_code == 503  # Bob's grant is untouched
    stored = gw.store.grant(grant["id"])
    assert (stored.revoked_by, stored.revoked_at) == ("stub:alice", gw.store.now())

    for transport in (mine, other_tab):
        [event] = transport.changes()
        assert event == {"change": "revoked", "grant": {"id": grant["id"], "client_name": "Claude Code"},
                         "at": event["at"]} and isinstance(event["at"], int)
        [frame] = transport.frames
        assert frame["method"] == "event" and frame["params"]["type"] == "mcp.changed" \
            and frame["params"]["session_id"] == ""
    assert bobs.frames == [] and nobody.frames == []

    [line] = [x for x in audit_lines() if x["event"] == "mcp_grant_revoked"]
    assert (line["by"], line["grant_id"], line["user_id"], line["client_name"]) == \
        ("stub:alice", grant["id"], "stub:alice", "Claude Code")
    log = json.dumps(audit_lines())
    for secret in (alices.tokens["access_token"], alices.tokens["refresh_token"]):
        assert secret not in log


def test_every_other_id_is_the_same_404(gw, transports, clock):
    listener = transports(ALICE_ID)
    gw.connect(ALICE)
    bobs = gw.connect(BOB)
    mine = gw.connect(ALICE)
    ended = gw.connect(ALICE)
    by_client = {g.client_id: g.id for g in gw.store.grants()}
    [bob_id, mine_id, ended_id] = [by_client[f.client_id] for f in (bobs, mine, ended)]
    assert revoke(gw, mine_id).status_code == 200  # already revoked below
    clock.advance(1)
    listener.frames.clear()

    ids = {"somebody else's": bob_id, "unknown": "x" * 24, "already revoked": mine_id, "empty": "",
           "too long": "a" * 65, "not an id": "bad id!", "a slash": "a/b", "encoded": "%2e%2e",
           "an id's lookalike": bob_id.lower() + "x"}
    answers = {}
    for name, grant_id in ids.items():
        r = revoke(gw, grant_id)
        answers[name] = (r.status_code, r.json(), r.headers["cache-control"])
    assert all(a == (404, NOT_FOUND, "no-store") for a in answers.values()), answers

    clock.advance(91 * 86400)  # an ended grant of Alice's: the same answer again
    r = revoke(gw, ended_id)
    assert (r.status_code, r.json()) == (404, NOT_FOUND)
    assert listener.changes() == [] and gw.store.grant(bob_id).revoked_at is None
    assert [x for x in audit_lines() if x["event"] == "mcp_grant_revoked"
            and x.get("grant_id") != mine_id] == []


def test_of_two_parallel_revokes_exactly_one_wins(gw):
    gw.connect(ALICE)
    [grant] = grants_of(gw)
    barrier = threading.Barrier(2)
    results: list = []

    def attempt():
        barrier.wait()
        results.append(gw.store.revoke_grant(grant["id"], by="stub:alice", user_id="stub:alice", live_only=True))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(r is None for r in results) == [False, True]


def test_the_operator_may_still_revoke_what_the_person_cannot(gw, clock):
    gw.connect(ALICE)
    [grant] = grants_of(gw)
    assert gw.store.revoke_grant(grant["id"], by="operator").revoked_by == "operator"
    again = gw.store.revoke_grant(grant["id"], by="operator")  # no live_only: the CLI's call is unchanged
    assert again is not None and again.revoked_by == "operator"
    assert gw.store.revoke_grant(grant["id"], by="stub:alice", user_id="stub:alice", live_only=True) is None


def test_a_cookie_write_needs_a_listed_origin_and_a_bearer_needs_none(make_gateway):
    # The dashboard's own write-origin check (on by itself with two listed origins) is switched off, so that
    # it is these routes' rule that answers.
    gw = make_gateway(dashboard={"public_urls": [OTHER_ORIGIN], "write_origin_check": "off"})
    for _ in range(3):
        gw.connect(ALICE)
    ids = [g["id"] for g in grants_of(gw)]

    for origin in (None, "https://evil.example.invalid", "null", f"{BASE}.evil.example.invalid", f"{BASE}:8443"):
        r = revoke(gw, ids[0], headers=cookie(ALICE, origin=origin))
        assert (r.status_code, r.json()["error"]) == (403, "origin_not_listed"), origin
    assert len(grants_of(gw)) == 3
    refused = [x for x in audit_lines() if x["event"] == "mcp_write_refused"]
    assert len(refused) == 5 and {x["reason"] for x in refused} == {"origin_not_listed"}
    assert {x["auth"] for x in refused} == {"cookie"}

    assert revoke(gw, ids[0], headers=cookie(ALICE, origin=BASE)).status_code == 200
    assert revoke(gw, ids[1], headers=cookie(ALICE, origin=OTHER_ORIGIN)).status_code == 200  # a second listed one
    assert revoke(gw, ids[2], headers=idp_bearer(ALICE)).status_code == 200  # a bearer carries no Origin
    assert grants_of(gw) == []


def test_the_dashboards_own_origin_check_still_applies_in_front(make_gateway):
    gw = make_gateway(dashboard={"public_urls": [OTHER_ORIGIN]})  # two origins: write_origin_check is on (auto)
    gw.connect(ALICE)
    [grant] = grants_of(gw)
    assert revoke(gw, grant["id"], headers=cookie(ALICE, origin="https://evil.example.invalid")).status_code == 403
    assert len(grants_of(gw)) == 1
    assert revoke(gw, grant["id"], headers=cookie(ALICE, origin=OTHER_ORIGIN)).status_code == 200


def test_a_read_needs_no_origin(gw):
    assert gw.client.get(PAGE, headers=cookie(ALICE, origin=None)).status_code == 200


def test_the_body_is_a_json_object_of_at_most_16_kib(gw):
    gw.connect(ALICE)
    [grant] = grants_of(gw)
    path, headers = revoke_path(grant["id"]), idp_bearer()

    for content, status in ((b"", 400), (b"not json", 400), (b"[]", 400), (b'"x"', 400), (b"null", 400),
                            (b"{" + b" " * api_routes.BODY_CAP + b"}", 413)):
        r = gw.client.post(path, headers=headers | {"Content-Type": "application/json"}, content=content)
        assert r.status_code == status, (content[:20], r.text)
        assert r.json()["error"] in ("bad_request", "body_too_large")
    assert len(grants_of(gw)) == 1  # nothing above reached the store

    r = gw.client.post(path, headers=headers | {"Content-Type": "application/json"},
                       content=b"{" + b" " * (api_routes.BODY_CAP - 2) + b"}")
    assert r.status_code == 200


def test_a_body_never_names_a_user(gw):
    gw.connect(ALICE)
    bobs = gw.connect(BOB)
    [bob_grant] = grants_of(gw, BOB)
    [grant] = grants_of(gw)
    r = revoke(gw, grant["id"], json={"user_id": "stub:bob", "user": "bob", "by": "operator", "grant_id": bob_grant["id"]})
    assert r.status_code == 200
    stored = gw.store.grant(grant["id"])
    assert stored.revoked_by == "stub:alice" and gw.store.grant(bob_grant["id"]).revoked_at is None
    assert gw.call(bobs.tokens["access_token"]).status_code == 503


# ── mcp.changed: granted ─────────────────────────────────────────────────────────────────────────


def test_a_new_client_is_announced_when_its_code_is_exchanged(gw, transports):
    mine, bobs = transports(ALICE_ID), transports(BOB_ID)
    flow = gw.consent(gw.register(), ALICE)  # the person pressed Allow: no grant exists yet
    assert mine.changes() == [] and grants_of(gw) == []

    assert gw.token(flow).status_code == 200  # the grant exists from its code exchange
    [event] = mine.changes()
    [grant] = grants_of(gw)
    assert event == {"change": "granted", "grant": {"id": grant["id"], "client_name": "Claude Code"},
                     "at": grant["created_at"]}
    assert bobs.changes() == []
    assert gw.token(flow).status_code == 400  # a code is single use: the replay revokes, and says so
    assert [c["change"] for c in mine.changes()] == ["granted", "revoked"]
    assert bobs.changes() == []


def test_a_refresh_does_not_announce(gw, transports):
    flow = gw.connect(ALICE)
    mine = transports(ALICE_ID)
    assert gw.refresh(flow).status_code == 200
    assert mine.changes() == []


def test_a_failed_token_exchange_announces_nothing(gw, transports):
    mine = transports(ALICE_ID)
    flow = gw.consent(gw.register(), ALICE)
    assert gw.token(flow, code_verifier="x" * 50).status_code == 400
    assert mine.changes() == []


def test_the_frame_is_what_the_contract_says():
    from tui_gateway import server, user_events

    transport = FakeTransport("stub:alice")
    server.register_live_transport(transport)
    try:
        payload = {"change": "granted", "grant": {"id": "mcg_1", "client_name": "Claude Code"}, "at": 1790000000}
        assert user_events.announce_mcp_changed("stub:alice", payload) == 1
        assert user_events.announce_mcp_changed("", payload) == 0
        assert user_events.announce_mcp_changed("stub:bob", payload) == 0
    finally:
        server.unregister_live_transport(transport)
    assert transport.frames == [{"jsonrpc": "2.0", "method": "event",
                                 "params": {"type": "mcp.changed", "session_id": "", "payload": payload}}]


def test_the_event_has_a_contract():
    from tui_gateway.contracts import registry

    contract = registry.EVENTS["mcp.changed"]
    assert set(contract.payload.model_fields) == {"change", "grant", "at"}
    registry.check_payload("mcp.changed", {"change": "revoked", "grant": {"id": "g", "client_name": "n"}, "at": 1})


# ── mcp.changed: revoked by the gateway or by the client ────────────────────────────────────────────


def _revocations() -> list[dict]:
    return [x for x in audit_lines() if x["event"] == "mcp_grant_revoked"]


def test_a_replayed_code_revokes_audits_and_announces_once(gw, transports):
    mine, bobs = transports(ALICE_ID), transports(BOB_ID)
    flow = gw.connect(ALICE)
    [grant] = grants_of(gw)
    mine.frames.clear()
    for _ in range(2):
        r = gw.token(flow)
        assert (r.status_code, r.json()["error"]) == (400, "invalid_grant")
    assert gw.call(flow.tokens["access_token"]).status_code == 401
    [line] = _revocations()
    assert (line["by"], line["grant_id"], line["user_id"], line["client_id"], line["client_name"]) == \
        ("code_reuse", grant["id"], ALICE_ID, flow.client_id, "Claude Code")
    assert mine.changes() == [{"change": "revoked", "grant": {"id": grant["id"], "client_name": "Claude Code"},
                               "at": gw.store.grant(grant["id"]).revoked_at}]
    assert bobs.changes() == []
    assert flow.code not in json.dumps(audit_lines())


def test_a_reused_refresh_token_revokes_audits_and_announces_once(gw, transports, clock):
    mine = transports(ALICE_ID)
    flow = gw.connect(ALICE)
    [grant] = grants_of(gw)
    assert gw.refresh(flow).status_code == 200
    mine.frames.clear()
    clock.advance(store_mod.REFRESH_RACE_GRACE)  # past the parallel-refresh grace: a reuse
    for _ in range(2):
        assert gw.refresh(flow).status_code == 400
    [line] = _revocations()
    assert (line["by"], line["grant_id"], line["user_id"]) == ("refresh_reuse", grant["id"], ALICE_ID)
    [event] = mine.changes()
    assert event["change"] == "revoked" and event["grant"]["id"] == grant["id"]
    assert grants_of(gw) == []


def test_a_rotated_refresh_token_sent_to_revoke_is_a_reuse_too(gw, transports, clock):
    mine = transports(ALICE_ID)
    flow = gw.connect(ALICE)
    assert gw.refresh(flow).status_code == 200
    mine.frames.clear()
    clock.advance(store_mod.REFRESH_RACE_GRACE)
    r = gw.client.post("/mcp/revoke", data={"token": flow.tokens["refresh_token"], "client_id": flow.client_id,
                                            "token_type_hint": "refresh_token"})
    assert r.status_code == 200
    [line] = _revocations()
    assert line["by"] == "refresh_reuse"
    assert [c["change"] for c in mine.changes()] == ["revoked"]


def test_a_clients_own_revoke_is_announced_once(gw, transports):
    mine, bobs = transports(ALICE_ID), transports(BOB_ID)
    flow = gw.connect(ALICE)
    [grant] = grants_of(gw)
    mine.frames.clear()
    for _ in range(2):  # the second finds nothing live: a silent 200, no second line or event
        r = gw.client.post("/mcp/revoke", data={"token": flow.tokens["access_token"], "client_id": flow.client_id})
        assert r.status_code == 200
    [line] = _revocations()
    assert (line["by"], line["grant_id"], line["user_id"], line["client_name"]) == \
        ("client", grant["id"], ALICE_ID, "Claude Code")
    assert mine.changes() == [{"change": "revoked", "grant": {"id": grant["id"], "client_name": "Claude Code"},
                               "at": gw.store.grant(grant["id"]).revoked_at}]
    assert bobs.changes() == [] and grants_of(gw) == []


def test_a_parallel_refresh_announces_nothing(gw, transports):
    mine = transports(ALICE_ID)
    flow = gw.connect(ALICE)
    mine.frames.clear()
    assert gw.refresh(flow).status_code == 200
    assert gw.refresh(flow).status_code == 400  # the same refresh token again within the grace
    assert mine.changes() == [] and _revocations() == []
