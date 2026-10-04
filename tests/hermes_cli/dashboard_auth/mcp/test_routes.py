"""The MCP authorization server on the real dashboard app (``hermes_cli/dashboard_auth/mcp/{mount,routes}``):
a stub sign-in provider, the real gate, the real store, the SDK's handlers.

Pinned here: the whole flow an MCP client walks (registration, authorize, the sign-in redirect, consent,
code, token, refresh, revoke); the off matrix (disabled or ungated = answered as on a gateway without the
feature, and nothing public); the gate's registry opens exact paths only; metadata at both well-known
paths; ``resource`` on the token route; a public client revoking without a secret; a store that cannot be
used is 503, never 400/401; the per-address limits; another host is 404; ``/mcp`` admits only this
store's tokens; ``auth_flows`` carries ``mcp`` exactly while on; and no token, code or secret in the
audit log.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.mcp import mount, routes
from hermes_cli.dashboard_auth.mcp.store import MCPStore, StoreError
from hermes_cli.dashboard_auth.public_paths import is_registered_public, registered_public_paths
from hermes_cli.dashboard_auth.request_utils import is_safe_next_path
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider, _sign

BASE = "https://gw.example.invalid"
ISSUER = f"{BASE}/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"
CLIENT_NAME = "Claude Code"
ALICE, BOB = "alice", "bob"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def cookie(user: str = ALICE, *, origin: str | None = BASE) -> dict:
    token = _sign({"sub": user, "email": f"{user}@example.invalid", "name": user.title(), "org_id": "",
                   "exp": int(time.time()) + 3600})
    headers = {"Cookie": f"hermes_session_at={token}"}
    if origin is not None:
        headers["Origin"] = origin
    return headers


def idp_bearer(user: str = ALICE) -> dict:
    token = _sign({"sub": user, "email": "", "name": user.title(), "org_id": "", "exp": int(time.time()) + 3600})
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Flow:
    client_id: str = ""
    client_secret: str | None = None
    verifier: str = ""
    txn: str = ""
    nonce: str = ""
    code: str = ""
    tokens: dict = field(default_factory=dict)


class Gateway:
    def __init__(self, client: TestClient, store: MCPStore):
        self.client, self.store = client, store

    def register(self, **extra) -> Flow:
        body = {"redirect_uris": [REDIRECT], "client_name": CLIENT_NAME, "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]} | extra
        r = self.client.post("/mcp/register", json=body)
        assert r.status_code == 201, r.text
        data = r.json()
        return Flow(client_id=data["client_id"], client_secret=data.get("client_secret"))

    def authorize(self, flow: Flow, **extra) -> str:
        flow.verifier, challenge = pkce()
        params = {"response_type": "code", "client_id": flow.client_id, "redirect_uri": REDIRECT,
                  "code_challenge": challenge, "code_challenge_method": "S256", "state": "state-marker",
                  "resource": ISSUER} | extra
        r = self.client.get("/mcp/authorize", params=params)
        assert r.status_code == 302, r.text
        return r.headers["location"]

    def open_consent(self, flow: Flow, user: str = ALICE) -> str:
        location = self.authorize(flow)
        assert location.startswith(f"{BASE}/mcp/consent?txn=")
        flow.txn = parse_qs(urlsplit(location).query)["txn"][0]
        r = self.client.get(f"/mcp/consent?txn={flow.txn}", headers=cookie(user))
        assert r.status_code == 200, r.text
        flow.nonce = re.search(r'name="nonce" value="([^"]+)"', r.text).group(1)
        return r.text

    def decide(self, flow: Flow, decision: str = "allow", user: str = ALICE, headers: dict | None = None):
        return self.client.post("/mcp/consent", data={"txn": flow.txn, "nonce": flow.nonce, "decision": decision},
                                headers=headers if headers is not None else cookie(user))

    def consent(self, flow: Flow, user: str = ALICE) -> Flow:
        self.open_consent(flow, user)
        r = self.decide(flow, user=user)
        assert r.status_code == 303, r.text
        query = parse_qs(urlsplit(r.headers["location"]).query)
        assert r.headers["location"].startswith(REDIRECT + "?")
        assert query["state"] == ["state-marker"]
        flow.code = query["code"][0]
        return flow

    def token(self, flow: Flow, **extra):
        form = {"grant_type": "authorization_code", "code": flow.code, "redirect_uri": REDIRECT,
                "client_id": flow.client_id, "code_verifier": flow.verifier, "resource": ISSUER} | extra
        return self.client.post("/mcp/token", data=form)

    def connect(self, user: str = ALICE) -> Flow:
        flow = self.consent(self.register(), user)
        r = self.token(flow)
        assert r.status_code == 200, r.text
        flow.tokens = r.json()
        return flow

    def refresh(self, flow: Flow, refresh_token: str | None = None):
        return self.client.post("/mcp/token", data={"grant_type": "refresh_token", "client_id": flow.client_id,
                                                     "refresh_token": refresh_token or flow.tokens["refresh_token"]})

    def call(self, access_token: str | None, method: str = "POST"):
        headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
        return self.client.request(method, "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1,
                                                                          "method": "ping"})


@pytest.fixture
def make_gateway(monkeypatch, tmp_path):
    clear_providers()
    register_provider(StubAuthProvider())
    mount.reset_for_tests()
    stores: list[MCPStore] = []

    def make(mcp: dict | None = None, *, gated: bool = True, dashboard: dict | None = None) -> Gateway:
        config = {"dashboard": {"public_url": BASE, "mcp": {"enabled": True} | (mcp or {})} | (dashboard or {})}
        monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
        monkeypatch.setattr("hermes_cli.config.load_config", lambda: copy.deepcopy(config))
        for name in ("auth_required", "bound_host", "trusted_public_hosts", "public_origins", "write_origin_check"):
            monkeypatch.setattr(web_server.app.state, name, getattr(web_server.app.state, name, None), raising=False)
        web_server.app.state.bound_host = "127.0.0.1"
        web_server._configure_auth_gate("127.0.0.1", False, None, None)
        store = MCPStore(tmp_path / "dashboard_auth" / "mcp.db")
        stores.append(store)
        web_server.app.state.auth_required = gated  # gated: as a non-loopback bind would be
        mount.configure(web_server.app, cfg=config, store=store)
        return Gateway(TestClient(web_server.app, base_url=BASE, follow_redirects=False), store)

    yield make
    mount.reset_for_tests()
    clear_providers()


@pytest.fixture
def gw(make_gateway) -> Gateway:
    return make_gateway()


def audit_lines() -> list[dict]:
    from hermes_constants import get_hermes_home

    path = get_hermes_home() / "logs" / "dashboard-auth.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ── the whole flow ──────────────────────────────────────────────────────────────────────────────


def test_a_client_walks_the_whole_flow(gw):
    flow = gw.register()
    location = gw.authorize(flow)
    # The consent page sits behind the normal sign-in, which brings the browser back to it.
    r = gw.client.get(urlsplit(location).path + "?" + urlsplit(location).query, headers={"Accept": "text/html"})
    assert r.status_code == 302
    assert quote(f"/mcp/consent?txn={parse_qs(urlsplit(location).query)['txn'][0]}", safe="") \
        in r.headers["location"]
    assert is_safe_next_path("/mcp/consent?txn=abc")

    page = gw.open_consent(flow)
    assert CLIENT_NAME in page and "127.0.0.1:33418" in page and "Alice" in page
    r = gw.decide(flow)
    assert r.status_code == 303
    flow.code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]

    r = gw.token(flow)
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600
    assert r.headers["cache-control"] == "no-store"
    assert gw.call(tokens["access_token"]).json()["error"] == "bridge_not_ready"

    r = gw.refresh(flow, tokens["refresh_token"])
    assert r.status_code == 200, r.text
    rotated = r.json()
    assert gw.call(rotated["access_token"]).status_code == 503

    # A public client revokes without a client_secret; the whole grant ends.
    r = gw.client.post("/mcp/revoke", data={"token": rotated["refresh_token"], "client_id": flow.client_id})
    assert r.status_code == 200, r.text
    assert gw.call(rotated["access_token"]).status_code == 401
    [grant] = gw.store.grants(include_inactive=True)
    assert (grant.user_id, grant.client_name, grant.revoked_by) == ("stub:alice", CLIENT_NAME, "client")

    events = [line["event"] for line in audit_lines() if line["event"].startswith("mcp_")]
    for event in ("mcp_client_registered", "mcp_authorize_start", "mcp_consent_granted", "mcp_token_issued",
                  "mcp_token_refreshed", "mcp_grant_revoked"):
        assert event in events, event
    log = json.dumps(audit_lines())
    for secret in (tokens["access_token"], tokens["refresh_token"], rotated["refresh_token"], flow.code,
                   flow.verifier, flow.nonce):
        assert secret not in log


def test_a_secret_client_authenticates_against_the_stored_hash(gw):
    flow = gw.register(token_endpoint_auth_method="client_secret_post")
    assert flow.client_secret
    flow = gw.consent(flow)
    assert gw.token(flow).status_code == 401  # no secret
    r = gw.token(flow, client_secret=flow.client_secret)
    assert r.status_code == 200, r.text
    refresh = r.json()["refresh_token"]
    r = gw.client.post("/mcp/revoke", data={"token": refresh, "client_id": flow.client_id})
    assert r.status_code == 401
    r = gw.client.post("/mcp/revoke", data={"token": refresh, "client_id": flow.client_id,
                                            "client_secret": flow.client_secret})
    assert r.status_code == 200
    assert gw.store.grants(include_inactive=True)[0].revoked_by == "client"


def test_a_parallel_refresh_is_refused_without_ending_the_grant(gw):
    flow = gw.connect()
    first, late = gw.refresh(flow), gw.refresh(flow)  # the same refresh token twice, as two parallel requests
    assert first.status_code == 200, first.text
    assert (late.status_code, late.json()["error"]) == (400, "invalid_grant")
    [grant] = gw.store.grants()
    assert grant.revoked_at is None
    assert gw.call(first.json()["access_token"]).status_code == 503  # bridge_not_ready: admitted
    assert gw.refresh(flow, first.json()["refresh_token"]).status_code == 200
    assert not [line for line in audit_lines() if line["event"] == "mcp_grant_revoked"]


def test_a_token_request_for_another_resource_is_invalid_target(gw):
    flow = gw.consent(gw.register())
    r = gw.token(flow, resource="https://other.example.invalid/mcp")
    assert (r.status_code, r.json()["error"]) == (400, "invalid_target")
    assert gw.token(flow).status_code == 200  # the code was not spent by the refusal


def test_the_endpoint_admits_only_this_stores_tokens(gw):
    r = gw.call(None)
    assert r.status_code == 401
    header = r.headers["www-authenticate"]
    assert header.startswith("Bearer ") and f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in header
    assert gw.call("not-a-token").status_code == 401
    # The person's own IdP bearer (the native app's) is not an MCP token.
    r = gw.client.post("/mcp", headers=idp_bearer(), json={})
    assert r.status_code == 401
    for method in ("GET", "DELETE"):
        assert gw.call(None, method).status_code == 405


# ── metadata ────────────────────────────────────────────────────────────────────────────────────


def test_metadata_names_the_path_issuer_on_both_well_known_paths(gw):
    a = gw.client.get("/.well-known/oauth-authorization-server/mcp")
    b = gw.client.get("/.well-known/oauth-authorization-server")
    assert a.status_code == b.status_code == 200 and a.json() == b.json()
    meta = a.json()
    assert meta["issuer"] == ISSUER
    assert meta["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert meta["token_endpoint"] == f"{ISSUER}/token"
    assert meta["registration_endpoint"] == f"{ISSUER}/register"
    assert meta["revocation_endpoint"] == f"{ISSUER}/revoke"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "none" in meta["token_endpoint_auth_methods_supported"]
    assert a.headers["cache-control"] == "no-store"
    prm = gw.client.get("/.well-known/oauth-protected-resource/mcp")
    assert prm.status_code == 200 and prm.headers["cache-control"] == "no-store"
    assert prm.json()["resource"] == ISSUER and prm.json()["authorization_servers"] == [ISSUER]
    # Public clients may read it cross-origin (the SDK's CORS on metadata), and nothing cookie-bound is here.
    r = gw.client.get("/.well-known/oauth-authorization-server/mcp", headers={"Origin": "https://x.example.invalid"})
    assert r.headers.get("access-control-allow-origin") == "*"


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_every_decision_carries_the_issuer_the_sdk_client_checks(gw, decision):
    # RFC 9207, checked with the mcp SDK's own client code: the metadata advertises iss, and the
    # consent page's answer carries exactly the metadata's issuer (compared as strings, no normalising).
    from mcp.client.auth.exceptions import OAuthFlowError
    from mcp.client.auth.utils import validate_authorization_response_iss
    from mcp.shared.auth import OAuthMetadata

    meta = gw.client.get("/.well-known/oauth-authorization-server/mcp").json()
    assert meta["authorization_response_iss_parameter_supported"] is True
    parsed = OAuthMetadata.model_validate(meta)
    flow = gw.register()
    gw.open_consent(flow)
    r = gw.decide(flow, decision)
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["iss"] == [ISSUER] == [meta["issuer"]]
    assert ("code" in query) == (decision == "allow") and query["state"] == ["state-marker"]
    validate_authorization_response_iss(query["iss"][0], parsed)  # what the SDK's client runs: accepted
    with pytest.raises(OAuthFlowError):  # and a response without it would now be refused: it must be there
        validate_authorization_response_iss(None, parsed)
    with pytest.raises(OAuthFlowError):
        validate_authorization_response_iss("https://other.example.invalid/mcp", parsed)


def test_the_sdk_accepts_an_issuer_with_a_path():
    from mcp.server.auth.routes import validate_issuer_url
    from pydantic import AnyHttpUrl
    validate_issuer_url(AnyHttpUrl(ISSUER))
    with pytest.raises(ValueError):
        validate_issuer_url(AnyHttpUrl("http://gw.example.invalid/mcp"))


# ── off is the same as absent ───────────────────────────────────────────────────────────────────

PROBES = [("GET", "/.well-known/oauth-authorization-server/mcp"), ("GET", "/.well-known/oauth-authorization-server"),
          ("GET", "/.well-known/oauth-protected-resource/mcp"), ("GET", "/mcp/authorize"), ("GET", "/mcp/consent"),
          ("POST", "/mcp/token"), ("POST", "/mcp/register"), ("POST", "/mcp/revoke"), ("POST", "/mcp"),
          ("GET", "/mcp"), ("POST", "/mcp/consent")]


def _answer(gw: Gateway, method: str, path: str, headers: dict | None = None) -> tuple:
    gw.client.cookies.clear()  # the auto sign-in's loop guard is a cookie
    r = gw.client.request(method, path, headers=headers or {}, data={"x": "1"} if method == "POST" else None)
    return r.status_code, r.headers.get("location"), r.headers.get("allow"), r.content


@pytest.mark.parametrize("mcp, gated", [({"enabled": False}, True), ({"enabled": "yes"}, True),
                                        ({"enabled": True}, False), ({"enabled": False}, False)])
def test_off_answers_exactly_like_a_gateway_without_the_feature(make_gateway, monkeypatch, mcp, gated):
    gw = make_gateway(mcp, gated=gated)
    assert mount.current() is None and registered_public_paths() == frozenset()
    headers = {} if gated else {web_server._SESSION_HEADER_NAME: web_server._SESSION_TOKEN}
    seen = {(m, p): _answer(gw, m, p, headers) for m, p in PROBES}
    monkeypatch.setattr(web_server.app.router, "routes",
                        [r for r in web_server.app.router.routes if r is not mount._ROUTE])
    for (method, path), got in seen.items():
        assert got == _answer(gw, method, path, headers), (method, path)
    assert not gw.store.exists()


def test_while_on_the_gate_opens_exact_paths_only(gw):
    assert registered_public_paths() == frozenset(mount.PUBLIC_PATHS)
    assert not is_registered_public("/mcp/consent") and not is_registered_public("/mcp/")
    assert not is_registered_public("/mcp/token/x")
    # The consent page and anything else under /mcp stay behind the cookie sign-in.
    r = gw.client.get("/mcp/consent?txn=x")
    assert r.status_code == 302 and "login" in r.headers["location"]
    r = gw.client.post("/mcp/consent", data={"txn": "x"})
    assert r.status_code == 302
    assert gw.client.get("/mcp/elsewhere").status_code == 302


def test_another_host_gets_404(make_gateway):
    gw = make_gateway(dashboard={"public_urls": ["https://app.example.invalid"]})
    other = TestClient(web_server.app, base_url="https://app.example.invalid", follow_redirects=False)
    for method, path in PROBES:
        if path == "/mcp/consent":
            continue  # gated: the sign-in redirect comes first
        assert other.request(method, path).status_code == 404, (method, path)
    assert gw.client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


def test_auth_flows_carries_mcp_exactly_while_on(make_gateway):
    gw = make_gateway()
    assert "mcp" in gw.client.get("/api/status").json()["auth_flows"]
    gw = make_gateway({"enabled": False})
    assert "mcp" not in gw.client.get("/api/status").json()["auth_flows"]


@pytest.mark.parametrize("dashboard, why", [({"public_url": ""}, "no dashboard.public_url"),
                                            ({"public_url": f"{BASE}/hermes"}, "path prefix"),
                                            ({"public_url": "http://gw.example.invalid"}, "not https")])
def test_it_stays_off_without_a_usable_primary_url(make_gateway, caplog, dashboard, why):
    make_gateway(dashboard=dashboard)
    assert mount.current() is None
    assert why in caplog.text


def test_it_stays_off_without_the_mcp_package(make_gateway, monkeypatch, caplog):
    import builtins

    real_import = builtins.__import__

    def no_routes(name, *args, **kwargs):
        if name == "hermes_cli.dashboard_auth.mcp" and args[2] and "routes" in args[2]:
            raise ImportError("No module named 'mcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_routes)
    make_gateway()
    assert mount.current() is None
    assert "pip install 'hermes-agent[mcp]'" in caplog.text


# ── failures and limits ─────────────────────────────────────────────────────────────────────────


def test_a_store_that_cannot_be_used_is_503_never_400_or_401(gw, monkeypatch):
    flow = gw.connect()

    def broken(*_a, **_k):
        raise StoreError("mcp store: disk I/O error")

    for name in ("client", "verify_access", "add_client", "open_consent", "consent", "load_refresh", "take_code"):
        monkeypatch.setattr(gw.store, name, broken)
    answers = [
        gw.client.post("/mcp/register", json={"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"}),
        gw.client.get("/mcp/authorize", params={"response_type": "code", "client_id": flow.client_id,
                                                "redirect_uri": REDIRECT, "code_challenge": pkce()[1]}),
        gw.client.get("/mcp/consent?txn=abc", headers=cookie()),
        gw.refresh(flow),
        gw.client.post("/mcp/revoke", data={"token": "x", "client_id": flow.client_id}),
        gw.call(flow.tokens["access_token"]),
    ]
    for r in answers:
        assert r.status_code == 503, (r.request.url, r.status_code, r.text)
        assert r.json()["error"] == "temporarily_unavailable"


def test_registration_and_token_requests_are_limited_per_address(gw):
    body = {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"}
    assert all(gw.client.post("/mcp/register", json=body).status_code == 201 for _ in range(10))
    r = gw.client.post("/mcp/register", json=body)
    assert r.status_code == 429 and r.json()["error"] == "rate_limited" and r.headers["retry-after"] == "3600"
    for _ in range(60):
        gw.client.post("/mcp/token", data={"grant_type": "refresh_token", "client_id": "x", "refresh_token": "y"})
    r = gw.client.post("/mcp/token", data={"grant_type": "refresh_token", "client_id": "x", "refresh_token": "y"})
    assert r.status_code == 429
    limited = [line for line in audit_lines() if line["event"] == "mcp_rate_limited"]
    assert {line["route"] for line in limited} == {"register", "token"}


def test_bodies_are_capped(gw):
    r = gw.client.post("/mcp/token", content=b"a=" + b"x" * (routes.BODY_CAP + 1),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    r = gw.client.post("/mcp/register", content=b"{" + b" " * routes.BODY_CAP + b"}",
                       headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_registration_refuses_redirects_outside_https_and_loopback(gw):
    for uri in ("http://gw.example.invalid/callback", "myapp://callback", "https://x.example.invalid/cb#frag"):
        r = gw.client.post("/mcp/register", json={"redirect_uris": [uri], "token_endpoint_auth_method": "none"})
        assert r.status_code == 400, uri


PHISH = "https://phish.example.invalid/x"


@pytest.mark.parametrize("extra, error", [({"scope": "nope"}, "invalid_scope"),
                                          ({"code_challenge_method": "plain"}, "invalid_request"),
                                          ({"resource": "https://other.example.invalid/mcp"}, "invalid_target")])
def test_authorize_never_redirects_a_refusal_to_the_client(gw, extra, error):
    # Anyone may register any https redirect URI; a refusal sent there before the person saw the client on
    # the consent page would make the gateway an open redirector (no sign-in needed to trigger it).
    flow = gw.register(redirect_uris=[PHISH])
    _, challenge = pkce()
    params = {"response_type": "code", "client_id": flow.client_id, "redirect_uri": PHISH,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": "state-marker",
              "resource": ISSUER} | extra
    r = gw.client.get("/mcp/authorize", params=params)
    assert r.status_code == 400 and "location" not in r.headers, (r.status_code, r.headers)
    assert r.json()["error"] == error and r.headers["cache-control"].startswith("no-store")
    page = gw.client.get("/mcp/authorize", params=params, headers={"Accept": "text/html"})
    assert page.status_code == 400 and "location" not in page.headers
    assert page.headers["content-type"].startswith("text/html") and "phish.example.invalid" not in page.text
    assert "<script" not in page.text and page.headers["x-frame-options"] == "DENY"
    r = gw.client.post("/mcp/authorize", data=params)
    assert r.status_code == 400 and "location" not in r.headers
    lines = [line for line in audit_lines() if line["event"] == "mcp_authorize_start"]
    assert lines and all((line["outcome"], line["reason"], line["status"]) == ("refused", error, 400)
                         for line in lines)
    # The same client with a valid request still reaches the consent page, and only that.
    params.pop("scope", None)
    params |= {"code_challenge_method": "S256", "resource": ISSUER}
    r = gw.client.get("/mcp/authorize", params=params)
    assert r.status_code == 302 and r.headers["location"].startswith(f"{BASE}/mcp/consent?txn=")


def test_loopback_any_port_is_a_one_line_switch(gw, monkeypatch):
    flow = gw.register()
    other_port = "http://127.0.0.1:40001/callback"
    _, challenge = pkce()
    params = {"response_type": "code", "client_id": flow.client_id, "redirect_uri": other_port,
              "code_challenge": challenge, "resource": ISSUER}
    assert gw.client.get("/mcp/authorize", params=params).status_code == 400
    monkeypatch.setattr(routes, "LOOPBACK_ANY_PORT", True)
    r = gw.client.get("/mcp/authorize", params=params)
    assert r.status_code == 302 and r.headers["location"].startswith(f"{BASE}/mcp/consent?")
    params["redirect_uri"] = "http://127.0.0.1:40001/elsewhere"
    assert gw.client.get("/mcp/authorize", params=params).status_code == 400


def test_both_gates_honour_the_registry_and_only_while_registered(make_gateway):
    from hermes_cli.dashboard_auth.public_paths import register_public_path, unregister_public_path

    probe = "/api/registry-probe-marker"
    gated = make_gateway()
    legacy = make_gateway(gated=False)
    assert gated.client.get(probe).status_code == 401  # gated: no cookie
    assert legacy.client.get(probe).status_code == 401  # session-token mode: no token
    register_public_path(probe)
    try:
        web_server.app.state.auth_required = True
        assert gated.client.get(probe).status_code == 404  # through the gate, to the unknown-API answer
        web_server.app.state.auth_required = False
        assert legacy.client.get(probe).status_code == 404
    finally:
        unregister_public_path(probe)
    assert legacy.client.get(probe).status_code == 401
