"""The consent page (``hermes_cli/dashboard_auth/mcp/consent.py``): the one place an MCP grant is born.

Pinned here: the page shows the client's name AND its redirect host, escaped; it cannot be framed or
cached and runs no script; a decision needs the cookie session (never a bearer) and this gateway's own Origin;
the nonce is bound to the transaction and a transaction is decided once; Deny sends ``access_denied`` back;
the per-person cap refuses with the transaction left open; the identity comes from the gate's session only;
and the audit lines name the decision without the nonce or the code.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.requests import Request

from hermes_cli.dashboard_auth.mcp import consent
from tests.hermes_cli.dashboard_auth.mcp.test_routes import (  # noqa: F401 - fixtures
    BASE, REDIRECT, Gateway, audit_lines, cookie, gw, idp_bearer, make_gateway)


def _consent_open(gw: Gateway, **register):
    flow = gw.register(**register)
    page = gw.open_consent(flow)
    return flow, page


def test_the_page_names_client_and_redirect_host_escaped_and_cannot_be_framed(gw):
    flow, page = _consent_open(gw, client_name='<b>Helper</b>" onmouseover="x')
    assert "&lt;b&gt;Helper&lt;/b&gt;&quot; onmouseover=&quot;x" in page
    assert "<b>Helper</b>" not in page
    assert "127.0.0.1:33418" in page and "Alice" in page
    assert "<script" not in page
    r = gw.client.get(f"/mcp/consent?txn={flow.txn}", headers=cookie())
    assert r.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


# What a browser puts in ``Origin`` on a same-origin form POST, by the page's referrer policy (Fetch,
# "serializing a request origin"): ``no-referrer`` turns it into ``null``; every other policy keeps the page's
# origin for a same-origin request. TestClient sends whatever a test writes, so the policy is pinned here.
def _browser_post_origin(policy: str, page_origin: str) -> str:
    return "null" if policy.strip().lower() == "no-referrer" else page_origin


def test_the_page_policy_lets_a_browser_send_its_real_origin(gw):
    # Pinned: same-origin. Under no-referrer a real browser POSTs "Origin: null" and the Origin rule refuses
    # every Allow and Deny (TestClient hid that by setting Origin by hand). same-origin still sends no
    # Referer to the client's host on the 303, so the transaction id in the page's address does not leak.
    flow, _ = _consent_open(gw)
    page = gw.client.get(f"/mcp/consent?txn={flow.txn}", headers=cookie())
    policy = page.headers["referrer-policy"]
    assert policy == "same-origin"
    refused = gw.client.get("/mcp/consent?txn=gone", headers=cookie() | {"Accept": "text/html"})
    assert refused.status_code == 404 and refused.headers["referrer-policy"] == "same-origin"

    # What the old no-referrer page made a browser send: refused, and the transaction stays open.
    r = gw.decide(flow, headers=cookie(origin=_browser_post_origin("no-referrer", BASE)))
    assert (r.status_code, r.json()["error"]) == (403, "origin_not_listed")
    # What this page makes a browser send: the decision goes through.
    r = gw.decide(flow, headers=cookie(origin=_browser_post_origin(policy, BASE)))
    assert r.status_code == 303 and r.headers["location"].startswith(REDIRECT + "?")
    # The way back to the client carries no referrer of its own either.
    assert r.headers["referrer-policy"] == "no-referrer"


def test_a_cookie_decision_needs_this_gateways_origin(gw):
    flow, _ = _consent_open(gw)
    for origin in (None, "https://evil.example.invalid", "null", "http://gw.example.invalid"):
        r = gw.decide(flow, headers=cookie(origin=origin))
        assert (r.status_code, r.json()["error"]) == (403, "origin_not_listed"), origin
    assert not gw.store.grants(include_inactive=True)
    refused = [line for line in audit_lines() if line["event"] == "mcp_consent_denied"]
    assert refused and all(line["reason"] == "origin_not_listed" and line["outcome"] == "refused" for line in refused)
    # The transaction is still open: the real page's form goes through.
    assert gw.decide(flow).status_code == 303


def test_a_bearer_may_not_decide_a_consent(gw):
    # Security 2: a grant is born from the cookie session on this page, never from a bearer, which would
    # also skip the Origin rule. With the right Origin, with none, or beside a cookie: refused.
    flow, _ = _consent_open(gw)
    for headers in (idp_bearer(), idp_bearer() | {"Origin": BASE}, cookie() | idp_bearer()):
        for decision in ("allow", "deny"):
            r = gw.decide(flow, decision, headers=headers)
            assert (r.status_code, r.json()["error"]) == (403, "cookie_session_required"), headers
    assert not gw.store.grants(include_inactive=True)
    refused = [line for line in audit_lines() if line["event"] == "mcp_consent_denied"]
    assert refused and all((line["reason"], line["auth"]) == ("bearer", "bearer") for line in refused)
    # The transaction is still open for the person's own browser.
    r = gw.decide(flow)
    assert r.status_code == 303 and "code=" in r.headers["location"]


def test_the_nonce_is_bound_and_a_transaction_is_decided_once(gw):
    flow, _ = _consent_open(gw)
    real_nonce = flow.nonce
    flow.nonce = "x" * len(real_nonce)
    r = gw.decide(flow)
    assert (r.status_code, r.json()["error"]) == (404, "not_found")
    flow.nonce = real_nonce
    assert gw.decide(flow).status_code == 303
    r = gw.decide(flow)
    assert (r.status_code, r.json()["error"]) == (404, "not_found")
    r = gw.client.get(f"/mcp/consent?txn={flow.txn}", headers=cookie() | {"Accept": "text/html"})
    assert r.status_code == 404 and r.headers["content-type"].startswith("text/html")
    assert "no longer open" in r.text


def test_deny_sends_access_denied_back_and_mints_nothing(gw):
    flow, _ = _consent_open(gw)
    r = gw.decide(flow, "deny")
    assert r.status_code == 303
    location = r.headers["location"]
    assert location.startswith(REDIRECT + "?")
    query = parse_qs(urlsplit(location).query)
    assert query["error"] == ["access_denied"] and query["state"] == ["state-marker"] and "code" not in query
    assert not gw.store.grants(include_inactive=True)
    [line] = [line for line in audit_lines() if line["event"] == "mcp_consent_denied"]
    assert (line["outcome"], line["user_id"], line["client_name"]) == ("denied", "stub:alice", "Claude Code")


def test_the_cap_refuses_and_leaves_the_transaction_open(make_gateway):
    gw = make_gateway({"enabled": True, "max_grants_per_user": 1})
    first = gw.connect()
    flow, _ = _consent_open(gw)
    r = gw.decide(flow)
    assert (r.status_code, r.json()["error"]) == (409, "too_many_grants")
    gw.store.revoke_grant(gw.store.grants()[0].id, by="stub:alice")
    assert gw.call(first.tokens["access_token"]).status_code == 401
    r = gw.decide(flow)
    assert r.status_code == 303 and "code=" in r.headers["location"]


def test_the_decision_names_the_person_from_the_session_only(gw):
    flow, _ = _consent_open(gw)
    r = gw.client.post("/mcp/consent", headers=cookie("bob"),
                       data={"txn": flow.txn, "nonce": flow.nonce, "decision": "allow", "user_id": "stub:alice",
                             "provider": "stub"})
    assert r.status_code == 303
    flow.code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    assert gw.token(flow).status_code == 200
    [grant] = gw.store.grants()
    assert (grant.user_id, grant.user_name) == ("stub:bob", "Bob")
    [line] = [line for line in audit_lines() if line["event"] == "mcp_consent_granted"]
    assert line["user_id"] == "stub:bob" and line["client_id"] == flow.client_id
    log = json.dumps(audit_lines())
    assert flow.nonce not in log and flow.code not in log


def test_a_request_without_a_signed_in_person_is_no_identity(gw):
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    for method in ("GET", "POST"):
        scope = {"type": "http", "method": method, "path": "/mcp/consent", "query_string": b"txn=x", "headers": [],
                 "state": {}, "client": ("203.0.113.9", 1)}
        response = pytest.importorskip("anyio").run(consent.consent_endpoint, Request(scope, receive))
        assert (response.status_code, json.loads(response.body)["error"]) == (403, "no_identity")


def test_a_bad_form_is_refused(gw):
    flow, _ = _consent_open(gw)
    r = gw.client.post("/mcp/consent", headers=cookie(), data={"txn": flow.txn, "nonce": flow.nonce,
                                                                "decision": "maybe"})
    assert (r.status_code, r.json()["error"]) == (400, "bad_request")
    r = gw.client.post("/mcp/consent", headers=cookie() | {"Content-Type": "application/x-www-form-urlencoded"},
                       content=b"txn=" + b"x" * 20000)
    assert r.status_code == 413
    assert re.search(r"code=", gw.decide(flow).headers["location"])
