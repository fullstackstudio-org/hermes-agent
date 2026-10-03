"""The consent page (``hermes_cli/dashboard_auth/mcp/consent.py``): the one place an MCP grant is born.

Pinned here: the page shows the client's name AND its redirect host, escaped; it cannot be framed or
cached and runs no script; a cookie decision needs this gateway's own Origin (a bearer caller is exempt);
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
    assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"


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


def test_a_bearer_decision_is_exempt_from_the_origin_rule(gw):
    flow, _ = _consent_open(gw)
    r = gw.decide(flow, headers=idp_bearer())
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
