"""The OAuth provider and token verifier over the MCP store: registration rules, authorize and consent,
code exchange, refresh rotation and reuse, access tokens and their resource, revocation, client
authentication against the stored hash, and the whole flow through the SDK's own handlers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import sqlite3
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from hermes_cli.dashboard_auth.mcp import store as store_mod
from hermes_cli.dashboard_auth.mcp.provider import (
    UNNAMED_CLIENT, MCPClientAuthenticator, MCPProvider, MCPTokenVerifier, canonical_resource, current_request,
    redirect_uri_allowed, request_bound)
from hermes_cli.dashboard_auth.mcp.settings import SCOPES, MCPSettings, default_section, parse
from hermes_cli.dashboard_auth.mcp.store import (
    BY_CLIENT, BY_CODE_REUSE, BY_REFRESH_REUSE, ConsentInvalid, LimitReached, MCPStore, hash_secret)

RESOURCE = "https://gw.example.invalid/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"


def run(coro):
    return asyncio.run(coro)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


class Clock:
    def __init__(self, t: float | None = None):
        self.t = t if t is not None else float(int(time.time()))

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path, clock) -> MCPStore:
    return MCPStore(tmp_path / "dashboard_auth" / "mcp.db", clock=clock)


@pytest.fixture
def provider(store) -> MCPProvider:
    return MCPProvider(store, resource_url=RESOURCE)


def client_info(client_id: str = "client-1", *, method: str = "none", redirect_uris=(REDIRECT,),
                scope: str | None = None, name: str | None = "Example Agent") -> OAuthClientInformationFull:
    data = {"client_id": client_id, "redirect_uris": list(redirect_uris), "token_endpoint_auth_method": method,
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "client_name": name, "scope": scope}
    if method != "none":
        data["client_secret"] = "client-secret-marker"
    return OAuthClientInformationFull.model_validate(data)


def params(challenge: str, *, resource: str | None = RESOURCE, scopes=None, explicit: bool = True,
           redirect: str = REDIRECT) -> AuthorizationParams:
    return AuthorizationParams(state="state-1", scopes=scopes, code_challenge=challenge, redirect_uri=AnyUrl(redirect),
                               redirect_uri_provided_explicitly=explicit, resource=resource)


async def consented(provider: MCPProvider, client, *, user: str = "alice", resource: str | None = RESOURCE
                    ) -> tuple[str, str]:
    """``(code, verifier)`` after the person allowed."""
    verifier, challenge = pkce()
    url = await provider.authorize(client, params(challenge, resource=resource))
    txn = parse_qs(urlsplit(url).query)["txn"][0]
    view = await provider.consent_view(txn)
    assert view is not None
    decision = await provider.approve(txn, view.nonce, provider="self_hosted", provider_user_id=user,
                                      user_name=user.title())
    query = parse_qs(urlsplit(decision.redirect_url).query)
    assert query["state"] == ["state-1"]
    return query["code"][0], verifier


async def tokens(provider: MCPProvider, client, **kw):
    code, _ = await consented(provider, client, **kw)
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    return await provider.exchange_authorization_code(client, loaded)


async def registered(provider: MCPProvider, **kw) -> OAuthClientInformationFull:
    info = client_info(**kw)
    await provider.register_client(info)
    got = await provider.get_client(info.client_id)
    assert got is not None
    return got


# ── settings ───────────────────────────────────────────────────────────────────────────────────────


def test_settings_defaults_and_parse():
    assert MCPSettings() == parse({})[0] and parse({})[1] == []
    assert default_section()["enabled"] is False and default_section()["max_grants_per_user"] == 5
    settings, problems = parse({"dashboard": {"mcp": {"enabled": True, "access_token_ttl": 600,
                                                      "max_grants_per_user": "lots", "label": " gw "}}})
    assert settings.enabled and settings.access_token_ttl == 600 and settings.label == "gw"
    assert settings.max_grants_per_user == 5 and len(problems) == 1
    assert parse({"dashboard": {"mcp": "yes"}})[1] and not parse({"dashboard": {"mcp": "yes"}})[0].enabled
    assert parse({"dashboard": {"mcp": {"enabled": "true"}}})[0].enabled is False
    assert parse({"dashboard": {"mcp": {"refresh_token_ttl": 1}}})[1]
    assert set(SCOPES) == {"bots:read", "bots:prompt", "requests:read", "requests:clarify"}


# ── URL rules ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("uri,ok", [
    ("http://127.0.0.1:33418/callback", True),
    ("http://127.0.0.1/callback", True),
    ("http://localhost:8080/cb", True),
    ("https://app.example.invalid/oauth/callback", True),
    ("http://app.example.invalid/callback", False),  # http to a non-loopback host
    ("http://127.0.0.1.example.invalid/cb", False),
    ("http://localhost@app.example.invalid/cb", False),  # user info
    ("https://user:pw@app.example.invalid/cb", False),
    ("https://app.example.invalid/cb#frag", False),
    ("https://app.example.invalid/cb#", False),
    ("cursor://anysphere.cursor-retrieval/oauth/callback", False),  # custom scheme
    ("javascript:alert(1)", False),
    ("http://[::1]:33418/callback", False),  # outside the plan's loopback list
    ("http://127.0.0.1:99999/cb", False),
    ("https:///nohost", False),
])
def test_redirect_rule(uri, ok):
    assert redirect_uri_allowed(uri) is ok


def test_canonical_resource():
    assert canonical_resource("HTTPS://GW.Example.Invalid:443/mcp/") == RESOURCE
    assert canonical_resource("http://127.0.0.1:9119/mcp") == "http://127.0.0.1:9119/mcp"
    for bad in ("ftp://gw.example.invalid/mcp", "https://gw.example.invalid/mcp?x=1", "/mcp", "",
                "https://gw.example.invalid/mcp#a", "https://u@gw.example.invalid/mcp"):
        with pytest.raises(ValueError):
            canonical_resource(bad)


# ── registration ───────────────────────────────────────────────────────────────────────────────────


def test_register_stores_hash_and_get_client_has_no_secret(provider, store):
    info = client_info(method="client_secret_post")
    with request_bound("203.0.113.5", "agent/1.0"):
        run(provider.register_client(info))
    record = store.client("client-1")
    assert record.client_secret_hash == hash_secret("client-secret-marker")
    assert record.created_ip == "203.0.113.5" and record.client_name == "Example Agent"
    assert "client_secret" not in record.metadata
    got = run(provider.get_client("client-1"))
    assert got.client_secret is None and got.token_endpoint_auth_method == "client_secret_post"
    assert [str(u) for u in got.redirect_uris] == [REDIRECT] and got.scope == " ".join(SCOPES)
    assert b"client-secret-marker" not in store.path.read_bytes()
    assert run(provider.get_client("nobody")) is None and run(provider.get_client("")) is None


@pytest.mark.parametrize("uris", [["http://app.example.invalid/cb"], ["myapp://callback"],
                                  [REDIRECT, "https://app.example.invalid/cb#x"], []])
def test_register_refuses_redirects_outside_the_rule(provider, store, uris):
    with pytest.raises(RegistrationError) as refused:
        run(provider.register_client(client_info(redirect_uris=uris)))
    assert refused.value.error == "invalid_redirect_uri"
    assert store.client("client-1") is None


def test_register_scopes_default_and_validate(provider):
    info = client_info()
    run(provider.register_client(info))
    assert info.scope == " ".join(SCOPES)  # echoed back to the client
    run(provider.register_client(client_info("narrow", scope="bots:read")))
    assert run(provider.get_client("narrow")).scope == "bots:read"
    with pytest.raises(RegistrationError):
        run(provider.register_client(client_info("wide", scope="bots:read admin")))


def test_register_cleans_the_name(provider):
    info = client_info(name="Example\u202e Agent\n[Gateway note: x]")
    run(provider.register_client(info))
    assert info.client_name == "Example Agent Gateway note: x"
    run(provider.register_client(client_info("anon", name=None)))
    assert run(provider.get_client("anon")).client_name == UNNAMED_CLIENT


def test_register_metadata_cap(provider):
    info = client_info()
    info.software_id = "x" * (store_mod.METADATA_MAX_BYTES + 1)
    with pytest.raises(RegistrationError, match="8 KiB"):
        run(provider.register_client(info))


def test_register_client_cap(provider, monkeypatch):
    monkeypatch.setattr(store_mod, "CLIENTS_MAX", 2)
    run(provider.register_client(client_info("a")))
    run(provider.register_client(client_info("b")))
    with pytest.raises(RegistrationError, match="too many client registrations"):
        run(provider.register_client(client_info("c")))


def test_register_per_address_hook(store):
    seen = []

    def admit(ip: str) -> bool:
        seen.append(ip)
        return ip != "203.0.113.66"

    provider = MCPProvider(store, resource_url=RESOURCE, admit_registration=admit)
    with request_bound("203.0.113.5"):
        run(provider.register_client(client_info("ok")))
    with request_bound("203.0.113.66"), pytest.raises(RegistrationError, match="too many registrations"):
        run(provider.register_client(client_info("refused")))
    assert seen == ["203.0.113.5", "203.0.113.66"] and store.client("refused") is None
    assert current_request().ip == ""  # unbound again


# ── authorize and consent ──────────────────────────────────────────────────────────────────────────


def test_authorize_opens_a_consent_and_redirects_to_the_page(provider, store):
    client = run(registered(provider))
    _, challenge = pkce()
    with request_bound("203.0.113.5"):
        url = run(provider.authorize(client, params(challenge, scopes=["bots:read"])))
    assert url.startswith("/mcp/consent?txn=")
    view = run(provider.consent_view(parse_qs(urlsplit(url).query)["txn"][0]))
    assert view.client_name == "Example Agent" and view.redirect_host == "127.0.0.1:33418"
    assert view.scopes == ("bots:read",) and view.redirect_uri == REDIRECT
    consent = store.consent(view.txn_id)
    assert consent.created_ip == "203.0.113.5" and consent.params["resource"] == RESOURCE
    assert consent.params["code_challenge"] == challenge and consent.params["state"] == "state-1"
    assert run(provider.consent_view("unknown")) is None and run(provider.consent_view("")) is None


@pytest.mark.parametrize("resource", ["https://other.example.invalid/mcp", "https://gw.example.invalid/api",
                                      "not a url"])
def test_authorize_refuses_another_resource(provider, resource):
    client = run(registered(provider))
    _, challenge = pkce()
    with pytest.raises(AuthorizeError) as refused:
        run(provider.authorize(client, params(challenge, resource=resource)))
    assert refused.value.error == "invalid_target"


def test_authorize_without_resource_binds_this_one(provider, store):
    client = run(registered(provider))
    code, _ = run(consented(provider, client, resource=None))
    assert run(provider.load_authorization_code(client, code)).resource == RESOURCE
    alt = run(consented(provider, client, resource="https://GW.example.invalid:443/mcp/"))
    assert alt


def test_authorize_refusals(provider, monkeypatch):
    client = run(registered(provider))
    _, challenge = pkce()
    for p, error in ((params(challenge, explicit=False), "invalid_request"),
                     (params("too-short"), "invalid_request"),
                     (params(challenge, scopes=["admin"]), "invalid_scope")):
        with pytest.raises(AuthorizeError) as refused:
            run(provider.authorize(client, p))
        assert refused.value.error == error
    monkeypatch.setattr(store_mod, "CONSENTS_TOTAL", 1)
    run(provider.authorize(client, params(challenge)))
    with pytest.raises(AuthorizeError) as full:
        run(provider.authorize(client, params(challenge)))
    assert full.value.error == "temporarily_unavailable"


def test_deny_redirects_access_denied(provider, store):
    client = run(registered(provider))
    _, challenge = pkce()
    url = run(provider.authorize(client, params(challenge)))
    view = run(provider.consent_view(parse_qs(urlsplit(url).query)["txn"][0]))
    decision = run(provider.deny(view.txn_id, view.nonce))
    query = parse_qs(urlsplit(decision.redirect_url).query)
    assert query["error"] == ["access_denied"] and query["state"] == ["state-1"] and not decision.granted
    assert decision.redirect_url.startswith(REDIRECT)
    with pytest.raises(ConsentInvalid):
        run(provider.approve(view.txn_id, view.nonce, provider="self_hosted", provider_user_id="alice"))


def test_approve_needs_identity_and_the_nonce(provider):
    client = run(registered(provider))
    _, challenge = pkce()
    url = run(provider.authorize(client, params(challenge)))
    view = run(provider.consent_view(parse_qs(urlsplit(url).query)["txn"][0]))
    with pytest.raises(ConsentInvalid):
        run(provider.approve(view.txn_id, view.nonce, provider="", provider_user_id="alice"))
    with pytest.raises(ConsentInvalid):
        run(provider.approve(view.txn_id, "forged", provider="self_hosted", provider_user_id="alice"))
    decision = run(provider.approve(view.txn_id, view.nonce, provider="self_hosted", provider_user_id="alice"))
    assert decision.granted and decision.client_name == "Example Agent"


def test_sixth_grant_per_person_refused_at_consent(store):
    provider = MCPProvider(store, resource_url=RESOURCE, settings=MCPSettings(max_grants_per_user=2))
    client = run(registered(provider))
    run(tokens(provider, client))
    run(tokens(provider, client))
    _, challenge = pkce()
    url = run(provider.authorize(client, params(challenge)))
    view = run(provider.consent_view(parse_qs(urlsplit(url).query)["txn"][0]))
    with pytest.raises(LimitReached):
        run(provider.approve(view.txn_id, view.nonce, provider="self_hosted", provider_user_id="alice"))
    run(tokens(provider, client, user="bob"))


def test_per_person_cap_at_exchange_is_a_token_error(store):
    provider = MCPProvider(store, resource_url=RESOURCE, settings=MCPSettings(max_grants_per_user=1))
    client = run(registered(provider))
    code_a, _ = run(consented(provider, client))
    code_b, _ = run(consented(provider, client))
    a = run(provider.load_authorization_code(client, code_a))
    b = run(provider.load_authorization_code(client, code_b))
    run(provider.exchange_authorization_code(client, a))
    with pytest.raises(TokenError) as refused:
        run(provider.exchange_authorization_code(client, b))
    assert refused.value.error == "invalid_grant" and "revoke one" in (refused.value.error_description or "")


# ── codes and tokens ───────────────────────────────────────────────────────────────────────────────


def test_code_exchange_issues_bound_tokens(provider, store):
    client = run(registered(provider))
    code, _ = run(consented(provider, client))
    loaded = run(provider.load_authorization_code(client, code))
    assert loaded.subject == "self_hosted:alice" and loaded.resource == RESOURCE
    assert loaded.redirect_uri_provided_explicitly and str(loaded.redirect_uri) == REDIRECT
    with request_bound("198.51.100.7", "agent/1.0"):
        token = run(provider.exchange_authorization_code(client, loaded))
    assert token.token_type == "Bearer" and token.expires_in == 3600 and token.scope == " ".join(SCOPES)
    access = run(provider.load_access_token(token.access_token))
    assert access.subject == "self_hosted:alice" and access.client_id == "client-1" and access.resource == RESOURCE
    assert access.claims == {"name": "Alice", "client_name": "Example Agent", "grant_id": access.grant_id,
                             "provider": "self_hosted", "provider_user_id": "alice"}
    grant = store.grant(access.grant_id)
    assert (grant.created_ip, grant.created_user_agent) == ("198.51.100.7", "agent/1.0")


def test_code_single_use_and_reuse_revokes(provider, store):
    client = run(registered(provider))
    code, _ = run(consented(provider, client))
    loaded = run(provider.load_authorization_code(client, code))
    token = run(provider.exchange_authorization_code(client, loaded))
    assert run(provider.load_authorization_code(client, code)) is None
    with pytest.raises(TokenError):
        run(provider.exchange_authorization_code(client, loaded))  # replaying the loaded object
    assert run(provider.load_access_token(token.access_token)) is None
    assert store.grant(loaded.grant_id).revoked_by == BY_CODE_REUSE


def test_two_concurrent_exchanges_of_one_code_one_wins(provider):
    client = run(registered(provider))
    code, _ = run(consented(provider, client))

    async def both():
        return await asyncio.gather(*(provider.load_authorization_code(client, code) for _ in range(5)))

    loaded = [x for x in run(both()) if x is not None]
    assert len(loaded) == 1
    assert run(provider.exchange_authorization_code(client, loaded[0])).access_token


def test_refresh_rotation_and_reuse_revokes_the_grant(provider, store, clock):
    client = run(registered(provider))
    first = run(tokens(provider, client))
    rt = run(provider.load_refresh_token(client, first.refresh_token))
    assert rt.subject == "self_hosted:alice" and rt.scopes == list(SCOPES)
    second = run(provider.exchange_refresh_token(client, rt, rt.scopes))
    assert second.refresh_token != first.refresh_token and second.access_token != first.access_token
    assert run(provider.load_access_token(second.access_token)) is not None
    clock.t += store_mod.REFRESH_RACE_GRACE  # past the parallel-refresh grace
    assert run(provider.load_refresh_token(client, first.refresh_token)) is None  # reuse
    assert store.grant(rt.grant_id).revoked_by == BY_REFRESH_REUSE
    assert run(provider.load_access_token(second.access_token)) is None
    assert run(provider.load_refresh_token(client, second.refresh_token)) is None


def test_refresh_exchange_with_a_stale_object_is_reuse(provider, store, clock):
    client = run(registered(provider))
    first = run(tokens(provider, client))
    rt = run(provider.load_refresh_token(client, first.refresh_token))
    run(provider.exchange_refresh_token(client, rt, rt.scopes))
    with pytest.raises(TokenError) as raced:  # a parallel refresh: refused, the grant stays
        run(provider.exchange_refresh_token(client, rt, rt.scopes))
    assert raced.value.error == "invalid_grant" and store.grant(rt.grant_id).live
    clock.t += store_mod.REFRESH_RACE_GRACE
    with pytest.raises(TokenError) as refused:
        run(provider.exchange_refresh_token(client, rt, rt.scopes))
    assert refused.value.error == "invalid_grant" and store.grant(rt.grant_id).revoked_by == BY_REFRESH_REUSE


def test_refresh_scope_widening_is_invalid_scope(provider):
    client = run(registered(provider, scope="bots:read"))
    first = run(tokens(provider, client))
    rt = run(provider.load_refresh_token(client, first.refresh_token))
    with pytest.raises(TokenError) as refused:
        run(provider.exchange_refresh_token(client, rt, ["bots:read", "bots:prompt"]))
    assert refused.value.error == "invalid_scope"


def test_access_token_expiry(provider, clock):
    client = run(registered(provider))
    token = run(tokens(provider, client))
    clock.t += 3599
    assert run(provider.load_access_token(token.access_token)) is not None
    clock.t += 1
    assert run(provider.load_access_token(token.access_token)) is None


def test_last_used_bumped_at_most_once_a_minute(provider, store, clock):
    client = run(registered(provider))
    token = run(tokens(provider, client))
    with request_bound("192.0.2.1"):
        access = run(provider.load_access_token(token.access_token))
    with request_bound("192.0.2.2"):
        clock.t += 30
        run(provider.load_access_token(token.access_token))
    g = store.grant(access.grant_id)
    assert (g.last_used_ip, g.last_used_at) == ("192.0.2.1", int(clock.t) - 30)
    clock.t += 30
    with request_bound("192.0.2.3"):
        run(provider.load_access_token(token.access_token))
    assert store.grant(access.grant_id).last_used_ip == "192.0.2.3"


def test_verifier_refuses_another_resource(provider, store):
    client = run(registered(provider))
    token = run(tokens(provider, client))
    assert run(MCPTokenVerifier(provider).verify_token(token.access_token)) is not None
    assert run(MCPTokenVerifier(provider, resource_url="https://gw.example.invalid/mcp/").verify_token(
        token.access_token)) is not None
    other = MCPTokenVerifier(provider, resource_url="https://second.example.invalid/mcp")
    assert run(other.verify_token(token.access_token)) is None
    # A provider moved to another primary URL refuses tokens bound to the old one.
    moved = MCPProvider(store, resource_url="https://new.example.invalid/mcp")
    assert run(MCPTokenVerifier(moved).verify_token(token.access_token)) is None
    assert run(MCPTokenVerifier(provider).verify_token(token.refresh_token)) is None
    assert run(MCPTokenVerifier(provider).verify_token("not-a-token")) is None


@pytest.mark.parametrize("kind", ["access", "refresh"])
def test_revoke_either_kind_revokes_the_grant(provider, store, kind):
    client = run(registered(provider))
    token = run(tokens(provider, client))
    loaded = run(provider.load_access_token(token.access_token)) if kind == "access" else \
        run(provider.load_refresh_token(client, token.refresh_token))
    run(provider.revoke_token(loaded))
    assert store.grant(loaded.grant_id).revoked_by == BY_CLIENT
    assert run(provider.load_access_token(token.access_token)) is None
    assert run(provider.load_refresh_token(client, token.refresh_token)) is None


def test_registry_surface(provider):
    client = run(registered(provider))
    run(tokens(provider, client))
    run(tokens(provider, client, user="bob"))
    grants = run(provider.grants_for("self_hosted:alice"))
    assert len(grants) == 1 and grants[0].client_name == "Example Agent"
    assert run(provider.revoke_grant(grants[0].id, by="self_hosted:bob", user_id="self_hosted:bob")) is None
    assert run(provider.revoke_grant(grants[0].id, by="self_hosted:alice", user_id="self_hosted:alice")).revoked_at
    assert run(provider.grants_for("self_hosted:alice")) == []
    run(provider.record_chat(user_id="self_hosted:alice", profile="default", session_key="s1", grant_id=grants[0].id))
    assert [c.session_key for c in run(provider.chats_for("self_hosted:alice", "default"))] == ["s1"]
    assert run(provider.has_chat(user_id="self_hosted:alice", profile="default", session_key="s1"))
    assert not run(provider.has_chat(user_id="self_hosted:bob", profile="default", session_key="s1"))


# ── client authentication ──────────────────────────────────────────────────────────────────────────


def _form_request(form: dict, headers: dict | None = None) -> Request:
    from urllib.parse import urlencode
    body = urlencode(form).encode()
    raw_headers = [(b"content-type", b"application/x-www-form-urlencoded")]
    raw_headers += [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "path": "/mcp/token", "headers": raw_headers,
                    "query_string": b""}, receive)


def test_client_authenticator_against_the_hash(provider):
    run(provider.register_client(client_info("post", method="client_secret_post")))
    run(provider.register_client(client_info("basic", method="client_secret_basic")))
    run(provider.register_client(client_info("public")))
    auth = MCPClientAuthenticator(provider)
    ok = run(auth.authenticate_request(_form_request({"client_id": "post", "client_secret": "client-secret-marker"})))
    assert ok.client_id == "post" and ok.client_secret is None
    basic = base64.b64encode(b"basic:client-secret-marker").decode()
    assert run(auth.authenticate_request(_form_request({"client_id": "basic"},
                                                       {"Authorization": f"Basic {basic}"}))).client_id == "basic"
    assert run(auth.authenticate_request(_form_request({"client_id": "public"}))).client_id == "public"
    for form, headers in (({"client_id": "post", "client_secret": "wrong"}, None),
                          ({"client_id": "post"}, None),
                          ({"client_id": "basic"}, {"Authorization": "Basic " + base64.b64encode(b"basic:no").decode()}),
                          ({"client_id": "basic"}, {"Authorization": "Basic " + base64.b64encode(b"other:client-secret-marker").decode()}),
                          ({"client_id": "basic"}, {"Authorization": "Basic !!!"}),
                          ({"client_id": "nobody"}, None),
                          ({}, None)):
        with pytest.raises(AuthenticationError):
            run(auth.authenticate_request(_form_request(form, headers)))


def test_sdk_default_authenticator_fails_closed_for_secret_clients(provider):
    run(provider.register_client(client_info("post", method="client_secret_post")))
    with pytest.raises(AuthenticationError):
        run(ClientAuthenticator(provider).authenticate_request(
            _form_request({"client_id": "post", "client_secret": "client-secret-marker"})))


# ── the whole flow through the SDK's handlers ──────────────────────────────────────────────────────


def _app(provider: MCPProvider) -> Starlette:
    authenticator = MCPClientAuthenticator(provider)
    options = ClientRegistrationOptions(enabled=True, valid_scopes=list(SCOPES), default_scopes=list(SCOPES))
    return Starlette(routes=[
        Route("/mcp/register", RegistrationHandler(provider, options).handle, methods=["POST"]),
        Route("/mcp/authorize", AuthorizationHandler(provider).handle, methods=["GET"]),
        Route("/mcp/token", TokenHandler(provider, authenticator).handle, methods=["POST"]),
        Route("/mcp/revoke", RevocationHandler(provider, authenticator).handle, methods=["POST"]),
    ])


@pytest.mark.parametrize("method", ["none", "client_secret_post"])
def test_flow_through_the_sdk_handlers(provider, store, clock, method):
    http = TestClient(_app(provider))
    reg = http.post("/mcp/register", json={"redirect_uris": [REDIRECT], "client_name": "Example Agent",
                                           "token_endpoint_auth_method": method,
                                           "grant_types": ["authorization_code", "refresh_token"]})
    assert reg.status_code == 201, reg.text
    client_id, secret = reg.json()["client_id"], reg.json().get("client_secret")
    assert (secret is None) == (method == "none")
    creds = {"client_id": client_id, **({"client_secret": secret} if secret else {})}

    verifier, challenge = pkce()
    auth = http.get("/mcp/authorize", params={"response_type": "code", "client_id": client_id,
                                              "redirect_uri": REDIRECT, "code_challenge": challenge,
                                              "code_challenge_method": "S256", "state": "state-1",
                                              "resource": RESOURCE}, follow_redirects=False)
    assert auth.status_code == 302 and auth.headers["location"].startswith("/mcp/consent?txn=")
    txn = parse_qs(urlsplit(auth.headers["location"]).query)["txn"][0]
    view = run(provider.consent_view(txn))
    decision = run(provider.approve(txn, view.nonce, provider="self_hosted", provider_user_id="alice",
                                    user_name="Alice"))
    code = parse_qs(urlsplit(decision.redirect_url).query)["code"][0]

    # A wrong verifier: the code was taken before the check, so it is burnt.
    bad = http.post("/mcp/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                        "code_verifier": "x" * 50, **creds})
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    again = http.post("/mcp/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                          "code_verifier": verifier, **creds})
    assert again.status_code == 400

    # A fresh consent, the right verifier.
    verifier, challenge = pkce()
    auth = http.get("/mcp/authorize", params={"response_type": "code", "client_id": client_id,
                                              "redirect_uri": REDIRECT, "code_challenge": challenge,
                                              "state": "state-1"}, follow_redirects=False)
    txn = parse_qs(urlsplit(auth.headers["location"]).query)["txn"][0]
    view = run(provider.consent_view(txn))
    code = parse_qs(urlsplit(run(provider.approve(txn, view.nonce, provider="self_hosted",
                                                  provider_user_id="alice")).redirect_url).query)["code"][0]
    ok = http.post("/mcp/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                       "code_verifier": verifier, **creds})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 3600
    assert run(MCPTokenVerifier(provider).verify_token(body["access_token"])).subject == "self_hosted:alice"

    if secret:
        wrong = http.post("/mcp/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"],
                                              "client_id": client_id, "client_secret": "wrong"})
        assert wrong.status_code == 401
    refreshed = http.post("/mcp/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"],
                                              **creds})
    assert refreshed.status_code == 200, refreshed.text
    new = refreshed.json()
    raced = http.post("/mcp/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"],
                                          **creds})
    assert raced.status_code == 400 and raced.json()["error"] == "invalid_grant"
    assert run(MCPTokenVerifier(provider).verify_token(new["access_token"])) is not None  # a parallel refresh
    clock.t += store_mod.REFRESH_RACE_GRACE
    reuse = http.post("/mcp/token", data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"],
                                          **creds})
    assert reuse.status_code == 400 and reuse.json()["error"] == "invalid_grant"
    assert run(MCPTokenVerifier(provider).verify_token(new["access_token"])) is None  # the grant is revoked

    # Revocation endpoint on a fresh grant, with the access token.
    verifier, challenge = pkce()
    auth = http.get("/mcp/authorize", params={"response_type": "code", "client_id": client_id,
                                              "redirect_uri": REDIRECT, "code_challenge": challenge},
                    follow_redirects=False)
    txn = parse_qs(urlsplit(auth.headers["location"]).query)["txn"][0]
    view = run(provider.consent_view(txn))
    code = parse_qs(urlsplit(run(provider.approve(txn, view.nonce, provider="self_hosted",
                                                  provider_user_id="alice")).redirect_url).query)["code"][0]
    third = http.post("/mcp/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                          "code_verifier": verifier, **creds}).json()
    # The SDK's RevocationRequest declares client_secret without a default, so a public client has to send
    # it empty (an SDK quirk the route layer may smooth over).
    assert http.post("/mcp/revoke", data={"token": third["access_token"], "client_secret": "", **creds}
                     ).status_code == 200
    assert run(MCPTokenVerifier(provider).verify_token(third["access_token"])) is None
    refused = http.post("/mcp/token", data={"grant_type": "refresh_token", "refresh_token": third["refresh_token"],
                                            **creds})
    assert refused.status_code == 400
    db = sqlite3.connect(store.path)
    assert {r[0] for r in db.execute("SELECT revoked_by FROM grants")} == {BY_REFRESH_REUSE, BY_CLIENT}


def test_authorize_handler_redirects_invalid_target_to_the_client(provider):
    # The SDK's own handler, as the provider drives it. The gateway's route (``routes.authorize_endpoint``)
    # never passes such a redirect on: it answers the refusal itself (test_routes.py).
    http = TestClient(_app(provider))
    client_id = http.post("/mcp/register", json={"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"}
                          ).json()["client_id"]
    _, challenge = pkce()
    auth = http.get("/mcp/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
                                              "code_challenge": challenge, "state": "s",
                                              "resource": "https://other.example.invalid/mcp"},
                    follow_redirects=False)
    assert auth.status_code == 302
    assert parse_qs(urlsplit(auth.headers["location"]).query)["error"] == ["invalid_target"]


def test_register_handler_refuses_a_custom_scheme(provider):
    http = TestClient(_app(provider))
    reg = http.post("/mcp/register", json={"redirect_uris": ["myapp://cb"], "token_endpoint_auth_method": "none"})
    assert reg.status_code == 400 and reg.json()["error"] == "invalid_redirect_uri"
