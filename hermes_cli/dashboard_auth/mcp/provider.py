"""The OAuth 2.1 authorization server behind ``/mcp``: the SDK's provider protocol over :class:`MCPStore`.

The gateway is the authorization server to MCP clients (issuer ``https://<primary public URL>/mcp``);
the identity provider stays behind the dashboard's cookie login, which the consent page uses. The SDK's
handlers (``/mcp/authorize``, ``/mcp/token``, ``/mcp/register``, ``/mcp/revoke``) call this provider;
the consent page calls :meth:`MCPProvider.consent_view`, :meth:`MCPProvider.approve` and
:meth:`MCPProvider.deny`; the ``/mcp`` endpoint admits a call only through :class:`MCPTokenVerifier`.

Rules (plan ``gateway-mcp.md`` D2-D4, Security 3-4):

- registration (RFC 7591): every redirect URI is ``https://`` or ``http://`` to ``127.0.0.1`` /
  ``localhost`` (no other ``http://``, no custom scheme, no fragment, no user info); metadata at most
  8 KiB; at most :data:`~.store.CLIENTS_MAX` registrations; an optional per-address admission hook;
  scopes a subset of :data:`~.settings.SCOPES` (all of them when none is asked for). A client secret is
  stored as its hash, so the token and revocation routes must authenticate clients with
  :class:`MCPClientAuthenticator` (the SDK's own authenticator compares a plaintext secret and refuses
  every secret client of this provider: it fails closed);
- authorize: PKCE S256 (the SDK accepts no other method; the challenge must have the S256 shape), an
  explicit ``redirect_uri``, and a ``resource`` (RFC 8707) that, when present, names this endpoint
  (else ``invalid_target``). The result is a consent transaction and a redirect to the consent page;
- a code is single use and is marked used when it is loaded, before the SDK checks the PKCE verifier;
  its grant and token family are minted in one transaction; a person holds at most
  ``max_grants_per_user`` live grants;
- tokens are opaque (256 bits), stored as SHA-256; access ``access_token_ttl``; refresh rotated on every
  use with ``refresh_token_ttl`` (sliding) and never past the grant's ``grant_max_age`` (absolute);
  presenting a rotated refresh token revokes the grant; revoking either kind revokes the grant;
- every token is bound to the resource it was issued for, and the verifier refuses a token of another
  resource.

The SDK's handlers do not pass the request to the provider. The route layer binds the client's address
and user agent around each call with :func:`bind_request`; without it they are recorded as "".

Store calls run on a worker thread (SQLite's busy wait must not block the event loop). A
:class:`~.store.StoreError` other than the refusals mapped below propagates: the caller answers it as a
server error, never as a success.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import functools
import re
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional
from urllib.parse import unquote, urlencode, urlsplit

import anyio.to_thread
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError, OAuthAuthorizationServerProvider,
    RefreshToken, RegistrationError, TokenError, TokenVerifier, construct_redirect_uri)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.requests import Request

from agent.turn_sender import NAME_LIMIT, clean_value
from hermes_cli.dashboard_auth.mcp.settings import SCOPES, MCPSettings
from hermes_cli.dashboard_auth.mcp.store import (
    BY_CLIENT, Chat, ClientRecord, CodeInvalid, ConsentInvalid, Grant, Issued, LimitReached, MCPStore, TokenInvalid)

UNNAMED_CLIENT = "MCP client"
TOKEN_AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")
USER_AGENT_LIMIT = 256
_S256_CHALLENGE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


# ── the request the SDK does not hand over ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class RequestInfo:
    ip: str = ""
    user_agent: str = ""


_UNBOUND = RequestInfo()
_request: ContextVar[RequestInfo] = ContextVar("dashboard_mcp_auth_request", default=_UNBOUND)


def bind_request(ip: str, user_agent: str = "") -> Token[RequestInfo]:
    """Make the client's settled address and user agent visible to the provider for this context."""
    return _request.set(RequestInfo(ip=str(ip or ""), user_agent=str(user_agent or "")[:USER_AGENT_LIMIT]))


def reset_request(token: Token[RequestInfo]) -> None:
    _request.reset(token)


@contextlib.contextmanager
def request_bound(ip: str, user_agent: str = "") -> Iterator[None]:
    token = bind_request(ip, user_agent)
    try:
        yield
    finally:
        reset_request(token)


def current_request() -> RequestInfo:
    return _request.get()


# ── URL rules ──────────────────────────────────────────────────────────────────────────────────


def canonical_resource(url: str) -> str:
    """*url* in the form resources are compared in: scheme and host lowercased, the default port
    dropped, no trailing slash. ``ValueError`` for anything that is not an absolute http(s) URL without
    query, fragment or user info."""
    text = str(url or "").strip()
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment or "#" in text \
            or parts.username is not None or parts.password is not None:
        raise ValueError("not a resource URL")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port  # ValueError for a bad port
    netloc = host if port is None or port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}"


def redirect_uri_allowed(uri: str) -> bool:
    """Security 3: ``https://<host>/…`` or ``http://127.0.0.1|localhost[:port]/…``; nothing else (no
    other ``http://`` host, no custom scheme, no fragment, no user info, no bad port)."""
    text = str(uri or "")
    parts = urlsplit(text)
    if "#" in text or parts.username is not None or parts.password is not None:
        return False
    try:
        _ = parts.port
    except ValueError:
        return False
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme == "https":
        return bool(host)
    return scheme == "http" and host in LOOPBACK_HOSTS


def person_id(provider: str, provider_user_id: str) -> str:
    """``<provider>:<user id>``, the author-stamp id (as ``_transport_auth_user`` builds it)."""
    return f"{str(provider or '').strip()}:{str(provider_user_id or '').strip()}"


def client_display_name(name: Any) -> str:
    """A registered client's name as the gateway shows and stamps it: one cleaned line, at most 80
    characters, :data:`UNNAMED_CLIENT` when nothing is left. Attacker-chosen text: show it with the
    redirect host."""
    return clean_value(name, NAME_LIMIT) or UNNAMED_CLIENT


def _dedupe(values: Any) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


# ── the SDK's models, with what this provider needs to carry ───────────────────────────────────


class MCPAuthorizationCode(AuthorizationCode):
    grant_id: str  # reserved when the code was taken; the exchange gives the grant this id
    user_name: str = ""
    provider: str = ""


class MCPRefreshToken(RefreshToken):
    grant_id: str


class MCPAccessToken(AccessToken):
    grant_id: str


@dataclass(frozen=True)
class ConsentView:
    """What the consent page shows (and the form posts back: ``txn_id`` and ``nonce``)."""
    txn_id: str
    nonce: str
    client_id: str
    client_name: str
    redirect_uri: str
    redirect_host: str
    scopes: tuple[str, ...]
    expires_at: int


@dataclass(frozen=True)
class ConsentDecision:
    """Where the consent page sends the browser after a decision, and what to audit."""
    redirect_url: str
    client_id: str
    client_name: str
    scopes: tuple[str, ...]
    granted: bool


class MCPProvider(OAuthAuthorizationServerProvider[MCPAuthorizationCode, MCPRefreshToken, MCPAccessToken]):
    """*resource_url* is the endpoint tokens are for (``https://<primary>/mcp``); *consent_url* the page
    :meth:`authorize` redirects to; *admit_registration*, called with the client's address, refuses a
    registration when it returns False (the route layer's per-address limit)."""

    def __init__(self, store: MCPStore, *, resource_url: str, settings: Optional[MCPSettings] = None,
                 consent_url: str = "/mcp/consent", admit_registration: Optional[Callable[[str], bool]] = None):
        self.store = store
        self.resource = canonical_resource(resource_url)
        self.settings = settings or MCPSettings()
        self.consent_url = consent_url
        self._admit_registration = admit_registration

    @staticmethod
    async def _run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))

    def resource_matches(self, resource: Optional[str]) -> bool:
        """True when *resource* is absent or names this endpoint (for a token request's ``resource``,
        which the SDK's token handler does not pass on)."""
        if resource is None or resource == "":
            return True
        try:
            return canonical_resource(resource) == self.resource
        except ValueError:
            return False

    # ── clients ──────────────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _client_info(record: ClientRecord) -> OAuthClientInformationFull:
        data = dict(record.metadata)
        data.pop("client_secret", None)
        data["client_id"] = record.client_id
        data["client_name"] = record.client_name
        data["redirect_uris"] = list(record.redirect_uris)
        data["token_endpoint_auth_method"] = record.token_endpoint_auth_method
        return OAuthClientInformationFull.model_validate(data)  # no secret: only its hash is stored

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        record = await self._run(self.store.client, client_id) if client_id else None
        return self._client_info(record) if record else None

    async def client_record(self, client_id: str) -> Optional[ClientRecord]:
        return await self._run(self.store.client, client_id) if client_id else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        ip = current_request().ip
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "at least one redirect URI is required")
        if not all(redirect_uri_allowed(u) for u in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect URIs must be https:// or http:// to 127.0.0.1 or localhost, without a fragment")
        method = client_info.token_endpoint_auth_method or "client_secret_post"
        if method not in TOKEN_AUTH_METHODS:
            raise RegistrationError("invalid_client_metadata",
                                    f"token_endpoint_auth_method must be one of {', '.join(TOKEN_AUTH_METHODS)}")
        if method != "none" and not client_info.client_secret:
            raise RegistrationError("invalid_client_metadata", "a secret-based client needs a secret")
        if client_info.scope is None or not client_info.scope.strip():
            client_info.scope = " ".join(SCOPES)
        elif not set(client_info.scope.split()) <= set(SCOPES):
            raise RegistrationError("invalid_client_metadata", f"scopes must be among: {' '.join(SCOPES)}")
        name = client_display_name(client_info.client_name)
        client_info.client_name = name  # echoed back with the registration
        client_info.token_endpoint_auth_method = method
        if self._admit_registration is not None and not self._admit_registration(ip):
            raise RegistrationError("invalid_client_metadata",
                                    "too many registrations from this address; try again later")
        metadata = client_info.model_dump(mode="json", exclude={"client_secret"}, exclude_none=True)
        try:
            await self._run(self.store.add_client, client_id=client_info.client_id,
                            client_secret=client_info.client_secret if method != "none" else None,
                            client_name=name, redirect_uris=uris, token_endpoint_auth_method=method,
                            metadata=metadata, created_ip=ip)
        except ValueError as exc:
            raise RegistrationError("invalid_client_metadata", "client metadata is larger than 8 KiB") from exc
        except LimitReached as exc:
            raise RegistrationError("invalid_client_metadata",
                                    "this gateway holds too many client registrations; try again later") from exc

    # ── authorize and consent ────────────────────────────────────────────────────────────────────

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not params.redirect_uri_provided_explicitly:
            raise AuthorizeError("invalid_request", "redirect_uri is required")
        redirect_uri = str(params.redirect_uri)
        if not redirect_uri_allowed(redirect_uri):
            raise AuthorizeError("invalid_request", "redirect_uri is not allowed")
        if not self.resource_matches(params.resource):
            raise AuthorizeError("invalid_target", "resource is not this gateway's MCP endpoint")
        if not _S256_CHALLENGE.fullmatch(params.code_challenge or ""):
            raise AuthorizeError("invalid_request", "code_challenge must be an S256 challenge")
        scopes = _dedupe(params.scopes or (client.scope or "").split() or SCOPES)
        if not set(scopes) <= set(SCOPES):
            raise AuthorizeError("invalid_scope", f"scopes must be among: {' '.join(SCOPES)}")
        consent_params = {
            "scopes": scopes, "code_challenge": params.code_challenge, "redirect_uri": redirect_uri,
            "redirect_uri_provided_explicitly": True, "resource": self.resource, "state": params.state}
        try:
            consent = await self._run(self.store.open_consent, client_id=client.client_id, params=consent_params,
                                      created_ip=current_request().ip)
        except LimitReached as exc:
            raise AuthorizeError("temporarily_unavailable",
                                 "too many sign-ins are waiting; try again in a few minutes") from exc
        except ConsentInvalid as exc:
            raise AuthorizeError("unauthorized_client", "unknown client") from exc
        return f"{self.consent_url}?{urlencode({'txn': consent.txn_id})}"

    async def consent_view(self, txn_id: str) -> Optional[ConsentView]:
        """The open transaction as the consent page shows it, or None (unknown, expired, decided)."""
        consent = await self._run(self.store.consent, txn_id) if txn_id else None
        if consent is None:
            return None
        record = await self._run(self.store.client, consent.client_id)
        if record is None:
            return None
        redirect_uri = consent.params["redirect_uri"]
        return ConsentView(txn_id=consent.txn_id, nonce=consent.nonce, client_id=consent.client_id,
                           client_name=record.client_name, redirect_uri=redirect_uri,
                           redirect_host=urlsplit(redirect_uri).netloc, scopes=tuple(consent.params["scopes"]),
                           expires_at=consent.expires_at)

    async def approve(self, txn_id: str, nonce: str, *, provider: str, provider_user_id: str,
                      user_name: str = "") -> ConsentDecision:
        """The signed-in person allowed. Mints the code and returns the redirect back to the client.

        Raises :class:`~.store.ConsentInvalid` (unknown, expired or decided transaction, wrong nonce, no
        identity) or :class:`~.store.LimitReached` ``grants_per_user`` (the transaction stays open: the
        person can revoke a grant and allow again)."""
        if not str(provider or "").strip() or not str(provider_user_id or "").strip():
            raise ConsentInvalid("no_identity")
        code, consent = await self._run(
            self.store.issue_code, txn_id=txn_id, nonce=nonce, user_id=person_id(provider, provider_user_id),
            user_name=clean_value(user_name, NAME_LIMIT), provider=str(provider).strip(),
            max_grants=self.settings.max_grants_per_user)
        record = await self._run(self.store.client, consent.client_id)
        url = construct_redirect_uri(consent.params["redirect_uri"], code=code, state=consent.params.get("state"))
        return ConsentDecision(redirect_url=url, client_id=consent.client_id,
                               client_name=record.client_name if record else UNNAMED_CLIENT,
                               scopes=tuple(consent.params["scopes"]), granted=True)

    async def deny(self, txn_id: str, nonce: str) -> ConsentDecision:
        """The person refused: the transaction is closed and the client told ``access_denied``."""
        consent = await self._run(self.store.deny_consent, txn_id=txn_id, nonce=nonce)
        record = await self._run(self.store.client, consent.client_id)
        url = construct_redirect_uri(consent.params["redirect_uri"], error="access_denied",
                                     error_description="The person did not allow access.",
                                     state=consent.params.get("state"))
        return ConsentDecision(redirect_url=url, client_id=consent.client_id,
                               client_name=record.client_name if record else UNNAMED_CLIENT,
                               scopes=tuple(consent.params["scopes"]), granted=False)

    # ── codes ────────────────────────────────────────────────────────────────────────────────────

    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> Optional[MCPAuthorizationCode]:
        # Taking marks the code used: the SDK checks the PKCE verifier only after this, so a wrong
        # verifier burns the code, and of two concurrent exchanges only one gets it.
        taken = await self._run(self.store.take_code, authorization_code, client_id=client.client_id)
        if taken is None:
            return None
        return MCPAuthorizationCode(
            code=authorization_code, scopes=list(taken.scopes), expires_at=float(taken.expires_at),
            client_id=taken.client_id, code_challenge=taken.code_challenge, redirect_uri=AnyUrl(taken.redirect_uri),
            redirect_uri_provided_explicitly=True, resource=taken.resource, subject=taken.user_id,
            grant_id=taken.grant_id, user_name=taken.user_name, provider=taken.provider)

    def _token_response(self, issued: Issued) -> OAuthToken:
        return OAuthToken(access_token=issued.access_token, token_type="Bearer",
                          expires_in=max(0, issued.access_expires_at - issued.issued_at),
                          scope=" ".join(issued.scopes), refresh_token=issued.refresh_token)

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: MCPAuthorizationCode) -> OAuthToken:
        request = current_request()
        s = self.settings
        try:
            issued = await self._run(
                self.store.exchange_code, code=authorization_code.code, grant_id=authorization_code.grant_id,
                client_id=client.client_id, access_ttl=s.access_token_ttl, refresh_ttl=s.refresh_token_ttl,
                grant_max_age=s.grant_max_age, max_grants=s.max_grants_per_user, created_ip=request.ip,
                created_user_agent=request.user_agent)
        except LimitReached as exc:
            raise TokenError("invalid_grant",
                             f"this person already has {s.max_grants_per_user} connected MCP clients; revoke one "
                             "in Settings › MCP and connect again") from exc
        except CodeInvalid as exc:
            raise TokenError("invalid_grant", "authorization code is invalid") from exc
        return self._token_response(issued)

    # ── refresh tokens ───────────────────────────────────────────────────────────────────────────

    async def load_refresh_token(self, client: OAuthClientInformationFull,
                                 refresh_token: str) -> Optional[MCPRefreshToken]:
        found = await self._run(self.store.load_refresh, refresh_token, client_id=client.client_id)
        if found is None:
            return None
        return MCPRefreshToken(token=refresh_token, client_id=found.grant.client_id, scopes=list(found.scopes),
                               expires_at=found.expires_at, subject=found.grant.user_id, grant_id=found.grant.id)

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: MCPRefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        s = self.settings
        try:
            issued = await self._run(self.store.rotate_refresh, refresh_token.token, client_id=client.client_id,
                                     scopes=scopes, access_ttl=s.access_token_ttl, refresh_ttl=s.refresh_token_ttl)
        except TokenInvalid as exc:
            if exc.reason == "scope":
                raise TokenError("invalid_scope", "cannot widen the scopes of a refresh token") from exc
            raise TokenError("invalid_grant", "refresh token is invalid") from exc
        return self._token_response(issued)

    # ── access tokens and revocation ─────────────────────────────────────────────────────────────

    async def load_access_token(self, token: str) -> Optional[MCPAccessToken]:
        found = await self._run(self.store.verify_access, token, ip=current_request().ip)
        if found is None:
            return None
        g = found.grant
        prefix = f"{g.provider}:"
        claims = {"name": g.user_name, "client_name": g.client_name, "grant_id": g.id, "provider": g.provider,
                  "provider_user_id": g.user_id[len(prefix):] if g.user_id.startswith(prefix) else g.user_id}
        return MCPAccessToken(token=token, client_id=g.client_id, scopes=list(found.scopes),
                              expires_at=found.expires_at, resource=g.resource, subject=g.user_id, claims=claims,
                              grant_id=g.id)

    async def revoke_token(self, token: MCPAccessToken | MCPRefreshToken) -> None:
        grant_id = getattr(token, "grant_id", None)
        if grant_id:
            await self._run(self.store.revoke_grant, grant_id, by=BY_CLIENT)

    # ── the registry, for the REST routes, the tools and the CLI's async callers ─────────────────

    async def revoke_grant(self, grant_id: str, *, by: str, user_id: Optional[str] = None,
                           live_only: bool = False) -> Optional[Grant]:
        return await self._run(self.store.revoke_grant, grant_id, by=by, user_id=user_id, live_only=live_only)

    async def grants_for(self, user_id: str) -> list[Grant]:
        return await self._run(self.store.grants_for, user_id)

    async def record_chat(self, *, user_id: str, profile: str, session_key: str, grant_id: str) -> Chat:
        return await self._run(self.store.record_chat, user_id=user_id, profile=profile, session_key=session_key,
                               grant_id=grant_id)

    async def chats_for(self, user_id: str, profile: Optional[str] = None) -> list[Chat]:
        return await self._run(self.store.chats_for, user_id, profile)

    async def has_chat(self, *, user_id: str, profile: str, session_key: str) -> bool:
        return await self._run(self.store.has_chat, user_id=user_id, profile=profile, session_key=session_key)


class MCPTokenVerifier(TokenVerifier):
    """The only admission to ``/mcp``: a live access token of this store, issued for *resource_url* (by
    default the provider's resource). A token for another resource is refused like an unknown one."""

    def __init__(self, provider: MCPProvider, *, resource_url: Optional[str] = None):
        self.provider = provider
        self.resource = canonical_resource(resource_url) if resource_url else provider.resource

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        found = await self.provider.load_access_token(token)
        if found is None or not found.resource:
            return None
        try:
            if canonical_resource(found.resource) != self.resource:
                return None
        except ValueError:
            return None
        return found


class MCPClientAuthenticator(ClientAuthenticator):
    """The SDK's client authentication (same methods, same errors) against the stored secret hash."""

    def __init__(self, provider: MCPProvider):
        super().__init__(provider)
        self.mcp_provider = provider

    async def authenticate_request(self, request: Request) -> OAuthClientInformationFull:
        form = await request.form()
        client_id = form.get("client_id")
        if not client_id or not isinstance(client_id, str):
            raise AuthenticationError("Missing client_id")
        record = await self.mcp_provider.client_record(client_id)
        if record is None:
            raise AuthenticationError("Invalid client_id")
        method = record.token_endpoint_auth_method
        secret: Optional[str] = None
        if method == "client_secret_basic":
            header = request.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                raise AuthenticationError("Missing or invalid Basic authentication in Authorization header")
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
                raise AuthenticationError("Invalid Basic authentication header") from exc
            if ":" not in decoded:
                raise AuthenticationError("Invalid Basic authentication header")
            basic_id, secret = (unquote(part) for part in decoded.split(":", 1))
            if basic_id != client_id:
                raise AuthenticationError("Client ID mismatch in Basic auth")
        elif method == "client_secret_post":
            raw = form.get("client_secret")
            secret = raw if isinstance(raw, str) else None
        elif method != "none":
            raise AuthenticationError(f"Unsupported auth method: {method}")
        if method != "none":
            if not secret:
                raise AuthenticationError("Client secret is required")
            matches = await MCPProvider._run(self.mcp_provider.store.client_secret_matches, client_id, secret)
            if not matches:
                raise AuthenticationError("Invalid client_secret")
        return MCPProvider._client_info(record)
