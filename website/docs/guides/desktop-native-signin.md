---
sidebar_position: 18
title: "Desktop Native Sign-In (RFC 8252)"
description: "How the Hermes Desktop app signs in to a gated gateway using your system browser and PKCE — no embedded webview, no session cookies"
---

# Desktop Native Sign-In (RFC 8252)

When the Hermes Desktop app connects to a **gated gateway** (a hosted or
self-hosted dashboard that sits behind an OAuth provider), it can sign in two
ways:

1. **Native sign-in (RFC 8252)** — the app opens your **real system browser**,
   you approve in the browser you already trust, and the app receives tokens it
   stores as owner-only files in its user-data directory (optionally encrypted
   with your OS keychain — Settings → Gateway). **No embedded webview, no
   browser session cookies.** This is the default whenever the gateway
   supports it.
2. **Embedded sign-in (legacy fallback)** — the app opens a small in-app
   browser window and captures the gateway's session cookie. Used automatically
   when the gateway is an older build that doesn't advertise native sign-in.

You don't choose between these — the app detects what the gateway supports and
picks the best one. This page explains what happens and why.

## Why native sign-in

Embedding a browser inside a native app for OAuth has well-known downsides:
the login page can't see your existing browser session (so you re-type
credentials and re-do MFA), password managers and passkeys often don't work,
and the app relies on reading a session cookie out of a private webview. RFC
8252 ("OAuth 2.0 for Native Apps") is the industry best practice that avoids
all of that: **do the authorization in the system browser and hand the app its
own tokens.**

For Hermes specifically, native sign-in means:

- **No embedded webview.** The authorization happens in Safari / Chrome /
  Firefox / Edge — whatever you use — with your logins, extensions, and
  passkeys intact.
- **No session cookies.** The app holds an OAuth **access token** (short-lived)
  and **refresh token**, stored as owner-only files — encrypted at rest via
  your OS keychain (Electron `safeStorage`) when the opt-in keychain toggle in
  Settings → Gateway is on. REST calls and WebSocket tickets are authenticated
  with an `Authorization: Bearer` header, not a cookie jar.

## How it works

```
Desktop app                Gateway (/auth/native/*)          Nous Portal (IDP)
   │ 1. open loopback 127.0.0.1:<random port>
   │ 2. system browser ─►  /auth/native/authorize
   │    (PKCE challenge)    (starts the normal PKCE login) ─► /oauth/authorize
   │                        ◄──── code ──── /auth/callback ◄──┘
   │                        3. mint one-time gateway code
   │ ◄─ 302 127.0.0.1/cb?code=… ─┘
   │ 4. POST /auth/native/token (code + PKCE verifier)
   │ ◄─ 5. { access_token, refresh_token, expires_at } ───────┘
   │ 6. store in local token store; use Bearer for REST + WS tickets
```

The gateway **brokers** the flow: it is the authorization server *to the
desktop app* and an OAuth client *to the upstream identity provider* (Nous
Portal). This is required because the upstream `client_id` and permitted
redirect URIs are bound to the gateway's own origin — a desktop app can't be a
direct client of the Portal. The desktop still gets the full RFC 8252
experience: its own PKCE pair, its own loopback redirect, and tokens it owns.

**PKCE (RFC 7636)** protects the loopback hop: the one-time gateway code is
useless without the code verifier, which never leaves the app. The code is
single-use and short-lived.

## Capability detection & fallback

The desktop reads the gateway's public `/api/status` endpoint, which advertises
an `auth_flows` array:

| `auth_flows` value | Meaning |
|--------------------|---------|
| `["cookie", "native_pkce", "native_revoke"]` | Gateway supports native sign-in → the app uses it, and can revoke its grant on sign-out |
| `["cookie", "native_pkce"]` | Gateway supports native sign-in, without the revoke endpoint |
| `["cookie"]` | Gateway supports only the legacy flow → the app uses the embedded webview |
| *(field absent)* | Older gateway → the app uses the embedded webview |

Read `auth_flows` as a set and test for the member you need: a gateway may
advertise members a client does not know, and the order carries no meaning.
`native_revoke` is advertised on every gated gateway that has the endpoint.

If native sign-in is advertised but fails for a local reason — e.g. a security
tool blocks the loopback listener, or you close the browser tab — the app
**falls back to the embedded flow automatically** so you can still sign in.

## Token lifecycle

- **Access token**: short-lived (minutes). Sent as `Authorization: Bearer` on
  every REST call and when minting a WebSocket ticket.
- **Refresh token**: longer-lived, rotating. When the access token is near
  expiry the app calls `/auth/native/refresh` to rotate both tokens, then
  updates its token store.
- **Terminal expiry**: if the refresh token is dead (expired / revoked /
  reuse-detected), the app clears its stored tokens and prompts a fresh
  sign-in.
- **Sign out**: clears both the stored native tokens and any legacy session
  cookie for that gateway. When the gateway advertises `native_revoke`, the
  app first hands its refresh token to `/auth/native/revoke` so the gateway can
  end the grant at the identity provider (see below).

## Revoking a native grant

`POST /auth/native/revoke` is the native counterpart of `/auth/logout`, for a
client that holds its refresh token itself rather than in a cookie:

```http
POST /auth/native/revoke
Content-Type: application/json

{"refresh_token": "<the client's refresh token>", "provider": "<provider name>"}
```

- `provider` is the `provider` value `/auth/native/token` and
  `/auth/native/refresh` returned with the token. When it names a registered
  provider, the token is handed to that provider only; without it, or with a
  name the gateway does not know, every interactive provider is tried in turn.
  Always send it: a token is then never shown to an identity provider that did
  not issue it.
- The answer is `200 {"ok": true}` for every well-formed request, whether the
  token was live, already dead or never issued, so the endpoint cannot be used
  to test a token. A missing `refresh_token` is `400`, a body over 16 KiB `413`,
  and more than 30 requests a minute from one address `429`.
- What "revoked" means is the provider's: an OIDC provider whose discovery
  document advertises a `revocation_endpoint` gets an RFC 7009 revocation
  request, and a refresh with that token then fails. The bundled password
  provider (`basic`) has stateless tokens and the Nous Portal offers no
  revocation grant: for those nothing is revoked, and the refresh token keeps
  working until it expires. A client must delete its own copy either way.
- An access token already issued stays valid until it expires; the gateway
  verifies access tokens without asking the provider.
- No session is needed (the refresh token is the authority, and no cookie is
  read), and the request is recorded in the dashboard-auth audit log as a
  `revoke` event that names the providers it went to and never the token.

## For gateway operators

Native sign-in is available automatically on any gated gateway with an
interactive session provider registered. No configuration is required — the
`/auth/native/*` routes and the `auth_flows` advertisement are part of the
dashboard-auth subsystem. OAuth providers (e.g. the bundled **Nous** provider)
broker the upstream IDP redirect; password providers (e.g. the bundled
**basic-auth** plugin) land the system browser on the gateway's `/login`
credential form instead — which is what lets OS password managers (macOS
Passwords, etc.) autofill the form, something no embedded desktop webview can
offer. Token-only credentials (e.g. drain) are not interactive sign-ins and do
not advertise `native_pkce`.

The relevant endpoints (all public, pre-auth bootstrap, same as the existing
`/auth/*` OAuth routes):

- `GET /auth/native/authorize` — starts the brokered PKCE login
- `POST /auth/native/token` — exchanges the loopback code + verifier for tokens
- `POST /auth/native/refresh` — rotates tokens from the app's refresh token
- `POST /auth/native/revoke` — ends the app's grant (best effort, always `{"ok": true}`)

## See also

- [OAuth over SSH / Remote Hosts](./oauth-over-ssh.md) — the loopback-callback
  pattern for provider/MCP OAuth on remote machines.
- [Run Hermes with Nous Portal](./run-hermes-with-nous-portal.md)
