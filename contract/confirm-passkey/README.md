# Contract: `confirm` at level `passkey`

This directory is the single written definition of how a `confirm` request at level `passkey` is
proven: the challenge construction, base URL serialisation, wire objects, and the order in which a
gateway verifies an answer. `vectors.json` holds test vectors every implementation (gateway, native
app, browser client, fake gateway) must pass; `generate.py` produces and checks them; `SHA256SUMS` pins
the three files.

The source of truth is the gateway's repository (the gateway is the verifier). Other repositories carry
a byte-identical copy of this directory; `sha256sum -c SHA256SUMS` (or `shasum -a 256 -c SHA256SUMS`)
checks a copy, and `python generate.py --check` rebuilds and compares everything.

Status: contract version 1. The gateway does not offer the level yet; until it does, a `passkey`
request is `unavailable` and nothing is sent. Nothing here changes level `plain`. Self-enrolment (a
fresh sign-in as an enrolment authority, §7.2 and §8) is an additive part of version 1: optional fields,
one new route and no change to any cryptographic construction or vector.

Structured fields (§4.1) add a second TEXT version: a `confirm` with `fields` carries `passkey.v: 2` and
its challenge commits to `text_digest_v2`. It is additive and opt-in on both sides: the gateway sends a
version-2 frame only to a connection that advertised `confirm_passkey {v: 2}` and `confirm_fields: true`
(§8), every version-1 vector and construction is unchanged, and the version-2 vectors live under keys of
their own (§13), so a client that does not do version 2 yet keeps passing the file.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119. Where this document and `vectors.json`
disagree, that is a bug in one of them; report it rather than picking one.

## 1. What a verified confirmation proves

A `confirmed` answer with `verified: true` means: a credential enrolled for this gateway user signed,
with user presence and user verification as reported by its authenticator, a challenge that commits to
this gateway's base URL and id, this session, this request id, a fresh nonce, and the SHA-256 of the
exact title, summary and detail the gateway sent (and, for a request with structured fields, those fields in
their order: §4.1).

"Enrolled for this gateway user" means one of three things (§7): the operator gave a code, the user
minted a code with an earlier passkey of their own, or the user signed in again, the identity provider
(or the gateway's own password check) reported that sign-in as fresh, and the gateway bound it to the
client that enrols.

It does not prove a biometric (user verification may be a device passcode or a password manager's PIN),
hardware (no attestation is checked), that the person understood the text, that the agent then does what
it described, or anything on a gateway that is itself compromised (the gateway is the verifier).
Where the operator allows self-enrolment, it also does not prove more than the sign-in does: whoever can
pass a fresh primary authentication as the person (and holds a session for them) can enrol a passkey and
then confirm with it. A gateway whose operator wants more switches self-enrolment off and keeps the codes.

## 2. Encoding

- Binary values on the wire and in the vectors are **base64url without padding** (RFC 4648 §5).
  A decoder MUST refuse padding (`=`), characters outside the alphabet, and non-canonical trailing bits
  (re-encoding the decoded bytes must give the input back).
- `S(s)` = 4-byte big-endian length of the UTF-8 encoding of `s`, followed by those bytes.
- `LP(b)` = 4-byte big-endian length of `b`, followed by `b`.
- `‖` is concatenation. `SHA-256` is FIPS 180-4.
- Strings are hashed exactly as received or rendered: no Unicode normalisation, no trimming, no
  newline conversion. The vectors include a precomposed and a decomposed `é` that give different digests.

## 3. Base URL serialisation

A gateway is named by its **base URL**: the URL it is reached at, including any path prefix (two
gateways may share a host under `/alice` and `/bob`). It is serialised as `origin` followed by the
normalised path prefix:

- `origin` is the WHATWG URL "ASCII serialization of an origin", `scheme://host[:port]`:
  - `scheme` is `http` or `https`, lower case. Anything else is not a base URL.
  - a domain host is lower-cased and each label converted to an A-label with UTS #46
    **non-transitional** processing (the WHATWG URL host parser); `ß` stays `ß` and becomes
    `xn--strae-oqa`, never `ss`. IPv4 in dotted-decimal form; IPv6 in brackets, lower case, compressed
    as RFC 5952 (`[2001:db8::1]`).
  - `port` is omitted when it is the scheme's default (443 for https, 80 for http), kept otherwise.
- The path prefix is the URL's path with trailing `/` removed (so `/` and the empty path give no prefix).
  It is case-sensitive and kept as written, except that percent-encoded triplets are upper-cased
  (`%2f` → `%2F`). An empty segment (`//`), a `.` or `..` segment, or a character outside RFC 3986
  `pchar` makes the URL not a base URL.
- Query, fragment and userinfo are never part of it.

Examples: `HTTPS://GW.Example.COM:443/` → `https://gw.example.com`;
`https://shared.example/alice/` → `https://shared.example/alice`.

Where it comes from:

| Side | Source |
| --- | --- |
| Native app | the gateway address it connected to, as stored for that gateway |
| Browser | `location.origin` (a browser client is only offered the level on a base URL without a path prefix, §10) |
| Gateway | each base URL in the operator's own list for this level (`confirm.passkey.base_urls`), serialised the same way. Not the dashboard's public URLs: a dashboard session can change those, and another gateway's address on the list would let answers given to that gateway verify here (§5, "What binds an answer to one gateway") |

`base_url_vectors` lists inputs, the expected base URL, its origin, and whether it counts as private
(§10), plus inputs that are not base URLs.

## 4. Text digest

```
text_digest = SHA-256( S("hermie-confirm-text-v1") ‖ S(title) ‖ S(summary) ‖ S(detail or "") )
```

`detail` absent, `null` and `""` give the same digest. For a `confirm`, title, summary and detail are
the strings in the request frame's params, which are also exactly what the client renders. A client
MUST compute the digest from the values its sheet displays, never from a second copy.

### 4.1 Structured fields (text version 2)

A `confirm` MAY carry `fields`: the key facts of the action (an amount, a recipient, a model…), shown apart
from the summary and detail. The gateway builds them; the agent never passes a frame through.

```json
"fields": [ { "id": "cost",   "kind": "amount", "label": "Estimated cost", "value": "4.20", "currency": "€" },
            { "id": "tokens", "kind": "count",  "label": "tokens",         "value": "1,200,000" },
            { "id": "model",  "kind": "model",  "label": "Model",          "value": "claude-opus-5-5" } ]
```

| Key | Rule |
| --- | --- |
| `fields` | absent, or 1 to **8** objects, in display order; never an empty list |
| `id` | `^[a-z][a-z0-9_]{0,31}$`, unique within the request |
| `kind` | `amount`, `text`, `recipient`, `domain`, `model`, `count`, `date` |
| `label` | 1 to **40** code points |
| `value` | 1 to **200** code points |
| `currency` | optional, 1 to **16** code points, only with `kind: amount` |

Lengths count Unicode code points (§6.3 of `contract/requests`). `label`, `value` and `currency` are each ONE
line and follow the verbatim character rules of `contract/requests` §6.2: no line break of any kind, no
control or format character (bidi marks, embeddings, overrides and isolates, zero-width characters), no
whitespace other than U+0020, no invisible letter, no default-ignorable code point, no unassigned code point,
at most 4 combining marks in a row, no run of more than 16 spaces, and no space at either end. The gateway
removes U+0020 at either end of what the agent wrote and REFUSES everything else above (the agent is told to
fix it); it rewrites nothing else, so what a client shows is exactly what was hashed.

Rendering (both levels): every field is shown, in order, as its label and its value, as plain text; a client
never parses, converts, rounds, localises or links a value, and never truncates or ellipsizes a label, value
or currency: one that does not fit wraps onto more lines. A client MUST refuse (error 4040, as for a frame it
cannot run) a frame whose `fields` break the rules above (count, keys, `id`, `kind`, lengths, `currency` off
an `amount`, a refused character): it shows nothing of it rather than part of it. `amount`: the value large and bold with
`currency` beside it; `recipient` and `domain`: monospaced, never a link; the other kinds plain. A client
that cannot show a field shows none of the request: it does not advertise `confirm_fields`.

Gating: a `confirm` with `fields` goes only to connections that advertised `confirm_fields: true` (§8) and,
at level `passkey`, also `confirm_passkey {v: 2}`. When none is attached the request is `unavailable
(no_capable_client)` and NOTHING is sent: a client that would drop the fields would ask the person to confirm
less than the agent asked.

At level `passkey` such a request is **version 2**: `passkey.v` is 2 and the challenge (§5) commits to

```
text_digest_v2 = SHA-256( S("hermie-confirm-text-v2") ‖ S(title) ‖ S(summary) ‖ S(detail or "") ‖ FIELDS )
FIELDS         = for each field, in the frame's order: S(id) ‖ S(kind) ‖ S(label) ‖ S(value) ‖ S(currency or "")
```

`currency` absent gives `S("")`. The order is part of the text: the same fields in another order give another
digest. A request without `fields` is version 1 and uses §4 unchanged. `text_digest_v2_vectors` give the
preimage, the digest and, for contrast, the version-1 digest of the same title, summary and detail.

## 5. Challenge

```
challenge = SHA-256( S("hermie-confirm-v1") ‖ S(purpose) ‖ S(base_url) ‖ LP(gateway_id) ‖ S(user_id)
                     ‖ S(session_id) ‖ S(request_id) ‖ LP(nonce) ‖ LP(text_digest) )
```

| Field | `confirm` | `register` | `invite` | `revoke` |
| --- | --- | --- | --- | --- |
| `purpose` | `"confirm"` | `"register"` | `"invite"` | `"revoke"` |
| `base_url` | the base URL the client dialed (§3) | same | same | same |
| `gateway_id` | 16 bytes, from the frame (`passkey.gateway_id`) | from `GET /api/auth/passkeys` | same | same |
| `user_id` | `"<provider>:<user id>"`, from the frame (`passkey.user.id`) | the signed-in user | same | same |
| `session_id` | the frame's `params.session_id` | `""` | `""` | `""` |
| `request_id` | the frame's JSON-RPC `id` | `registration_id` | `stepup_id` | `stepup_id` |
| `nonce` | 32 bytes, `passkey.nonce` | `nonce` from register/begin | `nonce` from stepup/begin | same |
| `text_digest` over (title, summary, detail) | the request's text | `("", credential name, "")` | `("", "invite", "")` | `("", credential id (base64url string), "")` |

The client computes the challenge itself from what it dialed and what it shows; the gateway never hands
out an opaque challenge and recomputes it from its own records. The WebAuthn `challenge` is these 32
bytes. `challenge_vectors` gives each purpose with the full preimage in hex, including two gateways on
one host under different path prefixes.

**What binds an answer to one gateway** is the base URL in the challenge, checked against the base URLs
the operator listed (§9 step 4). `gateway_id` does not: a client learns it from the gateway, so a
malicious gateway can present another gateway's id from the start. The client rule in §10 limits that.

## 6. User handle and identifiers

- `user_handle = HMAC-SHA-256(handle_key, "user-handle-v1" ‖ user_id)` (both UTF-8, no length
  prefixes), 32 bytes. `handle_key` is 32 random bytes the gateway creates once and keeps secret. The
  handle is stable per gateway and user and does not link a person across gateways.
- `gateway_id`: 16 random bytes created with the gateway's passkey store; public.
- `user_id`: `"<provider>:<user id>"` as the gateway's auth layer names the signed-in user.
- Credential ids: the authenticator's raw credential id, at most 1,023 bytes.

## 7. Enrolment authority: codes and fresh-authentication grants

A credential is enrolled with exactly one authority, never both and never none: an enrolment code (§7.1) or
a fresh-authentication grant (§7.2). The authority is spent in the same transaction that stores the
credential, so a failed enrolment leaves it unused.

### 7.1 Enrolment codes

A code is 100 random bits written as 20 Crockford base32 symbols (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) in
groups of five: `XXXXX-XXXXX-XXXXX-XXXXX`. To compare, canonicalise: upper-case, drop `-` and spaces,
map `O` to `0` and `I`, `L` to `1`; anything else, or a length other than 20, is invalid. The gateway
stores `SHA-256(canonical ASCII)` only. `enrolment_code_vectors` covers the canonicalisation.

A code comes from the operator (any user, or one named user) or from a person who signed an `invite`
step-up with a passkey they already have (bound to that person). A credential enrolled with the first is
`created_via: "operator"`, with the second `"passkey"`.

### 7.2 Fresh-authentication grants (self-enrolment)

A signed-in person can authorise one enrolment by signing in again. The gateway, not the client, decides
whether that sign-in counts: the provider says when the person authenticated and the gateway compares it
with when the grant was opened. A credential enrolled this way is `created_via: "self"`.

**Grant.** `id` is 16 random bytes, base64url (22 characters). It belongs to one user (`<provider>:<user
id>`), one sign-in provider and one client kind, `web` (a browser with a cookie session) or `native` (a
bearer caller, the app). It lives 600 s from opening (`expires_at = created_at + 600`) and has the states

```
open ──► fresh ──► spent
   └───► failed
```

`open` becomes `fresh` or `failed` exactly once, when the sign-in it asked for comes back. `spent` is
reached only by the credential insert, in the same transaction, and only from `fresh`. `failed` and `spent`
are final. An expired grant is unknown in every state. A grant authorises at most one credential.

**Binding.** The grant id alone is never enough: it can end up in a proxy's access log
(`/auth/login?…&reauth=<id>`) or in a browser history. Each grant is bound to the client that opened it,
from opening until the spend, with a secret that the gateway stores as SHA-256 only, compares in constant
time, and never logs:

| Client kind | Binding | Where it travels |
| --- | --- | --- |
| `web` | the cookie `__Host-hermes_reauth`, whose value is a 32-byte random secret (base64url), set when the grant is opened | required at `GET /auth/login?reauth=`, at the sign-in's completion (the callback or the password login), at `register/begin` and at `register/finish` (checked again inside the spend). Kept after the completion, fresh or failed; cleared by the response to a successful `register/finish`, at logout and by expiry |
| `native` | the app's PKCE verifier at `POST /auth/native/token`; a fresh completion hands back a one-time `use_secret` (32 random bytes, base64url) | `use_secret` in the body of `register/begin` and `register/finish`. A native grant that is not fresh has no `use_secret` yet |

The reauth cookie has exactly one shape, whatever the proxy prefix or the scheme the gateway itself sees:
`__Host-hermes_reauth=<secret>; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`, no `Domain`. It is
read under that name only: no `__Secure-` or bare variant counts, so a sibling host cannot toss one in. Safari does not keep a `Secure` cookie on `http://localhost`, so a
web grant fails there (the codes of §7.1 still work); behind a path prefix the `Path=/` cookie is also sent to
other applications on the same host (it holds only a grant secret, useless without the session).
A gateway therefore refuses to open a `web` grant for a browser that is not on https (the request's
`Origin`, or the request scheme when the `Origin` is not http) or on a loopback development host
(`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`): `insecure_binding`.

Without its binding a grant is `unknown` (§8, `reauth_invalid`) whatever its state; so is a grant used by
the other kind of client, another user's grant, and an expired or nonexistent one. Nobody learns whether
a grant exists.

**Freshness.** A completion is `fresh` only when the session the provider returned has the same provider
and the same `<provider>:<user id>` as the grant, and the provider's `auth_time` (Unix seconds) is not
older than the grant by more than the skew:

```
auth_time >= grant.created_at - 120
```

The checks run in this order, the first that fails is the `failure`:

1. `provider_mismatch` — the session's provider is not the grant's;
2. `user_mismatch` — the session's `<provider>:<user id>` is not the grant's;
3. `auth_time_missing` — the provider did not say when (0 or absent), unless the operator accepts that
   (`accept_missing_auth_time`), which makes the grant `fresh` with the time recorded as assumed. The
   option never excuses an `auth_time` that is present but old;
4. `auth_not_fresh` — `auth_time < created_at - 120`.

There is no upper bound: a later `auth_time` is fresh. A sign-in as another person (`user_mismatch`)
still completes as an ordinary login for that person: the grant fails, the login does not (a grant's
failure never undoes a sign-in). `reauth_freshness_vectors` is this table.

**Which providers can give a fresh authentication.** A provider that can be told to authenticate the
person again and reports when it did:

- an OpenID Connect provider is sent `prompt=login` and `max_age=0` for a grant's sign-in; OpenID Connect
  Core 3.1.2.1 makes `auth_time` REQUIRED in the ID token when `max_age` was requested. A provider that
  ignores `prompt=login` and reuses its own session returns the old `auth_time` (`auth_not_fresh`);
- the gateway's own password provider verifies the password itself and reports `auth_time` as now;
- a provider that cannot (no `prompt` or `max_age`, no `auth_time`) is `provider_no_reauth`: codes remain.

A gateway without a person behind the session (session-token mode, loopback mode) offers no passkeys at
all (§8, capability reason `no_identity`).

**Cooling-off.** The operator may set `cooling_off_s` (0 by default). A credential enrolled by a grant is
then listed with `usable_from` (Unix seconds) and cannot answer a `confirm` or sign an `invite` or `revoke`
step-up before it (it is in no snapshot of §9, so it cannot mint a code for an immediately usable second
credential), but it can be revoked by another usable credential or the operator. `usable_from` is absent
once it has passed and for every credential without cooling-off.

**Switch.** The operator may switch self-enrolment off (`self_enrol.enabled: false`): `reauth/begin`, and
a `register/begin` or `register/finish` that names a grant, are `self_enrol_disabled`, also for a grant
opened before the switch. Codes are unaffected.

## 8. Wire objects

Examples of every object are in `vectors.json` → `wire_examples`.

### Capability (`client.capabilities`, two calls)

1. The client calls `client.capabilities {server_requests: true}`. A gateway that knows the level adds
   to the result:

   ```json
   "confirm_passkey": { "v": 1, "enabled": true, "reason": "",
                        "gateway_id": "<b64u 16 bytes>",
                        "rp": { "native": ["confirm.hermie.dev"], "web": ["gw.example.com"] },
                        "versions": [1, 2] }
   ```

   `versions` (absent from a gateway that knows version 1 only) lists the `confirm_passkey.v` values the
   gateway accepts in the second call. A gateway that knows structured fields (§4.1) also adds
   `"confirm_fields": false` to every result (true once it accepted this connection's `confirm_fields`).

   `reason` is `""` when enabled, else one of: `disabled` (the operator has not enabled the level),
   `no_base_url` (the operator listed no base URL), `private_origin` (every listed base URL is private,
   §10, and the operator has not opted in), `no_identity` (this connection has no signed-in user).
2. The second call depends on the first result:
   - it carried `confirm_passkey` with `enabled: true` → the client MAY send
     `{server_requests: true, confirm: ["plain", "passkey"], confirm_passkey: {v: 1, kind: "native" | "web",
     rp_id: "..."}}`;
   - otherwise, if `server_requests` lists `confirm` → it sends `{server_requests: true, confirm: ["plain"]}`
     and nothing about passkeys. A gateway that knows `confirm` but not `confirm_passkey` rejects an
     unknown key with error 4000, and the connection would lose `plain` with it;
   - otherwise no second call.

   The result's `confirm` lists the levels accepted. `passkey` is accepted only when the level is
   enabled, the connection is signed in, and `rp_id` is accepted for `kind` (§10). Whether the user has a
   credential is decided per request.
3. Version 2 (§4.1). A client that shows structured fields adds `confirm_fields: true` to the second call
   when the first result carried the key `confirm_fields`; it is accepted together with at least one
   accepted level and echoed as `confirm_fields: true`. A client that also computes `text_digest_v2` sends
   `confirm_passkey {v: 2, kind, rp_id}` when the first result's `versions` lists 2 (a gateway without
   `versions` refuses `v: 2` and the level with it). A `v: 2` client takes `v: 1` and `v: 2` frames; a `v: 1`
   client is never sent a `v: 2` frame. A client sends `v: 2` only together with `confirm_fields: true`: the
   gateway needs both to send it a request with fields.

### `confirm` request params at level `passkey`

The PG-7 params (`session_id`, `title`, `summary`, `detail?`, `level`, `fields?` (§4.1)) plus:

```json
"passkey": { "v": 1, "nonce": "<b64u 32>", "gateway_id": "<b64u 16>", "base_url": "https://gw.example.com",
             "expires_at": 1790000120,
             "user": { "id": "self_hosted:7c1f0e2a", "name": "Alex Example" },
             "credentials": [ { "rp_id": "confirm.hermie.dev", "ids": ["<b64u>"] } ] }
```

`base_url` is informative (the base URL the gateway would accept from this connection); the client
always uses the base URL it dialed. `expires_at` is Unix seconds. `credentials` lists the bound user's
active credentials per RP. `v` is 1 for a request without `fields` (§4) and 2 for one with them
(§4.1); a client hashes the text of that version. A client MUST pass a non-empty `allowCredentials` for its
own RP and MUST refuse (error 4040) a request without one, with an unknown `v` (or `v: 2` without `fields`,
`v: 1` with them), or whose `gateway_id` breaks the pinning rule in §10.

### Answer (through `request.answer {id, result}`)

```json
{ "decision": "confirmed", "method": "passkey",
  "passkey": { "v": 1, "rp_id": "…", "base_url": "https://gw.example.com", "credential_id": "…",
               "authenticator_data": "…", "client_data_json": "…", "signature": "…",
               "user_handle": "…" } }
```

`user_handle` is optional. `verified` is never sent by a client. `v` repeats the request's `passkey.v` (1, or 2
for a request with fields); any other value is a `bad_shape` (§9 step 1).

A decline is exactly `{ "decision": "declined", "method": "tap" }`, with no `passkey` object. It does not
go through §9: it needs no assertion, it is not a `bad_shape`, it does not count toward the five
refusals, and it settles the request as `declined` with `verified: false`.

### Errors

| Code | Where | Meaning |
| --- | --- | --- |
| 4033 | `request.answer` | the connection is not attached to the request's session, is not signed in as the request's user, or did not advertise the level |
| 4034 | `request.answer` | the answer was refused; `data.reason` is one of §9; the request stays open (until the fifth refusal) |
| 4040 | client's JSON-RPC error response to the `confirm` frame | the client cannot run the ceremony (`data.reason`, e.g. `no_credential`); the gateway takes that connection out of the running |

Dismissing the system passkey sheet sends nothing.

### Self-enrolment routes (`/api/auth/passkeys`, REST)

The REST routes are behind the gateway's gate: nothing is public, the identity is the gate's (the session
cookie or the bearer), never a body field. A cookie caller's write needs an `Origin` that is the origin of
one of the level's accepted base URLs (`origin_not_listed` otherwise); a bearer caller is exempt. Bodies
are JSON objects of at most 16 KiB. While the level is off every route answers like an unknown path (404
for a GET, 405 for a POST). An answer other than 200 is `{"error": <code>, "detail": <text>, "reason"?,
"failure"?}` with `Cache-Control: no-store`; `reason` and `failure` are the only fields a client branches
on, `detail` is for people and logs.

**`GET /api/auth/passkeys`** (status) gains:

```json
"self_enrol": { "available": true, "reason": "", "cooling_off_s": 0 }
```

`reason` is `""` when the caller can add a passkey by signing in again, `"disabled"` when the operator
switched it off, `"provider_no_reauth"` when the caller's sign-in provider cannot give a fresh
authentication (§7.2). Each credential carries `created_via` (`"operator"`, `"passkey"` or `"self"`) and,
only while it is cooling off, `usable_from`. An older gateway has neither field: a client treats a missing
`self_enrol` as not available.

**`POST /api/auth/passkeys/reauth/begin`** with body `{}` opens a grant (§7.2) for the caller's session.

- A cookie caller (the web client) gets `{"grant_id", "expires_at", "provider", "login_path"}` and the
  binding cookie in `Set-Cookie`. `login_path` is `<prefix>/auth/login?provider=<p>&reauth=<id>`; the page
  appends `&next=<its own path>` and navigates the whole window there (a sign-in cannot be framed).
- A bearer caller (the app) gets `{"grant_id", "expires_at", "provider"}`, no cookie and no `login_path`.
- Errors: 403 `self_enrol_disabled`, 403 `provider_no_reauth`, 403 `insecure_binding` (cookie caller not on
  https or loopback), 403 `origin_not_listed`, 429 `rate_limited` with `Retry-After: 600` (5 per user and 5
  per address in 10 minutes). 404 or 405 while the level is off.
- A gateway that does not know the route answers 404 or 405: the client shows only the code path.

**The sign-in.** The grant is completed by a sign-in that carries its id:

- web: the browser goes to `GET <prefix>/auth/login?provider=<p>&reauth=<id>&next=<path>`. The gateway
  checks the binding cookie, that the grant is `open`, unexpired and for provider `p` before any redirect or
  cookie; otherwise it answers a plain page with status 400, never a redirect. Then the ordinary sign-in runs (with `prompt=login` and `max_age=0` for an
  OpenID Connect provider) and the browser lands on `next` signed in, whatever became of the grant.
- native: the app opens `GET /auth/native/authorize?…&reauth=<id>` (the usual parameters plus `reauth`) in
  the system browser and redeems the loopback code at `POST /auth/native/token` with its PKCE verifier. A
  re-authentication code returns **no tokens**:

  ```json
  { "reauth": { "grant_id": "…", "state": "fresh", "expires_at": 1790000600, "use_secret": "…" } }
  { "reauth": { "grant_id": "…", "state": "failed", "reason": "auth_not_fresh", "expires_at": 1790000600 } }
  ```

  `use_secret` is present only when `state` is `fresh`; `reason` only when it is `failed` (a `failure` of
  §7.2, or `unknown` / `not_open` / `client_mismatch` when the grant could not be completed and was left as
  it was). The app keeps its own token set untouched, and the gateway does not revoke the identity
  provider session the re-authentication minted (it is never handed out and expires by itself). A body that
  carries tokens is not a re-authentication answer.

Both sign-in routes are public, so a `reauth` parameter is rate limited before anything is read. Every check
reserves a slot in two budgets, per address (200 in 600 s, counted first) and per address and grant id (20 in
600 s); a check that finds the grant gives its slots back, so only refusals use them up. A malformed id is
not counted in the second. When a budget is used up the answer is 429 (a plain page for the web route and
for `authorize`) with `Retry-After`, the whole seconds (at least 1) until a slot frees; nothing was read. The
per-grant budget keeps one client behind a shared address from using up the address ceiling's room; once the
ceiling is used up every grant from that address gets 429 until a slot frees.

**`POST /api/auth/passkeys/register/begin`** takes `{rp_id, base_url, name}` and optionally `grant_id`
(and, from the app, `use_secret`; the browser's cookie travels by itself). With a `grant_id` the gateway
checks that the grant is fresh, this user's, unexpired, unspent, opened by this kind of client and presented
with its binding before it opens the registration, and the answer gains `"grant": {"expires_at": <int>}`.
A cancelled system sheet may repeat `begin` with the same grant while it is unspent.

**`POST /api/auth/passkeys/register/finish`** takes `{registration_id, base_url, credential, code}` **or**
`{registration_id, base_url, credential, grant_id}` (the app adds `use_secret`; the browser adds nothing):
exactly one of `code` and `grant_id`, else 400 `bad_request`. The grant is checked again and spent in the
transaction that stores the credential (§11); a web caller's response clears the binding cookie. The answer
is `{"ok": true, "credential": {…}}` with `created_via: "self"` and, with cooling-off, `usable_from`.

Grant errors, at `register/begin` and `register/finish`: 403 `reauth_invalid` with `reason`

| `reason` | Meaning | `failure` |
| --- | --- | --- |
| `unknown` | no such grant for this user, expired, presented without its binding, or opened by the other kind of client | — |
| `not_fresh` | still `open`: the sign-in did not come back | — |
| `spent` | used for a credential already | — |
| `failed` | the sign-in came back and did not count | one of `user_mismatch`, `provider_mismatch`, `auth_time_missing`, `auth_not_fresh` |

A grant refused at `register/finish` counts like a wrong enrolment code against the failure limiters
(5 per user, 5 per address in 10 minutes, 20 per gateway in an hour: 429 `rate_limited`). 403
`self_enrol_disabled` and `provider_no_reauth` are also possible at these two routes, and a grant a
native app has not completed fresh is `unknown` to it (it has no `use_secret` yet): the app learns why from
the token answer, a browser from `reauth_invalid` with its cookie.

## 9. Verifying an assertion (gateway)

Inputs: the open request (user `U`, session id, request id, nonce, the title/summary/detail and fields it sent),
the gateway context (`gateway_id`, `handle_key`, the listed base URLs, the private opt-in,
`native_rps`), and a snapshot of `U`'s stored credentials taken when the request opened. The check is a
pure function of these and the answer: no I/O, no logging of inputs. Steps run in this order; the first
failure is the refusal reason (error 4034 with `data.reason`). `generate.py` runs every vector through a
reference evaluator written from these steps; each vector passes the steps before its own and fails
exactly at its own.

Only answers from connections allowed to answer (attached to the session, signed in as `U`, advertised
the level; otherwise 4033) reach §9, and only their refusals count toward the five.

1. **`bad_shape`** — the result is a JSON object with exactly `decision`, `method`, `passkey` (a
   client-sent `verified` is a `bad_shape`); `decision` = `"confirmed"`, `method` = `"passkey"`;
   `passkey` is an object with exactly the keys `v`, `rp_id`, `base_url`, `credential_id`,
   `authenticator_data`, `client_data_json`, `signature` and optionally `user_handle`; `v` is the integer
   version of the request (1, or 2 for a request with fields, §4.1); `rp_id` a string of 1–253 characters, `base_url` a string of 1–512; the binary fields are valid
   base64url (§2) and decode to: `credential_id` 1–1,023 bytes, `authenticator_data` 37–1,024,
   `client_data_json` 1–4,096, `signature` 8–72, `user_handle` 1–64.
2. **`unknown_credential`** — the snapshot has a credential with this `credential_id` whose user is `U`,
   which is active, and whose `rp_id` equals the answer's `rp_id`. If `user_handle` is present it MUST
   equal `user_handle(handle_key, U)` (§6), compared in constant time.
3. **`rp_not_accepted`** — `rp_id` is an accepted native or web RP (§10).
4. **`base_url_not_accepted`** — `base_url` is byte-for-byte equal to one of the accepted base URLs
   (§10). It is never compared with the Host of the connection, and never normalised first.
5. **`rp_host_mismatch`** — for a web RP, the host of `base_url` equals `rp_id`. (Native RPs skip this.)
6. **`bad_client_data`** — `client_data_json` is UTF-8 JSON whose top level is an object without
   duplicate keys; `type` = `"webauthn.get"`; `challenge` is a string; `crossOrigin` is absent or the
   boolean `false`; `topOrigin` is absent; `origin` is: for a native RP, one of `native_rps[rp_id]`; for
   a web RP, the origin of `base_url`. Other keys are ignored. Never compare the bytes with a template.
7. **`challenge_mismatch`** — `challenge` decodes (§2) to 32 bytes equal, in constant time, to §5
   computed with purpose `confirm`, the answer's `base_url`, the gateway's `gateway_id`, `U`, the
   request's session id, request id and nonce, and the digest of the text the gateway sent.
8. **`bad_authenticator_data`** — `rpIdHash` (bytes 0–31) = SHA-256 of `rp_id`; the AT flag (0x40) is
   clear; BS (0x10) is not set without BE (0x08); if ED (0x80) is clear the length is exactly 37, if set
   the bytes after 37 are exactly one CBOR map (§12) and nothing else (the map is ignored).
9. **`uv_required`** — UP (0x01) and UV (0x04) are both set.
10. **`backup_state_mismatch`** — BE equals the stored `backup_eligible`.
11. **`signature_invalid`** — `signature` is a strict ASN.1 DER ECDSA signature (not raw `r‖s`) that
    verifies with the stored P-256 key (`x`, `y`) over `authenticator_data ‖ SHA-256(client_data_json)`
    with SHA-256 (ES256). Both low-S and high-S forms are valid; a verifier MUST NOT require low-S.
12. **`counter_regression`** — with `n` = signCount (bytes 33–36, big-endian) and `s` = stored: if both
    are 0, or `n > s`, the counter is fine. Otherwise: for a **device-bound** credential (stored
    `backup_eligible` false) the answer is refused; for a **synced** credential (BE true) it is accepted
    and the gateway writes an audit record (`counter_warning: true` in the vectors). Reason: a synced
    passkey is one key on several devices, each with its own counter (or none), so a lower value is
    expected and is not evidence of a cloned authenticator.

Accepted: the first answer that passes these steps settles the request, and `request.answer` answers
`{"status": "ok"}`, which means **received and valid**, not yet "confirmed"; other connections get
`request.cancel {reason: "resolved"}`. The gateway then commits it once, outside the request lock: it
re-reads the credential (revoked meanwhile → refused), stores `n` and BS with a compare-and-set, and
writes a receipt. Only a successful commit makes the outcome `confirmed` with `method: "passkey"` and
`verified: true`. A refused commit (revoked meanwhile, a replay, a counter regression against the value
stored now, a store error) makes it `unavailable` (`verification_failed`), and the session's connections
get `request.cancel {reason: "verification_failed"}`: a client clears any "confirmed" state it showed for
that id.

**`too_many_attempts`** — the fifth refused answer (from connections allowed to answer) for one request
is refused with this reason and settles the request as `unavailable` (`verification_failed`). See
`sequence_vectors`.

## 10. Base URLs, relying parties, and the client's pin

**Accepted base URLs.** The operator lists base URLs (§3). A listed base URL is **private** when its
scheme is `http`, its host is an IP literal that is not globally routable (loopback, RFC 1918, link-local,
CGNAT, unique-local, unspecified), `localhost` or `*.localhost`, a single label without a dot, or ends in
`.local`, `.internal`, `.lan` or `.home.arpa`. Private base URLs are accepted only when the operator sets
the explicit opt-in (`allow_private_base_urls`). Without any accepted base URL the level is not offered
(capability `reason: "private_origin"`).

With the opt-in there is **no relay protection between gateways reachable at the same address**: two
gateways that both answer at `http://192.168.1.10:9119` on different networks, or both at
`http://localhost:9119`, produce the same challenge for the same request fields, and the stored public
key is the only thing that tells them apart. Opt in only where that is acceptable.

**Native RPs** come from config `confirm.passkey.native_rps`: a map from RP ID to the allowed
`clientDataJSON.origin` values for it. Default: `{"confirm.hermie.dev": ["https://confirm.hermie.dev"]}`
(the official build's associated domain). The value Apple puts in `clientDataJSON.origin` for an
app-initiated ceremony is **not yet confirmed on a device**; it is config for that reason. Native RPs are
accepted when at least one base URL is accepted.

**Web RPs** are the hosts of accepted base URLs whose scheme is `https` and which have **no path
prefix**. The RP ID is the exact host, never the registrable domain, and the answer's `base_url` host MUST
equal it (§9 step 5). Gateways under path prefixes of one host share that host's browser security
boundary (any page on the origin can ask for the RP's passkeys with a challenge of its choosing), so the
browser path is not offered to them; the native path is.

A credential is stored with the RP it was created for. Each vector context lists its accepted base URLs
and RPs under `derived`.

**The client's gateway id pin (native and browser clients).**

- A client pins `gateway_id` per stored gateway on that gateway's **first successful enrolment**, not on
  first connect: before any credential exists there is nothing to protect, and pinning on first connect
  would let whoever answered first choose the id.
- After pinning, a frame or capability for that gateway with a different `gateway_id` is refused (4040)
  and shown as a notice, never silently accepted.
- A client MUST refuse a `gateway_id` that is already pinned for a different stored gateway (another
  base URL): two gateways never share an id, so a second gateway presenting a known id is impersonating it.

## 11. Verifying a registration (gateway)

`POST /api/auth/passkeys/register/finish` carries `{registration_id, base_url, credential: {id,
client_data_json, attestation_object, transports?}}` and exactly one authority (`code`, or `grant_id` with
the binding of §7.2) for an open registration (`rp_id`, `base_url`, `name`, `nonce`, user) created by
`register/begin`. The authority and "credential already stored" are checked by the route and the store, not
by this function, which ignores the authority fields. Order, each failure 422 `attestation_invalid` with
`reason`:

1. `bad_shape` — fields present, base64url valid, `credential.id` 1–1,023 bytes, `client_data_json`
   ≤ 4,096 bytes, `attestation_object` ≤ 16,384 bytes; `registration_id` and `base_url` equal the ones of
   the open registration.
2. `rp_not_accepted`, `base_url_not_accepted`, `rp_host_mismatch` — as §9 steps 3–5.
3. `bad_client_data` — as §9 step 6 with `type` = `"webauthn.create"`.
4. `challenge_mismatch` — §5 with purpose `register`, `session_id` `""`, `request_id` = `registration_id`,
   text `("", name, "")`.
5. `bad_attestation_object` — the attestation object is one CBOR map (§12) with exactly the text keys
   `fmt` (a text string), `attStmt` (a map) and `authData` (a byte string), consuming the whole input.
   Any `fmt` is accepted and `attStmt` is not checked.
6. `bad_authenticator_data` — `rpIdHash` = SHA-256(`rp_id`); AT set; BS not set without BE; then AAGUID
   (16 bytes), credential id length (2 bytes, big-endian), credential id equal to `credential.id`, then
   one CBOR map (the COSE key), then, if and only if ED is set, exactly one CBOR map of extensions;
   nothing else.
7. `uv_required` — UP and UV set.
8. `unsupported_algorithm` — the COSE key has `1` (kty) = 2, `3` (alg) = -7, `-1` (crv) = 1.
9. `bad_public_key` — `-2` (x) and `-3` (y) are 32-byte strings and the point is on P-256.

Stored: credential id, `rp_id`, `alg` -7, `x‖y`, signCount, BE, BS, AAGUID, transports, the name.

## 12. CBOR subset

Decoders for the attestation object, the COSE key and authenticator extensions accept only: major types
0 and 1 (integers up to 64 bits), 2 (byte string), 3 (UTF-8 text string), 4 (array), 5 (map), and the
simple values `false`, `true`, `null`. Definite lengths only (indefinite length 31 is refused); no tags,
no floats, no `undefined`, no other simple values. Nesting depth at most 4. Map keys are integers or
text; a duplicate key is refused. A decoder never reads past the buffer and reports how many bytes it
consumed; the caller refuses trailing bytes where this document says "exactly". Non-shortest integer
encodings are accepted.

## 13. The vectors

`vectors.json`:

| Key | Content |
| --- | --- |
| `keys` | the test keys (private scalar, `x`, `y`) and how each was derived; used nowhere else |
| `contexts` | the gateways under test (`main`, `private_allowed`, `only_private`, `prefixed`): `gateway_id`, `handle_key`, `base_urls`, `allow_private_base_urls`, `native_rps`, `user`, and `derived` (accepted base URLs and RPs, capability reason) |
| `base_url_vectors` | §3 and §10: `input` → `base_url`, `origin`, `private`; or `error: "not_a_base_url"` |
| `text_digest_vectors`, `challenge_vectors`, `user_handle_vectors`, `enrolment_code_vectors` | §4–§7 with expected outputs (`preimage_hex` for debugging) |
| `text_digest_v2_vectors` | §4.1: `title`, `summary`, `detail`, `fields` → `preimage_hex`, `text_digest`, and `text_digest_v1` (the same text without the fields, never equal). Includes an amount with a non-ASCII currency symbol in its label, the same fields in swapped order (another digest), a label/value boundary shift (another digest), a field without `currency`, and every kind |
| `assertion_vectors_v2` | as `assertion_vectors`, for a version-2 request (its `request` carries `fields`; the answer carries `v: 2`): accepted, signed over the version-1 text, over the fields in another order or with another value (`challenge_mismatch`), and the wrong `v` either way (`bad_shape`) |
| `assertion_refusal_order`, `registration_refusal_order` | §9's and §11's reasons in order |
| `assertion_vectors` | `context` (a key of `contexts`), `request`, `store` (credential records of several users, one revoked), `answer`, `signed_by` (informative), `expect`: `{ok: true, sign_count, backup_eligible, backed_up, counter_warning}` or `{ok: false, code: 4034, reason}` |
| `sequence_vectors` | multi-answer behaviour (`too_many_attempts`); steps name assertion vectors |
| `registration_vectors` | `context`, `begin` (the open registration), `finish` (the body), `expect` |
| `reauth_freshness_vectors` | §7.2: a `grant` (`provider`, `user_id`, `created_at`), the `session` its sign-in returned (`provider`, `user_id`, `auth_time`, 0 for none), `accept_missing_auth_time`, and `expect`: `{state: "fresh", auth_time_assumed}` or `{state: "failed", failure}`. A timestamp rule, not a construction: nothing here is signed |
| `wire_examples` | one example of each wire object in §8, including both second-call forms, the version-2 capability, second call and request frame (`*_v2`), the status route's `self_enrol`, `reauth/begin` for both client kinds, the binding cookie, the native token route's two `reauth` answers, `register/begin` and `register/finish` with a grant for both client kinds, the error answers of the self-enrolment routes, and the refusal pages of the sign-in routes (400 and 429 with `Retry-After`) |

Take `U`'s active credentials from `store` as the snapshot. Run every vector against the context it names.
A freshness vector needs no context: apply §7.2 to its `grant` and `session`.

Coverage: positives for the native RP (synced, counter 0/0), the web RP (device-bound, counter
increasing, unknown `clientDataJSON` keys), an extensions map, a high-S signature, a synced counter
regression (accepted with a warning), a private base URL with the opt-in, and a gateway under a path
prefix; at least one negative per refusal reason, including every size bound, the relay attack both ways
(a valid signature replayed with the other gateway's base URL: `base_url_not_accepted`; this gateway's
base URL claimed: `challenge_mismatch`) also between two gateways on one host, challenges for other text,
request (with the same and with another nonce), session, user, nonce, purpose and gateway id, a raw
`r‖s` signature, and malformed CBOR.

### Regenerating

```
python generate.py           # write vectors.json and SHA256SUMS
python generate.py --check   # rebuild in memory, compare byte for byte, verify SHA256SUMS (exit 1 on any difference)
```

Everything is derived from fixed labels and ECDSA signatures are deterministic (RFC 6979), so the files
are reproduced exactly. Before writing or checking, every vector goes through the reference evaluator in
`generate.py` (written from §9 and §11, independent of any production verifier); a vector labelled with a
result the README does not give fails the build. Needs Python 3.11+ and `cryptography` 43 or newer.

### Not covered yet

Real-device captures (iCloud Keychain and a third-party provider on iOS and macOS: `clientDataJSON`
bytes and origin, flags, signCount) are to be added once a build with the associated domain exists. RS256
and EdDSA are out of scope for version 1.

Self-enrolment depends on how the operator's identity provider behaves, which no vector can show: whether
it honours `prompt=login` and `max_age=0`, and whether its ID token carries `auth_time`. Neither is
verified against a real provider yet; until it is, a gateway whose provider falls short refuses with
`auth_time_missing` or `auth_not_fresh`, or the operator sets `accept_missing_auth_time`, and the codes of
§7.1 keep working. Safari's requirement of a user gesture for `navigator.credentials.create()` after the
sign-in redirect is likewise not verified for every version; the web client therefore runs the ceremony
from a button.
