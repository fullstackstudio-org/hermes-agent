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
request is `unavailable` and nothing is sent. Nothing here changes level `plain`.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119. Where this document and `vectors.json`
disagree, that is a bug in one of them; report it rather than picking one.

## 1. What a verified confirmation proves

A `confirmed` answer with `verified: true` means: a credential enrolled for this gateway user signed,
with user presence and user verification as reported by its authenticator, a challenge that commits to
this gateway's base URL and id, this session, this request id, a fresh nonce, and the SHA-256 of the
exact title, summary and detail the gateway sent.

It does not prove a biometric (user verification may be a device passcode or a password manager's PIN),
hardware (no attestation is checked), that the person understood the text, that the agent then does what
it described, or anything on a gateway that is itself compromised (the gateway is the verifier).

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

## 7. Enrolment codes

A code is 100 random bits written as 20 Crockford base32 symbols (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) in
groups of five: `XXXXX-XXXXX-XXXXX-XXXXX`. To compare, canonicalise: upper-case, drop `-` and spaces,
map `O` to `0` and `I`, `L` to `1`; anything else, or a length other than 20, is invalid. The gateway
stores `SHA-256(canonical ASCII)` only. `enrolment_code_vectors` covers the canonicalisation.

## 8. Wire objects

Examples of every object are in `vectors.json` → `wire_examples`.

### Capability (`client.capabilities`, two calls)

1. The client calls `client.capabilities {server_requests: true}`. A gateway that knows the level adds
   to the result:

   ```json
   "confirm_passkey": { "v": 1, "enabled": true, "reason": "",
                        "gateway_id": "<b64u 16 bytes>",
                        "rp": { "native": ["confirm.hermie.dev"], "web": ["gw.example.com"] } }
   ```

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

### `confirm` request params at level `passkey`

The PG-7 params (`session_id`, `title`, `summary`, `detail?`, `level`) plus:

```json
"passkey": { "v": 1, "nonce": "<b64u 32>", "gateway_id": "<b64u 16>", "base_url": "https://gw.example.com",
             "expires_at": 1790000120,
             "user": { "id": "self_hosted:7c1f0e2a", "name": "Alex Example" },
             "credentials": [ { "rp_id": "confirm.hermie.dev", "ids": ["<b64u>"] } ] }
```

`base_url` is informative (the base URL the gateway would accept from this connection); the client
always uses the base URL it dialed. `expires_at` is Unix seconds. `credentials` lists the bound user's
active credentials per RP. A client MUST pass a non-empty `allowCredentials` for its own RP and MUST
refuse (error 4040) a request without one, with an unknown `v`, or whose `gateway_id` breaks the pinning
rule in §10.

### Answer (through `request.answer {id, result}`)

```json
{ "decision": "confirmed", "method": "passkey",
  "passkey": { "v": 1, "rp_id": "…", "base_url": "https://gw.example.com", "credential_id": "…",
               "authenticator_data": "…", "client_data_json": "…", "signature": "…",
               "user_handle": "…" } }
```

`user_handle` is optional. `verified` is never sent by a client.

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

## 9. Verifying an assertion (gateway)

Inputs: the open request (user `U`, session id, request id, nonce, the title/summary/detail it sent),
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
   1; `rp_id` a string of 1–253 characters, `base_url` a string of 1–512; the binary fields are valid
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

`POST /api/auth/passkeys/register/finish` carries `{registration_id, base_url, code, credential: {id,
client_data_json, attestation_object, transports?}}` for an open registration (`rp_id`, `base_url`,
`name`, `nonce`, user) created by `register/begin`. The enrolment code and "credential already stored"
are checked by the route, not by this function. Order, each failure 422 `attestation_invalid` with
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
| `assertion_refusal_order`, `registration_refusal_order` | §9's and §11's reasons in order |
| `assertion_vectors` | `context` (a key of `contexts`), `request`, `store` (credential records of several users, one revoked), `answer`, `signed_by` (informative), `expect`: `{ok: true, sign_count, backup_eligible, backed_up, counter_warning}` or `{ok: false, code: 4034, reason}` |
| `sequence_vectors` | multi-answer behaviour (`too_many_attempts`); steps name assertion vectors |
| `registration_vectors` | `context`, `begin` (the open registration), `finish` (the body), `expect` |
| `wire_examples` | one example of each wire object in §8, including both second-call forms |

Take `U`'s active credentials from `store` as the snapshot. Run every vector against the context it names.

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
