# Contract: `confirm` at level `passkey`

This directory is the single written definition of how a `confirm` request at level `passkey` is
proven: the challenge construction, origin serialisation, wire objects, and the order in which a
gateway verifies an answer. `vectors.json` holds test vectors every implementation (gateway, native
app, browser client, fake gateway) must pass; `generate.py` produces and checks them.

Status: contract version 1. The gateway does not offer the level yet; until it does, a `passkey`
request is `unavailable` and nothing is sent. Nothing here changes level `plain`.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119. Where this document and `vectors.json`
disagree, that is a bug in one of them; report it rather than picking one.

## 1. What a verified confirmation proves

A `confirmed` answer with `verified: true` means: a credential enrolled for this gateway user signed,
with user presence and user verification as reported by its authenticator, a challenge that commits to
this gateway's origin and id, this session, this request id, a fresh nonce, and the SHA-256 of the
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

## 3. Origin serialisation

An origin is serialised as `scheme://host[:port]`, the WHATWG URL "ASCII serialization of an origin":

- `scheme` is `http` or `https`, lower case. Anything else is not an origin.
- `host`:
  - a domain is lower-cased and each label converted to an A-label with UTS #46 **non-transitional**
    processing (the WHATWG URL host parser); `ß` stays `ß` and becomes `xn--strae-oqa`, never `ss`;
  - IPv4 in dotted-decimal form;
  - IPv6 in brackets, lower case, compressed as RFC 5952 (`[2001:db8::1]`).
- `port` is omitted when it is the scheme's default (443 for https, 80 for http), kept otherwise.
- Path, query, fragment and userinfo are not part of an origin.

Where it comes from:

| Side | Source |
| --- | --- |
| Native app | the address of the gateway it connected to (`GatewayAddress.origin(of:)`) |
| Browser | `location.origin` |
| Gateway | each operator-listed public origin (`dashboard.public_url`, `dashboard.public_urls`), serialised the same way |

`origin_vectors` lists inputs and the expected serialisation, plus inputs that are not origins.

## 4. Text digest

```
text_digest = SHA-256( S("hermie-confirm-text-v1") ‖ S(title) ‖ S(summary) ‖ S(detail or "") )
```

`detail` absent, `null` and `""` give the same digest. For a `confirm`, title, summary and detail are
the strings in the request frame's params, which are also exactly what the client renders. A client
MUST compute the digest from the values its sheet displays, never from a second copy.

## 5. Challenge

```
challenge = SHA-256( S("hermie-confirm-v1") ‖ S(purpose) ‖ S(origin) ‖ LP(gateway_id) ‖ S(user_id)
                     ‖ S(session_id) ‖ S(request_id) ‖ LP(nonce) ‖ LP(text_digest) )
```

| Field | `confirm` | `register` | `invite` | `revoke` |
| --- | --- | --- | --- | --- |
| `purpose` | `"confirm"` | `"register"` | `"invite"` | `"revoke"` |
| `origin` | origin the client dialed (§3) | same | same | same |
| `gateway_id` | 16 bytes, from the frame (`passkey.gateway_id`) | from `GET /api/auth/passkeys` | same | same |
| `user_id` | `"<provider>:<user id>"`, from the frame (`passkey.user.id`) | the signed-in user | same | same |
| `session_id` | the frame's `params.session_id` | `""` | `""` | `""` |
| `request_id` | the frame's JSON-RPC `id` | `registration_id` | `stepup_id` | `stepup_id` |
| `nonce` | 32 bytes, `passkey.nonce` | `nonce` from register/begin | `nonce` from stepup/begin | same |
| `text_digest` over (title, summary, detail) | the request's text | `("", credential name, "")` | `("", "invite", "")` | `("", credential id (base64url string), "")` |

The client computes the challenge itself from what it dialed and what it shows; the gateway never hands
out an opaque challenge and recomputes it from its own records. The WebAuthn `challenge` is these 32
bytes. `challenge_vectors` gives each purpose with the full preimage in hex.

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

   `reason` is `""` when enabled, else `disabled`, `no_public_origin` or `no_identity`. A result without
   `confirm_passkey` means the gateway does not offer the level: show nothing.
2. Only if the first result lists `confirm` in `server_requests`, the client calls again with
   `{server_requests: true, confirm: ["plain", "passkey"], confirm_passkey: {v: 1, kind: "native" | "web",
   rp_id: "..."}}`. The result's `confirm` lists the levels accepted. `passkey` is accepted only when the
   level is enabled, the connection is signed in as a user, a public origin is listed and `rp_id` is
   accepted for `kind` (§10). Whether the user has a credential is decided per request.

### `confirm` request params at level `passkey`

The PG-7 params (`session_id`, `title`, `summary`, `detail?`, `level`) plus:

```json
"passkey": { "v": 1, "nonce": "<b64u 32>", "gateway_id": "<b64u 16>", "expires_at": 1790000120,
             "user": { "id": "self_hosted:7c1f0e2a", "name": "Alex Example" },
             "credentials": [ { "rp_id": "confirm.hermie.dev", "ids": ["<b64u>"] } ] }
```

`expires_at` is Unix seconds. `credentials` lists the bound user's active credentials per RP. A client
MUST pass a non-empty `allowCredentials` for its own RP and MUST refuse (error 4040) a request without
one, with an unknown `v`, or whose `gateway_id` differs from the one it pinned for this gateway.

### Answer (through `request.answer {id, result}`)

```json
{ "decision": "confirmed", "method": "passkey",
  "passkey": { "v": 1, "rp_id": "…", "origin": "https://gw.example.com", "credential_id": "…",
               "authenticator_data": "…", "client_data_json": "…", "signature": "…",
               "user_handle": "…" } }
```

`user_handle` is optional. A decline is `{ "decision": "declined", "method": "tap" }` with no `passkey`
object; it needs no assertion and is reported `verified: false`. `verified` is never sent by a client.

### Errors

| Code | Where | Meaning |
| --- | --- | --- |
| 4033 | `request.answer` | the connection is not signed in as the request's user, or did not advertise the level |
| 4034 | `request.answer` | the answer was refused; `data.reason` is one of §9; the request stays open (until the fifth refusal) |
| 4040 | client's JSON-RPC error response to the `confirm` frame | the client cannot run the ceremony (`data.reason`, e.g. `no_credential`); the gateway takes that connection out of the running |

Dismissing the system passkey sheet sends nothing.

## 9. Verifying an assertion (gateway)

Inputs: the open request (user `U`, session id, request id, nonce, the title/summary/detail it sent),
the gateway config (`gateway_id`, listed public origins, `native_rps`), and a snapshot of `U`'s stored
credentials taken when the request opened. The check is a pure function of these and the answer: no
I/O, no logging of inputs. Steps run in this order; the first failure is the refusal reason (error 4034
with `data.reason`). Every vector exercises the steps before its own and fails exactly at its own.

1. **`bad_shape`** — the result is a JSON object with exactly `decision`, `method`, `passkey`;
   `decision` = `"confirmed"`, `method` = `"passkey"`; `passkey` is an object with exactly the keys
   `v`, `rp_id`, `origin`, `credential_id`, `authenticator_data`, `client_data_json`, `signature` and
   optionally `user_handle`; `v` = 1; `rp_id` a string of 1–253 characters, `origin` a string of 1–512;
   the binary fields are valid base64url (§2) and decode to: `credential_id` 1–1,023 bytes,
   `authenticator_data` 37–1,024, `client_data_json` 1–4,096, `signature` 8–72, `user_handle` 1–64.
2. **`unknown_credential`** — the snapshot has a credential with this `credential_id` whose user is `U`,
   which is active, and whose `rp_id` equals the answer's `rp_id`. If `user_handle` is present it MUST
   equal `user_handle(handle_key, U)` (§6), compared in constant time.
3. **`rp_not_accepted`** — `rp_id` is an accepted RP (§10).
4. **`origin_not_accepted`** — `origin` is byte-for-byte equal to one of the serialised listed public
   origins. It is never compared with the Host of the connection, and never normalised first.
5. **`bad_client_data`** — `client_data_json` is UTF-8 JSON whose top level is an object without
   duplicate keys; `type` = `"webauthn.get"`; `challenge` is a string; `crossOrigin` is absent or
   `false`; `topOrigin` is absent; `origin` is: for a native RP, one of `native_rps[rp_id]`; for a web RP,
   equal to the answer's `origin`. Other keys are ignored. Never compare the bytes with a template.
6. **`challenge_mismatch`** — `challenge` decodes (§2) to 32 bytes equal, in constant time, to §5
   computed with purpose `confirm`, the answer's `origin`, the gateway's `gateway_id`, `U`, the request's
   session id, request id and nonce, and the digest of the text the gateway sent.
7. **`bad_authenticator_data`** — `rpIdHash` (bytes 0–31) = SHA-256 of `rp_id`; the AT flag (0x40) is
   clear; BS (0x10) is not set without BE (0x08); if ED (0x80) is clear the length is exactly 37, if set
   the bytes after 37 are exactly one CBOR map (§12) and nothing else (the map is ignored).
8. **`uv_required`** — UP (0x01) and UV (0x04) are both set.
9. **`backup_state_mismatch`** — BE equals the stored `backup_eligible`.
10. **`signature_invalid`** — `signature` is an ASN.1 DER ECDSA signature that verifies with the stored
    P-256 key (`x`, `y`) over `authenticator_data ‖ SHA-256(client_data_json)` with SHA-256 (ES256).
11. **`counter_regression`** — with `n` = signCount (bytes 33–36, big-endian) and `s` = stored: if both
    are 0, accept; otherwise `n` MUST be greater than `s`.

Accepted: the outcome is `confirmed` with `method: "passkey"` and `verified: true`; the gateway then
re-reads the credential (revoked meanwhile → refused, `verification_failed`), stores `n` and BS with a
compare-and-set, and writes a receipt. The first verified answer settles the request; other connections
get `request.cancel {reason: "resolved"}`.

**`too_many_attempts`** — the fifth refused answer for one request is refused with this reason and
settles the request as `unavailable` (`verification_failed`). See `sequence_vectors`.

## 10. Relying parties and client origins

- **Native** RPs come from config `confirm.passkey.native_rps`: a map from RP ID to the allowed
  `clientDataJSON.origin` values for it. Default: `{"confirm.hermie.dev": ["https://confirm.hermie.dev"]}`
  (the official build's associated domain). The value Apple puts in `clientDataJSON.origin` for an
  app-initiated ceremony is **not yet confirmed on a device**; it is config for that reason.
- **Web** RPs are the hosts of listed public origins whose scheme is `https`, plus `localhost`. The RP ID
  is the exact host, never the registrable domain. The answer's `origin` host MUST equal the RP ID.
- A credential is stored with the RP it was created for. The vectors' `context.accepted_rps` lists the
  RPs accepted under `context`.

## 11. Verifying a registration (gateway)

`POST /api/auth/passkeys/register/finish` carries `{registration_id, origin, code, credential: {id,
client_data_json, attestation_object, transports?}}` for an open registration (`rp_id`, `origin`, `name`,
`nonce`, user) created by `register/begin`. The enrolment code and "credential already stored" are
checked by the route, not by this function. Order, each failure 422 `attestation_invalid` with `reason`:

1. `bad_shape` — fields present, base64url valid, `credential.id` 1–1,023 bytes, `client_data_json`
   ≤ 4,096 bytes, `attestation_object` ≤ 16,384 bytes.
2. `rp_not_accepted`, `origin_not_accepted` — as §9 steps 3–4, for the registration's `rp_id` and
   `origin` (the `origin` in the body MUST equal the one given to `register/begin`).
3. `bad_client_data` — as §9 step 5 with `type` = `"webauthn.create"`.
4. `challenge_mismatch` — §5 with purpose `register`, `session_id` `""`, `request_id` = `registration_id`,
   text `("", name, "")`.
5. `bad_attestation_object` — the attestation object is one CBOR map (§12) with exactly the text keys
   `fmt` (text), `attStmt` (map) and `authData` (bytes), consuming the whole input. Any `fmt` is
   accepted and `attStmt` is not checked.
6. `bad_authenticator_data` — `rpIdHash` = SHA-256(`rp_id`); AT set; then AAGUID (16 bytes), credential
   id length (2 bytes, big-endian), credential id equal to `credential.id`, then one CBOR map (the COSE
   key), then, only if ED is set, exactly one CBOR map of extensions; nothing else. BS not set without BE.
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
| `context` | the gateway under test: `gateway_id`, `handle_key`, `public_origins`, `native_rps`, `accepted_rps`, `user` |
| `origin_vectors` | §3: `input` → `origin`, or `error: "not_an_origin"` |
| `text_digest_vectors`, `challenge_vectors`, `user_handle_vectors`, `enrolment_code_vectors` | §4–§7 with expected outputs (`preimage_hex` for debugging) |
| `assertion_refusal_order` | §9's reasons in order |
| `assertion_vectors` | `request`, `store` (credential snapshot, all users), `answer`, `signed_by` (informative), `expect`: `{ok: true, sign_count, backup_eligible, backed_up}` or `{ok: false, code: 4034, reason}` |
| `sequence_vectors` | multi-answer behaviour (`too_many_attempts`), steps name assertion vectors |
| `registration_vectors` | `begin` (the open registration), `finish` (the body), `expect` |
| `wire_examples` | one example of each wire object in §8 |

`store` holds credentials of other users and a revoked one on purpose; take `U`'s active credentials
from it as the snapshot. Run every assertion vector against `context` and the vector's own `request` and
`store`.

Positives cover the native RP (synced, counter 0/0), the web RP (device-bound, counter increasing,
unknown `clientDataJSON` keys), and a listed private `http` origin on the native path. There is at
least one negative per refusal reason, the relay attack both ways (a valid signature replayed with the
other gateway's origin: `origin_not_accepted`; the same with this gateway's origin claimed:
`challenge_mismatch`), and challenges for other text, request, session, user, nonce, purpose and gateway.

### Regenerating

```
python generate.py           # write vectors.json
python generate.py --check   # rebuild in memory, compare byte for byte (exit 1 on any difference)
```

Everything is derived from fixed labels, so the file is reproduced exactly, except ECDSA signatures,
which are random and therefore stored: a rebuild keeps each stored signature while it still verifies
over its vector's message, and `--check` fails when one no longer does. Needs Python 3.11+ and
`cryptography`.

### Not covered yet

Real-device captures (iCloud Keychain and a third-party provider on iOS and macOS: `clientDataJSON`
bytes and origin, flags, signCount) are to be added once a build with the associated domain exists. RS256
and EdDSA are out of scope for version 1.
