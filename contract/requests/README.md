# Contract: interactive requests

This directory is the written definition of the interactive server→client requests: questions the
agent asks the person through a connected client, beyond `clarify`, `approval` and `confirm`. Phase 1
defines three methods:

| Method | Asks for | Result |
| --- | --- | --- |
| `input.form` | typed fields (1–12) | `{status: answered, values}` or `{status: skipped}` |
| `input.file` | one or more files, uploaded | `{status: answered, files, text?}` or `{status: skipped}` |
| `review.draft` | approval of a draft, optionally edited | `{decision: approved, text}` or `{decision: rejected, comment?}` |

Files:

- `schema.json`: JSON Schema (2020-12) of every params and result object, one `$defs`. Rendered from
  the gateway's models (`tui_gateway/contracts/server_requests.py`) by
  `scripts/gen_gateway_contracts.py`; never edit it by hand.
- `examples.json`: frames, invalid frames (params the gateway never sends, §4), valid answers, invalid
  answers with the reason the gateway refuses them, and one field definition with valid and invalid
  values per form field kind.
- `SHA256SUMS`: pins the three files above (`sha256sum -c SHA256SUMS` or
  `shasum -a 256 -c SHA256SUMS`).

The source of truth is the gateway's repository (the gateway validates every answer). Other
repositories carry a byte-identical copy of this directory. In the gateway repository,
`python scripts/gen_gateway_contracts.py --check` rebuilds `schema.json` and `SHA256SUMS` and compares
them, and `tests/tui_gateway/contracts/test_requests_contract.py` checks every example against the
models.

**The examples are normative.** A client MUST produce answers the valid examples describe and MUST be
able to show every valid frame; a gateway MUST accept every valid answer and refuse every invalid one
with exactly the `reason` given. Where this document, `schema.json` and `examples.json` disagree, that
is a bug in one of them; report it rather than picking one.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119.

## 1. Advertising

A connection receives a method only after it advertised it. The second `client.capabilities` call
carries `requests`, the methods this connection can SHOW on this device:

```json
{"server_requests": true, "confirm": ["plain"], "requests": ["input.form", "input.file", "review.draft"]}
```

- Send `requests` only after the FIRST call's result lists at least one of these methods under
  `server_requests`. A gateway that knows the methods knows the key; an older one refuses the unknown
  key with `4000` and the whole call, `confirm` levels included.
- List only methods this device can show at all (a client that cannot upload files does not list
  `input.file`). A single request it cannot show (no camera for a `capture: photo` and no picker either)
  is answered with `4041` (§3).
- The result's `requests` echoes the methods the gateway accepted (`[]` when none). Unknown names are
  ignored; the list holds at most 32 entries.
- A request MAY arrive before the result of that `client.capabilities` call: a request that was waiting
  for a capable device is delivered as soon as the advertisement is accepted. Handle request frames from
  the moment the call is sent.

## 2. The envelope

Every params object is built and bounded by the gateway; the agent never passes one through. All
methods share these keys (`InteractiveRequestParams`), next to the transport's `session_id`:

| Key | Type | Meaning |
| --- | --- | --- |
| `v` | `1` | Contract version. A client that does not know the version answers `4041` with reason `unsupported_version`. |
| `title` | string, 1–80, one line: no CR, LF, VT, FF, NEL, U+2028 or U+2029 | Heading. |
| `summary` | string, 1–500 | The agent's words: what it asks and why. |
| `detail` | string ≤2,000 or absent | Extra context, shown monospaced. |
| `expires_at` | integer, Unix seconds | When the gateway stops waiting. |
| `optional` | boolean | Whether Skip is offered. `input.*`: true unless the agent says otherwise; `review.*`: false. |
| `acting_user` | `{id, name}` or absent | The person the turn acts for, when the gateway can name them. Informative: the gateway decides who may answer. |

Rendering rules (the same as `confirm`'s):

- Every string is PLAIN TEXT. A client renders it verbatim, never as markdown or HTML, and never lets
  it style the frame around it.
- The text is the AGENT's: a client marks it as such and never presents it as a message from the app
  or the system.
- Button wording is the client's own.

`expires_at`: a client hides the request at that time (a countdown is optional) and does not answer
after it. The gateway withdraws the request with `request.cancel {reason: timeout}`; an answer that
arrives later is not an answer (`request.answer` reports `expired`). The two clocks may differ:
`request.cancel` is authoritative, and a client MUST NOT present a request as still answerable once
`expires_at` has passed by its own clock.

## 3. Results, refusals and `cannot_show`

Every result starts with a closed enum:

- `input.*`: `status` ∈ `answered`, `skipped`. `skipped` only when the request is `optional`.
- `review.*`: `decision` ∈ `approved`, `rejected`. There is no skip: the person rejects.

A client answers with a JSON-RPC response to the request frame, or with `request.answer {id, result}`
from a connection that did not receive the frame. Both are accepted.

**Cannot show.** A client that cannot show a request (it has no camera and the person cannot pick a
file either, a permission was denied, an upload failed, it does not know a form field kind, it is
shutting down) answers a JSON-RPC ERROR, never a made-up `skipped` or `rejected`:

```json
{"jsonrpc": "2.0", "id": "<request id>", "error": {"code": 4041, "message": "cannot_show", "data": {"reason": "no_camera"}}}
```

`data.reason` is a short machine string; the set is open. In use: `no_camera`,
`not_supported_on_device`, `permission_denied`, `upload_failed`, `unsupported_version`,
`shutting_down`. The gateway reports the request as `unavailable` to the agent, which is not an answer.

**Refused answers.** The gateway checks every answer: first against the result model (`schema.json`),
then against the request's params. A refused answer is `request.answer` error `4034` (or the same
refusal on a bare response) with `data.reason`, and the request STAYS OPEN: the client shows the reason
next to the input and lets the person correct it. The tenth refused answer withdraws the request: that
refusal carries `data.reason: too_many_attempts` (not the problem it was refused for), the request is
withdrawn (`request.cancel {reason: too_many_attempts}`) and the agent is told it is unavailable.

| Reason | Methods | Meaning |
| --- | --- | --- |
| `bad_shape` | all | The result does not match the method's result in `schema.json`. |
| `not_optional` | `input.*` | `skipped` for a request whose `optional` is false. |
| `field:<id>:<problem>` | `input.form` | §4. |
| `files:too_many` | `input.file` | More files than `upload.max_files`, or more than one without `multiple`. |
| `files:too_large` | `input.file` | The files' `bytes` together exceed `upload.max_total_bytes`. |
| `file:<n>:outside_dir` | `input.file` | File `n` (0-based) is not directly in `upload.dir` (§5). |
| `file:<n>:too_large` | `input.file` | File `n` declares more `bytes` than `upload.max_bytes`. |
| `text:not_verbatim` | `review.draft` | The approved text contains something that cannot be shown as it is (§6). |
| `text:edited` | `review.draft` | The text differs from the draft while `editable` is false. |

The reason is the FIRST problem found, in this order: shape; `not_optional`; then per method as in §4,
§5 and §6.

## 4. `input.form`

Params: the envelope plus `fields`, 1–12 field objects. Every field has:

| Key | Type |
| --- | --- |
| `id` | `^[a-z][a-z0-9_]{0,31}$`, unique within the form |
| `kind` | `text`, `number`, `amount`, `date`, `time`, `datetime`, `daterange`, `choice`, `toggle` |
| `label` | string, 1–60 |
| `hint` | string ≤200, optional |
| `required` | boolean, default false |
| `default` | a value of the field's kind, optional: the client pre-fills it (never `""`: omit it for none) |

Per kind:

| Kind | Extra keys | Value |
| --- | --- | --- |
| `text` | `multiline` (false), `max_length` (≤4,000), `input`: `plain` \| `email` \| `phone` \| `url` | string, at most `max_length` (else 4,000) code points; no newline unless `multiline` |
| `number` | `min`, `max`, `step` (>0), `integer` (false) | JSON number in `[min, max]`; whole when `integer`; `min` (else 0) plus a whole multiple of `step` |
| `amount` | `currency` (ISO 4217, `^[A-Z]{3}$`), `min`, `max` (decimal strings) | decimal STRING `^-?(0\|[1-9][0-9]{0,14})(\.[0-9]{1,3})?$` in `[min, max]`, with at most as many decimals as the currency's ISO 4217 minor unit (EUR 2, JPY 0, KWD 3); never a JSON number |
| `date` | `min`, `max` (`YYYY-MM-DD`), `tz` | `"2026-10-03"`, a real calendar date |
| `time` | `min`, `max` (`HH:MM`), `tz` | `"14:30"`, 24-hour |
| `datetime` | `min`, `max` (instants, below), `tz` | `"2026-10-03T14:30:00+02:00[Europe/Amsterdam]"` (below) |
| `daterange` | `min`, `max` (`YYYY-MM-DD`), `tz` | `{"start": "2026-10-03", "end": "2026-10-05"}`, both inclusive |
| `choice` | `options` (1–12 `{value ≤64, label ≤80}`), `multiple` (false), `min_selected`, `max_selected` | one option `value` (string); with `multiple` a list of distinct option values |
| `toggle` | — | JSON boolean |

`input` on a text field is a keyboard hint, not a check: the gateway does not validate an address,
number or URL. `tz` is an IANA zone name; for `date` and `daterange` it says which day "today" is.

**Datetime values** carry the offset AND the zone. Exactly:

- An INSTANT is `YYYY-MM-DDTHH:MM` with optional `:SS`, no fractions of a second, and a numeric offset
  `±HH:MM`. `Z` is not used (write `+00:00`). A datetime field's `min`, `max` and `default` are
  instants; the client shows `default` in the answer's zone.
- A VALUE (the answer) is an instant followed by its IANA zone as an RFC 9557 suffix in brackets:
  `2026-10-03T14:30+02:00[Europe/Amsterdam]`. The suffix is REQUIRED. The zone is the field's `tz` when
  it has one, else the device's zone; the offset MUST be that zone's offset at that instant.
- To parse one, strip the bracketed suffix first and hand the rest to `Date` / `ISO8601DateFormatter` /
  `datetime.fromisoformat`; none of them accepts the suffix.

**Field definitions are consistent.** The gateway never sends a form whose fields contradict
themselves, and its models refuse one: field ids are unique; option values are distinct;
`min` ≤ `max` (compared as numbers, decimals, calendar dates, times or instants, and a date that only
looks like one, `2026-02-30`, is refused); a `default` is a valid value of its field (in range, whole
when `integer`, on a `step`, one line unless `multiline`, within `max_length`, one of the options, a
list of distinct options of allowed length with `multiple`, a range whose end is not before its start);
`min_selected` ≤ `max_selected` ≤ the number of options, and both only with `multiple`. JSON Schema
cannot express most of these, so `schema.json` accepts such a frame; `examples.json` lists them under
`invalid_frames` (layer `cross_field`). A client MAY refuse such a frame with `4041` and reason
`not_supported_on_device`.

Result: `{"status": "answered", "values": {<id>: <value>, ...}}` or `{"status": "skipped"}`. A field
without a value is left out of `values` (never `null`). `""` counts as no value for every
string-valued kind (`text`, `amount`, `date`, `time`, `datetime`, a single `choice`), and so does `[]`
for a multiple choice: valid for a field that is not `required`, `missing` for one that is.

Every `values` key is a well-formed field id (`^[a-z][a-z0-9_]{0,31}$`; `schema.json` says so with
`propertyNames`): any other key fails the result model and is refused as `bad_shape`, so no text of the
client's ever goes into a reason. The gateway then checks the keys (a well-formed id the form does not
have: `field:<id>:unknown`), then each field in `fields` order, and refuses the first problem as
`field:<id>:<problem>`. Within one field the problems are checked in the order of this table, so the
structural ones come before the range ones (a range is only judged on a well-formed value) and a
range's `order` before its bounds; of `below_min` and `above_max`, a range's `start` is checked first:

| Problem | When |
| --- | --- |
| `missing` | a `required` field has no value |
| `type` | the JSON type is wrong for the kind (a number for an amount, a list for a single choice, …) |
| `format` | a string is not in the kind's format (not a calendar date, three decimals, no zone, a newline in a one-line text, …) |
| `too_long` | text longer than `max_length` (else 4,000) code points |
| `zone` | a datetime zone that is unknown, or not the field's `tz` |
| `offset` | a datetime offset that is not the zone's offset at that instant |
| `order` | a range whose `end` is before its `start` |
| `not_an_option` | a choice value that is not one of the options' `value`s (labels are not values) |
| `duplicate` | a multiple choice that lists a value twice |
| `below_min` / `above_max` | number, amount, date, time, datetime outside `[min, max]`; a range whose `start` is before `min` or `end` after `max` |
| `not_integer` | a fraction where `integer` is true |
| `step` | not `min` (else 0) plus a whole multiple of `step` |
| `too_few` / `too_many` | a multiple choice with fewer than `min_selected` or more than `max_selected` values |

Values reach the agent as given. The agent asks only for what it needs.

## 5. `input.file`

Params: the envelope plus

| Key | Type |
| --- | --- |
| `accept` | `image`, `document`, `audio`, `any` |
| `capture` | `photo`, `scan`, `audio`, or absent: a preference, never a forced camera; the person may always pick an existing file |
| `multiple` | boolean |
| `upload` | `{dir, max_bytes (≤104,857,600), max_total_bytes (≥ max_bytes, ≤104,857,600), max_files (≤10), strip_metadata}` |

**The upload rule.** Files never travel inside the answer. The client uploads each file through the
gateway's existing HTTP upload route, with the credentials it already uses for attachments, to
`<upload.dir>/<16 lowercase hex>-<safe name>`, and then answers with references:

```json
{"status": "answered", "files": [{"path": "<upload.dir>/3f9c2a7b1d4e8f60-receipt.jpg", "name": "receipt.jpg", "mime": "image/jpeg", "bytes": 482113, "sha256": "<64 lowercase hex>"}], "text": "optional transcript"}
```

- `path` is absolute, at most 4,096 characters, and DIRECTLY in `upload.dir`: after resolving `.`, `..`
  and empty segments lexically (in both), its parent is `upload.dir` and its last segment is a name (not
  empty, `.` or `..`). A sibling directory sharing a prefix, `upload.dir` itself and a file in a
  subdirectory of it are all `outside_dir`: the layout is flat.
- `bytes` (a JSON integer) and `sha256` describe the bytes as uploaded (after metadata stripping).
- `upload.max_bytes` bounds EACH file; `upload.max_total_bytes` bounds all files of the answer
  together. A client checks both before uploading.
- `strip_metadata`: remove EXIF and GPS data from camera and library images before uploading.
  Documents are uploaded untouched.
- `text` (≤4,000) is an audio answer's transcript, when the client has one.
- A failed or cancelled upload is `4041 upload_failed`, never an answer naming a file that is not
  there.

The answer is checked in two steps. While the request is open: shape, `not_optional`, the file count
(`files:too_many`), then each file in order (`file:<n>:outside_dir`, `file:<n>:too_large`), then the
total (`files:too_large`). After it
settled, the gateway checks every file on disk without following a symbolic link anywhere (`upload.dir`
is the real path of a directory, the file sits directly in it and is a regular file, not a link, and
its size and SHA-256 match); a mismatch makes the request `unavailable (bad_upload)` for the agent, and
the client is not asked again. The upload route writes below the `uploads/hermie` part of a path
without following a symbolic link either: a client gets an error instead of a file stored elsewhere.

## 6. `review.draft`

Params: the envelope plus

| Key | Type |
| --- | --- |
| `kind` | `mail`, `post`, `message`, `document` |
| `text` | string, 1–20,000: the draft, shown verbatim (monospaced where whitespace matters, never re-wrapped into hidden line breaks) |
| `subject` | string ≤200, optional, display only |
| `recipients` | up to 10 strings ≤120, optional, display only |
| `editable` | boolean, default true: whether the person may change the text before approving |

Subject and recipients are shown apart from the body. The gateway builds the draft only from text it
can show as it is.

Result: `{"decision": "approved", "text": "..."}` (1–20,000; the text as approved, unchanged unless
`editable`) or `{"decision": "rejected", "comment": "..."}` (`comment` ≤1,000, optional).

The gateway removes whitespace at the end of each line of an approved text, exactly: the text is split
on LF only, every character for which Python's `str.isspace()` is true is stripped from the end of
each line (so CR, tab, VT, FF, NEL U+0085, NBSP U+00A0, U+3000, U+2028, U+2029 and every other Unicode
space at a line end) and then from the end of the whole text, which also drops trailing blank lines;
leading whitespace is kept. It then refuses text that still cannot be shown verbatim (a tab, a control, format or bidi character, a line separator, …:
`text:not_verbatim`) and, when `editable` is false, any change (`text:edited`). Whether the text was
edited is the gateway's computation, not the client's.

## 7. Versioning

Additive changes (a new method, a new optional key, a new `cannot_show` reason) keep `v: 1`. A client
never drops what it does not understand without saying so: it declines an unknown method with `-32601`
and a form with an unknown field kind with `4041 not_supported_on_device`. A change that would make a
v1 client show or answer a request wrongly bumps `v`.
