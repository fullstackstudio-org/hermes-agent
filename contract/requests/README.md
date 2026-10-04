# Contract: interactive requests

This directory is the written definition of the interactive server→client requests: questions the
agent asks the person through a connected client, beyond `clarify`, `approval` and `confirm`. Phase 1
defines three methods and phase 2 adds a fourth:

| Method | Asks for | Result |
| --- | --- | --- |
| `input.form` | typed fields (1–12) | `{status: answered, values}` or `{status: skipped}` |
| `input.file` | one or more files, uploaded | `{status: answered, files, text?}` or `{status: skipped}` |
| `review.draft` | approval of a draft, optionally edited | `{decision: approved, text}` or `{decision: rejected, comment?}` |
| `review.diff` | approval of the changes to a file, hunk by hunk | `{decision, hunks: {<id>: approved or rejected}}` |

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
{"server_requests": true, "confirm": ["plain"], "requests": ["input.form", "input.file", "review.draft", "review.diff"]}
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
- `review.*`: `decision` ∈ `approved`, `rejected`. There is no skip: the person rejects. (`review.diff` also
  decides every hunk, §7.)

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
`shutting_down`, `declined`. The gateway reports the request as `unavailable` to the agent, which is
not an answer.

**Declined.** `declined` means the PERSON chose not to provide it; it is not a limitation of the device
or the app. A client MUST let the person refuse a request that is not `optional` (an `input.*` request
whose `optional` is false has no Skip): it offers a plain refusal ("Don't share") and answers
`{"jsonrpc": "2.0", "id": "<request id>", "error": {"code": 4041, "message": "cannot_show", "data": {"reason": "declined"}}}`.
It applies to every interactive method. For `review.draft` Reject (`decision: rejected`) is the normal
refusal, but `declined` is still valid there (the person refuses to review it at all). The gateway
passes the reason on to the agent and the audit record as `cannot_show:declined`, with a sentence that
tells the agent to respect the choice and not to ask again at once; it is never taken for an answer,
a skip or a rejection. For an `optional` request Skip (`status: skipped`) stays the normal refusal.

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
| `hunk:<id>:unknown` | `review.diff` | `hunks` has an id the request does not (§7). |
| `hunk:<id>:missing` | `review.diff` | A hunk of the request has no entry in `hunks` (§7). |
| `decision:inconsistent` | `review.diff` | `approved` with no hunk approved, or `rejected` with one approved (§7). |

The reason is the FIRST problem found, in this order: shape; `not_optional`; then per method as in §4,
§5, §6 and §7.

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

The gateway removes whitespace at the end of each line of an approved text (§6.1), then refuses text
that still cannot be shown verbatim (§6.2 to §6.4: `text:not_verbatim`) and, when `editable` is false,
any change (`text:edited`). Whether the text was edited is the gateway's computation, not the client's.

### 6.1 Stripping (the only thing the gateway rewrites)

The text is split on LF (U+000A) ONLY. Every character for which Python's `str.isspace()` is true is
stripped from the end of each line (so CR, tab, VT, FF, U+001C to U+001F, NEL U+0085, NBSP U+00A0,
U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000 at a line end) and then from the end
of the whole text, which also drops trailing blank lines and a final LF. A line made only of spaces
becomes an empty line. Leading whitespace is kept. Stripping happens FIRST: everything in §6.2 to §6.4 is
checked on the stripped text, so a tab at the end of a line is removed and a tab anywhere else is
refused. A text that is empty after stripping is refused. A client strips the same way before it checks.

### 6.2 What is refused: characters

After stripping, the text is refused when it contains any of these. Only LF and U+0020 (space) are
allowed as whitespace.

1. A control character (`Cc`) other than LF: every C0 control (so CR, tab, VT, FF, ESC), DEL and every
   C1 control. A bare CR in the middle of a line is refused, not read as a line break.
2. Any other whitespace: `Zs` other than U+0020 (NBSP, U+1680, U+2000 to U+200A, U+202F, U+205F,
   U+3000), `Zl` (U+2028) and `Zp` (U+2029), and in general every character that `str.isspace()`
   accepts other than LF and space.
3. A format character (`Cf`: zero-width space and joiners, the bidi marks, embeddings, overrides and
   isolates, the soft hyphen U+00AD, the invisible operators, the language tags, U+FEFF), a surrogate
   (`Cs`), a private-use character (`Co`) and an unassigned code point (`Cn`).
4. An invisible letter or symbol: U+115F and U+1160 (Hangul Choseong and Jungseong fillers), U+3164
   (Hangul filler), U+FFA0 (halfwidth Hangul filler), U+2800 (blank Braille pattern) and U+1D159
   (musical null notehead).
5. A default-ignorable code point: one that the table below contains. It is a copy of Unicode's
   `Default_Ignorable_Code_Point` (`DerivedCoreProperties.txt`, unchanged from Unicode 14.0 through
   16.0). Clients use THIS table, not their platform's property, so a platform that updates the property
   does not change the answer. Besides most of the `Cf` characters above it holds the variation
   selectors (U+FE00 to U+FE0F and U+E0100 to U+E01EF) with no exception for an emoji's U+FE0F, the
   combining grapheme joiner U+034F, the Mongolian free variation selectors, the Khmer inherent vowels
   U+17B4 and U+17B5, the Hangul fillers and the reserved ranges.
6. More than `MAX_COMBINING_MARKS` = 4 combining marks in a row (see below).

Default-ignorable table (inclusive ranges, code points in hexadecimal):

```text
00AD
034F
061C
115F-1160
17B4-17B5
180B-180F
200B-200F
202A-202E
2060-206F
3164
FE00-FE0F
FEFF
FFA0
FFF0-FFF8
1BCA0-1BCA3
1D173-1D17A
E0000-E0FFF
```

Combining marks: a combining mark is a character of category `Mn` or `Me` (a spacing mark, `Mc`, is not
one). The count is of consecutive such characters, whatever the character before them: it starts at
0, rises by one for each `Mn` or `Me` character, and resets to 0 at any character that is not one (a
base letter, a space, an LF, an `Mc`). A text is refused when the count exceeds `MAX_COMBINING_MARKS`: 5 marks in a
row, even at the very start of the text. 4 in a row is fine. A mark that is also default-ignorable
(U+034F, U+FE0F, …) is refused as that, before it is counted.

An unassigned code point (`Cn`) is judged by a Unicode database, and databases differ between versions.
A client uses one of Unicode 14.0 or later. The gateway's answer is final: a text it refuses comes back
as `4034 text:not_verbatim` and the request stays open.

### 6.3 What is refused: layout

The layout limits keep padding from pushing part of a text out of view (a command followed by 300
spaces and a second command, or 80 blank lines before it). They apply to the stripped text, line by line,
with the lines split on LF only. All lengths count Unicode code points: not UTF-16 units, bytes or
grapheme clusters. Every combining mark counts as a character, and so does every character of a
supplementary plane.

| Limit | Value | What is counted | Refused when |
| --- | --- | --- | --- |
| `MAX_SPACE_RUN` | 16 | U+0020 in a row, after the line's first non-space character | a run of more than 16 |
| `MAX_INDENT` | 32 | U+0020 at the start of a line | more than 32 |
| `MAX_BLANK_LINES` | 3 | empty lines in a row | a 4th |
| `MAX_LINE_CHARS` | 2000 | the whole line, indent included, without its LF | more than 2000 |

- Only the space matters here: tabs and every other whitespace were refused in §6.2 already.
- A leading run of spaces is the indent, measured against `MAX_INDENT` only, and is NOT also a space
  run. Every later run on the line, however deeply the line is indented, is measured against
  `MAX_SPACE_RUN`. So 32 spaces and then `x` passes, `x` and then 17 spaces and `y` does not.
- A blank line is an empty line (after stripping no line of spaces remains). Blank lines at the start of
  the text count as blank lines in a row too: `"\n\n\n\nx"` begins with four, and is refused.
  Blank lines at the end of the text are stripped, never counted. Three empty lines between two lines of
  text is the most that passes (four LF in a row; five is refused).
- There is no exemption of any kind: a draft is plain text, not JSON, so the allowance the `confirm`
  request makes for the indentation inside a tool call's JSON string does not exist here.

### 6.4 Total length

As sent, `text` is 1 to 20,000 code points (more is `bad_shape`, as above), and after stripping it must not
be empty.

### 6.5 What a client does

Clients MUST refuse or flag exactly the same set of texts as §6.1 to §6.4 describe: they run the
stripping, then the character rules, then the layout limits, with these numbers and no others, on every
text the person edits, BEFORE they send an approval, and show the problem next to the editor (the exact
wording is the client's own). A client does not rewrite what it refuses: not by removing the characters
or the padding, not by replacing a tab with spaces. It also never sends a text it knows is in the refused
set, and the person cannot approve one. A client MUST NOT be more lenient than this, and SHOULD NOT be
stricter: a text the client refuses and the gateway accepts is a text the person cannot approve though
they could. The gateway re-checks everything: an approval refused with `text:not_verbatim` is shown the
same way, and the request stays open.

## 7. `review.diff`

The agent shows the changes it wants to make to ONE file, hunk by hunk, and the person approves or rejects each
hunk. Params: the envelope (`optional` is false: there is no skip) plus

| Key | Type |
| --- | --- |
| `path` | string, 1–300, one line, optional: the file's relative path, display only. A renamed file shows `old -> new`. |
| `hunks` | 1–200 hunks (below), `id` unique within the request |

A hunk:

| Key | Type |
| --- | --- |
| `id` | `h1`, `h2`, … numbered by the gateway in the diff's order (`^h[1-9][0-9]{0,2}$`) |
| `header` | string, at most 200: `@@ -a,b +c,d @@`, optionally followed by a space and the section text (the function the hunk is in); one line. A count left out is 1. |
| `lines` | 1–400 strings of at most 500 code points |

A line is one line of the hunk, in the order of the diff. Its first character is its marker: a space (context,
unchanged), `+` (added) or `-` (removed). The rest is the line's text. The one other line there is, git's note that
the file has no final newline, is exactly `\ No newline at end of file`; it belongs to the line before it. The
header's counts say how many old (` ` and `-`) and new (` ` and `+`) lines the hunk has, and the gateway built the
hunk so that they agree with `lines`. The starting line numbers are as the agent's diff gave them.

The gateway reads the agent's unified diff itself (at most 64 KiB, at most 200 hunks, at most 400 lines in a hunk)
and numbers the hunks; the agent never passes a hunk. A diff of several files, a binary diff and a diff the gateway
cannot show as it is are refused to the agent, and nothing is sent.

### 7.1 What is shown

Every line is shown verbatim: the person sees exactly what would be written. The gateway refuses to build the
request when a line does not pass, so a client only ever receives lines that do. The rule, per line: take the marker
off; the rest, as a text of one line, must pass §6.2 (characters) and §6.3 (layout: the indent, a run of spaces
and the length of a line; the limits for blank lines in a row do not come into play on one line) with the same
numbers, and no whitespace at its end (§6.1 does not strip here: a line with whitespace at its end is refused, not
rewritten, because a change that only adds or removes it would be invisible). A blank context line is a single
space. A tab, a carriage return that is part of a line, a bidi or zero-width character, a long run of spaces or a
line of more than 500 code points refuses the diff. The header must pass the same rule as a whole.

A client shows a hunk monospaced, one row per line, with the marker in a gutter apart from the text, added and
removed lines distinguished by more than colour, and scrolls long rows sideways instead of wrapping them into a
hidden break. It never trims, re-wraps, expands tabs in or re-orders a line, and never opens anything in it as a
link. `path` and `header` are display text like a subject (§6): shown apart from the lines.

### 7.2 The result

`{"decision": "approved" | "rejected", "hunks": {"<id>": "approved" | "rejected", ...}}`: `hunks` has an entry for
EVERY hunk of the request, keyed by its `id` (at least one entry, at most 200; a key that is not of the form `h<n>`
fails the model). There is no skip and no comment, and the person does not edit a hunk. The gateway refuses, as the
FIRST problem found:

1. `hunk:<id>:unknown`: a key of `hunks` that is no hunk of the request (in the order of the answer);
2. `hunk:<id>:missing`: a hunk of the request that has no entry (in the order of the request);
3. `decision:inconsistent`: `decision` is `approved` and every hunk is rejected, or `decision` is `rejected` and
   some hunk is approved. So `approved` means "apply what I approved" (some, or all) and `rejected` means "apply
   nothing".

The request stays open after a refusal (§3). A client disables Approve while no hunk is approved.

### 7.3 What the agent receives

The gateway keeps its own copy of the hunks. When the request settles, it writes the patch of exactly the approved
hunks from that copy, never from anything in the answer: the agent gets `approved_patch` (git's form, for
`git apply`; it names `path`) and the decision of each hunk. A rejected hunk before an approved one moves the latter's
new-side start back by the net change of the rejected one. The client's answer carries no text, so there is nothing
of the client's to put in the patch.

## 8. Versioning

Additive changes (a new method, a new optional key, a new `cannot_show` reason) keep `v: 1`. A client
never drops what it does not understand without saying so: it declines an unknown method with `-32601`
and a form with an unknown field kind with `4041 not_supported_on_device`. A change that would make a
v1 client show or answer a request wrongly bumps `v`.
