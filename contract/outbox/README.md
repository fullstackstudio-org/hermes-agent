# Contract: files a bot shares

This directory is the written definition of how a file a bot sends reaches the person in the Hermie apps:
the attachment a reply carries and the route its bytes come from.

Files:

- `schema.json`: JSON Schema (2020-12) of one attachment (`OutboxAttachment`). Rendered from the gateway's
  model (`tui_gateway/contracts/common.py`) by `scripts/gen_gateway_contracts.py`; never edit it by hand.
- `examples.json`: valid and invalid attachments, a `message.complete` payload, a `session.history` row,
  and the answers of the route to byte ranges.
- `SHA256SUMS`: pins the three files above (`sha256sum -c SHA256SUMS` or `shasum -a 256 -c SHA256SUMS`).

The source of truth is the gateway's repository. Other repositories carry a byte-identical copy of this
directory. In the gateway repository `python scripts/gen_gateway_contracts.py --check` rebuilds
`schema.json` and `SHA256SUMS` and compares them, and `tests/tui_gateway/contracts/test_outbox_contract.py`
checks every example against the model and the route.

Normative words: MUST, MUST NOT, SHOULD as in RFC 2119.

## 1. When a file is shared

An agent attaches a file to its reply with a line `MEDIA:<path>` (the convention every messaging platform
delivers natively). Some tools produce one in their result: `text_to_speech` (`<home>/cache/audio/tts_*.mp3`,
`.ogg`, ...; whatever its `voice_compatible`) and `image_generate`. For a session whose `source` is listed in
the gateway's `files.outbox_sources` (default `["hermie"]`, the source the Hermie apps create sessions with),
at the end of a completed turn the gateway:

1. takes the reply's `MEDIA:` directives (examples in code and quotes excluded) and this turn's producer tool
   results;
2. checks each path as native delivery does (the credential and system denylist, strict mode, a sandbox path
   mapped to the host), plus the read guard and a basename denylist (`.env*`, credential stores, keys),
   resolves links first, and reads exactly the judged file (every component opened without following a
   link); it takes only a regular file with one link, of at most `files.outbox_max_file_mb` (200), and never
   a file in any profile's `outbox/` or in a person's upload folder (`uploads/hermie/`): a copy shared in
   one conversation is never handed to another;
3. copies it to `<profile home>/outbox/<token>/` (a new random token per copy; the agent's file is not
   touched), at most `files.outbox_max_turn_files` (20) files and `files.outbox_max_turn_mb` (500) per reply,
   all within `files.outbox_turn_timeout_s` (120): a copy still running then is abandoned and removed, so a
   slow file delays the reply by that much at most;
4. sends the attachments with `message.complete` and records them on the reply's row.

A file that cannot be shared (refused, over a limit, out of time) is never shown by its path: the text gets
one note, `(1 file could not be shared.)` / `(N files could not be shared.)`, without a name or a reason (the
gateway logs the reason).

Other sessions (the TUI, the Desktop app, the dashboard Chat tab) are not changed: they keep the `MEDIA:` line
in the text and render it from the path themselves.

## 2. The attachment

```json
{"id": "q3Wm0B2v7yXk4Lr9TzPa1sDf6GhJ8cNe", "name": "tts_20261004_225730_989324.mp3",
 "mime": "audio/mpeg", "kind": "audio", "size": 48213,
 "sha256": "<64 lower-case hex>", "created_at": 1791148287.08,
 "url": "/api/files/outbox/q3Wm0B2v7yXk4Lr9TzPa1sDf6GhJ8cNe/tts_20261004_225730_989324.mp3"}
```

| Key | Meaning |
| --- | --- |
| `id` | The token: 32 characters of `A-Z a-z 0-9 _ -`. |
| `name` | The file's base name as the bot named it: one component, no control character, `/` or `\`, at most 180 characters. Plain text: show it verbatim. |
| `mime` | The type the gateway recorded. `application/octet-stream` when the bytes contradict the name. |
| `kind` | `image`, `video`, `audio`, `pdf`: shown inline, and the gateway checked the bytes against the type. `file`: a download (HTML, SVG, scripts, archives, documents, anything unknown). |
| `size` | Bytes. |
| `sha256` | Of the bytes. |
| `created_at` | Unix seconds. |
| `url` | Where to fetch it, relative to the gateway's origin; the name percent-encoded. |

A client:

- MUST NOT expect a path on the server anywhere: there is none.
- SHOULD show `image` as an image, `video` and `audio` as a player (seekable, see §4), `pdf` as a document,
  and `file` as a file with its `name` and `size` that the person opens or saves deliberately.
- MUST NOT render a `file` (HTML, SVG, ...) in a web view of the app's own origin or with the app's
  credentials.
- MUST ignore an attachment with a `kind` it does not know, or show it as a `file`.

## 3. Where attachments appear

- `message.complete` carries `attachments: [...]`; its `text` then has no `MEDIA:` directive (and the note
  above when files could not be shared). `[]` when the reply named files and none could be shared. The key is
  absent when the reply named none, and on every session the outbox does not serve.
- The `message.delta` frames of such a session never carry a `MEDIA:` directive outside a fenced code block: a
  line holding one is held back and let through without it (what is held when the reply ends comes as one last
  `message.delta` before `message.complete`). The `message.complete` text is the authority, as before.
- `session.history`, the `messages` of `session.resume`, `GET /api/sessions/{id}/messages` and
  `GET /api/sessions/{id}/messages/around` show that assistant row with `attachments` beside `text` (`content` on the REST page) and without its
  directives. `display_metadata` does not repeat them.
- The row the model reads keeps what the agent wrote: the agent's next turn sees its own `MEDIA:` line.
- Session previews (`session.list`, the profile roster, `GET /api/sessions`), timeline entries and search
  snippets never show a `MEDIA:` directive, on any surface.

What still names a path (the agent's own working data, not a reply to the person): the `tool.*` frames and
tool rows (a tool's result, as for every tool), `message.interim` notes, and the text of a turn that ended
in an error or was interrupted (nothing is shared then). A client SHOULD NOT turn a `MEDIA:` line it sees
there into a link.
## 4. The route

`GET /api/files/outbox/{id}/{name}` (and `HEAD`), with `?profile=<name>` exactly like every other per-profile
route (the dashboard's own profile when absent).

- Authentication: the session header or the session cookie, like every `/api/` route. Never `?token=`.
- Access: the profile asked for, the recorded copy whose recorded name is `name`, and only a caller the
  conversation belongs to: the login it was created under, its stored owner, everyone who had attached when
  the file was shared, and whoever has attached since. A caller with no per-person identity (the
  loopback session token) is one trust domain and may fetch. Everything else is `404`, without saying
  whether the file exists.
- Every response carries `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none';
  sandbox`, `Cross-Origin-Resource-Policy: same-origin`, `Referrer-Policy: no-referrer`,
  `Accept-Ranges: bytes`, `ETag` (strong, from the SHA-256) and `Cache-Control: private, max-age=86400`.
- `Content-Disposition` is `inline` only for `image`, `video`, `audio` and `pdf`; every other file is
  `attachment` and is labelled `application/octet-stream` when its type is active content (HTML, SVG,
  XML, JavaScript). The file name is given as `filename` (ASCII) and `filename*` (UTF-8). A `pdf` requested
  as a page by a browser (`Sec-Fetch-Dest` `document`, `iframe`, `frame`, `embed` or `object`) is an
  `attachment`: browsers' built-in PDF viewers do not run under the sandbox, and the sandbox is not relaxed
  for them. An app that fetches it (no `Sec-Fetch-Dest`, or `empty`) and shows it in its own viewer gets it
  `inline`.
- Ranges: one `bytes` range: `first-last`, `first-` or `-suffix` → `206` with `Content-Range`. A range that
  starts past the end, ends before it starts, is malformed (a number of more than 18 digits included) or asks
  for zero bytes → `416` with
  `Content-Range: bytes */<size>`. Another unit or several ranges → `200` with the whole file.
  `If-Range` with another validator → `200`. `If-None-Match` with the `ETag` → `304`.

## 5. Retention

`files.outbox_retention_days` (30): older shared files are removed. `files.outbox_max_total_mb` (2048) and
10,000 files per profile: a new share first lets expired files go, then only the same conversation's oldest
(never a file of the reply being shared); when that is not enough the new file is refused, so one
conversation can never push out another's recent files. The periodic pass (dashboard start, then every six
hours) removes expired files, and the oldest of any conversation only when the outbox is over its cap (the cap
was lowered). Deleting a conversation (or pruning old sessions) removes its shared files. A removed file is
`404`; a client SHOULD show the attachment as no longer available.
