# tui_gateway/ + ui-tui/ — the TUI and its JSON-RPC backend

Applies on top of the root `AGENTS.md`. The TUI fully replaces the classic prompt_toolkit CLI;
activate with `hermes --tui` or `HERMES_TUI=1`. `tui_gateway` is ALSO the backend the Desktop app
and the dashboard `/chat` talk to — changes here have three consumers.

## Process model

```
hermes --tui
  └─ Node (Ink)  ──stdio JSON-RPC──  Python (tui_gateway)
       │                                  └─ AIAgent + tools + sessions
       └─ renders transcript, composer, prompts, activity
```

TypeScript owns the screen. Python owns sessions, tools, model calls, and slash-command logic.
Never move agent behaviour into the renderer.

## Transport

Newline-delimited JSON-RPC over stdio, peer-to-peer: client→server method calls, server→client
**requests** (the agent asking the user something: `approval`, `clarify`, `sudo`, `secret`, `vault.*`,
`connection`, the desktop read/act bridges) and server→client `event` notifications. `tui_gateway/server.py`
is the facade with the method/event catalog; methods live in `methods_*.py` siblings (`methods_config`,
`methods_complete`, `methods_browser`, `methods_bot_relay`, ...), event publishing in
`event_publisher.py` / `event_replay.py`, server→client requests in `server_requests.py` (`send()` blocks
the agent thread until the response frame with the same `srq-<n>` id arrives; `cancel*` withdraws with a
`request.cancel` event; `open_requests(sid)` is what `session.resume` / `session.events.since` replay so a
reconnecting client re-renders the still-open questions). A client says once per connection that it
answers them (`client.capabilities {server_requests: true}`, sent by the shared channel on `gateway.ready`);
a WebSocket client that never did is an app build older than server→client requests, and `send()` fails
fast for it instead of stalling the agent for the deadline. Desktop reaches the same server over WebSocket
via `apps/shared` (`JsonRpcGatewayClient`, `onRequest`). New RPC = a new `methods_<topic>.py` or an entry
in an existing topical sibling, registered in the table — no `if method == ...` chain (root shape rules).

**The wire is declared in Python and generated for TypeScript** (`tui_gateway/contracts/`). Every method
has a `Params` + `Result` model, every server→client request a `Params` + `Result`, every event a
`Payload` — one Pydantic class each, `extra="forbid"` by default (`OpenModel` for producer-owned dicts).
`register_method` refuses an undeclared name at import; the dispatcher rejects unknown param keys
(`4000` + key path) and, under `HERMES_TEST_ISOLATION=1`, raises `ContractViolation` when a handler's
result or an emitted payload does not match its model (production only logs). `apps/shared/src/
gateway-contract.generated.ts` (`RpcMethods`, `ServerRequestMap`, `BackendGatewayEventMap` + every value
shape) and `gateway-contract.openrpc.json` are rendered by `scripts/gen_gateway_contracts.py`;
`tests/tui_gateway/contracts/test_generated.py` fails when they are stale, so the loop is: change the model →
regenerate → `tsc` shows every consumer the field moved. `apps/shared/src/gateway-events.ts` only adds
the client-local synthetic events and the `GatewayEvent` envelope on top.
New question for the user = `_ask("<method>", sid, params, timeout)` in the emitter, a handler in
`apps/desktop/.../gateway-event/server-requests.ts` and `ui-tui/src/app/createServerRequestHandler.ts`,
and a `server_request(...)` in `contracts/server_requests.py`.
New event = `event("<type>", Payload)` in `contracts/events.py`; the emitter is checked against it.
A frame of a turn's stream (`message.*`, `reasoning.*`, `thinking.delta`, `tool.*`, `error`) carries the turn's
`turn_id` on its ENVELOPE (`params.turn_id`, stamped by `_event_frame` from the running turn), never in its payload, and
names the persisted rows it becomes (`row_id`, `call_row_id` + `call_index`); a new frame of that stream goes into
`tui_gateway/row_identity.py` `TURN_STREAM_EVENTS`. `tests/tui_gateway/test_transcript_row_identity_e2e.py` is the wire
truth for all of it. A turn's id reaches `_run_prompt_submit` only through the row's `display_metadata` or the explicit
`session["_pending_turn_id"]` hand-off (`begin_turn_id`); never read `session["turn_id"]` to adopt one, and call
`release_turn_identity` wherever `running` is force-released. Clients: a stamped `error` is not necessarily the turn's
terminal error (settle on `message.complete`), and a Codex commentary interim can carry only the undelivered text while
naming the right row.

## Profile scope in RPC methods

One `serve` process may host sessions from several profile homes (Desktop pooled backends launch
under a profile; the dashboard serves several). The launch profile is a profile: "default" means
the launch home, never `~/.hermes`. The first non-launch home hosted flips
`launch_profile_policy.py` → `set_multiplex_active(True)`; without it every fail-closed guard is
silently off. Every method that reads or writes home-, config- or `.env`-derived state runs under
`server.py::@_profile_scoped` (resolved from the live session's `profile_home`, or the explicit
`profile` argument for sessionless calls) and, for tool/agent construction,
`methods_tools.py::_profile_scoped_rpc`; the tokens come from `model_switch.py::
_profile_runtime_scope_tokens(profile_home)` — home + secret scope + terminal scope together.
**A method that sets only `get_hermes_home_override()` is half-bound**: config paths resolve to the
right profile while credentials and `TERMINAL_*` policy still come from the launch profile.
Off-turn paths bind the same way: `session_lifecycle.py::_finalize_session` / `_teardown_session`
enter `_session_profile_runtime_scope(session)` around `on_session_end`, the memory commit and
`agent.close()` (their callers are unscoped reapers, Timers, atexit and pool threads); background
threads start via `agent.memory_provider.spawn_context_thread`, never bare `threading.Thread`;
children act for the served profile through `tools/environments/local.py::served_profile_child_env`
(`hermes -p X` workers, `key_cmd` helpers, browser drivers), never `dict(os.environ)`. Grep for
unscoped handlers before adding one: `rg -n "^(async )?def " tui_gateway/methods_*.py | rg -v
_profile_scoped`. Probe with two on-disk homes and a `.env` name present only in the secondary:
call the method for that session and assert the secondary's value resolves and the launch
profile's does not, and that `os.environ` is unchanged afterwards.

## Key surfaces

| Surface | Ink component | Gateway method / event |
|---|---|---|
| Chat streaming | `app.tsx` + `messageLine.tsx` | `prompt.submit` → `message.delta` / `message.complete` |
| Tool activity | `thinking.tsx` | `tool.start` / `tool.generating` / `tool.complete` |
| Approvals | `prompts.tsx` | server→client request `approval` → response `{choice}` |
| Clarify / sudo / secret | `prompts.tsx`, `maskedPrompt.tsx` | server→client requests `clarify` / `sudo` / `secret` (`server_requests.py`) |
| Session picker | `sessionPicker.tsx` | `session.list` / `session.resume` |
| Slash commands | local handler + fallthrough | `slash.exec` → `_SlashWorker`; `command.dispatch` |
| Completions | `useCompletion` hook | `complete.slash`, `complete.path` (under a non-local `terminal.backend`, `complete.path` lists the directory through the session's terminal backend — never the gateway host, whose same-named tree would look right and be wrong) |
| Theming | `theme.ts` + `branding.tsx` | `gateway.ready` carries skin data |
| Plugin compat notice | — | `plugins.compat_report` (see `plugins/AGENTS.md`) |
| Connection operations (desktop card) | desktop `store/connection-request.ts` | `connection.request` → `connection.update`* → `connection.respond {op_id}`; `connectors.operation.status`. The op lives in `tools/connectors/live.py`; the card never parks the tool thread (`methods_connectors.py`). |
| Confirm (fork) | the apps' own confirm sheet | server→client request `confirm` (levels `plain`, `passkey`), gated on `client.capabilities {confirm: [...]}`; structured `fields` only to `confirm_fields: true` (at `passkey` also `confirm_passkey {v: 2}`, text digest v2); `draft_id` takes the detail from `review_register`; tool `confirm_action`. Guide: `website/docs/guides/confirm-sensitive-actions.md`. |
| Interactive requests (fork) | the apps' own form, file, draft, diff, signature and device sheets | server→client requests `input.form`, `input.file`, `review.draft`, `review.diff`, `input.signature`, `device.location`, `device.contact`, `device.calendar`, `device.scan`, gated on `client.capabilities {requests: [...]}`; tools `ask_form`, `ask_file`, `review_draft`, `review_diff`, `ask_signature` (toolset `interactive`) and `device_location`, `device_contact`, `device_calendar`, `device_scan` (toolset `device`). See "Interactive requests" below. |
| Shared files (fork) | the apps' attachment views | `message.complete {attachments}` and the history row's `attachments`, bytes from `GET /api/files/outbox/{token}/{name}`. Only for sessions whose `source` is in `files.outbox_sources` (default `hermie`): `outbox_share.py` takes the reply's `MEDIA:` lines and this turn's `text_to_speech` / `image_generate` results, `outbox.py` checks and copies each into `<profile home>/outbox/<token>/`; text, deltas and every history projection lose the directive (`outbox_share.project_row`), the stored row keeps it for the model. Never put a path in `display_metadata.attachments`; never share from any `outbox/` or `uploads/hermie/` (the read guard denies `outbox/` too); paths are judged by what they name (`agent/path_identity.py`: inode identity, folded case on case-insensitive volumes, the opened descriptor's own path), never by string alone; a copy is staged in `outbox/.staging/` and published under the lock; a conversation (compression lineage root, `record.conversation_id`) holds at most half the cap and half the entry count, a share that cannot fit is refused before anything is evicted, else it evicts expired files, its own conversation's oldest and other conversations' files older than 24 h, never the current reply's; deleting a session removes its copies (`SessionDB._remove_session_outbox`); previews and snippets go through `hermes_state_common.strip_media_for_preview`. Contract: `contract/outbox/`. |
| Provider account usage (fork) | the apps' usage view | `account.usage {profile?, refresh?}` (`methods_account_usage.py`, the work in `agent/account_usage_view.py`): one entry per provider the profile's model and fallback chain run on, windows and credits as fields, under `@_profile_scoped`. Every entry is built field by field from the snapshot (never its `raw` body, a header or an exception's text; credential-shaped free text is dropped whole); ~60 s cache per (profile, provider), `refresh` at most once per 15 s, 10 s per provider, one fetch for concurrent callers (a caller never waits it out: stale entry, or after 2 s "being refreshed"). Readable for any profile by any signed-in connection, as `config.get`. A new provider needs a `fetch_account_usage_strict` source, nothing here. Docs: `website/docs/developer-guide/programmatic-integration.md`. |
| Stop everything (fork) | the apps' "stop all" control | `session.interrupt_all {profile?}` (`methods_session.py`): one pass over `_sessions` under its lock, `_transport_may_access_session` per session as `session.interrupt`, and a signed-in connection stops only its own login's turns (`_turn_is_callers`); the stops follow outside the lock, each under the turn-start fence and only if the same turn (`_turn_token`) is still running and still the caller's. A shared chat is stopped narrowly (`_stop_turn_narrowly`, as an MCP agent's stop: other people's queue and delegations stay), the caller's own chat fully. Runs on `_stop_pool` (`_STOP_HANDLERS`), never behind `_pool`. Cron runs are outside the registry and carry no owner login, so they are left alone. |
| Standing approvals (fork) | the apps' permissions view | `approval.grants` / `approval.revoke` (`methods_prompt.py`; shaping `approval_grants.py`; state `tools/approval.py`). A grant is the group of stored keys whose rules overlap (aliases are neither symmetric nor transitive), labelled with every rule; ids recomputed on revoke, labels force-redacted. `revoke_permanent(choose)` decides and writes under `_permanent_write_lock` → `_config_mutation_lock()` → `_lock` (`_persist_choice` holds the first across snapshot and save). Everyone but an MCP agent (4033), as `config.set`; sessions via `_transport_may_access_session`. Session grants move on compression, end on `tui_close` / `setup_reset`. |
| Per-turn client surface | — | `prompt.submit {surface}`, allowlist `_CLIENT_SURFACES` (`hud`, `voice-live`, `voice-call`); unknown values clear it. The note for the surface (`session_notifications._hud_surface_note`) is prepended to the MODEL INPUT of that turn only, never persisted. `voice-live` and `voice-call` also take `voice_context` (recent spoken exchange, cut at 6000 chars). `voice-call` (fork) is the app's hands-free voice mode, reply read aloud as it streams: the note (`tools/voice_live.VOICE_CALL_TURN_NOTE`) tells the bot to announce slow work first. An MCP agent's submit may carry none of these (`agent_guard.AGENT_SUBMIT_PARAMS`). |

## Interactive requests (fork)

Nine server→client requests beyond `clarify`, `approval` and `confirm`: `input.form` (typed fields, 1-12),
`input.file` (files, uploaded; a voice note is `accept: audio` with `capture: audio`), `review.draft` (approve, edit or
reject a draft), `review.diff` (approve or reject each hunk of the changes to one file), `input.signature` (sign a
statement), and four that ask the person's device for something of theirs: `device.location`, `device.contact`,
`device.calendar` and `device.scan`. Code: `server_requests.py`
(the gate and the parking), `interactive.py` (the builders, the validators' bridge, the outcomes, the audit),
`interactive_validate.py` / `interactive_fields.py` (pure checks), `interactive_device.py` (what the gateway does
with the answers of the device requests and the signature: rounding, filtering, cleaning, the statement hash, the
calendar item), `diff_hunks.py` (a unified diff into hunks, and
the approved patch back), `review_register.py`, `upload_dirs.py`,
`request_hooks.py`; the agent's side is `tools/interactive_tools.py` and `tools/device_tools.py`. The wire is declared in
`contracts/server_requests.py` (`INTERACTIVE_METHODS`) like every other request.

**The written contract is `contract/requests/`** (`README.md`, `schema.json`, `examples.json`, `SHA256SUMS`).
It is NORMATIVE and this repository is its source of truth (the gateway validates every answer); the apps carry
a byte-identical copy. `schema.json` and `SHA256SUMS` are rendered, never edited by hand:
`python scripts/gen_gateway_contracts.py` writes them, `--check` compares them, and
`tests/tui_gateway/contracts/test_requests_contract.py` runs every example against the models. Change a model, a
rule or an example, regenerate, and expect the copies in the app repositories to follow. A new `cannot_show` reason
or an optional key is additive (`v: 1` stays).

**Method gate.** `send_gated(level=None)` qualifies a connection on the METHOD: it must have listed it under
`client.capabilities {requests: [...]}` (a second call, after the first call's result lists the method under
`server_requests`; a gateway that does not know the key answers `4000` for the whole call). The frame goes only to
qualifying connections attached right now. An answer is accepted only from one (`4033` otherwise, `4034` for a
result the validator refuses, with `data.reason`; the request stays open, and the tenth refusal withdraws it:
`unavailable (too_many_attempts)`). An error response from every connection the frame went to settles
`unavailable (error_response)`. The first valid answer wins and the others get `request.cancel {reason: resolved}`.
A connection whose `auth_identity` carries `agent` (an agent acting through MCP) never qualifies: its advertisement
is ignored and it can answer none of these.

**Acting user.** The target predicate is `acting_user_target`: only connections signed in as the login the turn
acts for. When the gateway cannot name one: with no auth provider every capable connection qualifies; in a shared
(ambiguous) session `input.*` goes to every capable connection and the outcome names `answered_by`, but `review.*`
goes to NOBODY and ends `unavailable (no_acting_user)` at once (`STRICT_ACTING_USER_PREFIXES`); a failure reading
the login also fails closed. A request for the wrong person is worse than none: do not widen this.

**Parking.** When no qualifying connection is attached the request is registered open with no targets, `on_open`
runs with 0 connections reached and `pre_server_request` fires with `reached: 0` (the push that brings the
person's phone). A qualifying connection that attaches later gets it from `open_requests` (or from
`deliver_late`, when it advertises the method while already attached) and becomes a target. One rule decides the
wait: while the request has a target it waits for its `timeout` (300 s); while it has none it waits for the park
window (`min(timeout, park_seconds)`, 120 s) and then settles `unavailable (no_capable_client)`. A target is lost
by a failed write, a disconnect (`forget`) or an advertisement that no longer lists the method. A request that was
shown and then lost its last target gets a FRESH window from that moment, never past its `timeout`
(`_drop_target_locked`): a phone sent to the background may come back to it. `request.cancel {reason: timeout}`
goes out with `no_capable_client` only when some connection was ever shown the request. `confirm` keeps declining
at once; parking is for method-gated requests only. Turn isolation (`HERMES_COMPUTE_HOST_CHILD`) fails closed
(`unavailable (turn_isolation)`), as for `confirm`.

**Envelope.** The gateway builds every params object and the agent never passes one through (`build_form_params`,
`build_file_params`, `build_draft_params`, `build_diff_params`). All share `v`, `title` (1-80), `summary` (1-500), `detail` (at most
2,000), `expires_at`, `optional` (`input.*`: true unless the agent says otherwise; `review.*`: false) and
`acting_user`. Text is cleaned and refused, never truncated, when empty or over a bound; a draft is not cleaned
but must be showable verbatim (line-end whitespace is removed, a tab, control, format or bidi character is refused).
Params and results are never logged; the audit log gets `interactive_request` and `interactive_outcome` (session,
request id, method, acting user, connections reached, outcome, reason, answering login and peer; never a title,
summary, value, path, name or draft).

**Toolsets and tools.** `interactive` holds `ask_form`, `ask_file`, `review_draft`, `review_diff` and
`ask_signature`; `device` holds `device_location`, `device_contact`, `device_calendar` and `device_scan`. Both are in
`_DEFAULT_OFF_TOOLSETS` (`hermes_cli/tools_config.py`), like `confirm`, so a new install has them off; `hermes tools`
turns each on per platform. The tools are withheld outside the interactive gateway (CLI, messaging, cron: the bridge is not installed) and a call that
still arrives is `unavailable (no_session)`. Every tool result is JSON `{outcome, ..., reason?, message}` where
`message` is one sentence that says only what is known; `unavailable` and `timeout` are never an answer (for a
draft never an approval) and the agent is told to tell the person and not retry at once. One open request per
conversation across both toolsets (`interactive._reserve`), and per 10 minutes 12 `input.*` / `review.*` sent
(`interactive._limiter`) and 6 `device.*` (`interactive._device_limiter`), both separate from `confirm`'s; a request
that reached nobody does not count. A device request waits 180 s, the others 300 s (`interactive.timeout_for`). An approved draft's final text goes into `review_register` under a `draft_id`
(memory only, 1 hour, 20 per conversation, 256 conversations); no tool consumes the id yet.

**Signature and the device requests** (contract README §8-§12). What is personal is kept to what the person chose to
share, on the gateway as well as on the sheet (`interactive_device.py`, called by both the validator and the
hand-off, so they cannot disagree). `input.signature`: the statement is shown VERBATIM (built like a draft: line-end
whitespace removed, anything that cannot be shown as it is refused, at most 500 characters), the answer is a PNG and an
SVG uploaded like `input.file`'s plus `statement_sha256`, which must be the SHA-256 of the exact UTF-8 bytes of the
frame's `statement` (`statement:mismatch`); after the request settled, `verify_files(sniff=...)` also checks that the
PNG begins with the PNG signature and the SVG passes `interactive_device._svg_problem` (`bad_upload`): strict UTF-8, no
`&`, no `url(` and no backslash, no control or hidden character, expat with handlers that refuse a doctype, entity, CDATA
and processing instruction, and an ALLOWLIST of unprefixed elements and of attributes whose VALUES each match a grammar
(number, colour, path, points, viewBox, transform; ASCII whitespace only and none at the ends, lowercase keywords, numbers of at most 32 characters: a denylist is bypassed by a prefix, a character reference, another
encoding or a CSS escape), and no text at all.
The files' names must end `.png` and `.svg` (`file:<n>:extension`), and the whole file is read (up to 1 MiB, however the
reads were split). The agent gets
`signed`, `statement_sha256`, `signed_at` (the client's clock), `received_at` (the gateway's), `signer_name?` and the
two files. `device.location`: the answer is JSON numbers in range, refused as `precision:too_precise` for a
`precise` answer to an `approximate` request; the agent receives coordinates ROUNDED by the gateway whatever the
client sent (`approximate`: two decimals, `accuracy_m` at least 1,000; `precise`: six decimals), and `lowered: true`
when the person shared less than asked. `device.contact`: `fields` names what may be shared; a key outside it is
refused (`contact:<key>:not_requested`, a null included), as is a contact with nothing usable left once cleaned
(`contact:empty`), and the hand-off cuts the contact to the requested keys again and cleans every string.
`device.calendar`: the agent's item is cleaned, bounded and held to the contract model (dates when `all_day`, instants
with an offset otherwise, `end` after `start`, a reminder has no `end`; a `url` with user information (`user@host`) or any hidden character is refused); the client opens the system sheet and only the
person's Save is `done`; the agent receives `{saved: true, kind}` and nothing identifying. `device.scan`: the value is
untrusted text, bounded at 4,096, shown to the person before it is sent; the agent receives it cleaned (control,
format, private-use and invisible characters removed, spacing kept) with `cleaned` saying whether that changed it.
`input.signature` and every `device.*` request go only to the acting person's own connections, and in a shared session
that names nobody to nobody (`STRICT_ACTING_USER_PREFIXES`: `unavailable (no_acting_user)`), because where a person is,
one of their contacts and a signature in their name are not for whoever answers first. No coordinate, contact, scanned
value, statement, path or file name reaches a log, an audit record or a hook; the tool result is the one place values
live.

**Voice notes.** `input.file` with `accept: audio` and `capture: audio` asks for a recording; the contract holds
`capture: audio` to `accept: audio` and the other way round, the answer check refuses a file that is not
`audio/<subtype>` without parameters (`file:<n>:not_audio`) and a transcript for an image or a document request
(`text:not_audio`), and the builder sends `strip_metadata: false`. The optional `text` is a transcript made ON the
device (the web sends none); the agent receives it cleaned and is told it may be wrong.

**Uploads.** `input.file` answers name files by reference; the bytes never travel in the answer. The app uploads
through the existing upload route to `upload.dir`, which the gateway builds as the flat
`<session cwd>/uploads/hermie/<YYYY-MM-DD>` and creates 0700 (files 0600). Everything from `uploads` down is walked
one component at a time with `O_NOFOLLOW` (`upload_dirs.py`): a symbolic link or a non-directory at any component
is `unavailable (upload_dir_unsafe)` with nothing sent (`upload_dir_unavailable` when the folder cannot be made).
Links ABOVE `uploads`, the working directory included, are followed by design (read the `upload_dirs` docstring for
what that assumes of a sandbox). While the request is open the validator checks the file count, each file's
declared size and that it sits directly in `upload.dir` (no subdirectory); after it settled, outside every lock,
`verify_files` opens each file by name under the directory's descriptor, refuses a link, and checks regular file,
size and SHA-256 against the declaration. A mismatch is `unavailable (bad_upload)`; nothing is deleted. The upload
routes (`hermes_cli/web_routers/files.py`) follow no link at or below `uploads/hermie` either and never replace an
existing file when the client said not to overwrite.

**Diff review.** `review_diff` hands the gateway a unified diff of ONE file as text; `diff_hunks.parse` turns it
into hunks the gateway numbers (`h1..`) and bounds (64 KiB, 200 hunks, 400 lines per hunk, 500 characters per
line, 200 per header) and the request carries those hunks, never the agent's text. A hunk is read by its header's
counts (the way `patch` does); every line passes `request_text.verbatim_problem` with its marker (space, `+`, `-`)
taken off (a tab is allowed, leading and inside a line, so Go and Makefile diffs work; its layout limits are a diff's own, in columns with a tab stop every 8: indent at most 96, any other run of spaces and tabs at most 32, all of them together at most 160, no combining mark after a space; `diff_hunks.text_problem`), so a CR that is part of a line, a hidden character or trailing whitespace (a tab included) refuses the diff instead
of being rewritten (a diff whose own line ending is CRLF is read like an LF one). Binary diffs, several files and a
diff without a hunk are refused; the `\ No newline at end of file` line is kept only in the LAST hunk, once per
side, directly after the last `-`/`+` line of the hunk and never after a context line (anywhere else `git apply`
glues a line to the next one invisibly). The file's head (kind `modify`, `new`, `delete` or `rename`, from the
`---`/`+++`, `new file mode`, `deleted file mode` and `rename from/to` lines) is read into a structure and the
header the agent wrote is thrown away; only regular files of mode 100644 can be created or deleted (a link, a
submodule, an executable or a mode change is refused), paths are relative with no `..` or `.git` segment and no
control character, a diff of bare hunks needs the agent's `path`, and a hunk without a context line is refused unless it starts at line 0 or 1, and a hunk with no context line after its last change must be the last one (`git apply` pins it to the end of the file whatever its header says). Each hunk carries `anchor` (`start`, `end`, `both`, from `diff_hunks.anchor_of`) so clients can say so; the header's line numbers are not checked against the file. The request carries `kind`, `path` (required)
and a rename's `old_path`. The answer carries only a decision per hunk id (`interactive_validate._diff_problem`: every
hunk decided once, `approved` only with some hunk approved, `rejected` only with none). When it settles, an approved
outcome's `approved_patch` is `diff_hunks.compose_patch` over the gateway's stored hunks and head, with the
approved hunks only (git's form, new-side starts corrected for the rejected hunks before them), so it names exactly
the path the person was shown and contains exactly the lines they saw. A client has no way to put text in it.

**`4041 cannot_show`.** An app that cannot show a request answers a JSON-RPC error `4041` with
`data.reason`, never a made-up `skipped` or `rejected`. The reasons the contract lists (`no_camera`,
`not_supported_on_device`, `permission_denied`, `upload_failed`, `unsupported_version`, `shutting_down`,
`declined`) reach the
agent and the audit record as `unavailable (cannot_show:<reason>)`, each with a sentence of its own
(`interactive.CANNOT_SHOW_REASONS`). Any other reason (the set is open) is plain `error_response`: only a short
machine word from a `4041` is ever read, so nothing else of the client's reaches the agent.

**Hooks.** `send_gated` itself fires `pre_server_request` / `post_server_request`; nothing in `interactive.py`
calls a hook. The interactive methods are listed under `pre_server_request` in `website/docs/user-guide/features/
hooks.md`, with `reached` possibly 0, and `tests/tui_gateway/test_request_hooks.py` pins that table against
`request_hooks.METHODS`. Add a method to one and the test fails until the other follows.

Tests: `tests/tui_gateway/test_interactive_request.py`, `test_interactive_device.py`, `test_interactive_validate.py`, `test_diff_hunks.py`, `test_request_hooks.py`,
`tests/tui_gateway/contracts/test_requests_contract.py`, `tests/tools/test_interactive_tools.py`, `tests/tools/test_device_tools.py`.

## Shared subagent snapshots

`subagent.list({session_id})` returns `{subagents, delegations}` for the calling
transport's live session. The roster is read-only and follows the CONVERSATION: exact-owner
records plus children whose durable lineage (`owner_agent_session_id` → compression tip, the
same spine as in-process `delegate_task(action="list")`) is the session's agent, because a
Desktop reconnect / resume remints the UI session id and compression rotates the key while the
children keep running (#114909). Control (`steer` / `interrupt` / `tail`) stays pinned to the
exact session record and transport. Child authority is resolved at RPC time against the owning session's
LIVE transport slot, so every authenticated reattach path (prompt.submit, queued drain,
resume, activate, viewer failover) carries it with no registry bookkeeping — never add a
per-record transport sync at an attach site; foreign or retired generations remain uncontrollable. `last_tool` is the last started tool, not an in-flight
indicator. Async completion units are not agents and lack exact generation authority;
`delegations` remains an empty array for wire compatibility. No dispatch context,
results, callbacks, or routing keys are sent. Clients hydrate from this snapshot
on their existing poll and avoid updates when unchanged.

`subagent.tail({session_id, subagent_id})` returns
`{subagent_id, available, text, truncated}`: the last 16 KiB of the live child's
existing transcript. Poll only the selected detail. Missing/finished/foreign
children return an unavailable empty snapshot; no client-supplied path is opened.
This is live-only, not persisted completion history. Invalid session/transport
returns error 4001. `subagent.steer({session_id, subagent_id, text})` remains the
shared control: `status: queued` acknowledges acceptance, not delivery; final
boundary races are reported by the existing runtime as `missed_steer`.
`subagent.interrupt({session_id, subagent_id})` requires the same exact live
session/transport/generation ownership, including for subtree members. Missing
RPC session authority is rejected; direct in-process `interrupt_subagent(id)`
retains its legacy unscoped contract.

## Slash command flow

1. Built-in client commands (`/help`, `/quit`, `/clear`, `/resume`, `/copy`, `/paste`, ...) are
   handled locally in `app.tsx`.
2. Everything else → `slash.exec`, which runs in the persistent `_SlashWorker` subprocess →
   `command.dispatch` fallback, which the gateway resolves into a skill / alias / exec directive
   (a skill command resolves to `{type: "skill", message}` and is submitted as a normal prompt).

`commands.catalog` (empty-query list) and `complete.slash` (typed-query completions) already include
built-ins, user `quick_commands`, AND skill-derived commands (`scan_skill_commands()` /
`get_skill_commands()`) — clients do not need a new RPC to see skills. The command definitions
themselves come from `hermes_cli/commands.py` (`hermes_cli/AGENTS.md`).

## Dev commands

```bash
cd ui-tui
npm install       # first time
npm run dev       # watch mode (rebuilds hermes-ink + tsx --watch)
npm start         # production
npm run build     # full build (hermes-ink + tsc)
npm run typecheck # tsc --noEmit
npm run lint      # eslint
npm run fmt       # prettier
npm test          # vitest
```

Python tests: `tests/tui_gateway/` via `scripts/run_tests.sh`. TS tests: vitest in `ui-tui`. A
Python test that asserts about `package.json` / `.ts` sources will not run on a JS-only PR — keep
JS-side assertions in vitest (root testing rules). Root TypeScript style rules apply.

Related: `web/AGENTS.md` (dashboard embeds this TUI over a PTY), `apps/desktop/AGENTS.md` (own
renderer on the same backend).
