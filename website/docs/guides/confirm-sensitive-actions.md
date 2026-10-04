---
title: "Ask the Person to Confirm a Sensitive Action"
description: "Turn on the confirm_action tool so an agent asks for a confirmation in the connected app before it spends money, deletes data or acts on someone's behalf, set up the passkey level the gateway verifies itself, and learn exactly what each level proves"
---

# Ask the Person to Confirm a Sensitive Action

The `confirm_action` tool lets an agent stop before a sensitive step (a payment, a deletion, a message
sent on someone's behalf, an access change) and ask for a confirmation in the connected app. The app shows
the agent's text with its own Confirm and Decline buttons, and the agent gets one of four answers back.

The title, summary and detail are **the agent's own words**. Apps show them verbatim and mark them as
coming from the agent, but an agent can word them to look like a system or security message. Read them
as the agent's description of what it is about to do, nothing more.

## Two levels

| Level | What `confirmed` means | `verified` |
| --- | --- | --- |
| `plain` | Someone tapped Confirm in an app attached to this conversation. | always `false` |
| `passkey` | The person this turn works for confirmed with their passkey, and the gateway checked the signature over exactly the text it sent. | `true` |

The agent picks the level (`confirm_action(level="passkey")`). `passkey` is offered to the agent only
while the operator has enabled it, and works only on a gateway with a sign-in provider (see
[Set up the passkey level](#set-up-the-passkey-level)). The operator can also force a passkey
confirmation for commands and tools, whatever the agent asks (see
[Operator rules](#operator-rules-force-a-passkey)).

## What `plain` proves

A `plain` confirmation proves that **someone tapped Confirm in an app attached to this conversation**.
Nothing more:

- not who tapped it, and not that it was the account owner. Any app attached to the conversation that
  supports confirmations can answer: your other devices, and in a shared conversation any participant.
  An app that only knows the conversation's id cannot: it has to attach (resume the conversation) first,
  which the gateway logs and which marks the conversation as shared;
- not that the app is genuine: any client that can attach to the conversation can say it handles
  `plain` and answer it, and the gateway cannot check that;
- not that the person read or understood the text.

It only helps when the agent chooses to ask. Nothing makes an agent call `confirm_action` before an
action, so it does not stop an agent that acts without asking. Where an agent does ask, it guards against
the agent going ahead with a step the person wanted to see first, and against a slip.

A `plain` result always carries `verified: false`. The gateway sets that field itself; it never takes it
from the app.

## What `passkey` proves, and what it does not

A `confirmed` answer with `verified: true` means: a passkey that was enrolled for this gateway user (with
an enrolment code from the operator, a code minted with an earlier passkey of the same user, or a sign-in
of that user that the sign-in provider reported as fresh and the gateway bound to the enrolling app or
browser) signed, with user
presence and user verification as reported by its authenticator, a challenge that commits to this
gateway's base URL, this conversation, this request, a fresh random value and the exact title, summary and
detail the gateway sent. The gateway checks the signature against the public key it stored at enrolment,
re-reads the passkey before it accepts (one revoked meanwhile is refused), and keeps a receipt (digests and
the signed bytes, never the text) for `confirm.passkey.receipts_days`. In the official app, the operating
system only lets that app ask for its passkeys, and the app computes the challenge from the text it shows.

Who is asked: the person **the running turn works for**, as the gateway itself knows them: the signed-in
user whose app submitted the turn. Never a name the agent passes, never the person who created a shared
conversation, never someone else who happens to be watching. Only that person's apps that can use a
passkey for this gateway see the request; anyone else attached to the conversation never sees it and
cannot answer it.

What it does **not** prove:

1. Not a biometric. User verification can be the device passcode, or whatever the passkey provider accepts
   (a password manager's master password or PIN). Someone who holds the device and knows its passcode
   passes.
2. Not hardware. No attestation is checked; a software authenticator is accepted and the user-verification
   flag is the authenticator's own statement. With a synced passkey, the security is that of the sync
   account or vault.
3. Not that the person started the conversation, read the text or understood it. A stolen session can open
   a request that the real person then sees in their app; the text is verbatim, the app names the gateway
   and the bot, and the decision is theirs.
4. Not that the agent then does what it described, and nothing at all about actions the agent takes
   without asking.
5. Not anything on a gateway that is itself compromised. The gateway is the verifier. A malicious plugin,
   the operator, or an agent with an unsandboxed terminal on the gateway host can write the store, change
   the code or report any outcome.
6. **A stolen dashboard session can go around the mechanism rather than through it.** A signed-in session
   can edit `config.yaml`, set environment variables, upload files, use a console and drive the agent's
   terminal. The direct doors to the passkey state are closed (the file manager refuses the store, the
   config writers refuse `confirm.passkey.*`, only the operator CLI mints a first code), but an agent with
   a local terminal running as the gateway's own user can still reach the store or run the CLI. The level
   is a real barrier where the agent's terminal is sandboxed (a container or remote backend without the
   gateway's home) or where the operator's rules cover the commands that matter (`confirm.passkey.require`,
   see [Operator rules](#operator-rules-force-a-passkey)); elsewhere it raises the cost and leaves evidence
   (an audit line, a receipt, `passkey.changed`, a push) without being a wall.
7. In a browser, the page is the client. The browser enforces the origin, but what the page displayed is
   asserted by code the gateway served: a script injected into the gateway's origin, or a dashboard plugin
   page on the same origin, can show one text and request a signature for another. The native app does
   not have this weakness.
8. On a plain-`http` gateway a network attacker cannot forge a confirmation, but owns the session.
9. Bootstrap. The first passkey comes from an operator code or, where the operator allows self-enrolment,
   from a fresh sign-in. With a code, whoever redeems it while signed in as the user gets the passkey: hand
   it over out of band, and bind it with `--user` when the id is known. With self-enrolment the passkey
   level is exactly as strong as that sign-in plus the detection around it: **whoever holds a session and
   can also sign in again as the person (their password, and the identity provider's second factor if it
   asks for one) can add a passkey and then confirm.** A stolen session alone cannot: the sign-in has to
   happen again, now.

A `declined` is never verified: declining needs no passkey.

### No downgrade

Once a `passkey` request in a conversation fails in a way someone else could cause after it was sent
(declined, timed out, `verification_failed`, `error_response`, withdrawn, or `no_capable_client`), the
gateway refuses `plain` requests in that conversation for ten minutes (`unavailable`, reason
`downgrade_refused`), without showing anything, and the tool tells the agent not to ask again at `plain`
and not to reach the same effect another way. A `passkey` request that is `unavailable` before anything is
sent (the level is off, nobody to bind it to, no passkey enrolled, turn isolation, a rate limit) opens
nothing: where the level is off, `plain` is the level the gateway has, and the tool says so.

## Turn it on

The tool is off by default. Enable the `confirm` toolset for the platform your interactive sessions run
on (the desktop app, the dashboard chat and the terminal UI use the `cli` platform):

```bash
hermes tools          # tick "Confirm Actions" for the platform
```

or in `config.yaml`:

```yaml
platform_toolsets:
  cli: [hermes-cli, confirm]
```

The tool only appears in sessions served by the interactive gateway (desktop, dashboard, terminal UI).
In a messaging platform, a cron job, the classic CLI or any other context it is withheld, and a call that
still arrives answers `unavailable` without sending anything. With `dashboard.turn_isolation` enabled the
tool also answers `unavailable`: the isolated worker cannot see which app offered which level.

## Set up the passkey level

On the gateway host, as the gateway's user:

1. The gateway needs a sign-in provider (OIDC, Nous or basic): a passkey belongs to a signed-in user
   (`<provider>:<user id>`). In session-token or loopback mode the level is `unavailable` (`no_identity`).
2. List the address (base URL) the apps dial for this gateway: `hermes dashboard passkey base-url add
   https://gw.example.com`. This list is separate from `dashboard.public_url(s)` on purpose. A private or
   plain-`http` address counts only with `confirm.passkey.allow_private_base_urls: true` (read the
   contract's note on what that gives up).
3. Enable it in `config.yaml` (`confirm.passkey.enabled: true`) and restart.
4. Either let people add a passkey themselves (self-enrolment, on by default, below) or mint an enrolment
   code for the person (`hermes dashboard passkey invite --user <provider>:<user id>`) and hand it over out
   of band. They add a passkey in the app with it; later passkeys (another provider, a browser) they can
   add with a code they mint themselves with a passkey they already have.
5. `hermes dashboard passkey status` names every reason the level is unavailable and what to set.

### Self-enrolment: add a passkey by signing in again

With `confirm.passkey.self_enrol.enabled: true` (the default), a signed-in person can add a passkey from
the app's or the web client's settings without a code: they sign in again, the sign-in provider confirms
it happened just now, and that one fresh sign-in authorises one passkey for that person, from the app or
browser that asked (it expires after 10 minutes and is used up by the passkey). The browser stays bound by
an https-only cookie and the app by a one-time secret only its own sign-in receives, from the start until
the passkey is added; so the web client needs the page on https. It needs a provider that
can force a fresh sign-in: the password provider (`basic`) and OIDC (`self_hosted`, which asks the
identity provider for `prompt=login` and `max_age=0` and checks the returned `auth_time`). Nous cannot,
so people signed in with Nous need a code.

```yaml
confirm:
  passkey:
    self_enrol:
      enabled: true                  # `hermes dashboard passkey self-enrol off` for codes only
      accept_missing_auth_time: false  # true: trust an identity provider that does not send auth_time
      cooling_off_s: 0               # > 0: a passkey added this way is listed but unusable this long
```

An identity provider that ignores `prompt=login` and reuses its single sign-on session returns an old
`auth_time`; the gateway refuses that sign-in for enrolment (the person signs out of the identity provider
and tries again). During a cooling-off period the new passkey is no `confirm` target and cannot sign an
invite or revoke step-up, but another passkey or the operator can revoke it. Every passkey added this way
is marked `self` (`hermes dashboard passkey list`, the `on_passkey_change` hook's `via`), so the security
notification can say it was added after a new sign-in. Like the rest of `confirm.passkey`, the section is
protected: only the operator changes it.

## Operator rules: force a passkey

The agent asks for a confirmation only when it decides to. A prompt-injected agent does not. The operator
can force one for the actions that matter, under `confirm.passkey.require` in `config.yaml` on the gateway
host (a dashboard session cannot change this section):

```yaml
confirm:
  passkey:
    enabled: true
    require:
      # Shell commands, as globs. Matched like approvals.deny (case-insensitive, over the normalised
      # and de-obfuscated forms of the command, each part of a compound command, sh -c unwrapped),
      # plus what eval, a here-string (<<<) or xargs runs. See the limits below.
      commands: ["git push*", "kubectl delete *", "*terraform apply*"]
      # Tool names, as globs (case-insensitive). Every call of a matching tool.
      tools: ["send_message", "home_*", "execute_code"]
      # Every dangerous-command approval (see below).
      approvals: false
      # The owner's override of a smart-approval (guardian) DENY.
      smart_denied: true
```

What each rule covers:

| Rule | Covers | Skipped by yolo, `approvals.mode: off`, an isolated container, cron approve mode, the allowlist? |
| --- | --- | --- |
| `commands` | Every terminal command that matches a glob. | No. Decided at the floor of the approval gate, beside the hardline blocklist and `approvals.deny`. |
| `tools` | Every call of a tool whose name matches a glob, after the plugin hooks (a plugin's block wins without asking). | No. |
| `approvals` | Every command the dangerous-command detector flags, decided at the floor like `commands`; and every other approval the command and `execute_code` gates would ask (a security-scanner finding, an `execute_code` script), asked as a passkey confirmation instead. | The detector part: no. The rest: yes, with the approval it replaces (yolo and `mode: off` ask nothing). |
| `smart_denied` | The owner's override of a guardian DENY (smart approval mode). | Only with smart approval itself. |

A forced confirmation is a `confirm` request at level `passkey` that the gateway builds itself: title
"Approve a command" ("Approve a script" for `execute_code`, "Approve a tool call" for a tool), the
gateway's description as the summary, and the command exactly as it will run (or the tool's name and
arguments) as the detail. It goes to the person the running turn works for, on their apps that can use
their passkey, like any `passkey` request.

The detail is never shortened, masked or cleaned up: what the person signs is what runs. A command with
a secret in it (anything the gateway's secret redactor would mask: a key block, a token, a password) is
therefore not shown at all; it is blocked, and the agent is told to reference secrets through environment
variables or the vault, never inline. Masking would be worse than blocking: the redactor replaces whole
regions, so a prompt-injected agent could hide a second command inside a fake key block. On a command
match the security scanner still runs first: its findings are added to the summary, and a scanner
`block` stays a block that no confirmation lifts. The summary also says where the command runs (in the
desktop app's batch of commands, the call's own `workdir`, or that the directory is the session's when
the command's turn comes). The detail travels verbatim: indentation, runs of spaces and line breaks are
kept. Because no rendering shows them, a command with whitespace at the end of a line, or with tabs, is
refused rather than shown, and so is a character that renders as nothing: a default-ignorable code
point (variation selectors and the combining grapheme joiner included) or one the gateway's Unicode
database does not know. The gateway also limits padding: apps keep every space and scroll long lines
sideways, so `git status` followed by 300 spaces and `; curl … | sh` would show as `git status`. It
refuses more than 16 spaces in a row after a line's first non-space character, a line indented more than
32 spaces (8 levels of 4-space Python, 16 levels of 2-space YAML), more than 3 blank lines in a row, and
a line over 2,000 characters. Ordinary indented scripts, manifests and heredocs stay well inside them.
These bounds limit padding; they do not keep every command in view. Gaps just under them, repeated, many
short lines, a long visible prefix or wide glyphs (U+FDFD three hundred times) still run past the edge
of the sheet, which is why apps must mark a detail that overflows and keep Confirm disabled until it has
been scrolled to its end (see "Limits"). Nothing is collapsed to fit: the passkey signs the exact text, so
the command is blocked (`padding`). This is the one block after which the agent is told to submit again: the
same command without the extra whitespace, never the padded form. Nothing was shown to the person, and
the compact command is a new confirmation, shown in full and signed with a passkey like any other. A
tool call's detail is its name and arguments as indented JSON, so a file's indentation shows as spaces
right after a visible `\n`; there a run up to 32 spaces counts as indentation. A tool call that still
breaks a bound (deeper code, JSON nested more than 16 levels) is blocked as `not_showable`, without that
invitation: the agent cannot respace a file it writes without changing it.

- It never enters the approval queue: `/approve`, `/approve all`, `approval.respond` and messaging
  surfaces cannot answer it.
- `confirmed` (verified) lets this one operation run. Nothing is remembered: the next identical command
  asks again. There is no "session" or "always".
- `declined` is a deny.
- Anything else blocks the operation and tells the agent that a passkey confirmation in the Hermie app is
  required: `timeout`, every `unavailable` reason (including `disabled`, `not_enrolled`,
  `no_acting_user`), a conversation that cannot ask for one (the terminal CLI, a messaging platform, a
  scheduled job), a command longer than the 2,000 characters a confirmation can show (counted on the
  command as it runs), a command with invisible, control or tab characters or with whitespace at the end
  of a line, a command padded so that part of it could sit out of view (`padding`), a command with a
  secret in it (`redacted`), or a security-scanner block. It never falls back to an ordinary approval.
- In the desktop app's batch of terminal commands, the confirmation is asked once, while the batch
  prepares its approvals, and its outcome holds for that command in that batch only: declined stays
  declined when the command's turn comes, and a stopped batch takes a confirmation with it.

Consequences to know before you turn a rule on:

- Rules apply whether or not `confirm.passkey.enabled` is on. With the level off, every matched command
  and tool call is blocked. Remove the rules to go back to ordinary approvals.
- Cron jobs, messaging platforms and the classic CLI cannot ask, so a matched command or tool call never
  runs there. With `approvals: true` that includes every dangerous command those contexts would otherwise
  run under their approve modes.
- A glob is a pattern over text, not an understanding of the shell. `commands` sees each part of a
  compound command, `sh -c` strings, and what `eval`, a here-string or `xargs` runs, but not reordered
  options (`git -C repo push` does not match `git push*`), aliases, functions, or variables that build a
  command (`$CMD`). For a hard guarantee use `tools: ["terminal"]` (every command asks); `approvals: true`
  adds every command the dangerous-command detector flags.
- A rule matches what the gate sees. `commands` sees the command text the terminal gate is asked about.
  It does not see:
  - code run by `execute_code`, or a script the agent writes to a file and then runs under another name;
  - input typed into a running process: `terminal(command="bash", background=true, pty=true)` followed
    by `process(action="submit", data="git push --force")` reaches a shell without any command guard
    (the gateway does not parse what is typed into a process);
  - on the Codex app-server runtime, the commands Codex's own sandbox runs without asking: Hermes sees a
    Codex command only when Codex sends an approval request, and then the floor (including these rules)
    runs before any automatic approval.

  Cover those with `tools`: `execute_code` for scripts, `process` for typing into processes (and
  `terminal` itself if background shells must never start unconfirmed), and keep the agent's terminal
  sandboxed (point 6 above).
- A forced request counts under its own limit (one open and six per ten minutes per conversation,
  separately from the agent's own `confirm_action` requests), so neither can use up the other. A forced
  request that is declined, times out or fails once sent opens the no-downgrade window of the
  conversation like any `passkey` request.
- Each decision writes a `confirm_forced` record to `dashboard-auth.log`: the rule, your pattern, the
  session, the user the session names, the outcome and the reason. Never the command text. The request
  itself writes `confirm_request` and `confirm_outcome` with `forced: true`.

`hermes approvals test -- <command>` reports `ask-passkey` (exit 2) for a command a rule covers, and
`hermes dashboard passkey status` lists the rules in force.

## The four outcomes

| Outcome | Meaning | What the agent should do |
| --- | --- | --- |
| `confirmed` | `plain`: someone tapped Confirm in a connected app. `passkey`: verified, see above. | Do exactly what the summary said, nothing more. |
| `declined` | The person said no. | Do not do it. |
| `unavailable` | Nothing that counts as consent was obtained; `reason` says why (table below). | Not consent. Do not do it; tell the person. After a `passkey` request that failed once sent: do not ask again at `plain`. |
| `timeout` | No answer within 120 seconds. | Not consent. Do not do it; tell the person. |

`unavailable` and `timeout` are never a `declined`, and never a `confirmed`.

| `reason` | Level | Meaning |
| --- | --- | --- |
| `no_capable_client` | both | No app attached to this conversation can answer (at `passkey`: none signed in as the person, with a passkey for this gateway). |
| `error_response`, `write_failed` | both | The app could not show it, or it could not be delivered. |
| `already_pending`, `rate_limited` | both | Another confirmation is open, or too many were sent. |
| `cancelled:<why>` | both | Withdrawn: the turn was stopped, the conversation closed, the gateway shut down. |
| `turn_isolation` | both | Turns run isolated on this gateway. |
| `no_session` | both | Not an interactive app session. |
| `downgrade_refused` | `plain` | A `passkey` request in this conversation did not succeed in the last ten minutes. |
| `disabled` | `passkey` | `confirm.passkey.enabled` is off. |
| `no_base_url`, `private_origin` | `passkey` | No usable base URL is listed. |
| `no_identity` | `passkey` | Nobody on this conversation is signed in (no sign-in provider). |
| `no_acting_user` | `passkey` | The turn was not submitted by a signed-in person: a scheduled run, a relayed message, a continuation, or a shared conversation with nobody to bind it to. |
| `not_enrolled` | `passkey` | The person has no passkey for this gateway. |
| `verification_failed` | `passkey` | Five answers were refused, or the passkey was revoked or the store failed when the gateway tried to accept the answer. |
| `settings_unavailable`, `store_unavailable` | `passkey` | The gateway could not read its passkey settings or store. |

A forced confirmation (an operator rule) can also end blocked for `no_callback` (the conversation cannot
ask), `too_long`, `hidden_characters`, `trailing_whitespace`, `padding` (spacing that could hide part of the
command), `redacted` (the command holds a secret),
`not_showable`, `scanner_block` or `error`.

## Limits

- `title` at most 80 characters, `summary` at most 500, `detail` at most 2,000. Longer text is refused
  and goes back to the agent to shorten; it is never cut off silently. Control and invisible formatting
  characters are removed, and apps show the text as plain text, never as markdown or HTML.
- One open confirmation per conversation, and at most six sent per ten minutes. Requests that reached
  no app do not count. Confirmations forced by an operator rule have their own count with the same
  limits.
- At `passkey`: five refused answers end the request (`verification_failed`).
- Each request and each outcome writes one record to the dashboard auth audit log
  (`$HERMES_HOME/logs/dashboard-auth.log`, events `confirm_request` and `confirm_outcome`): the session,
  the request id, the level, the signed-in user the turn works for, how many apps were asked, the outcome
  and method, whether it was verified, and the signed-in user and network address of the app whose answer
  counted. At `passkey` every refused answer (`confirm_passkey_refused`, with the reason) and every accepted
  one (`confirm_passkey_verified`) is recorded too, with the first characters of the passkey's id, its RP,
  the base URL and the digest of the text. The title, summary, detail, nonce and signature are never logged.
- Plugins can send a push for a request through the `pre_confirm_request` hook (ids, level, user and
  expiry; never the text).

## For app developers

`confirm` is a server→client request like `clarify` or `approval`
(`apps/shared/src/gateway-contract.generated.ts`, `ServerRequestMap.confirm`).

1. Advertise it in a second `client.capabilities` call, only after the first call's result lists
   `confirm` in `server_requests`: `{"server_requests": true, "confirm": ["plain"]}`. A gateway older
   than `confirm` rejects the unknown `confirm` key, and with it the whole call. The shared
   `JsonRpcRequestChannel` does this when given `confirmLevels`.
2. The gateway writes the request only to connections attached to the conversation that advertised
   its level, and accepts an answer only from such a connection. Answer with
   `{"decision": "confirmed" | "declined", "method": "tap"}`. If you cannot answer right now, send a
   JSON-RPC error; never a made-up `declined`.
3. The first valid answer wins. The other connections get `request.cancel` with reason `resolved`; a
   timeout sends reason `timeout`.
4. After a reconnect, resume (or activate) the conversation first: `open_requests` then lists a pending
   `confirm` to your new connection if it advertised the level. A connection that is not attached, or did
   not advertise the level, gets `4033` from `request.answer`. A malformed answer is refused (`4034`) and
   the request stays open.
5. Show the title, summary and detail as plain text, marked as coming from the agent; never let them
   style the buttons or the surrounding frame. Do not let a keystroke meant for something else answer
   the card.

Level `passkey` follows `contract/confirm-passkey/README.md` (challenge, wire objects, the order of the
checks, test vectors):

- Every `client.capabilities` result carries `confirm_passkey {v, enabled, reason, gateway_id, rp: {native,
  web}}`. Only when `enabled` is true, add `"passkey"` to `confirm` and send `confirm_passkey: {v: 1, kind:
  "native" | "web", rp_id}`. `passkey` is accepted only from a signed-in connection with an RP the gateway
  lists for that kind; anything else drops `passkey` and keeps `plain`.
- The frame carries `params.passkey {v, nonce, gateway_id, base_url, expires_at, user: {id, name},
  credentials: [{rp_id, ids}]}`. Compute the challenge from the base URL you dialed and the strings you
  render, pass the ids for your RP as `allowCredentials`, require user verification.
- Answer through `request.answer` with `{decision: "confirmed", method: "passkey", passkey: {v: 1, rp_id,
  base_url, credential_id, authenticator_data, client_data_json, signature, user_handle?}}`, or exactly
  `{decision: "declined", method: "tap"}`. Never send `verified`. A refusal is `4034` with `data.reason`;
  the fifth one is `too_many_attempts` and ends the request (`request.cancel` with reason
  `too_many_attempts`). If you cannot run the ceremony, answer the frame with error `4040` and
  `data.reason`. Dismissing the system sheet sends nothing.
- `{"status": "ok"}` from `request.answer` means the answer was received and valid, not yet confirmed: the
  gateway then commits it. If that fails (the passkey was revoked meanwhile, a store error), the connections
  get `request.cancel` with reason `verification_failed`; clear any "confirmed" state for that id.
- At `plain` the method is always `tap`; an answer with `method: "passkey"` is refused (`4034`).
- A confirmation forced by an operator rule is an ordinary `confirm` frame at level `passkey` (title
  "Approve a command", "Approve a script" or "Approve a tool call"). It can be open at the same time as one
  the agent asked for, so handle more than one open `confirm` per conversation, by request id. Its
  `detail` is the command verbatim: render `detail` monospaced with whitespace preserved (`white-space:
  pre` or the platform's equivalent; scroll long lines rather than reflow them), never collapsed or trimmed.
  The gateway never sends a detail with more than 16 spaces in a row inside a line, an indent over 32
  spaces, more than 3 blank lines in a row or a line over 2,000 characters. That limits padding and no
  more: a detail inside every bound can still be wider or longer than the sheet (gaps just under the
  bounds, repeated; many short lines; wide glyphs). Apps must show that a detail overflows (a marker on
  the side that runs past the edge, or a caption with its line count and longest line) and keep Confirm
  disabled until the detail has been scrolled to its end, both ways.
- `confirm_passkey` in the second call is checked by the gateway, not by the contract: unknown extra keys
  are allowed, and a shape it does not accept only drops `passkey`.
