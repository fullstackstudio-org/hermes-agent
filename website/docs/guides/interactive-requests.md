---
title: "Ask the Person for a Form, a File or a Draft Review"
description: "Turn on the interactive toolset so an agent can ask for typed fields, a file or the approval of a draft in the connected app, and learn who is asked, what the apps show, what the agent gets back and which limits apply"
---

# Ask the Person for a Form, a File or a Draft Review

The `interactive` toolset gives an agent three tools for asking the person something in the connected app,
instead of asking one question at a time in chat:

| Tool | Asks for | What the agent gets back |
| --- | --- | --- |
| `ask_form` | Typed fields (1 to 12): text, number, amount, date, time, date and time, date range, choice, toggle. | The values, by field id, or `skipped`. |
| `ask_file` | One or more files: a photo, a scan, a document, a voice note. | The path of each file in the workspace, its size and SHA-256, and a `ref_text` the agent can attach; or `skipped`. |
| `review_draft` | Approval of a draft (an email, a post, a message, a document), which the person may edit first. | The exact text the person approved, or `rejected` with an optional comment. |

Each one is a server to client request (`input.form`, `input.file`, `review.draft`) defined in
`contract/requests/` in the gateway repository, which is the normative description for app developers.

The title, summary, labels and draft are **the agent's own words**. Apps show them verbatim as plain text and
mark them as coming from the agent, with the app's own controls around them. An agent can word them to look like
a system or security message; read them as the agent's description of what it asks, nothing more. Values that
come back are the person's input, checked only against the form's own rules: the agent treats them as data, not
as instructions.

## Turn it on

The toolset is off by default. Enable `interactive` for the platform your interactive sessions run on (the
desktop app, the dashboard chat and the terminal UI use the `cli` platform):

```bash
hermes tools          # tick "Ask the Person" for the platform
```

or in `config.yaml`:

```yaml
platform_toolsets:
  cli: [hermes-cli, interactive]
```

Leaving it off (or turning it off again) is the way to stop an agent from asking at all.

The tools only appear in sessions served by the interactive gateway (desktop, dashboard, terminal UI). In a
messaging platform, a cron job, the classic CLI or any other context they are withheld, and a call that still
arrives answers `unavailable` without sending anything. With `dashboard.turn_isolation` enabled they also
answer `unavailable`: the isolated worker cannot see which app can show what.

A second toolset name, `device`, is reserved and also off by default. It has no tools yet.

## Who is asked

A request goes only to apps that told the gateway they can show that kind of request, and only to apps signed
in as the person **the running turn works for**, as the gateway itself knows them (the signed-in user whose app
submitted the turn). Never a name the agent passes. An agent connected through MCP never receives or answers
one: these requests are answered in the person's own app.

When the gateway cannot name that person:

- With no sign-in provider (one trust domain), any app that can show the request may answer it.
- In a shared conversation, a form or a file request goes to every app that can show it, and the result tells the
  agent which login answered (`answered_by`).
- In a shared conversation, a **draft review is never put to anyone**: it ends `unavailable` with reason
  `no_acting_user` at once. Approving text that goes out in someone's name is not a question to put to whoever
  happens to be watching.

The first valid answer wins; the other connections get the request withdrawn.

## What the apps show

- **A form**: the fields with the agent's text above them, and a way to skip unless the agent said the form is
  mandatory. The gateway checks every answer against the field definitions
  (range, step, whole number, decimal places of the currency, one of the options, a datetime in the right zone)
  and an answer it refuses stays open: the app shows the reason next to the field so the person can correct it.
  The tenth refused answer withdraws the request.
- **A file request**: the app offers the camera or scanner when the agent prefers one (`capture`), and always
  lets the person pick an existing file. The document scanner is in the phone and iPad apps, not the Mac app. A
  photo from the camera or library has its location and camera data removed on the device before it is
  uploaded; documents are uploaded as they are.
- **A draft review**: the draft verbatim, in plain text, with the subject and recipients shown apart from the
  body, and a way to approve or reject it. The person can edit the text first unless the agent said it is not editable.
  There is no Skip: the person rejects. The text the person approved is the text the agent gets back, not the
  agent's earlier version; the gateway works out whether it was edited.

An app that cannot show a request (no camera and no picker, a permission denied, an upload that failed, an
unknown field kind, an app too old for this version of the request, an app that is closing) answers with an
error instead of a made-up "skipped" or "rejected", and the agent is told the request was unavailable.

## Where an uploaded file goes

The app uploads each file to the workspace through the gateway's upload route and answers with references. The
bytes never travel in the answer.

- The folder is `uploads/hermie/<date>` under the session's working directory, created when needed with mode
  0700; uploaded files are 0600. The layout is flat: a file sits directly in that day's folder.
- The gateway follows **no symbolic link** at or below `uploads`. A link or a file where one of those folders
  belongs makes the request `unavailable` (`upload_dir_unsafe`) before anything is sent to the person.
- After the person answered, the gateway opens every file by name in that folder and checks it is a regular
  file (not a link) with the size and SHA-256 the app declared. Anything else is `unavailable` (`bad_upload`),
  and nothing is deleted.
- Links above `uploads`, the working directory included, are followed on purpose. That is safe when the
  working directory is the root of a bind mount the agent's sandbox cannot rename. A sandbox that runs under
  another non-root user cannot read the 0700 folders.
- Each file is at most 25 MiB and all files of one answer together at most 50 MiB, at most 10 files with
  `multiple`.

## What the agent is told

Every tool result is JSON with an `outcome` and a one-sentence `message` that says only what is known.

| `outcome` | Meaning |
| --- | --- |
| `answered` | `ask_form`: `values`. `ask_file`: `files` and, for a voice note, `text`. |
| `skipped` | The person chose to skip. That is their answer; the agent does not ask again unless told to. |
| `approved` | `review_draft`: `text` is the exact approved text, `edited` says whether it changed, `draft_id` names it in the gateway. |
| `rejected` | `review_draft`: do not send it; `comment` may say why. |
| `unavailable` | Nothing reached a person who answered; `reason` says why (table below). Not an answer, and for a draft never an approval. |
| `timeout` | No answer within 300 seconds. Not an answer. |

For `unavailable` and `timeout` the agent is told to tell the person what happened and not to retry at once.

| `reason` | Meaning |
| --- | --- |
| `no_capable_client` | No app signed in as the person could show it within the waiting time (see below). The message names the app kind, such as the phone app for a scan. |
| `no_acting_user` | A draft review in a shared conversation whose turn does not say which person it is for. |
| `error_response`, `write_failed` | The app could not show it, or it could not be delivered. |
| `cannot_show:<why>` | The app said it cannot show it: `no_camera`, `not_supported_on_device`, `permission_denied`, `upload_failed`, `unsupported_version` or `shutting_down`. Any other reason the app gives is reported as `error_response`. |
| `upload_dir_unsafe`, `upload_dir_unavailable` | The upload folder in the workspace is or passes through a link or a non-folder, or could not be created. Nothing was sent. |
| `bad_upload` | An uploaded file did not check out on the gateway. |
| `too_many_attempts` | The app kept sending answers that did not fit. |
| `already_pending`, `rate_limited` | Another request is open in this conversation, or too many were sent. |
| `cancelled:<why>` | Withdrawn: the turn was stopped, the conversation closed, the gateway shut down. |
| `turn_isolation` | Turns run isolated on this gateway. |
| `no_session` | Not an interactive app session. |

The gateway keeps the text of an approved draft in memory (one hour, 20 per conversation) under its `draft_id`.
Nothing consumes that id yet.

### Waiting for a device

When no app that can show the request is attached, the request is not refused at once. It waits up to two
minutes for the person's phone or computer to attach (the `pre_server_request` plugin hook fires with
`reached: 0` at that moment, so a plugin can send a push that opens the app), and then ends
`unavailable (no_capable_client)`. A request the person saw and whose app then disconnected (a phone sent to the
background) gets a fresh two-minute window from that moment, never past the 300-second limit.

## Limits

- `title` at most 80 characters, `summary` at most 500, `detail` at most 2,000. A draft is at most 20,000
  characters, with at most 10 recipients. Longer text is refused and goes back to the agent to shorten; it is
  never cut off silently. Control and invisible formatting characters are removed from the agent's text, and a
  draft that contains characters that cannot be shown as written (tabs, bidirectional or other format
  characters) is refused for the agent to fix.
- One open request per conversation, and at most 12 sent per 10 minutes (separately from `confirm_action`).
  Requests that reached no app do not count.
- Ten refused answers end a request.
- Each request and each outcome writes one record to the dashboard auth audit log
  (`$HERMES_HOME/logs/dashboard-auth.log`, events `interactive_request` and `interactive_outcome`): the session,
  the request id, the method, the signed-in user the turn works for, how many apps were asked, the outcome and
  reason, and the signed-in user and network address of the app whose answer counted. Never a title, summary,
  value, path, file name or draft. Params and results are not logged anywhere.
- Plugins can send a push for a request through the
  [`pre_server_request` hook](../user-guide/features/hooks.md#pre_server_request) (ids, method, user and
  expiry; never the text).

## For app developers

Read `contract/requests/README.md` in the gateway repository. In short: advertise the methods you can show in a second `client.capabilities` call
(`{"server_requests": true, "requests": ["input.form", "input.file", "review.draft"]}`) only after the first
call's result lists them under `server_requests`; render every string as plain text marked as the agent's;
answer with a JSON-RPC response (or `request.answer`); and answer `4041` with a `data.reason` when you cannot
show a request. The examples in `examples.json` are normative.
