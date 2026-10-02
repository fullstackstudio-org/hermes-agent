---
title: "Ask the Person to Confirm a Sensitive Action"
description: "Turn on the confirm_action tool so an agent asks for a confirmation in the connected app before it spends money, deletes data or acts on someone's behalf, and learn exactly what that confirmation proves"
---

# Ask the Person to Confirm a Sensitive Action

The `confirm_action` tool lets an agent stop before a sensitive step (a payment, a deletion, a message
sent on someone's behalf, an access change) and ask for a confirmation in the connected app. The app shows
the agent's text with its own Confirm and Decline buttons, and the agent gets one of four answers back.

The title, summary and detail are **the agent's own words**. Apps show them verbatim and mark them as
coming from the agent, but an agent can word them to look like a system or security message. Read them
as the agent's description of what it is about to do, nothing more.

## What a confirmation proves today

There is one level today, `plain`. A `plain` confirmation proves that **someone tapped Confirm in an app
attached to this conversation**. Nothing more:

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

Every result carries `verified: false`. The gateway sets that field itself; it never takes it from the
app.

A verified level, which the gateway will check itself, is planned. Its name is reserved (`passkey`):
asking for it today returns `unavailable` without showing anything, and no app can offer it yet.

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

## The four outcomes

| Outcome | Meaning | What the agent should do |
| --- | --- | --- |
| `confirmed` | Someone tapped Confirm in a connected app. | Do exactly what the summary said, nothing more. |
| `declined` | The person said no. | Do not do it. |
| `unavailable` | No connected app can answer, an app answered with an error, the request was withdrawn, a rate limit was hit, or the level is not implemented. | Not consent. Do not do it; tell the person. |
| `timeout` | No answer within 120 seconds. | Not consent. Do not do it; tell the person. |

`unavailable` and `timeout` are never a `declined`, and never a `confirmed`.

## Limits

- `title` at most 80 characters, `summary` at most 500, `detail` at most 2,000. Longer text is refused
  and goes back to the agent to shorten; it is never cut off silently. Control and invisible formatting
  characters are removed, and apps show the text as plain text, never as markdown or HTML.
- One open confirmation per conversation, and at most six sent per ten minutes. Requests that reached
  no app do not count.
- Each request and each outcome writes one record to the dashboard auth audit log
  (`$HERMES_HOME/logs/dashboard-auth.log`, events `confirm_request` and `confirm_outcome`): the session,
  the request id, the level, the signed-in user the turn works for, how many apps were asked, the outcome
  and method, and the signed-in user and network address of the app whose answer counted. The title,
  summary and detail are never logged.

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
