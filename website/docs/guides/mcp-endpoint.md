---
title: "Talk to Your Bots from an MCP Client"
description: "Turn on the gateway's remote MCP endpoint so an agent such as Claude Code can list your bots, start chats and get replies as you, marked as an agent, and see what it can and cannot do"
---

# Talk to Your Bots from an MCP Client

The dashboard can serve a remote [MCP](https://modelcontextprotocol.io) endpoint at `/mcp`. An MCP client
that speaks OAuth 2.1 (Claude Code, for example) connects to it once, the person signs in and allows it, and
from then on the client can list that person's bots, start or continue chats, send prompts and read the
replies.

The agent acts **as the person who allowed it, and is marked as an agent everywhere**: the stored message
says who sent it and through which client ("Alice via Claude Code"), the bot is told the message came from an
agent on the person's behalf, and the audit log names the grant. Anything the person must do themselves
stays with the person (see [What an agent cannot do](#what-an-agent-cannot-do)).

This is different from [`hermes mcp serve`](../user-guide/features/mcp.md), which runs on the host over
stdio and bridges messaging platforms. Nothing here changes that command.

## For the operator: turning it on

The endpoint is off by default. It turns on only when **all** of these hold, and otherwise stays off with one
line in the dashboard log saying why:

1. `dashboard.mcp.enabled` is `true`. Only the operator can set it: in `config.yaml`, with
   `hermes config set dashboard.mcp.enabled true`, or in a container with
   `HERMES_DASHBOARD_MCP_ENABLED=true`. The dashboard's own settings pages refuse to change it, so a stolen
   dashboard session cannot switch it on.
2. The dashboard has its sign-in gate engaged (OIDC or basic sign-in on a non-loopback bind). An ungated
   dashboard has no signed-in person to act for, so the endpoint stays off there.
3. A **public URL** is configured (`dashboard.public_url`, or the first entry of `dashboard.public_urls`) that
   is `https://` and has no path prefix. The OAuth issuer and the address tokens are bound to are
   `<public URL>/mcp`, and the OAuth metadata must be served at the host root. The endpoint answers on that
   primary host only; any other listed origin answers 404.
4. The `mcp` package is installed (the `[mcp]` extra: `pip install 'hermes-agent[mcp]'` in a venv install).
   Without it the endpoint stays off and the log says so.

```yaml
dashboard:
  public_url: "https://hermes.example.invalid"
  mcp:
    enabled: true
    # The defaults; change only when you need to.
    access_token_ttl: 3600          # seconds an access token lives
    refresh_token_ttl: 2592000      # 30 days, renewed on every refresh
    grant_max_age: 7776000          # 90 days, then the person allows the client again
    answer_clarify: true            # false: clarify questions also wait for the person's app
    max_running_turns_per_grant: 3
    max_grants_per_user: 5
    label: ""                       # the server name in the add command; "" = hermie-<public host>
```

Settings are read at start; restart the dashboard after a change. Check from outside that
`https://hermes.example.invalid/.well-known/oauth-protected-resource/mcp` answers with JSON.

Grants live in `$HERMES_HOME/dashboard_auth/mcp.db` (tokens only as hashes). Backups, profile copies,
exports and the file manager skip that file: a grant copied to another host would let that host accept the
tokens.

## For the person: connecting Claude Code

```bash
claude mcp add --transport http hermes https://hermes.example.invalid/mcp
```

Then, inside Claude Code, run `/mcp` and choose the server to sign in. Your browser opens the gateway's
consent page (after the gateway's normal sign-in when you are not signed in yet). It shows the client's name
**and the address it will send you back to**: the name is whatever the client registered, so check the
address too. Allow it, and Claude Code receives its tokens.

Another MCP client that does OAuth 2.1 with dynamic client registration connects the same way. A project
`.mcp.json` entry:

```json
{"mcpServers": {"hermes": {"type": "http", "url": "https://hermes.example.invalid/mcp"}}}
```

### What the agent can do

| Tool | What it does |
| --- | --- |
| `whoami` | Who it acts for, as which client and grant, and what it cannot do. |
| `bots_list` | Your bots: name, display name, description, model. |
| `chats_list` | Chats opened through MCP, and your chats that are live right now. |
| `chat_new` | Start a chat with a bot (send the first prompt within 10 minutes). |
| `chat_open` | Open one of your chats by its id, under the same access rules as your app. |
| `chat_history` | Read a chat opened through MCP; each message names its author and `via`. |
| `bot_prompt` | Send a prompt and wait up to 90 seconds for the reply (default 60). |
| `bot_wait` | Keep waiting for a reply that was not finished. |
| `bot_interrupt` | Stop a turn this agent started. |
| `requests_open` | What the bot is waiting for: clarify questions, approvals, secret prompts. |
| `clarify_answer` | Answer a clarify question. The answer is stored as the agent's, not yours. |

A reply that takes longer than the wait comes back as `running` with a `turn_id`; the agent calls
`bot_wait` to keep waiting. A client that asks for progress gets the tail of the reply while it is written.
When a chat is busy (you are talking to the bot yourself), the agent's prompt is **queued** for its own turn:
it never steers or interrupts your turn, and it is never told your turn's reply as its own. If the gateway
restarts during a turn, the agent gets `restarted` and waits again; the turn continues after the restart.

### What an agent cannot do

- Approve or deny a command, confirm with a passkey, hand over a secret, or answer a sudo or vault prompt.
  These requests stay open for **your own app**; the agent sees them as `waiting_for_person`.
- Change settings, delete, rename or hide chats, or read chats it was not given: it sees the chats it opened
  and your live chats, not every stored conversation on the gateway. A chat you have only in your app can be
  opened by its id with `chat_open`; that is logged.
- Act on someone else's chats: the same access rules apply as for your own app.

Every string the agent gets from a bot or a transcript is untrusted model output or other people's text; the
server tells the client so.

What an agent can and cannot see on a gateway several people share is set out in the dashboard guide's
[privacy section](../user-guide/features/web-dashboard.md#mcp-clients-what-an-agent-can-and-cannot-see).

### Limits

Per connection (grant): 60 tool calls a minute, 20 prompts in 10 minutes, 3 turns running at once, one
waiter per turn. A refused call says when to try again (`retry_after_seconds`). Each person can have 5
connected clients; the sixth consent asks to remove one first.

## Seeing and revoking connected clients

The person sees every connected client (name, when it was connected and last used, from which address) in
the app under **Settings › MCP**, and can revoke any of them; the client's next call is refused and it has to
be allowed again.

The page gets everything it shows from the gateway: the endpoint address, the `claude mcp add` command and
the `.mcp.json` fragment (built from the public URL and the server name, which is also the name the `whoami`
tool reports), and the person's own active grants, newest first. The server name is the slug of
`dashboard.mcp.label` (lower-case letters, digits and hyphens), or `hermie-<public host>` when that is empty,
so two gateways get two different names in one client. A grant that is revoked or has ended is no longer
listed; the app refreshes by itself when a client is allowed or revoked (the `mcp.changed` event), and a
revoke done with the operator's command shows up the next time the page is opened.

The operator can do the same on the gateway host:

```bash
hermes dashboard mcp status
hermes dashboard mcp list [--user <provider>:<user id>] [--all]
hermes dashboard mcp revoke <grant id>
hermes dashboard mcp revoke --user <provider>:<user id>   # every client of one person, e.g. a lost device
hermes dashboard mcp prune
```

Setting `dashboard.mcp.enabled: false` (and restarting) turns everything off at once; the grants stay in
`mcp.db` and do nothing until it is turned on again.

## The audit log

`$HERMES_HOME/logs/dashboard-auth.log` gets one line per registration, consent, token, revocation, tool call
(`mcp_tool_call`: the tool, the chat, the outcome), chat opened (`mcp_chat_opened`), refused limit
(`mcp_rate_limited`), clarify answer and refused browser write to Settings › MCP (`mcp_write_refused`).
Lines carry ids, names, addresses and outcomes, never a prompt, a reply, an answer, a token or a code.
