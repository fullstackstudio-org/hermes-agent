---
sidebar_position: 7
title: "Hermes Docker Setup"
description: "Running Hermes Agent in Docker and using Docker as a terminal backend"
---

# Hermes Docker Setup

There are two distinct ways Docker intersects with Hermes Agent:

1. **Running Hermes IN Docker** — the agent itself runs inside a container (this page's primary focus)
2. **Docker as a terminal backend** — the agent runs on your host but executes every command inside a single, persistent Docker sandbox container that survives across tool calls, `/new`, and subagents for the life of the Hermes process (see [Configuration → Docker Backend](./configuration.md#docker-backend))

This page covers option 1. The container stores all user data (config, API keys, sessions, skills, memories) in a single directory mounted from the host at `/opt/data`. The image itself is stateless and can be upgraded by pulling a new version without losing any configuration.

## Quick start

If this is your first time running Hermes Agent, create a data directory on the host and start the container interactively to run the setup wizard:

:::caution Avoid browser-based VPS consoles for the install commands
Some VPS providers (Hetzner Cloud, and several others) offer a browser-based
console for managing hosts. These consoles transmit special characters
incorrectly — `:` may arrive as `;`, `@` may be mis-rendered, and non-English
keyboard layouts fare worse — which silently corrupts `docker run` arguments
like `-v ~/.hermes:/opt/data`, `-e KEY=value`, and pasted API keys / tokens.

**Connect over SSH instead** (`ssh root@<host>`) for copy-paste-safe command
entry. If you must use the browser console, type the commands manually
instead of pasting, and double-check every `:`, `@`, `=`, and `/` in the
result before hitting Enter.
:::

```sh
mkdir -p ~/.hermes
docker run -it --rm \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent setup
```

This drops you into the setup wizard, which will prompt you for your API keys and write them to `~/.hermes/.env`. You only need to do this once. It is highly recommended to set up a chat system for the gateway to work with at this point.

:::tip
Inside the container, run `hermes setup --portal` once — the refresh token persists in the mounted `~/.hermes` volume. See [Nous Portal](../integrations/nous-portal.md).
:::

## Running in gateway mode

Once configured, run the container in the background as a persistent gateway (Telegram, Discord, Slack, WhatsApp, etc.):

```sh
docker run -d \
  --name hermes \
  --restart unless-stopped \
  -v ~/.hermes:/opt/data \
  -p 8642:8642 \
  nousresearch/hermes-agent gateway run
```

Port 8642 exposes the gateway's [OpenAI-compatible API server](./features/api-server.md) and health endpoint. It's optional if you only use chat platforms (Telegram, Discord, etc.), but required if you want the dashboard or external tools to reach the gateway.

:::tip Gateway runs supervised
Inside the official Docker image, `gateway run` is **automatically supervised by s6-overlay**: if the gateway process crashes it's restarted within a couple of seconds without losing the container, and the dashboard (when `HERMES_DASHBOARD=1` is set) is supervised alongside it. The `gateway run` CMD process itself is a `sleep infinity` heartbeat that keeps the container alive while s6 manages the actual gateway process — so `docker stop` still shuts everything down cleanly, but `docker logs` shows the supervised gateway's output.

You'll see a one-line breadcrumb in `docker logs` confirming the upgrade. To opt out — and get the historical "gateway is the container's main process, container exit = gateway exit" semantics — pass `--no-supervise` or set `HERMES_GATEWAY_NO_SUPERVISE=1`. The opt-out is useful for CI smoke tests that want the container to exit with the gateway's status code; for production deployments the supervised default is strictly better.

This behavior applies to the s6-based image only. Earlier (tini-based) images still run `gateway run` as the foreground main process.
:::

:::note Where gateway logs go
See the [Where the logs go](#where-the-logs-go) section below for the full routing map (per-profile gateways, dashboard, boot reconciler, container-wide `docker logs`).
:::

:::note Tool-loop hard stops for unattended gateways
Unattended gateway and cron sessions enable tool-loop hard stops by default through `non_interactive_hard_stop_enabled`. Interactive CLI, TUI, Desktop, and ACP sessions remain warning-only. To opt an unattended deployment out in the profile's `config.yaml`:

```yaml
tool_loop_guardrails:
  non_interactive_hard_stop_enabled: false
```
:::

Note: the API server is gated on `API_SERVER_ENABLED=true`. To expose it beyond `127.0.0.1` inside the container, also set `API_SERVER_HOST=0.0.0.0` and an `API_SERVER_KEY` (minimum 8 characters — generate one with `openssl rand -hex 32`). Example:

```sh
docker run -d \
  --name hermes \
  --restart unless-stopped \
  -v ~/.hermes:/opt/data \
  -p 8642:8642 \
  -e API_SERVER_ENABLED=true \
  -e API_SERVER_HOST=0.0.0.0 \
  -e API_SERVER_KEY="$(openssl rand -hex 32)" \
  -e API_SERVER_CORS_ORIGINS='*' \
  nousresearch/hermes-agent gateway run
```

Opening any port on an internet facing machine is a security risk. You should not do it unless you understand the risks.

## Running the dashboard

The built-in web dashboard runs as a supervised s6-rc service alongside the gateway in the same container. Set `HERMES_DASHBOARD=1` to bring it up:

```sh
docker run -d \
  --name hermes \
  --restart unless-stopped \
  -v ~/.hermes:/opt/data \
  -p 8642:8642 \
  -p 9119:9119 \
  -e HERMES_DASHBOARD=1 \
  nousresearch/hermes-agent gateway run
```

The dashboard is supervised by s6 — if it crashes, `s6-supervise` restarts it automatically after a short backoff. Dashboard stdout/stderr is forwarded to `docker logs <container>` (no prefix; the gateway's own output now lives in a per-profile s6-log file — see [Where the logs go](#where-the-logs-go) below — so the two streams don't clash).

| Environment variable | Description | Default |
|---------------------|-------------|---------|
| `HERMES_DASHBOARD` | Set to `1` (or `true` / `yes`) to enable the supervised dashboard service | *(unset — service is registered but stays down)* |
| `HERMES_DASHBOARD_HOST` | Bind address for the dashboard HTTP server | `0.0.0.0` |
| `HERMES_DASHBOARD_PORT` | Port for the dashboard HTTP server | `9119` |
| `HERMES_DASHBOARD_INSECURE` | **Deprecated / no-op.** Formerly bypassed the auth gate; as of the June 2026 hardening it no longer disables authentication. A non-loopback bind always requires an auth provider | *(ignored — configure a provider instead)* |

The dashboard inside the container defaults to binding `0.0.0.0` — without it, the published `-p 9119:9119` port would not be reachable from the host. To restrict the bind to container loopback (for sidecar / reverse-proxy setups), set `HERMES_DASHBOARD_HOST=127.0.0.1`.

The dashboard's auth gate engages automatically when both of the following are true:

1. The bind host is non-loopback (e.g. the default `0.0.0.0` inside the container), **and**
2. A `DashboardAuthProvider` plugin is registered.

There are three bundled ways to satisfy the second condition:

- **Username/password** — the simplest for a self-hosted / on-prem / homelab container on a trusted network or behind a VPN: set `HERMES_DASHBOARD_BASIC_AUTH_USERNAME` + `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD` (and `HERMES_DASHBOARD_BASIC_AUTH_SECRET` for restart-stable sessions). Not suitable for direct public-internet exposure.
- **OAuth (Nous Portal)** — for hosted/public deploys: the `dashboard_auth/nous` provider activates whenever `HERMES_DASHBOARD_OAUTH_CLIENT_ID` is set.
- **Self-hosted OIDC** — to authenticate against your own identity provider via standard OpenID Connect: the `dashboard_auth/self_hosted` provider activates when `HERMES_DASHBOARD_OIDC_ISSUER` + `HERMES_DASHBOARD_OIDC_CLIENT_ID` are set.

Whichever you choose, the gate redirects callers to a login page before they can reach any protected route. See [Web Dashboard → Authentication](features/web-dashboard.md#authentication-gated-mode) for all three providers.

When a reverse proxy such as Traefik or nginx runs in another container, its
bridge-network address is not trusted by default. Set the dashboard's public
URL and trust only that proxy's exact IP, or a bounded CIDR for a dedicated
proxy network, in the mounted `config.yaml`:

```yaml
dashboard:
  public_url: "https://dashboard.example.com"
  trusted_proxies:
    - "172.20.0.5"
    # Or, if the proxy address is dynamic on a dedicated network:
    # - "172.20.0.0/24"
```

This allows the proxy's `X-Forwarded-Proto: https` to control secure OAuth
cookies while leaving forwarding headers from other peers untrusted. Do not
use `*`, `0.0.0.0/0`, or `::/0`; Hermes rejects those unbounded entries.

If no provider is registered and the bind is non-loopback, the dashboard **fails closed at startup** with a specific error pointing at the missing env var. There is no longer an escape hatch that serves the dashboard unauthenticated on a public bind: `HERMES_DASHBOARD_INSECURE=1` is now a deprecated no-op (it logs a warning and is ignored). Configure a provider, or bind `HERMES_DASHBOARD_HOST=127.0.0.1` and reach the dashboard over an SSH tunnel / Tailscale instead.

:::warning Why `--insecure` was removed
An unauthenticated public dashboard was the entry point for the June 2026 MCP-config persistence campaign: internet scanners reached exposed dashboards (and OpenAI API servers) and drove the agent into planting an SSH-key backdoor. The auth gate is now mandatory on every non-loopback bind. For a trusted-LAN / homelab box, the bundled username/password provider (`HERMES_DASHBOARD_BASIC_AUTH_USERNAME` + `_PASSWORD`) is the zero-infra way to satisfy it.
:::

Running the dashboard as a separate container **is** supported when that container shares the host PID and network namespace (e.g. `network_mode: host`, as the repo's own `docker-compose.yml` does — see its `dashboard` service). Its gateway-liveness detection requires a shared PID namespace with the gateway process, so the limitation only applies to dashboards run in isolated bridge-network containers without a shared PID namespace.

## Running interactively (CLI chat)

To open an interactive chat session against a running data directory:

```sh
docker run -it --rm \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent
```

Or if you have already opened a terminal in your running container (via Docker Desktop for instance), just run:

```sh
/opt/hermes/.venv/bin/hermes
```

## Persistent volumes

The `/opt/data` volume is the single source of truth for all Hermes state. It maps to your host's `~/.hermes/` directory and contains:

| Path | Contents |
|------|----------|
| `.env` | API keys and secrets |
| `config.yaml` | All Hermes configuration |
| `SOUL.md` | Agent personality/identity |
| `sessions/` | Conversation history |
| `memories/` | Persistent memory store |
| `skills/` | Installed skills |
| `home/` | Per-profile HOME for Hermes tool subprocesses (`git`, `ssh`, `gh`, `npm`, and skill CLIs) |
| `cron/` | Scheduled job definitions |
| `hooks/` | Event hooks |
| `logs/` | Runtime logs |
| `skins/` | Custom CLI skins |

### Filesystem requirements for `state.db` in containers

Hermes keeps sessions in a SQLite database (`/opt/data/state.db`) that is opened in WAL journal mode by default. WAL relies on shared memory (`state.db-shm`) being coherent between every process that has the file open. Bind mounts that cross a VM boundary do not provide that: **virtiofs** (Docker Desktop and Podman on macOS, OrbStack) and **9p / drvfs** (Docker Desktop on Windows) both let concurrent writers silently corrupt a WAL database while the main file still passes `PRAGMA integrity_check`.

What Hermes does about it (since v2026.9.14):

- A **fresh** database whose directory is on a virtiofs/9p mount is created in rollback (`DELETE`) journal mode and a one-time warning is logged. Nothing to do.
- An **existing** WAL database on such a mount is never live-downgraded — other Hermes processes may hold it open, and a live switch destroys their uncheckpointed commits. Instead, every process logs a one-time error at startup and `hermes doctor` flags the database. Fix it one of two ways:
  1. Stop every Hermes process that uses the database, then run a one-time offline conversion with the Python that ships in the image (it has no `sqlite3` shell): `docker exec hermes python3 -c "import sqlite3; print(sqlite3.connect('/opt/data/state.db').execute('PRAGMA journal_mode=DELETE').fetchone()[0])"`. Set `database.journal_mode: delete` in `config.yaml` so a later open does not switch it back to WAL.
  2. Move the data directory onto a native volume — a named Docker volume (`-v hermes-data:/opt/data`) lives on the VM's own ext4 filesystem and supports WAL normally.

Detection reads `/proc/self/mountinfo` inside the container, so it works regardless of the host operating system. It does not classify NFS, SMB, or generic FUSE mounts; on those, set `database.journal_mode: delete` explicitly. Hermes does not offer SQLite's `locking_mode=EXCLUSIVE` as an alternative because the gateway, cron, and worker processes open the database concurrently.

### Immutable install tree

In hosted and published Docker images, `/opt/hermes` is the installed application tree. It is root-owned and read-only to the runtime `hermes` user, so agent turns, gateway sessions, dashboard actions, and normal `docker exec hermes hermes ...` commands cannot edit the core source, bundled `.venv`, `node_modules`, or TUI bundle in place.

All mutable Hermes state belongs under `/opt/data`: config, `.env`, profiles, skills, memories, sessions, logs, dashboard uploads, plugins, and other user-managed files. The image also disables runtime `.pyc` writes and Hermes lazy dependency installs into `/opt/hermes`; optional platform dependencies needed by the published image should be baked into the image or installed through a new image build.

On hosted/published images, agent self-improvement is scoped to skills, memory, plugins, and config under `/opt/data`. The installed core source under `/opt/hermes` is immutable; core changes are made via PRs to the repo and shipped by updating the image, not by live-editing the running install.

If an operator needs to repair or inspect files outside `/opt/data`, use a root shell intentionally. The `hermes` shim normally drops `docker exec hermes hermes ...` back to the runtime user; set `HERMES_DOCKER_EXEC_AS_ROOT=1` for a one-off root invocation when you explicitly need root semantics.

Skill CLIs that store credentials under `~` must be initialized against the subprocess HOME, not just the data-volume root. For example, the [xurl skill](./skills/bundled/social-media/social-media-xurl.md) stores OAuth state in `~/.xurl`; in the official Docker layout, Hermes tool calls read that as `/opt/data/home/.xurl`, so run manual xurl auth with `HOME=/opt/data/home` and verify with `HOME=/opt/data/home xurl auth status`.

:::warning
Never run two Hermes **gateway** containers against the same data directory simultaneously — session files and memory stores are not designed for concurrent write access.
:::

## Multi-profile support

Hermes supports [multiple profiles](../reference/profile-commands.md) — separate `~/.hermes/` subdirectories that let you run independent agents (different SOUL, skills, memory, sessions, credentials) from a single installation. **Inside the official Docker image, the s6 supervision tree treats each profile as a first-class supervised service**, so the recommended deployment is **one container hosting all profiles**.

Each profile created with `hermes profile create <name>` gets:

- A dedicated s6 service slot at `/run/service/gateway-<name>/`, registered dynamically by the runtime — no container rebuild required.
- Auto-restart on crash, backoff-managed by `s6-supervise`.
- Per-profile rotated logs at `${HERMES_HOME}/logs/gateways/<name>/current` (10 archives × 1 MB each).
- State persistence across container restarts: the boot-time reconciler reads `gateway_state.json` from each profile directory and brings the slot back up only for profiles whose last recorded state was `running`. Only a gateway you explicitly stopped (`hermes gateway stop`) stays down across a restart — a container restart, image upgrade, or unexpected exit leaves the recorded state as `running`, so the gateway auto-starts on the next boot.

A profile created from the **host** against a bind-mounted `~/.hermes` gets its directory but no slot (the host process cannot reach the container's `/run/service`). Inside the container, `hermes -p <name> gateway start` registers the missing slot on demand and starts it — no `docker restart` needed. Only `start` does this, and only for a real profile directory (one carrying `SOUL.md`); `stop`/`restart` on an unregistered profile and a mistyped `-p` name still fail with `✗ no such gateway`.

The lifecycle commands you'd run on the host work the same way from inside the container:

```sh
# Create a profile — registers the gateway-<name> s6 slot.
docker exec hermes hermes profile create coder

# Start / stop / restart — dispatches s6-svc; the gateway lifecycle survives docker restart.
docker exec hermes hermes -p coder gateway start
docker exec hermes hermes -p coder gateway stop
docker exec hermes hermes -p coder gateway restart

# Status — reports `Manager: s6 (container supervisor)` inside the container.
docker exec hermes hermes -p coder gateway status

# Remove a profile — tears down the s6 slot too.
docker exec hermes hermes profile delete coder
```

Under the hood, `hermes gateway start/stop/restart` inside the container is intercepted and routed to `s6-svc` against the right service directory; you don't need to learn the s6 commands directly. For raw supervisor state, use `/command/s6-svstat /run/service/gateway-<name>` (note `/command/` is on PATH only for processes spawned by the supervision tree — when calling from `docker exec`, pass the absolute path).

### Reaching more than one profile from outside the container

Two different surfaces reach a profile's gateway from outside, and they behave differently — don't conflate them:

**Hermes Desktop (and the web dashboard).** The Desktop app's **Remote Gateway** connection talks to a `hermes dashboard` backend (default **port 9119**, enabled by `HERMES_DASHBOARD=1`) — *not* the OpenAI API server. One dashboard backend serves **every** co-located profile: the app's profile switcher sends the target profile with each request and the backend opens that profile's `HERMES_HOME` on disk. So you do **not** need a second port — or a second connection — per profile for Desktop; one `:9119` connection covers them all through the switcher.

**OpenAI-compatible API clients (Open WebUI, LobeChat, `/v1/...`).** These talk to each profile's **API server**, which binds **port 8642 for every profile** (resolved from `API_SERVER_PORT` / `platforms.api_server.extra.port` — there is no auto-allocation and no `config.yaml`/`gateway.port` key). If you want a client to reach a *specific* second profile, give that profile a distinct `API_SERVER_PORT` in **its own** `.env`, otherwise its gateway tries to bind 8642 too and conflicts with the default profile:

```sh
# Create the profile (registers its gateway-<name> s6 slot)
docker exec hermes hermes profile create work

# Point its API server at a free port (write to the profile's own .env)
cat >> /opt/data/profiles/work/.env <<'EOF'
API_SERVER_ENABLED=true
API_SERVER_PORT=8643
EOF

docker exec hermes hermes -p work gateway restart
```

Keep `API_SERVER_PORT` in each profile's **own** `.env`, never in the container-wide `environment:` block — a global value would force every profile onto the same port and they would collide. With bridge networking, publish the extra port in `docker-compose.yml` (`- "8643:8643"`); with `network_mode: host` it is already reachable on the host. The default profile's 8642 connection is untouched.

### Why one container with many profiles, not many containers

Before the s6 migration, "one container per profile" was the recommended pattern because there was no in-container supervisor to manage multiple gateways. With s6 as PID 1, that's no longer necessary, and the single-container layout is simpler in almost every dimension:

| | One container, many profiles | One container per profile |
|---|---|---|
| Disk overhead | One image, one bundled venv, one Playwright cache | N images / N caches |
| Memory overhead | Shared Python interpreter cache, shared node_modules | Duplicated per container |
| Profile creation | `docker exec ... hermes profile create <name>` (seconds) | New `docker run` invocation + port allocation + bind-mount config |
| Per-profile crash recovery | `s6-supervise` auto-restart | Docker's `--restart unless-stopped` (slower, kills sibling work) |
| Logs | Per-profile rotated file via `s6-log`, plus container-boot audit log | `docker logs <name>` per container — no built-in rotation |
| Backup | One `~/.hermes` directory | N directories to coordinate |

The default profile (`default`) is always registered on first boot, so a fresh container ships with one supervised gateway out of the box. Additional profiles are pure runtime adds.

### When you DO want a separate container

Profile-in-container is the default. Run a separate container per profile only when you have a specific reason:

- **Resource isolation per workload** — e.g. a runaway browser-tool session in profile A shouldn't be able to OOM profile B. Containers give you `--memory` / `--cpus` per profile.
- **Independent image pinning** — different upstream image tags per workload.
- **Network segmentation** — distinct Docker networks per profile (e.g. one customer-facing, one internal).
- **Compliance / blast radius** — distinct credentials never share an OS-level process tree.

In those cases, declare one service per profile with distinct `container_name`, `volumes`, and `ports`:

```yaml
services:
  hermes-work:
    image: nousresearch/hermes-agent:latest
    container_name: hermes-work
    restart: unless-stopped
    command: gateway run
    ports:
      - "8642:8642"
    volumes:
      - ~/.hermes-work:/opt/data

  hermes-personal:
    image: nousresearch/hermes-agent:latest
    container_name: hermes-personal
    restart: unless-stopped
    command: gateway run
    ports:
      - "8643:8642"
    volumes:
      - ~/.hermes-personal:/opt/data
```

The warning from [Persistent volumes](#persistent-volumes) still applies: never point two containers at the same `~/.hermes` directory simultaneously. The s6 supervisor inside each container manages its own profile set; cross-container sharing of a data volume corrupts session files and memory stores.

## Where the logs go

The s6 container has four distinct log surfaces, and "why isn't my gateway showing anything in `docker logs`" is a common surprise. Cheatsheet:

| Source | Where it lands | How to read it |
|---|---|---|
| **Per-profile gateway** (`hermes gateway run` and per-profile gateways under s6) | Tee'd to two places: `docker logs <container>` (real time, no extra prefix) **and** `${HERMES_HOME}/logs/gateways/<profile>/current` (rotated, ISO-8601 timestamped, 10 archives × 1 MB each) | `docker logs -f hermes` or `tail -F ~/.hermes/logs/gateways/default/current` on the host |
| **Dashboard** (when `HERMES_DASHBOARD=1`) | `docker logs <container>` (no prefix) | `docker logs -f hermes` — interleaved with gateway lines |
| **Boot reconciler** (records which profile gateways were restored on each container start) | `${HERMES_HOME}/logs/container-boot.log` (append-only audit log) | `tail -F ~/.hermes/logs/container-boot.log` |
| **Generic Hermes logs** (`agent.log`, `errors.log`) | `${HERMES_HOME}/logs/` (profile-aware) | `docker exec hermes hermes logs --follow [--level WARNING] [--session <id>]` |

Two practical consequences worth knowing:

- The file copy at `logs/gateways/<profile>/current` is what survives container restarts. `docker logs` only retains output from the current container's lifetime (and is wiped on `docker rm`); the rotated files persist on the bind-mounted volume.
- The boot reconciler's audit line shape is `<iso-timestamp> profile=<name> prior_state=<state> action=<registered|started>`, so a quick `grep profile=coder ~/.hermes/logs/container-boot.log` reveals when a given profile was last restored and whether s6 auto-started it.

## Environment variable forwarding

API keys are read from `/opt/data/.env` inside the container. You can also pass environment variables directly:

```sh
docker run -it --rm \
  -v ~/.hermes:/opt/data \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e OPENAI_API_KEY="sk-..." \
  nousresearch/hermes-agent
```

This is useful for CI/CD or secrets-manager integrations where you don't want keys on disk. A key with the same name in `/opt/data/.env` wins over the `-e` value (Hermes loads that file with override semantics), so keep each key in one place. The exception is the variables of [Configure from environment variables](#configure-from-environment-variables): a copy of one of those is removed from `.env` at start. Named profiles read their own `profiles/<name>/.env`, not the container environment.

:::note Looking for Docker as the **terminal backend**?
This page covers running Hermes itself inside Docker. If you want Hermes to execute the agent's `terminal` / `execute_code` calls inside a Docker sandbox container (one long-lived container shared across Hermes processes — see issue #20561), that's a separate config block — `terminal.backend: docker` plus `terminal.docker_image`, `terminal.docker_volumes`, `terminal.docker_forward_env`, `terminal.docker_env`, `terminal.docker_run_as_host_user`, `terminal.docker_extra_args`, `terminal.docker_persist_across_processes`, and `terminal.docker_orphan_reaper`. See [Configuration → Docker Backend](configuration.md#docker-backend) for the full set including container-lifecycle rules.
:::

## Configure from environment variables

The image can set itself up from environment variables, so a Kubernetes Deployment (or a plain
`docker run -e …`) gets a working gateway and dashboard without anyone running `hermes setup` by
hand. On every start, the init step `/etc/cont-init.d/018-env-config` (it calls
`hermes_cli/container_env_config.py`) runs after the data volume is prepared and before any gateway
or the dashboard starts. It writes the settings below into `/opt/data/config.yaml`, the default
profile's config. The dashboard and `profiles.max` read their settings from that file.

| Variable | Effect |
|---|---|
| `HERMES_DASHBOARD_PUBLIC_URL` | Sets `dashboard.public_url`, the primary public URL. Must be an absolute `http(s)://host[/prefix]` URL. |
| `HERMES_DASHBOARD_PUBLIC_URLS` | Comma-separated further public URLs for `dashboard.public_urls` (for example Hermie Web on its own domain), written as a list. Each entry is checked the way the dashboard parses that list: an absolute `http(s)://host[:port][/prefix]` URL, no credentials, query or fragment. Register every `<url>/auth/callback` at your OIDC provider. |
| `HERMES_DASHBOARD_WRITE_ORIGIN_CHECK` | `auto`, `on` or `off` for `dashboard.write_origin_check` (refuse cookie-authenticated writes from a browser `Origin` that is not listed). |
| `HERMES_DASHBOARD_BASIC_AUTH_USERNAME` | Sets `dashboard.basic_auth.username` (username/password dashboard login). |
| `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD` | Hashed at start with the basic auth plugin's own `hash_password` (scrypt). Only the hash is written, to `dashboard.basic_auth.password_hash`. The plaintext never reaches the volume. |
| `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH` | A precomputed hash for `dashboard.basic_auth.password_hash`. If both password variables are set, the hash wins, at start and in the running dashboard. |
| `HERMES_DASHBOARD_BASIC_AUTH_SECRET` | The session-signing secret, at least 16 bytes (e.g. `openssl rand -base64 32`). It stays in the environment and is not written to disk. If it is unset and basic auth is configured, a secret is generated once and kept in `dashboard.basic_auth.secret` on the volume, so sessions survive restarts. |
| `HERMES_DASHBOARD_OIDC_ISSUER`, `HERMES_DASHBOARD_OIDC_CLIENT_ID` | Configure the self-hosted OIDC provider (`dashboard.oauth.self_hosted.issuer` / `.client_id`). They must be set together, and the issuer must use `https://` (plain `http` is allowed on localhost only). |
| `HERMES_DASHBOARD_OIDC_CLIENT_SECRET` | Optional (without it the client is a public PKCE client). It is not allowed on its own. It stays in the environment and is not written to disk. |
| `HERMES_DASHBOARD_OIDC_SCOPES` | Optional. Sets `dashboard.oauth.self_hosted.scopes` and must include `openid`. |
| `HERMES_DASHBOARD_TRUSTED_PROXIES` | Comma-separated IP addresses or bounded CIDR networks for `dashboard.trusted_proxies`. `*`, `0.0.0.0/0` and `::/0` are refused. |
| `HERMES_PROFILES_MAX` | Sets `profiles.max` (a whole number; `0` = unlimited). |
| `HERMIE_PLUGIN` | The Hermie companion plugin; see [below](#the-hermie-plugin). |
| `HERMES_DASHBOARD` | `1` starts the supervised dashboard (see [Running the dashboard](#running-the-dashboard)). |
| `HERMES_DASHBOARD_HOST` / `HERMES_DASHBOARD_PORT` | Where the dashboard binds. Defaults: `0.0.0.0` and `9119`. Validated at start. |
| `HERMES_MESSAGING_GATEWAY` | `on` (default) or `off`. `off` keeps the messaging gateway — and its per-profile gateways — from starting in this container; see [Turning the messaging gateway off](#turning-the-messaging-gateway-off) below. Not written to `config.yaml`: it is a live, container-level switch, re-read on every boot. |

The dashboard-auth variables have the same names the dashboard's auth plugins already read, so
they mean the same thing inside and outside a container.

How it behaves:

- **The environment is the source of truth for the keys it sets.** Every start reasserts exactly
  the keys whose variable is set, even if someone changed them in the dashboard in between.
  Keys that have no variable are never touched, so everything else you configure in the
  dashboard survives restarts.
- **Unsetting a variable does not delete its key.** The last value stays in `config.yaml` until you
  change it there. A variable set to an empty string counts as unset.
- **Nothing is written when nothing changed.** Two starts in a row with the same environment
  leave `config.yaml` byte-identical, and the file is not rewritten at all. A write goes through a
  temporary file and a rename. It keeps the rest of the file, including its comments, and it
  keeps the file's owner and mode.
- **Invalid values stop the container.** Examples: a URL without a scheme, a `HERMES_PROFILES_MAX`
  that is not a whole number, an OIDC issuer without a client id, a username without a password.
  Every problem is listed in the log, `config.yaml` is left exactly as it was, and the container
  exits with code 1. Nothing runs on the configuration it refused: no profile gateway is
  registered or started, the dashboard and the other supervised services do not start, and the
  container's command does not run. (Only this step's failure does that; the image keeps s6's
  default of carrying on past other failed init scripts.)
- **Secrets stay out of the log.** The log names the keys that were set, never their values.
- When the environment configures basic auth, an existing plaintext `dashboard.basic_auth.password`
  is turned into a hash and removed from `config.yaml`. The `basic` plugin is taken out of
  `plugins.disabled` if it was there, and the same goes for the OIDC plugin when OIDC variables
  are set.
- Precedence at runtime: the dashboard's auth plugins read these variables directly as well, and a
  non-empty variable wins over `config.yaml`.
- **A copy in `/opt/data/.env` never outranks the environment.** Hermes loads that file with
  override semantics, so a key written there (through the dashboard's key editor or by the agent)
  would beat the container's value and survive a rotation. At start, every variable in the table
  above that is set in the container environment is removed from `/opt/data/.env`; the log names
  the key, never the value. The dashboard's env writer also refuses every
  `HERMES_DASHBOARD_BASIC_AUTH_*` and `HERMES_DASHBOARD_OIDC_*` name.
- **A new password ends existing sessions.** Sessions are signed tokens that refresh for up to 30
  days. When a start writes a new password hash (or a new username) and the session secret is the
  generated one in `config.yaml`, that secret is regenerated in the same write, so every session
  signed with the old one is refused. When you supply `HERMES_DASHBOARD_BASIC_AUTH_SECRET`
  yourself, rotate that secret together with the password to revoke sessions.
- **Agent processes never see the dashboard's secrets.** The password, password hash, session
  secret and OIDC client secret are stripped from every process the agent starts (terminal,
  code execution, browser, CLI agents).

### Where the dashboard binds, and why that needs auth

Inside the container, the dashboard binds `0.0.0.0:9119` by default, so a Kubernetes Service, an
Ingress or a sidecar can reach it. A non-loopback bind always engages the dashboard's auth gate.
If no auth provider is registered (basic auth, self-hosted OIDC or Nous OAuth), the dashboard
**refuses to start**. It does not fall back to serving without auth, and `HERMES_DASHBOARD_INSECURE`
no longer changes that. The init step logs a warning when `HERMES_DASHBOARD=1` is set on a
non-loopback bind with no provider configured. A `dashboard.public_url` with a non-loopback host
engages the gate even on a loopback bind. To keep the dashboard private to the pod (for example
behind an authenticating sidecar), set `HERMES_DASHBOARD_HOST=127.0.0.1`. Basic auth is meant for
trusted networks and VPNs. On the open internet, put the dashboard behind OIDC or Nous OAuth.

### Turning the messaging gateway off

`HERMES_MESSAGING_GATEWAY=off` keeps this container's messaging gateway — and every per-profile
gateway — from starting, regardless of what was running before. This is the container-level switch
for a tenant you want kept fully off (billing paused, offboarding, an incident); it is validated
the same way as every other variable in the table above and fails the container closed on a value
that is not `on`/`off` (also `1`/`0`, `true`/`false`, `yes`/`no`).

What turning it off costs:

- **No messaging platforms.** Telegram, Discord, Slack, WhatsApp and every other configured
  platform adapter stay disconnected — nothing connects, nothing is delivered.
- **No cron scheduler.** Scheduled jobs do not fire while the gateway is off; they resume on their
  normal schedule once it is back on. Nothing is silently skipped or lost — jobs simply do not run
  during the window the switch was off.
- **The dashboard keeps working.** It is a separate supervised service and does not depend on the
  gateway; port 9119 stays reachable, and you can still browse sessions, logs and settings.
- **The container keeps running.** When the container's command is `gateway run` (the documented
  command, and the one in `docker-compose.yml`), it does not start a gateway and does not exit
  either: it logs one line, `[hermes] HERMES_MESSAGING_GATEWAY=off: not starting the messaging
  gateway; …`, and idles like `sleep infinity`. A `restart: unless-stopped` policy or a Kubernetes
  Deployment therefore sees a running container, not a restart loop, the dashboard stays up, and
  `docker stop` ends the container at once. You do not need to swap the command for
  `sleep infinity` to turn the gateway off. This holds with `--no-supervise` too (it opts out of
  supervision, not of the switch) and in the unsupervised non-PID-1 fallback. Outside a container
  the variable has no effect and `gateway run` behaves as always.
- **`hermes gateway start` explains itself instead of starting anything.** Run from inside the
  container (`docker exec … hermes gateway start`), it prints that the messaging gateway is off by
  configuration and exits non-zero, rather than silently doing nothing or fighting the switch on
  the next restart.

Unlike the other variables in this section, `HERMES_MESSAGING_GATEWAY` is **not** written to
`config.yaml` — it is read live, at every container boot and by `hermes gateway start` and `gateway run`, so
unsetting it (or setting it back to `on`) and restarting the container brings the gateway back
exactly as it was: whatever was durably recorded as running before the switch was flipped off
starts again, and whatever was stopped stays stopped. That durability is the other half of this
fix (HERM-131): a deliberate `hermes gateway stop` now survives a pod recreate on its own, even
without the environment switch — see the following note.

:::note `hermes gateway stop` now survives a container/pod recreate
Stopping the gateway with `hermes gateway stop` records that intent durably (`desired_state:
stopped` next to the gateway's other runtime state, on the persistent volume). A pod recreate, a
`docker restart`, or the gateway crashing no longer bring a deliberately-stopped gateway back:
only another explicit `hermes gateway start` (or unsetting `HERMES_MESSAGING_GATEWAY`, if that is
what is holding it off) does. Before this fix, the gateway's own shutdown path could overwrite that
recorded intent back to "running" while exiting, so a customer who had turned messaging off could
see it come back on its own after infrastructure churn.
:::

### The Hermie plugin

The image bakes the [Hermie](https://github.com/fullstackstudio-org/hermie-plugin) companion plugin
in at build time. The build arg `HERMIE_PLUGIN_REF` (a tag, branch or full commit SHA; the fork's
image workflow passes the plugin's latest release tag) selects the version, and the image label
`org.hermie.plugin.ref` records it. The optional `HERMIE_PLUGIN_COMMIT` pins the commit that ref
must resolve to (the workflow resolves it first, so a tag moved mid-build fails the build).
`HERMIE_PLUGIN_REPO` ends up in the image history, so a URL with credentials in it is refused.
The build runs the plugin security scanner once and prints the report in the build log. A caution
verdict is accepted, the same as `hermes plugins install --force`, and a dangerous verdict fails
the build. An empty `HERMIE_PLUGIN_REF` builds an image without the plugin.

At start, `HERMIE_PLUGIN` decides what happens:

| Value | Effect |
|---|---|
| unset | Use the baked plugin. `plugins/hermie` is made an exact copy of it, like `rsync --delete`, and recorded as a pinned install of the baked commit. If the copy already matches, it is left alone, and no scanner runs in the container. `hermie` is enabled only on the **first** install (no install record for it yet), and not even then when `plugins.disabled` names it. After that, whether it is enabled is up to you: the tree is kept in sync, `plugins.enabled`/`plugins.disabled` are not touched. To turn it off, use `hermes plugins disable hermie` (or set `HERMIE_PLUGIN=false`), not `hermes plugins remove hermie`: removing it deletes the install record, so the next start treats it as a first install and enables it again. |
| `true` | The same sync, and the plugin is **reasserted** on every start: added to `plugins.enabled` and taken out of `plugins.disabled`. A deployment controller that owns the plugin sets this. On an image built without the plugin, `true` stops the container (unset just logs that there is nothing to install). |
| `false` | Do nothing. No plugin is installed, synced, enabled or disabled, and a copy that is already there, whether an earlier start synced it or you installed it yourself, stays as it is, enabled or not. Disable or remove it with `hermes plugins disable hermie` / `hermes plugins remove hermie`. |
| a git ref (tag, branch or full 40-character SHA) | Development override. The ref is fetched from the plugin's repository at start, the security scanner runs and prints its report in the container log (caution is accepted, dangerous blocks), and the plugin is installed pinned to that commit and reasserted like `true`. The install is skipped when that commit is already installed. A branch moves, so each start installs its current head. If the repository cannot be reached and a copy is already installed, that copy is kept, with a warning. If nothing is installed, the container stops. |

**Every profile gets it.** The multiplexed gateway loads plugins per profile: each profile reads its
own `plugins/` directory and its own `plugins.enabled`. So the same copy and the same enable rule
are applied to the default profile and to every named profile (`/opt/data/profiles/<name>`), and a
profile created while the container runs (`hermes profile create`, the dashboard) gets the plugin
as it is created, before the gateway starts serving it. A profile that arrives another way
(`hermes profile import`, a distribution install) gets it at the next container start. A named profile whose files cannot be
updated is skipped with a warning instead of stopping the container. With `HERMIE_PLUGIN=false`
no profile is touched.

The installed copy is pinned, so `hermes plugins update hermie` refuses it, and the baked copy
comes back on the next start anyway. To change the version, change the image or set a ref. The
sync replaces any `plugins/hermie` it finds, including one you installed yourself from another
source or fork; to keep your own copy, set `HERMIE_PLUGIN=false`.

### Provider keys and the model

Pass provider keys (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …) as ordinary
environment variables, for example from a Kubernetes Secret. Nothing needs to be written for them.
Keep three things in mind:

- A key with the same name in `/opt/data/.env` **wins** over the container environment. Hermes
  loads that file with override semantics. The dashboard variables above are the exception: a
  copy of one of those is removed from `.env` at start.
- The process environment serves the default profile only. A named profile (`hermes profile
  create …`) reads its credentials from its own `profiles/<name>/.env`.
- The model and provider choice live in `config.yaml` (`model.default`, `model.provider`,
  `model.base_url`) and are not set from the environment. They travel together, and a provider
  alone would not select a working endpoint. The seeded config uses OpenRouter, so
  `OPENROUTER_API_KEY` alone gives a working gateway. To choose something else, pick the model
  in the dashboard, or run `hermes model` once in the container. The environment never
  overwrites that choice.

### Example: `docker run`

```sh
docker run -d --name hermes --restart unless-stopped \
  -v hermes-data:/opt/data \
  -p 9119:9119 \
  -e HERMES_DASHBOARD=1 \
  -e HERMES_DASHBOARD_PUBLIC_URL=https://hermes.example.com \
  -e HERMES_DASHBOARD_BASIC_AUTH_USERNAME=admin \
  -e HERMES_DASHBOARD_BASIC_AUTH_PASSWORD="$(cat ./dashboard-password)" \
  -e HERMES_DASHBOARD_TRUSTED_PROXIES=172.20.0.5 \
  -e HERMES_PROFILES_MAX=5 \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  ghcr.io/fullstackstudio-org/hermes-agent:main gateway run
```

### Example: Kubernetes

One replica per volume. The gateway holds a lock in the data volume, so use `strategy: Recreate`.
The container must start as root, because the init steps remap the `hermes` user and fix volume
ownership before they drop privileges. Do not set `runAsNonRoot` or `runAsUser` on it.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hermes
type: Opaque
stringData:
  HERMES_DASHBOARD_BASIC_AUTH_PASSWORD: change-me
  HERMES_DASHBOARD_BASIC_AUTH_SECRET: replace-with-openssl-rand-base64-32
  OPENROUTER_API_KEY: sk-or-...
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: hermes-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hermes
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: {app: hermes}
  template:
    metadata:
      labels: {app: hermes}
    spec:
      containers:
        - name: hermes
          image: ghcr.io/fullstackstudio-org/hermes-agent:main
          args: ["gateway", "run"]
          ports:
            - {name: dashboard, containerPort: 9119}
          env:
            - {name: HERMES_DASHBOARD, value: "1"}
            - {name: HERMES_DASHBOARD_PUBLIC_URL, value: "https://hermes.example.com"}
            - {name: HERMES_DASHBOARD_BASIC_AUTH_USERNAME, value: "admin"}
            # The pod network your ingress controller runs in; bounded, never 0.0.0.0/0.
            - {name: HERMES_DASHBOARD_TRUSTED_PROXIES, value: "10.42.0.0/16"}
            - {name: HERMES_PROFILES_MAX, value: "5"}
          envFrom:
            - secretRef: {name: hermes}
          volumeMounts:
            - {name: data, mountPath: /opt/data}
          readinessProbe:
            httpGet: {path: /api/status, port: dashboard}
            periodSeconds: 10
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: hermes-data}
---
apiVersion: v1
kind: Service
metadata:
  name: hermes
spec:
  selector: {app: hermes}
  ports:
    - {name: dashboard, port: 9119, targetPort: dashboard}
```

To use your own identity provider instead of a password, replace the two basic-auth variables with
`HERMES_DASHBOARD_OIDC_ISSUER` and `HERMES_DASHBOARD_OIDC_CLIENT_ID`, plus
`HERMES_DASHBOARD_OIDC_CLIENT_SECRET` from the Secret for a confidential client. Register
`https://hermes.example.com/auth/callback` as the redirect URI at the provider.

## Docker Compose example

For persistent deployment with both the gateway and dashboard, a `docker-compose.yaml` is convenient:

```yaml
services:
  hermes:
    image: nousresearch/hermes-agent:latest
    container_name: hermes
    restart: unless-stopped
    command: gateway run
    ports:
      - "8642:8642"   # gateway API
      - "9119:9119"   # dashboard (only reached when HERMES_DASHBOARD=1)
    volumes:
      - ~/.hermes:/opt/data
    environment:
      - HERMES_DASHBOARD=1
      # Uncomment to forward specific env vars instead of using .env file:
      # - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      # - OPENAI_API_KEY=${OPENAI_API_KEY}
      # - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: "2.0"
```

Start with `docker compose up -d` and view logs with `docker compose logs -f`. The supervised gateway's stdout is also tee'd to `${HERMES_HOME}/logs/gateways/<profile>/current` on the volume — see [Where the logs go](#where-the-logs-go) for the full routing map.

## Optional: Linux desktop audio bridge

Voice mode in Docker needs two separate things to work: Hermes must be allowed to probe audio devices inside the container, and the container must be able to reach your host audio server. The setup below covers the host audio plumbing for Linux desktops that expose a PulseAudio-compatible socket, including many PipeWire setups.

:::caution
This is a Linux desktop workaround, not a general Docker Desktop feature. It is useful when you already have host audio working and want CLI voice mode inside the Hermes container. If Hermes still reports `Running inside Docker container -- no audio devices`, use a build that includes Docker audio probing support for `PULSE_SERVER` / `PIPEWIRE_REMOTE`.
:::

First, create an ALSA config next to your Compose file:

```conf title="asound.conf"
pcm.!default {
    type pulse
    hint {
        show on
        description "Default ALSA Output (PulseAudio)"
    }
}

pcm.pulse {
    type pulse
}

ctl.!default {
    type pulse
}
```

Then build a small derived image with the ALSA PulseAudio plugin installed:

```dockerfile title="Dockerfile.audio"
FROM nousresearch/hermes-agent:latest

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends libasound2-plugins \
    && rm -rf /var/lib/apt/lists/*
```

Use that image in Compose and pass through the host user's PulseAudio socket and cookie:

```yaml
services:
  hermes:
    build:
      context: .
      dockerfile: Dockerfile.audio
    image: hermes-agent-audio
    container_name: hermes
    restart: unless-stopped
    command: gateway run
    volumes:
      - ~/.hermes:/opt/data
      - /run/user/${HERMES_UID}/pulse:/run/user/${HERMES_UID}/pulse
      # no-tmp: ok — path inside the container
      - ~/.config/pulse/cookie:/tmp/pulse-cookie:ro
      - ./asound.conf:/etc/asound.conf:ro
    environment:
      - HERMES_UID=${HERMES_UID}
      - HERMES_GID=${HERMES_GID}
      - XDG_RUNTIME_DIR=/run/user/${HERMES_UID}
      - PULSE_SERVER=unix:/run/user/${HERMES_UID}/pulse/native
      # no-tmp: ok — path inside the container
      - PULSE_COOKIE=/tmp/pulse-cookie
```

Start it with your host UID/GID so the container process can access the per-user audio socket:

```sh
export HERMES_UID="$(id -u)"
export HERMES_GID="$(id -g)"
docker compose up -d --build
```

To verify what PortAudio sees inside the container:

```sh
docker exec hermes /opt/hermes/.venv/bin/python -c "import sounddevice as sd; print(sd.query_devices())"
```

## Resource limits

The Hermes container needs moderate resources. Recommended minimums:

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Memory | 1 GB | 2–4 GB |
| CPU | 1 core | 2 cores |
| Disk (data volume) | 500 MB | 2+ GB (grows with sessions/skills) |

Browser automation (Playwright/Chromium) is the most memory-hungry feature. If you don't need browser tools, 1 GB is sufficient. With browser tools active, allocate at least 2 GB.

Set limits in Docker:

```sh
docker run -d \
  --name hermes \
  --restart unless-stopped \
  --memory=4g --cpus=2 \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent gateway run
```

## What the Dockerfile does

The official image is based on `debian:13.4` and includes:

- Python 3.13 with dependencies synced from the lockfile via `uv sync --frozen --no-install-project` for the baked extras (`all`, `messaging`, Anthropic/Bedrock/Azure identity, Matrix), followed by a no-dependency editable install of Hermes itself. Catalog plugins such as the Hindsight memory provider are not baked in; `hermes plugins install hindsight` installs the plugin and its dependencies into `HERMES_LAZY_INSTALL_TARGET` (`/opt/data/lazy-packages`) at install time.
- Node.js 26 + npm (for browser automation, WhatsApp bridge, TUI/Desktop bundles, and workspace build tooling)
- Playwright with Chromium (`npx playwright install --with-deps chromium --only-shell`)
- ripgrep, ffmpeg, git, and `xz-utils` as system utilities
- **`docker-cli`** — so agents running inside the container can drive the host's Docker daemon (bind-mount `/var/run/docker.sock` to opt in) for `docker build`, `docker run`, container inspection, etc.
- **`openssh-client`** — enables the [SSH terminal backend](./configuration.md#ssh-backend) from inside the container. The SSH backend shells out to the system `ssh` binary; without this, it failed silently in containerized installs.
- The WhatsApp bridge (`scripts/whatsapp-bridge/`)
- **[`s6-overlay`](https://github.com/just-containers/s6-overlay) v3** as PID 1 (replaces the older `tini`) — supervises the dashboard and per-profile gateways with auto-restart on crash, reaps zombie subprocesses, and forwards signals.

The image treats `/opt/hermes` as an immutable install tree at runtime. Optional Python extras, Node workspaces, and TUI assets that must be available inside Docker need to be baked during the image build; runtime lazy installs are disabled so supervised gateways and `docker exec hermes …` commands do not try to write dependency artifacts back into the read-only source tree.

The container's `ENTRYPOINT` is a small dispatcher (`docker/entrypoint-dispatch.sh`). When the container owns PID 1 (normal Docker / Podman), it exec's s6-overlay's `/init` and you get the full supervision tree described below. When a platform wraps the image entrypoint under its own PID-1 init (Fly.io Machines, `docker run --init`, some Nomad/Kubernetes setups), `/init` would abort with `s6-overlay-suexec: fatal: can only run as pid 1` — so the dispatcher instead runs the stage2 bootstrap directly and exec's the main wrapper without s6. On that fallback path the requested command still runs, but supervised services (dashboard, per-profile gateways) are unavailable.

On the PID-1 path, `/init`:
1. Runs `/etc/cont-init.d/01-hermes-setup` (= `docker/stage2-hook.sh`) as root: optional UID/GID remap, fixes volume ownership, seeds `.env` / `config.yaml` / `SOUL.md` on first boot, runs non-interactive config-schema migrations unless `HERMES_SKIP_CONFIG_MIGRATION=1`, syncs bundled skills.
2. Runs `/etc/cont-init.d/02-reconcile-profiles` (= `hermes_cli.container_boot`): walks `$HERMES_HOME/profiles/<name>/`, recreates the per-profile gateway s6 service slot under `/run/service/gateway-<profile>/`, and auto-starts only those whose last recorded state was `running` (see [Per-profile gateway supervision](#per-profile-gateway-supervision)).
3. Starts the static `main-hermes` and `dashboard` s6-rc services.
4. Exec's the container's CMD as the main program (`/opt/hermes/docker/main-wrapper.sh`), which routes the arguments the user passed to `docker run`:
   - no args → `hermes` (the default)
   - first arg is an executable on PATH (e.g. `sleep`, `bash`) → exec it directly
   - anything else → `hermes <args>` (subcommand passthrough)
   The container exits when this main program exits, with its exit code.

:::warning Breaking change vs. pre-s6 images
The container ENTRYPOINT is now the `entrypoint-dispatch.sh` dispatcher (which delegates to s6-overlay's `/init` under PID 1), not `/usr/bin/tini`. All five documented `docker run` invocation patterns (no args, `chat -q "…"`, `sleep infinity`, `bash`, `--tui`) behave identically to the tini-based image. If you have a downstream wrapper that depended on tini-specific signal behavior or hard-coded `/usr/bin/tini --` invocation, pin to the previous image tag.
:::

:::warning Privilege model
Do not override the image entrypoint unless you keep `/init` (or, equivalently, the legacy `docker/entrypoint.sh` shim that forwards to the stage2 hook) in the command chain. s6-overlay's `/init` runs as root so it can chown the volume on first boot, then drops to the `hermes` user via `s6-setuidgid` for every supervised service AND for the main program. Starting `hermes gateway run` as root inside the official image is refused by default because it can leave root-owned files in `/opt/data` and break later dashboard or gateway starts. Set `HERMES_ALLOW_ROOT_GATEWAY=1` only when you intentionally accept that risk.
:::

:::warning Overriding `entrypoint:` also removes the zombie reaper
`/init` is what reaps orphaned grandchildren (headless browsers, MCP servers, `git`/`npm` helpers spawned by tools). A Compose service that overrides `entrypoint:` to call `hermes` directly — for example to run the dashboard as a non-root user — makes the hermes process itself PID 1, and nothing above it ever calls `wait()`: every orphan stays a `<defunct>` entry forever (one deployment reached 284 zombies in under three hours). Hermes prints `[hermes] WARNING: this process is PID 1 with no init above it` at startup in that configuration.

If you must override the entrypoint, add Docker's init as PID 1 so orphans are reaped:

```yaml
services:
  hermes-dashboard:
    image: nousresearch/hermes-agent:latest
    init: true                                      # docker-init becomes PID 1 and reaps orphans
    entrypoint: ["/opt/hermes/.venv/bin/hermes"]
    command: ["dashboard", "--host", "0.0.0.0", "--port", "9119", "--no-open", "--skip-build"]
```

(`docker run --init …` is the equivalent flag.) This fixes the zombie accumulation only — with `/init` out of the chain, the s6 supervision tree is still gone: the dashboard, `hermes gateway run` and per-profile gateways are unsupervised, exactly as the dispatcher's own non-PID-1 warning says. Keep the default `ENTRYPOINT` whenever you can.
:::

### `docker exec` automatically drops to the `hermes` user

`docker exec hermes <cmd>` defaults to running as root inside the container, but the image ships a thin shim at `/opt/hermes/bin/hermes` (earliest on PATH) that detects root callers and transparently re-execs through `s6-setuidgid hermes`. So `docker exec hermes login`, `docker exec hermes profile create …`, `docker exec hermes setup`, etc. all write files owned by UID 10000 — i.e. readable by the supervised gateway — with no extra `--user` flag needed. Non-root callers (the supervised processes themselves, `docker exec --user hermes`, kanban subagents inside the container) hit a short-circuit that exec's the venv binary directly, so there's no overhead on the hot paths.

If you specifically need a `docker exec` that retains root semantics (diagnostic sessions, inspecting root-only state, files outside `/opt/data` that root happens to own), opt out per invocation:

```sh
docker exec -e HERMES_DOCKER_EXEC_AS_ROOT=1 hermes <cmd>
```

The shim accepts `1` / `true` / `yes` (case-insensitive). Anything else — including typos like `=0` — falls through to the drop, so silent opt-outs aren't possible. If `s6-setuidgid` isn't available (custom builds that stripped s6-overlay), the shim refuses to run as root and exits 126 instead, surfacing the broken privilege model loudly rather than regressing to the historical footgun where `docker exec hermes login` would write `auth.json` as `root:root` and break the supervised gateway's auth on every chat platform message.

### Per-profile gateway supervision

Each profile created with `hermes profile create <name>` automatically gets an s6-supervised gateway service registered at `/run/service/gateway-<name>/`, with state-persistent auto-restart across container restarts. See [Multi-profile support](#multi-profile-support) above for the user-facing workflow and the lifecycle commands.

**Supervision benefits over the pre-s6 image:**

- Gateway crashes are auto-restarted by `s6-supervise` after a ~1s backoff.
- Dashboard, when enabled with `HERMES_DASHBOARD=1`, is supervised on the same supervision tree and gets the same auto-restart treatment.
- `docker restart`, image upgrades (`docker compose up -d --force-recreate`), and unexpected exits preserve running gateways: the cont-init reconciler reads `$HERMES_HOME/profiles/<name>/gateway_state.json` and brings the slot back up if the last recorded state was `running`. Only an explicit `hermes gateway stop` records `stopped` and keeps the gateway down across the restart; the container/s6 SIGTERM sent on a restart or upgrade is treated as "still running" and auto-starts.
- Per-profile gateway logs persist under `$HERMES_HOME/logs/gateways/<profile>/current` (rotated by `s6-log`), and the reconciler's actions are appended to `$HERMES_HOME/logs/container-boot.log` per boot. See [Where the logs go](#where-the-logs-go) for the full routing map.

`hermes status` inside the container reports `Manager: s6 (container supervisor)`. Use `/command/s6-svstat /run/service/gateway-<name>` for the raw supervisor view (note `/command/` is on PATH for supervision-tree processes only; pass the absolute path when calling from `docker exec`).

## Upgrading

Pull the latest image and recreate the container. Your data directory is
preserved, and the container runs non-interactive config-schema migrations
against the mounted `$HERMES_HOME/config.yaml` before starting the gateway.
When a migration is needed, Hermes writes timestamped backups next to
`config.yaml` and `.env` first.

```sh
docker pull nousresearch/hermes-agent:latest
docker rm -f hermes
docker run -d \
  --name hermes \
  --restart unless-stopped \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent gateway run
```

Or with Docker Compose:

```sh
docker compose pull
docker compose up -d
```

Set `HERMES_SKIP_CONFIG_MIGRATION=1` only if you need to inspect or migrate the
persisted config manually before letting the new image rewrite it.

## Skills and credential files

When using Docker as the execution environment (not the methods above, but when the agent runs commands inside a Docker sandbox — see [Configuration → Docker Backend](./configuration.md#docker-backend)), Hermes reuses a single long-lived container for all tool calls and automatically bind-mounts the skills directory (`~/.hermes/skills/`) and any credential files declared by skills into that container as read-only volumes. Skill scripts, templates, and references are available inside the sandbox without manual configuration, and because the container persists for the life of the Hermes process, any dependencies you install or files you write stay around for the next tool call.

The same syncing happens for SSH and Modal backends — skills and credential files are uploaded via rsync or the Modal mount API before each command.

## Installing more tools in the container

The official image ships with a curated set of utilities (see [What the Dockerfile does](#what-the-dockerfile-does)), but not every tool an agent might want is preinstalled. There are five recommended approaches, in increasing order of effort and durability.

### npm or Python tools — use `npx` or `uvx`

For any tool published to npm or PyPI, instruct Hermes to run it via `npx` (npm) or `uvx` (Python) and to remember that command in its persistent memory. If the tool needs a config file or credentials, instruct it to drop those under `/opt/data` (e.g. `/opt/data/<tool>/config.yaml`).

Dependencies are fetched on demand and cached for the life of the container. Configuration written under `/opt/data` survives container restarts because it lives on the bind-mounted host directory. The package cache itself is rebuilt after a `docker rm`, but `npx` and `uvx` re-fetch transparently the next time the tool runs.

### Other tools (apt packages, binaries) — install and remember

For anything outside npm or PyPI — `apt` packages, prebuilt binaries, language runtimes not already in the image — instruct Hermes how to install it (e.g. `apt-get update && apt-get install -y <package>`) and tell it to remember the install command. The tool persists for the rest of the container's lifetime, and Hermes will re-run the install command after a container restart when it next needs the tool.

This is a good fit for tools that are quick to install and used occasionally. For tools used constantly, prefer the next approach.

### Durable installs — build a derived image

When a tool must be available immediately on every container start with no re-install delay, build a new image that inherits from `nousresearch/hermes-agent` and installs the tool in a layer:

```dockerfile
FROM nousresearch/hermes-agent:latest

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends <your-package> \
    && rm -rf /var/lib/apt/lists/*
USER hermes
```

Build it and use it in place of the official image:

```sh
docker build -t my-hermes:latest .
docker run -d \
  --name hermes \
  --restart unless-stopped \
  -v ~/.hermes:/opt/data \
  -p 8642:8642 \
  my-hermes:latest gateway run
```

The entrypoint script and `/opt/data` semantics are inherited unchanged, so the rest of this page still applies. Remember to rebuild the image when pulling a newer upstream `nousresearch/hermes-agent`.

### Complex tools or multi-service stacks — run a sidecar container

For tools that bring their own service (a database, a web server, a queue, a headless browser farm) or that are too heavy to live inside the Hermes container, run them as a separate container on a shared Docker network. Hermes reaches the sidecar by container name, the same way it reaches a local inference server (see [Connecting to local inference servers](#connecting-to-local-inference-servers-vllm-ollama-etc)).

```yaml
services:
  hermes:
    image: nousresearch/hermes-agent:latest
    container_name: hermes
    restart: unless-stopped
    command: gateway run
    ports:
      - "8642:8642"
    volumes:
      - ~/.hermes:/opt/data
    networks:
      - hermes-net

  my-tool:
    image: example/my-tool:latest
    container_name: my-tool
    restart: unless-stopped
    networks:
      - hermes-net

networks:
  hermes-net:
    driver: bridge
```

From inside the Hermes container, the sidecar is reachable at `http://my-tool:<port>` (or whatever protocol it serves). This pattern keeps each service's lifecycle, resource limits, and upgrade cadence independent, and avoids bloating the Hermes image with dependencies that are only needed by one tool.

### Broadly useful tools — open an issue or pull request

If a tool is likely to be useful to most Hermes Agent users, consider contributing it upstream rather than carrying it in a private derived image. Open an issue or pull request on the [hermes-agent repository](https://github.com/NousResearch/hermes-agent) describing the tool and its use case. Tools that get bundled into the official image benefit every user and avoid the maintenance overhead of a downstream fork.

## Connecting to local inference servers (vLLM, Ollama, etc.)

When running Hermes in Docker and your inference server (vLLM, Ollama, text-generation-inference, etc.) is also running on the host or in another container, networking requires extra attention.

### Docker Compose (recommended)

Put both services on the same Docker network. This is the most reliable approach:

```yaml
services:
  vllm:
    image: vllm/vllm-openai:latest
    container_name: vllm
    command: >
      --model Qwen/Qwen2.5-7B-Instruct
      --served-model-name my-model
      --host 0.0.0.0
      --port 8000
    ports:
      - "8000:8000"
    networks:
      - hermes-net
    deploy:
      resources:
        reservations:
          devices:
            - capabilities: [gpu]

  hermes:
    image: nousresearch/hermes-agent:latest
    container_name: hermes
    restart: unless-stopped
    command: gateway run
    ports:
      - "8642:8642"
    volumes:
      - ~/.hermes:/opt/data
    networks:
      - hermes-net

networks:
  hermes-net:
    driver: bridge
```

Then in your `~/.hermes/config.yaml`, use the **container name** as the hostname:

```yaml
model:
  provider: custom
  model: my-model
  base_url: http://vllm:8000/v1
  api_key: "none"
```

:::tip Key points
- Use the **container name** (`vllm`) as the hostname — not `localhost` or `127.0.0.1`, which refer to the Hermes container itself.
- The `model` value must match the `--served-model-name` you passed to vLLM.
- Set `api_key` to any non-empty string (vLLM requires the header but doesn't validate it by default).
- Do **not** include a trailing slash in `base_url`.
:::

### Standalone Docker run (no Compose)

If your inference server runs directly on the host (not in Docker), use `host.docker.internal` on macOS/Windows, or `--network host` on Linux:

**macOS / Windows:**

```sh
docker run -d \
  --name hermes \
  -v ~/.hermes:/opt/data \
  -p 8642:8642 \
  nousresearch/hermes-agent gateway run
```

```yaml
# config.yaml
model:
  provider: custom
  model: my-model
  base_url: http://host.docker.internal:8000/v1
  api_key: "none"
```

**Linux (host networking):**

```sh
docker run -d \
  --name hermes \
  --network host \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent gateway run
```

```yaml
# config.yaml
model:
  provider: custom
  model: my-model
  base_url: http://127.0.0.1:8000/v1
  api_key: "none"
```

:::warning With `--network host`, the `-p` flag is ignored — all container ports are directly exposed on the host.
:::

### Verifying connectivity

From inside the Hermes container, confirm the inference server is reachable:

```sh
docker exec hermes curl -s http://vllm:8000/v1/models
```

You should see a JSON response listing your served model. If this fails, check:

1. Both containers are on the same Docker network (`docker network inspect hermes-net`)
2. The inference server is listening on `0.0.0.0`, not `127.0.0.1`
3. The port number matches

### Ollama

Ollama works the same way. If Ollama runs on the host, use `host.docker.internal:11434` (macOS/Windows) or `127.0.0.1:11434` (Linux with `--network host`). If Ollama runs in its own container on the same Docker network:

```yaml
model:
  provider: custom
  model: llama3
  base_url: http://ollama:11434/v1
  api_key: "none"
```

## Troubleshooting

### Container exits immediately

Check logs: `docker logs hermes`. Common causes:
- Missing or invalid `.env` file — run interactively first to complete setup
- Port conflicts if running with exposed ports

### "Permission denied" errors

The container's stage2 hook drops privileges to the non-root `hermes` user (UID 10000) via `s6-setuidgid` inside each supervised service. If your host `~/.hermes/` is owned by a different UID, set `HERMES_UID`/`HERMES_GID` — or their `PUID`/`PGID` aliases, for parity with LinuxServer.io and NAS images — to match your host user, or ensure the data directory is writable:

```sh
chmod -R 755 ~/.hermes
```

On a NAS (UGOS, Synology, unRAID) the data directory is typically a **bind mount** owned by a host UID the container cannot `chown`. Set `PUID`/`PGID` (or `HERMES_UID`/`HERMES_GID`) to that host user so the runtime runs as the owner of the mount rather than UID 10000:

```sh
docker run -d \
  --name hermes \
  -e PUID=1000 -e PGID=10 \
  -v /volume1/docker/hermes:/opt/data \
  nousresearch/hermes-agent gateway run
```

`docker exec hermes <cmd>` automatically drops to UID 10000 too — see [`docker exec` automatically drops to the `hermes` user](#docker-exec-automatically-drops-to-the-hermes-user) for details and the per-invocation opt-out.

### Shared data directory keeps resetting to `0700`

Outside a container Hermes locks `HERMES_HOME` (and its `cron/`, `sessions/`, `logs/`, `memories/` subdirectories) to owner-only `0700` on every start. Inside a container it leaves directory modes alone, so a bind mount shared with a sibling container running as a different UID (a web UI, a permissions fixer) keeps whatever mode and ACLs you set on the host. To force a specific directory mode anyway, set `HERMES_HOME_MODE` (octal, e.g. `HERMES_HOME_MODE=0755`); it is applied in containers too.

### "Permission denied" on every `docker exec` (install dir locked to 0700)

Images built before late August 2026 had a bug where writing a credential file directly under `/opt/hermes` restricted that directory to `0700`, locking the `hermes` user (UID 10000) out of the install tree. Every new `docker exec` then fails with `Permission denied`.

Pulling a newer image and recreating the container fixes it permanently (the install dir ships as `0755` and current releases no longer restrict it). If you need to recover a running container in place without recreating it:

```sh
docker exec -u root hermes chmod 0755 /opt/hermes
```

### Zombie (`<defunct>`) processes piling up under PID 1

`ps -eo stat,ppid,comm | awk '$1 ~ /^Z/'` inside the container lists dead children that were never reaped. This happens when hermes itself is PID 1 — almost always because a Compose service overrides `entrypoint:` and so skips `docker/entrypoint-dispatch.sh` → `/init`. Hermes also warns about it at startup (`this process is PID 1 with no init above it`). Restore the default entrypoint, or add `init: true` (Compose) / `docker run --init` so `docker-init` reaps orphans; see [What the Dockerfile does](#what-the-dockerfile-does). Recreating the container clears the existing zombies.

### Browser tools not working

Playwright needs shared memory. Add `--shm-size=1g` to your Docker run command:

```sh
docker run -d \
  --name hermes \
  --shm-size=1g \
  -v ~/.hermes:/opt/data \
  nousresearch/hermes-agent gateway run
```

### Gateway not reconnecting after network issues

The `--restart unless-stopped` flag handles most transient failures. If the gateway is stuck, restart the container:

```sh
docker restart hermes
```

### Checking container health

```sh
docker logs --tail 50 hermes          # Recent logs
docker run -it --rm nousresearch/hermes-agent:latest version     # Verify version
docker stats hermes                    # Resource usage
```
