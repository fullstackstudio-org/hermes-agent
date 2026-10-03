"""Configure a container's ``$HERMES_HOME`` from environment variables.

Wired into the image as ``/etc/cont-init.d/018-env-config``: it runs as the ``hermes`` user after
01-hermes-setup (volume chown, config seeding) and before 02-reconcile-profiles, so every gateway
and the dashboard start on the configuration the environment asked for. A Kubernetes Deployment
(or ``docker run -e``) can therefore set a deployment up without anyone running ``hermes setup``.

Contract (see website/docs/user-guide/docker.md, "Configure from environment variables"):

* The environment is the source of truth for the keys it sets. Every start reasserts exactly the
  keys whose variable is set (non-blank); keys with no variable are never touched, so settings a
  user makes in the dashboard survive restarts.
* Unsetting a variable leaves the last written value in place; it does not delete it.
* Secrets never reach the log (key names only) and the plaintext password never reaches disk.
  Secrets the dashboard auth plugins already read from the process environment (the basic-auth
  session secret, the OIDC client secret) are validated here and left in the environment.
* Everything is validated before anything is written: an invalid value fails the start with a
  clear message instead of producing a half-applied ``config.yaml``.
* ``config.yaml`` is rewritten through ``atomic_config_write`` (ruamel round-trip, temp file +
  rename, owner and mode kept) and only when something changed, so two starts in a row with the
  same environment leave the file byte-identical.

The Hermie plugin is baked into the image at build time (``bake`` below, run by the Dockerfile,
which also runs the plugin security scanner once). At start ``HERMIE_PLUGIN`` unset/true copies the
baked tree into ``$HERMES_HOME/plugins`` when it differs and enables it (no scan in the
container), ``false`` leaves plugins alone, and a git ref fetches that ref instead (scan included).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

TAG = "[env-config]"

# Existing variable names read by the dashboard and its auth plugins at runtime. Reused, never
# renamed, so a variable means the same thing inside and outside this init step.
PUBLIC_URL = "HERMES_DASHBOARD_PUBLIC_URL"
PUBLIC_URLS = "HERMES_DASHBOARD_PUBLIC_URLS"
WRITE_ORIGIN_CHECK = "HERMES_DASHBOARD_WRITE_ORIGIN_CHECK"
BASIC_USERNAME = "HERMES_DASHBOARD_BASIC_AUTH_USERNAME"
BASIC_PASSWORD = "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"
BASIC_PASSWORD_HASH = "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH"
BASIC_SECRET = "HERMES_DASHBOARD_BASIC_AUTH_SECRET"
OIDC_ISSUER = "HERMES_DASHBOARD_OIDC_ISSUER"
OIDC_CLIENT_ID = "HERMES_DASHBOARD_OIDC_CLIENT_ID"
OIDC_CLIENT_SECRET = "HERMES_DASHBOARD_OIDC_CLIENT_SECRET"
OIDC_SCOPES = "HERMES_DASHBOARD_OIDC_SCOPES"
DASHBOARD_HOST = "HERMES_DASHBOARD_HOST"
DASHBOARD_PORT = "HERMES_DASHBOARD_PORT"
# New variables: the fork had no environment surface for these settings.
TRUSTED_PROXIES = "HERMES_DASHBOARD_TRUSTED_PROXIES"
# Fork: the remote MCP endpoint (dashboard.mcp.enabled), operator-only like the rest of this list.
MCP_ENABLED = "HERMES_DASHBOARD_MCP_ENABLED"
PROFILES_MAX = "HERMES_PROFILES_MAX"
HERMIE_PLUGIN = "HERMIE_PLUGIN"
# HERM-131: keep the messaging gateway (and its cron scheduler) off for this container regardless of
# any `desired_state` recorded on the volume. Consumed live — by hermes_cli.container_boot at every
# boot and by `hermes gateway start` — not written into config.yaml: it is a container-level switch,
# the same kind of setting as HERMES_DASHBOARD_HOST/_PORT below, not a per-profile operator intent.
MESSAGING_GATEWAY = "HERMES_MESSAGING_GATEWAY"

# Every variable this step owns. When one is set in the container environment, a same-named line in
# $HERMES_HOME/.env is removed at start: Hermes loads that file with override semantics, so a copy
# written there (PUT /api/env, the agent) would otherwise outlive a rotation done by the controller.
MANAGED_ENV_NAMES = (
    PUBLIC_URL, PUBLIC_URLS, WRITE_ORIGIN_CHECK, BASIC_USERNAME, BASIC_PASSWORD, BASIC_PASSWORD_HASH, BASIC_SECRET,
    OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_SCOPES, DASHBOARD_HOST, DASHBOARD_PORT,
    TRUSTED_PROXIES, PROFILES_MAX, HERMIE_PLUGIN, MESSAGING_GATEWAY, MCP_ENABLED,
)

HERMIE_PLUGIN_REPO = "https://github.com/fullstackstudio-org/hermie-plugin.git"
# Baked at image build time by `python -m hermes_cli.container_env_config bake` (see Dockerfile).
BAKED_PLUGIN_DIR = Path("/opt/hermie-plugin")
BAKED_PLUGIN_META = Path("/etc/hermes/hermie-plugin.json")

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# A branch or tag name: git's own refname rules, narrowed to what a sane deployment uses.
_REF_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/-]+(?<![./])$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Bundled dashboard-auth plugin keys that must not sit in plugins.disabled while the environment
# configures that provider (the provider would silently never register).
_BASIC_PLUGIN_KEYS = ("basic", "dashboard_auth/basic")
_OIDC_PLUGIN_KEYS = ("self-hosted", "self_hosted", "dashboard_auth/self_hosted")


class EnvConfigError(Exception):
    """One or more environment values are invalid; nothing was written."""


def _log(message: str) -> None:
    print(f"{TAG} {message}", flush=True)


def _env(environ: Mapping[str, str], name: str) -> str:
    """The variable's value, or ``""`` when unset. Blank counts as unset (same rule the dashboard
    auth plugins use), so a provisioned-but-empty Secret key cannot clear a setting."""
    return (environ.get(name) or "").strip()


# ---------------------------------------------------------------------------------------------
# Parsing + validation (no side effects)
# ---------------------------------------------------------------------------------------------


@dataclass
class Plan:
    """The validated intent of one start: what to write and what to install."""

    # (dotted config path, value, source variable). Order is the order keys are applied/logged.
    assignments: list[tuple[str, Any, str]] = field(default_factory=list)
    # Plaintext password from the environment, hashed against the on-disk hash at apply time.
    basic_password: str = ""
    # True when the environment configures basic auth (username and/or a credential).
    basic_auth_from_env: bool = False
    basic_secret_from_env: bool = False
    oidc_from_env: bool = False
    # HERMIE_PLUGIN: "baked" (unset/true: sync the plugin baked into the image), "off" (false:
    # leave plugins alone), or "ref" (fetch ``hermie_ref`` at start — a branch, tag or full SHA).
    hermie_mode: str = "baked"
    hermie_ref: Optional[str] = None
    # True when HERMIE_PLUGIN=true was explicit: an image without a baked plugin is then an error.
    hermie_required: bool = False
    # HERMES_MESSAGING_GATEWAY: True unless explicitly set to an "off" value. Not written to
    # config.yaml — see MESSAGING_GATEWAY above.
    messaging_gateway_enabled: bool = True
    # Value-free remarks for the log.
    notes: list[str] = field(default_factory=list)


def _validate_public_url(raw: str) -> str:
    from hermes_cli.dashboard_auth.prefix import _normalise_public_url

    cleaned = _normalise_public_url(raw)
    if not cleaned or not urllib.parse.urlparse(cleaned).hostname:
        raise ValueError(
            f"{PUBLIC_URL} must be an absolute http(s) URL with a host, e.g. https://hermes.example.com "
            "(optionally with a path prefix); quotes, angle brackets and whitespace are not allowed")
    return cleaned


def _validate_public_urls(raw: str) -> list[str]:
    """``HERMES_DASHBOARD_PUBLIC_URLS``: comma-separated public URLs, each held to exactly what the
    dashboard accepts for ``dashboard.public_urls`` (``prefix._normalise_public_url`` and
    ``origins.parse_public_origin``: an absolute http(s) URL with a host and a valid port, an
    optional path prefix)."""
    from hermes_cli.dashboard_auth.origins import parse_public_origin
    from hermes_cli.dashboard_auth.prefix import _normalise_public_url

    entries = [part.strip() for part in raw.split(",") if part.strip()]
    if not entries:
        raise ValueError(f"{PUBLIC_URLS} is set but contains no URLs")
    urls: list[str] = []
    for position, entry in enumerate(entries, 1):
        cleaned = _normalise_public_url(entry)
        parsed = urllib.parse.urlsplit(cleaned) if cleaned else None
        if (not cleaned or parse_public_origin(cleaned) is None or parsed is None
                or parsed.username is not None or parsed.query or parsed.fragment):
            raise ValueError(f"{PUBLIC_URLS}: entry {position} is not an absolute http(s) URL with a host "
                             "(scheme://host[:port][/prefix], no credentials, query or fragment)")
        if cleaned not in urls:
            urls.append(cleaned)
    return urls


def _validate_trusted_proxies(raw: str) -> list[str]:
    entries = [part.strip() for part in raw.split(",") if part.strip()]
    if not entries:
        raise ValueError(f"{TRUSTED_PROXIES} is set but contains no addresses")
    normalized: list[str] = []
    for position, entry in enumerate(entries, 1):
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if network.prefixlen == 0:
                    raise ValueError("unbounded")
                value = str(network)
            else:
                value = str(ipaddress.ip_address(entry))
        except ValueError:
            raise ValueError(
                f"{TRUSTED_PROXIES}: entry {position} is not an IP address or a bounded CIDR network "
                "('*', 0.0.0.0/0 and ::/0 are refused)") from None
        if value not in normalized:
            normalized.append(value)
    return normalized


def _validate_profiles_max(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError:
        raise ValueError(f"{PROFILES_MAX} must be a whole number (0 = unlimited), got a non-integer") from None
    if value < 0:
        raise ValueError(f"{PROFILES_MAX} must be 0 (unlimited) or a positive whole number")
    return value


def _validate_password_hash(raw: str) -> str:
    """Accept exactly the ``scrypt$n$r$p$<salt_b64>$<dk_b64>`` format the basic plugin verifies."""
    parts = raw.split("$")
    ok = len(parts) == 6 and parts[0] == "scrypt"
    if ok:
        try:
            n, r, p = (int(x, 10) for x in parts[1:4])
            salt = base64.b64decode(parts[4], validate=True)
            dk = base64.b64decode(parts[5], validate=True)
            ok = n > 1 and (n & (n - 1)) == 0 and r > 0 and p > 0 and len(salt) > 0 and len(dk) > 0
        except (ValueError, binascii.Error):
            ok = False
    if not ok:
        raise ValueError(
            f"{BASIC_PASSWORD_HASH} is not a scrypt hash in the basic auth plugin's format "
            "(scrypt$<n>$<r>$<p>$<salt_b64>$<dk_b64>); create one with "
            "python -c \"from plugins.dashboard_auth.basic import hash_password; print(hash_password('...'))\"")
    return raw


def _secret_bytes(raw: str) -> bytes:
    """The signing key the basic plugin derives from *raw* (base64, then hex, then the raw text)."""
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            decoded = decoder(raw)
            if len(decoded) >= 16:
                return decoded
        except (ValueError, TypeError):
            pass
    return raw.encode("utf-8")


def _validate_issuer(raw: str) -> str:
    parsed = urllib.parse.urlparse(raw)
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return raw.rstrip("/")
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return raw.rstrip("/")
    raise ValueError(f"{OIDC_ISSUER} must be an https:// URL (http is accepted only on localhost)")


def _validate_plain_token(name: str, raw: str) -> str:
    if _CONTROL_RE.search(raw) or any(ch.isspace() for ch in raw):
        raise ValueError(f"{name} must not contain whitespace or control characters")
    return raw


def _validate_git_ref(name: str, raw: str) -> str:
    """A full commit SHA (lower-cased) or a branch/tag name; anything else raises ValueError."""
    if _FULL_SHA_RE.fullmatch(raw):
        return raw.lower()
    if not _REF_RE.fullmatch(raw) or raw.endswith(".lock") or len(raw) > 200:
        raise ValueError(
            f"{name} must be a full 40-character commit SHA or a branch/tag name; the value is not a valid git ref")
    return raw


def _validate_messaging_gateway(raw: str) -> bool:
    """``HERMES_MESSAGING_GATEWAY``: on/off (also 1/0, true/false, yes/no), any casing."""
    lowered = raw.strip().lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ValueError(f"{MESSAGING_GATEWAY} must be on or off (also accepts 1/0, true/false, yes/no)")


def messaging_gateway_enabled(environ: Optional[Mapping[str, str]] = None) -> bool:
    """Whether this container's messaging gateway (and its per-profile gateways) may run at all.

    Read live by ``hermes_cli.container_boot`` at every boot and by ``hermes gateway start`` — this
    is a container-level switch, not persisted operator intent, so there is nothing to reload from
    disk. Degrades to enabled (the pre-existing behaviour) on a missing or unrecognized value: an
    invalid value already fails the container closed in ``018-env-config`` (:func:`parse_environment`
    raises), so a live read here should only ever see a validated value or nothing.
    """
    raw = _env(environ if environ is not None else os.environ, MESSAGING_GATEWAY)
    if not raw:
        return True
    return raw.strip().lower() not in _FALSY


def _parse_hermie(raw: str) -> tuple[str, Optional[str], bool]:
    """``HERMIE_PLUGIN`` → ``(mode, ref, required)``: unset → baked; true → baked (required);
    false → off; anything else → that git ref, fetched at start."""
    if not raw:
        return "baked", None, False
    if raw.lower() in _TRUTHY:
        return "baked", None, True
    if raw.lower() in _FALSY:
        return "off", None, False
    if _FULL_SHA_RE.fullmatch(raw):
        return "ref", raw.lower(), True
    if not _REF_RE.fullmatch(raw) or raw.endswith(".lock") or len(raw) > 200:
        raise ValueError(
            f"{HERMIE_PLUGIN} must be true, false, a full 40-character commit SHA, or a branch/tag name; "
            "the value is not a valid git ref")
    return "ref", raw, True


def parse_environment(environ: Mapping[str, str]) -> Plan:
    """Validate every supported variable and return the plan. Collects ALL problems and raises one
    :class:`EnvConfigError` so an operator fixes the manifest in one pass. Values never appear in
    the messages."""
    plan = Plan()
    problems: list[str] = []

    def check(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except ValueError as exc:
            problems.append(str(exc))
            return None

    # -- dashboard.public_url
    raw = _env(environ, PUBLIC_URL)
    if raw:
        value = check(lambda: _validate_public_url(raw))
        if value is not None:
            plan.assignments.append(("dashboard.public_url", value, PUBLIC_URL))

    # -- dashboard.public_urls (several origins; the primary stays dashboard.public_url)
    raw = _env(environ, PUBLIC_URLS)
    if raw:
        value = check(lambda: _validate_public_urls(raw))
        if value is not None:
            plan.assignments.append(("dashboard.public_urls", value, PUBLIC_URLS))

    # -- dashboard.write_origin_check (auto | on | off). on/off are written as YAML booleans: an
    # unquoted `on` would read back as a boolean anyway and the next start would rewrite it.
    raw = _env(environ, WRITE_ORIGIN_CHECK)
    if raw:
        mode = {"auto": "auto", "on": True, "off": False}.get(raw.lower())
        if mode is None:
            problems.append(f"{WRITE_ORIGIN_CHECK} must be auto, on or off")
        else:
            plan.assignments.append(("dashboard.write_origin_check", mode, WRITE_ORIGIN_CHECK))

    # -- dashboard.trusted_proxies
    raw = _env(environ, TRUSTED_PROXIES)
    if raw:
        value = check(lambda: _validate_trusted_proxies(raw))
        if value is not None:
            plan.assignments.append(("dashboard.trusted_proxies", value, TRUSTED_PROXIES))

    # -- dashboard.mcp.enabled (true | false), written as a YAML boolean
    raw = _env(environ, MCP_ENABLED)
    if raw:
        if raw.lower() in _TRUTHY:
            plan.assignments.append(("dashboard.mcp.enabled", True, MCP_ENABLED))
        elif raw.lower() in _FALSY:
            plan.assignments.append(("dashboard.mcp.enabled", False, MCP_ENABLED))
        else:
            problems.append(f"{MCP_ENABLED} must be true or false")

    # -- profiles.max
    raw = _env(environ, PROFILES_MAX)
    if raw:
        value = check(lambda: _validate_profiles_max(raw))
        if value is not None:
            plan.assignments.append(("profiles.max", value, PROFILES_MAX))

    # -- basic auth
    username = _env(environ, BASIC_USERNAME)
    password = _env(environ, BASIC_PASSWORD)
    password_hash = _env(environ, BASIC_PASSWORD_HASH)
    if username:
        if check(lambda: _validate_plain_token(BASIC_USERNAME, username)) is not None:
            plan.assignments.append(("dashboard.basic_auth.username", username, BASIC_USERNAME))
    if password_hash:
        if check(lambda: _validate_password_hash(password_hash)) is not None:
            # The hash wins over a plaintext password when both are set.
            plan.assignments.append(("dashboard.basic_auth.password_hash", password_hash, BASIC_PASSWORD_HASH))
        if password:
            plan.notes.append(f"{BASIC_PASSWORD_HASH} and {BASIC_PASSWORD} are both set; the hash wins")
    elif password:
        plan.basic_password = password
    plan.basic_auth_from_env = bool(username or password or password_hash)
    basic_secret = _env(environ, BASIC_SECRET)
    if basic_secret:
        plan.basic_secret_from_env = True
        if len(_secret_bytes(basic_secret)) < 16:
            problems.append(f"{BASIC_SECRET} is too short: it must carry at least 16 bytes "
                            "(e.g. the output of `openssl rand -base64 32`)")

    # -- self-hosted OIDC: issuer + client_id travel together; the secret is optional (a public
    # PKCE client) but never alone.
    issuer = _env(environ, OIDC_ISSUER)
    client_id = _env(environ, OIDC_CLIENT_ID)
    client_secret = _env(environ, OIDC_CLIENT_SECRET)
    scopes = _env(environ, OIDC_SCOPES)
    if issuer or client_id or client_secret or scopes:
        missing = [n for n, v in ((OIDC_ISSUER, issuer), (OIDC_CLIENT_ID, client_id)) if not v]
        if missing:
            present = [n for n, v in ((OIDC_ISSUER, issuer), (OIDC_CLIENT_ID, client_id),
                                      (OIDC_CLIENT_SECRET, client_secret), (OIDC_SCOPES, scopes)) if v]
            problems.append(
                f"incomplete self-hosted OIDC configuration: {', '.join(present)} set but "
                f"{' and '.join(missing)} missing (issuer and client id are required together; "
                "the client secret is optional)")
        else:
            plan.oidc_from_env = True
            if check(lambda: _validate_issuer(issuer)) is not None:
                plan.assignments.append(("dashboard.oauth.self_hosted.issuer", issuer.rstrip("/"), OIDC_ISSUER))
            if check(lambda: _validate_plain_token(OIDC_CLIENT_ID, client_id)) is not None:
                plan.assignments.append(("dashboard.oauth.self_hosted.client_id", client_id, OIDC_CLIENT_ID))
            if scopes:
                words = scopes.split()
                if "openid" not in words:
                    problems.append(f"{OIDC_SCOPES} must include 'openid'")
                else:
                    plan.assignments.append(("dashboard.oauth.self_hosted.scopes", " ".join(words), OIDC_SCOPES))
            if client_secret and _CONTROL_RE.search(client_secret):
                problems.append(f"{OIDC_CLIENT_SECRET} must not contain control characters")

    # -- dashboard bind (consumed by the s6 dashboard service, validated here so a typo fails early)
    host = _env(environ, DASHBOARD_HOST)
    if host:
        check(lambda: _validate_plain_token(DASHBOARD_HOST, host))
    port = _env(environ, DASHBOARD_PORT)
    if port:
        try:
            port_ok = 1 <= int(port, 10) <= 65535
        except ValueError:
            port_ok = False
        if not port_ok:
            problems.append(f"{DASHBOARD_PORT} must be a port number between 1 and 65535")

    # -- Hermie plugin
    raw = _env(environ, HERMIE_PLUGIN)
    parsed = check(lambda: _parse_hermie(raw))
    if parsed is not None:
        plan.hermie_mode, plan.hermie_ref, plan.hermie_required = parsed

    # -- HERM-131: the messaging-gateway kill switch. Not a config.yaml key (see MESSAGING_GATEWAY);
    # validated here so a bad value fails the container closed at start, same as every other variable.
    raw = _env(environ, MESSAGING_GATEWAY)
    if raw:
        value = check(lambda: _validate_messaging_gateway(raw))
        if value is not None:
            plan.messaging_gateway_enabled = value
            if not value:
                plan.notes.append(
                    f"{MESSAGING_GATEWAY}=off: the messaging gateway and cron scheduler will not "
                    "start in this container (the dashboard is unaffected)")

    if problems:
        raise EnvConfigError("\n".join(f"  - {p}" for p in problems))
    return plan


# ---------------------------------------------------------------------------------------------
# config.yaml
# ---------------------------------------------------------------------------------------------


def _set_path(cfg: dict, dotted: str, value: Any) -> bool:
    """Set ``cfg[a][b][c] = value`` creating (or replacing non-dict) parents. True when changed."""
    parts = dotted.split(".")
    node = cfg
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    leaf = parts[-1]
    current = node.get(leaf, _MISSING)
    if current is not _MISSING and current == value and isinstance(current, bool) is isinstance(value, bool):
        return False
    node[leaf] = value
    return True


def _get_path(cfg: dict, dotted: str, default: Any = None) -> Any:
    node: Any = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _pop_path(cfg: dict, dotted: str) -> bool:
    parts = dotted.split(".")
    parent = _get_path(cfg, ".".join(parts[:-1])) if len(parts) > 1 else cfg
    if isinstance(parent, dict) and parts[-1] in parent:
        del parent[parts[-1]]
        return True
    return False


_MISSING = object()


def _undisable(cfg: dict, keys: tuple[str, ...]) -> bool:
    plugins_cfg = cfg.get("plugins")
    disabled = plugins_cfg.get("disabled") if isinstance(plugins_cfg, dict) else None
    if not isinstance(disabled, list) or not set(disabled) & set(keys):
        return False
    plugins_cfg["disabled"] = [name for name in disabled if name not in keys]
    return True


def _enable_plugin(cfg: dict, name: str, *, reassert: bool) -> bool:
    """Add *name* to ``plugins.enabled``. ``reassert`` also takes it out of ``plugins.disabled``;
    without it an explicit ``plugins.disabled`` entry wins and nothing changes."""
    plugins_cfg = cfg.get("plugins")
    disabled = plugins_cfg.get("disabled") if isinstance(plugins_cfg, dict) else None
    if not reassert and isinstance(disabled, list) and name in disabled:
        return False
    if not isinstance(plugins_cfg, dict):
        plugins_cfg = {}
        cfg["plugins"] = plugins_cfg
    changed = _undisable(cfg, (name,))
    enabled = plugins_cfg.get("enabled")
    if not isinstance(enabled, list):
        enabled = []
    if name not in enabled:
        plugins_cfg["enabled"] = [*enabled, name]
        changed = True
    return changed


def _new_secret() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def apply_to_config(cfg: dict, plan: Plan, *, enable_plugins: tuple[tuple[str, bool], ...] = ()) -> list[str]:
    """Apply *plan* to the raw config dict in place. *enable_plugins* holds ``(name, reassert)``
    pairs. Returns the human-readable list of changed keys (names only, never values)."""
    from plugins.dashboard_auth.basic import _verify_password, hash_password

    before_hash = _get_path(cfg, "dashboard.basic_auth.password_hash")
    before_user = _get_path(cfg, "dashboard.basic_auth.username")
    changed: list[str] = []

    if plan.basic_auth_from_env:
        # A plaintext password already in config.yaml becomes a hash before it is removed below, so
        # an env username paired with it keeps working instead of failing the start.
        plaintext = _get_path(cfg, "dashboard.basic_auth.password")
        if plaintext and not before_hash and not plan.basic_password and not any(
                dotted == "dashboard.basic_auth.password_hash" for dotted, _v, _e in plan.assignments):
            _set_path(cfg, "dashboard.basic_auth.password_hash", hash_password(str(plaintext)))
            changed.append("dashboard.basic_auth.password_hash (hashed from the plaintext in config.yaml)")

    for dotted, value, env_name in plan.assignments:
        if _set_path(cfg, dotted, value):
            changed.append(f"{dotted} (from {env_name})")

    if plan.basic_password:
        # Keep the stored hash when it already verifies the password: a fresh salt on every start
        # would rewrite config.yaml each boot (and it would no longer be byte-identical).
        current = _get_path(cfg, "dashboard.basic_auth.password_hash")
        if not (isinstance(current, str) and current and _verify_password(plan.basic_password, current)):
            _set_path(cfg, "dashboard.basic_auth.password_hash", hash_password(plan.basic_password))
            changed.append(f"dashboard.basic_auth.password_hash (hashed from {BASIC_PASSWORD})")

    if plan.basic_auth_from_env:
        # The environment owns the credential now: never leave a plaintext password at rest.
        if _get_path(cfg, "dashboard.basic_auth.password"):
            _pop_path(cfg, "dashboard.basic_auth.password")
            changed.append("dashboard.basic_auth.password (plaintext removed; the hash is kept)")
        if _undisable(cfg, _BASIC_PLUGIN_KEYS):
            changed.append("plugins.disabled (basic dashboard-auth plugin re-enabled)")
        if not plan.basic_secret_from_env:
            credential_changed = before_hash and (
                _get_path(cfg, "dashboard.basic_auth.password_hash") != before_hash
                or _get_path(cfg, "dashboard.basic_auth.username") != before_user)
            if not _get_path(cfg, "dashboard.basic_auth.secret"):
                # Sessions must survive restarts: persist one generated signing secret, once.
                _set_path(cfg, "dashboard.basic_auth.secret", _new_secret())
                changed.append("dashboard.basic_auth.secret (generated once; set "
                               f"{BASIC_SECRET} to manage it yourself)")
            elif credential_changed:
                # Sessions are stateless tokens signed with this secret and refreshed for 30 days: a
                # new password must also invalidate every session minted under the old one.
                _set_path(cfg, "dashboard.basic_auth.secret", _new_secret())
                changed.append("dashboard.basic_auth.secret (rotated with the credential; existing sessions end)")

    if plan.oidc_from_env and _undisable(cfg, _OIDC_PLUGIN_KEYS):
        changed.append("plugins.disabled (self-hosted OIDC dashboard-auth plugin re-enabled)")

    for name, reassert in enable_plugins:
        if _enable_plugin(cfg, name, reassert=reassert):
            changed.append(f"plugins.enabled (+{name}, the Hermie plugin)")
    return changed


def validate_effective_basic_auth(cfg: dict, plan: Plan) -> None:
    """After the plan is applied: basic auth configured by the environment must be complete."""
    if not plan.basic_auth_from_env:
        return
    username = _get_path(cfg, "dashboard.basic_auth.username")
    credential = _get_path(cfg, "dashboard.basic_auth.password_hash") or plan.basic_password
    missing = []
    if not username:
        missing.append(f"a username ({BASIC_USERNAME})")
    if not credential:
        missing.append(f"a password ({BASIC_PASSWORD} or {BASIC_PASSWORD_HASH})")
    if missing:
        raise EnvConfigError(
            "  - incomplete basic auth configuration: missing " + " and ".join(missing))


def preflight_config(config_path: Path, plan: Plan) -> None:
    """Everything that can fail about config.yaml, checked before the plugin step touches the volume:
    the file must be readable and parse, and the effective basic auth must be complete."""
    from hermes_cli.config import require_readable_config_before_write

    cfg = copy.deepcopy(require_readable_config_before_write(config_path))
    apply_to_config(cfg, plan)
    validate_effective_basic_auth(cfg, plan)


def write_config(config_path: Path, plan: Plan, *,
                 enable_plugins: tuple[tuple[str, bool], ...] = ()) -> list[str]:
    """Load, apply, validate and (only when something changed) atomically write ``config.yaml``."""
    from hermes_cli.config import atomic_config_write, require_readable_config_before_write

    # The raw mapping as written; raises on an unreadable or malformed file rather than letting a
    # write replace it with only our keys.
    original = require_readable_config_before_write(config_path)
    cfg = copy.deepcopy(original)
    changed = apply_to_config(cfg, plan, enable_plugins=enable_plugins)
    validate_effective_basic_auth(cfg, plan)
    if cfg != original:
        atomic_config_write(config_path, cfg)
    return changed


# ---------------------------------------------------------------------------------------------
# Hermie plugin
# ---------------------------------------------------------------------------------------------


class PluginInstallError(Exception):
    """The Hermie plugin could not be installed (and no usable copy is present)."""


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or "/opt/data")


def _existing_install(source: str) -> Optional[tuple[str, dict]]:
    """``(name, record)`` of an installed plugin whose recorded source is *source*, if its tree exists."""
    from hermes_cli import plugins_cmd

    try:
        metadata = plugins_cmd._read_install_metadata()
    except plugins_cmd.PluginOperationError:
        return None
    for name, record in sorted(metadata.items()):
        if isinstance(record, dict) and record.get("source") == source:
            if (plugins_cmd._plugins_dir() / name).is_dir():
                return name, record
    return None


def resolve_remote_ref(git_url: str, ref: str) -> str:
    """The commit SHA *ref* names on *git_url* (``HEAD`` = default branch; annotated tags peeled)."""
    from hermes_cli import plugins_cmd

    if _FULL_SHA_RE.fullmatch(ref):
        return ref.lower()
    git_exe = plugins_cmd._resolve_git_executable()
    if not git_exe:
        raise PluginInstallError("git is not installed or not on PATH")
    result = plugins_cmd._run_plugin_git(
        git_exe, plugins_cmd._plugins_dir(), "ls-remote", git_url,
        timeout=plugins_cmd._clone_timeout_seconds(), auth_url=git_url)
    if result.returncode != 0:
        raise PluginInstallError(f"could not list refs of {plugins_cmd._scrub_git_url(git_url)}: "
                                 f"{plugins_cmd._safe_git_error(result, git_url)}")
    refs: dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        sha, _, name = line.partition("\t")
        if _FULL_SHA_RE.fullmatch(sha.strip()) and name.strip():
            refs[name.strip()] = sha.strip().lower()
    if ref == "HEAD" or ref.startswith("refs/"):
        candidates = [f"{ref}^{{}}", ref]
    else:
        # Git's own lookup order: a tag shadows a branch of the same name.
        candidates = [f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"]
    for candidate in candidates:
        if candidate in refs:
            return refs[candidate]
    raise PluginInstallError(
        f"{HERMIE_PLUGIN}={ref!r} does not name a branch or tag of {plugins_cmd._scrub_git_url(git_url)} "
        "(abbreviated SHAs are not supported; use the full 40-character SHA)")


def _print_scan_report(tree: Path, identifier: str) -> None:
    from hermes_cli import plugins_cmd

    if not plugins_cmd._scan_on_install_enabled():
        _log("plugin security scan is disabled (plugins.scan_on_install: false)")
        return
    from tools.plugin_guard import format_scan_report, scan_plugin

    _log("plugin security scan report:")
    for line in format_scan_report(scan_plugin(tree, source=identifier)).splitlines():
        _log(f"  {line}")


def ensure_hermie_plugin(ref: str, *, git_url: str = HERMIE_PLUGIN_REPO) -> str:
    """Install the Hermie plugin at *ref* unless that exact commit is already installed. Returns the
    installed plugin name. A caution scan verdict is accepted (the operator opted in by setting the
    variable, the same as ``hermes plugins install --force``) and the report is printed; a dangerous
    verdict still blocks."""
    from hermes_cli import plugins_cmd
    from hermes_cli.plugins_cmd_catalog import raise_if_removed

    source = plugins_cmd._canonical_source(git_url, None)
    existing = _existing_install(source)
    wanted = "the default branch" if ref == "HEAD" else ref
    try:
        sha = resolve_remote_ref(git_url, ref)
    except PluginInstallError as exc:
        if existing is None:
            raise
        _log(f"WARNING: {exc}; keeping the installed {existing[0]} "
             f"({str(existing[1].get('revision', ''))[:12] or 'unknown revision'})")
        return existing[0]

    if existing is not None and str(existing[1].get("revision", "")).lower() == sha:
        _log(f"{HERMIE_PLUGIN}: {existing[0]} already at {sha[:12]} ({wanted}); nothing to install")
        return existing[0]

    _log(f"{HERMIE_PLUGIN}: installing {plugins_cmd._scrub_git_url(git_url)} at {sha[:12]} ({wanted})")
    try:
        raise_if_removed(git_url)
        target, _manifest, name = plugins_cmd._install_plugin_core(
            git_url, force=True, ref=sha, before_swap=lambda _m, tree: _print_scan_report(tree, git_url))
    except plugins_cmd.PluginOperationError as exc:
        # PluginScanBlocked carries the full scan report in its message.
        raise PluginInstallError(str(exc)) from exc
    warnings: list[str] = []
    plugins_cmd._install_python_dependencies_quietly(target, warnings)
    for warning in warnings:
        _log(f"WARNING: {warning}")
    _log(f"{HERMIE_PLUGIN}: installed {name} at {sha[:12]}")
    return name


def tree_digest(root: Path) -> str:
    """Content digest of a plugin tree: every relative path, file bytes, the executable bit and
    symlink targets. Two trees with the same digest are what ``rsync --delete`` would leave equal.
    Anything that is not a regular file, a directory or a symlink (a FIFO, a socket, a device) is
    recorded by name only — never opened, so it cannot hang the start — and so still makes the
    digest differ from a clean tree."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        digest.update(f"d\0{rel_dir}\0".encode())
        for name in sorted(filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]):
            path = Path(dirpath) / name
            rel = f"{rel_dir}/{name}"
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                digest.update(f"l\0{rel}\0{os.readlink(path)}\0".encode())
                continue
            if not stat.S_ISREG(st.st_mode):
                digest.update(f"o\0{rel}\0".encode())
                continue
            executable = "x" if st.st_mode & 0o111 else "-"
            digest.update(f"f\0{rel}\0{executable}\0".encode())
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    return digest.hexdigest()


def read_baked_plugin(meta_path: Optional[Path] = None, tree: Optional[Path] = None) -> Optional[dict]:
    """The build-time record of the plugin baked into this image, or ``None`` when there is none."""
    meta_path = meta_path or BAKED_PLUGIN_META
    tree = tree or BAKED_PLUGIN_DIR
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise PluginInstallError(f"the baked plugin record {meta_path} is unreadable ({type(exc).__name__})") from exc
    required = ("name", "source", "ref", "commit", "digest")
    if not isinstance(meta, dict) or not all(isinstance(meta.get(k), str) and meta[k] for k in required):
        raise PluginInstallError(f"the baked plugin record {meta_path} is incomplete")
    if not tree.is_dir():
        raise PluginInstallError(f"the baked plugin tree {tree} is missing")
    return meta


@dataclass(frozen=True)
class PluginCopy:
    """A plugin tree to replicate into a Hermes home, with the install record it gets there."""

    name: str
    tree: Path
    record: dict
    digest: str
    label: str  # for the log, e.g. "the image (v0.9.0, f29b4532a6c3)"


def baked_copy(*, required: bool, meta_path: Optional[Path] = None,
               tree: Optional[Path] = None) -> Optional[PluginCopy]:
    """The plugin baked into this image, or ``None`` (an image built without one)."""
    tree = tree or BAKED_PLUGIN_DIR
    meta = read_baked_plugin(meta_path, tree)
    if meta is None:
        if required:
            raise PluginInstallError(f"{HERMIE_PLUGIN}=true but this image has no baked Hermie plugin "
                                     "(it was built with an empty HERMIE_PLUGIN_REF)")
        return None
    record = {"pinned": True, "revision": meta["commit"], "source": meta["source"], "image_ref": meta["ref"]}
    return PluginCopy(meta["name"], tree, record, meta["digest"],
                      f"the image ({meta['ref']}, {meta['commit'][:12]})")


def installed_copy(name: str) -> PluginCopy:
    """The copy of *name* installed in the current ``get_hermes_home()`` (after a ref install)."""
    from hermes_cli import plugins_cmd

    record = plugins_cmd._read_install_metadata().get(name)
    tree = plugins_cmd._plugins_dir() / name
    if not isinstance(record, dict) or not tree.is_dir():
        raise PluginInstallError(f"{name} is not installed in the default profile")
    revision = str(record.get("revision", ""))
    return PluginCopy(name, tree, dict(record), tree_digest(tree), f"the default profile ({revision[:12]})")


def sync_plugin_copy(src: PluginCopy) -> bool:
    """Make ``<get_hermes_home()>/plugins/<name>`` an exact copy of *src* (``rsync --delete``
    semantics) with *src*'s install record. Leaves a matching copy alone. The security scan does not
    run here (the baked tree was scanned at build time, a ref install when it was fetched). Returns
    True when the home had no install record for the plugin before (a first install)."""
    from hermes_cli import plugins_cmd
    from utils import rmtree_readonly

    plugins_dir = plugins_cmd._plugins_dir()
    unresolved = plugins_dir / src.name
    if unresolved.is_symlink():
        raise PluginInstallError(f"{unresolved} is a symlink; refusing to replace what it points at")
    try:
        target = plugins_cmd._sanitize_plugin_name(src.name, plugins_dir)
    except ValueError as exc:
        raise PluginInstallError(str(exc)) from exc
    try:
        current = plugins_cmd._read_install_metadata().get(src.name)
    except plugins_cmd.PluginOperationError:
        current = None
    first_install = current is None
    if current == src.record and target.is_dir() and tree_digest(target) == src.digest:
        _log(f"{HERMIE_PLUGIN}: {src.name} in {plugins_dir.parent} already matches {src.label}")
        return first_install

    staging = Path(tempfile.mkdtemp(prefix=".hermie-sync-", dir=plugins_dir))
    try:
        staged = staging / "plugin"
        shutil.copytree(src.tree, staged, symlinks=True)
        if tree_digest(staged) != src.digest:
            raise PluginInstallError(f"the plugin tree {src.tree} does not match its recorded digest")
        try:
            plugins_cmd._swap_in_plugin(staged, target, staging / "previous", src.name, dict(src.record))
        except plugins_cmd.PluginOperationError as exc:
            raise PluginInstallError(str(exc)) from exc
    finally:
        rmtree_readonly(staging, ignore_errors=True)
    _log(f"{HERMIE_PLUGIN}: synced {src.name} into {plugins_dir.parent} from {src.label}")
    return first_install


def sync_baked_plugin(*, required: bool, meta_path: Optional[Path] = None,
                      tree: Optional[Path] = None) -> Optional[str]:
    """Sync the baked plugin into the current home; returns its name, or ``None`` without one."""
    src = baked_copy(required=required, meta_path=meta_path, tree=tree)
    if src is None:
        _log(f"{HERMIE_PLUGIN}: this image has no baked Hermie plugin; nothing to install")
        return None
    sync_plugin_copy(src)
    return src.name


@contextlib.contextmanager
def _in_home(home: Path):
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    token = set_hermes_home_override(home)
    try:
        yield
    finally:
        reset_hermes_home_override(token)


def _named_profile_homes() -> list[Path]:
    """Live named profiles under the default home (the multiplexed gateway serves each of them, and
    every one has its own ``plugins/`` directory and ``plugins.enabled`` list)."""
    from hermes_cli.profiles import _iter_named_profile_dirs

    return _iter_named_profile_dirs(live_only=True)


# How a home's config.yaml treats the plugin: "reassert" (enable, and undo plugins.disabled), "first"
# (enable once, on the first install, unless plugins.disabled names it), or "none".
_Enable = tuple[Path, str, str]  # (home, plugin name, mode)


def _enable_mode(plan: Plan, first_install: bool) -> str:
    if plan.hermie_mode == "ref" or plan.hermie_required:
        return "reassert"
    return "first" if first_install else "none"


def apply_hermie_plugin(plan: Plan, default_home: Path, profile_homes: list[Path]) -> list[_Enable]:
    """Carry out ``plan.hermie_mode`` in the default home and in every named profile. Returns what
    to enable where. A failure in the default home raises; one in a named profile is logged and
    that profile is skipped, so one broken bot cannot keep the gateway down."""
    if plan.hermie_mode == "off":
        _log(f"{HERMIE_PLUGIN}=false: leaving plugins as they are (nothing installed or enabled)")
        return []
    with _in_home(default_home):
        if plan.hermie_mode == "ref":
            name = ensure_hermie_plugin(str(plan.hermie_ref))
            src: Optional[PluginCopy] = installed_copy(name)
            first = False
        else:
            src = baked_copy(required=plan.hermie_required)
            if src is None:
                _log(f"{HERMIE_PLUGIN}: this image has no baked Hermie plugin; nothing to install")
                return []
            first = sync_plugin_copy(src)
    assert src is not None
    result: list[_Enable] = [(default_home, src.name, _enable_mode(plan, first))]
    for home in profile_homes:
        try:
            with _in_home(home):
                first = sync_plugin_copy(src)
        except Exception as exc:  # noqa: BLE001 — e.g. a corrupt install record; one bot must not stop the start
            _log(f"WARNING: {HERMIE_PLUGIN}: could not sync {src.name} into profile {home.name}: "
                 f"{type(exc).__name__}; that profile keeps what it had")
            continue
        result.append((home, src.name, _enable_mode(plan, first)))
    return result


def seed_new_profile(profile_home: Path) -> None:
    """Give a profile that is being created (``hermes_cli.profiles.create_profile``, on the staging
    tree before it is published) the same Hermie plugin every existing profile got at start. Only
    inside the image (a baked plugin record exists) and unless ``HERMIE_PLUGIN=false``; copies what
    the default profile has installed (the baked tree, or a ref override) and enables it with the
    start-time policy. Best-effort: never fails the profile creation."""
    try:
        if read_baked_plugin() is None:
            return
        plan = Plan()
        plan.hermie_mode, plan.hermie_ref, plan.hermie_required = _parse_hermie(_env(os.environ, HERMIE_PLUGIN))
        if plan.hermie_mode == "off":
            return
        from hermes_constants import get_default_hermes_root

        default_home = get_default_hermes_root()
        with _in_home(default_home):
            try:
                src: Optional[PluginCopy] = installed_copy("hermie")
            except (PluginInstallError, Exception):  # noqa: BLE001 — fall back to the baked tree
                src = baked_copy(required=False)
        if src is None:
            return
        with _in_home(profile_home):
            first = sync_plugin_copy(src)
        mode = _enable_mode(plan, first)
        if mode != "none":
            write_config(profile_home / "config.yaml", Plan(), enable_plugins=((src.name, mode == "reassert"),))
    except Exception as exc:  # noqa: BLE001 — a plugin seed must never block creating a profile
        _log(f"WARNING: could not give the new profile the Hermie plugin: {type(exc).__name__}")


def remove_shadowing_env_lines(environ: Mapping[str, str], hermes_home: Path) -> list[str]:
    """Drop every managed variable that is set in the container environment from
    ``$HERMES_HOME/.env``. Returns the removed key names."""
    from hermes_cli.config import remove_env_value

    removed: list[str] = []
    if not (hermes_home / ".env").is_file():
        return removed
    with _in_home(hermes_home):
        for name in MANAGED_ENV_NAMES:
            if not _env(environ, name):
                continue
            saved = os.environ.get(name)
            try:
                if remove_env_value(name):
                    removed.append(name)
            finally:
                # remove_env_value also drops the name from this process's environment.
                if saved is not None:
                    os.environ[name] = saved
    return removed


# ---------------------------------------------------------------------------------------------
# Build time: bake the plugin into the image
# ---------------------------------------------------------------------------------------------


def _git(*args: str, cwd: Optional[Path] = None) -> str:
    result = subprocess.run(["git", "-c", "advice.detachedHead=false", *args], cwd=cwd,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if result.returncode != 0:
        raise PluginInstallError(f"git {args[0]} failed: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()


def _validate_repo_url(repo: str) -> None:
    """The plugin repository URL goes into the image's build history: refuse embedded credentials,
    and anything git could read as an option."""
    if not repo or repo.startswith("-") or _CONTROL_RE.search(repo) or any(ch.isspace() for ch in repo):
        raise ValueError("HERMIE_PLUGIN_REPO is not a usable git URL")
    parsed = urllib.parse.urlsplit(repo)
    if parsed.scheme in ("http", "https", "ssh", "git") and (parsed.username or parsed.password):
        raise ValueError("HERMIE_PLUGIN_REPO must not carry credentials (they would stay in the image history)")
    if parsed.scheme in ("http", "https") and (parsed.query or parsed.fragment):
        raise ValueError("HERMIE_PLUGIN_REPO must not carry a query or fragment")


def bake_plugin(repo: str, ref: str, dest: Path, meta_path: Path, *, expect_commit: str = "") -> int:
    """Fetch *repo* at *ref* into *dest* (with its ``.git``, so the plugin can read its own build),
    run the plugin security scanner once and print its report, and record what was baked in
    *meta_path*. A dangerous verdict fails the build; a caution verdict is accepted, the same as
    ``hermes plugins install --force``."""
    ref = ref.strip()
    if not ref:
        print(f"{TAG} HERMIE_PLUGIN_REF is empty: this image ships without the Hermie plugin", flush=True)
        return 0
    try:
        ref = _validate_git_ref("HERMIE_PLUGIN_REF", ref)
        expect_commit = expect_commit.strip().lower()
        if expect_commit and not _FULL_SHA_RE.fullmatch(expect_commit):
            raise ValueError("HERMIE_PLUGIN_COMMIT must be a full 40-character commit SHA")
        _validate_repo_url(repo)
    except ValueError as exc:
        print(f"{TAG} ERROR: {exc}", file=sys.stderr, flush=True)
        return 1
    from hermes_cli.plugins_cmd import _canonical_source, _scrub_git_url
    from tools.plugin_guard import format_scan_report, scan_plugin, should_allow_plugin_install
    from utils import fast_safe_load

    try:
        if _FULL_SHA_RE.fullmatch(ref):
            dest.mkdir(parents=True)
            _git("init", "--quiet", cwd=dest)
            _git("remote", "add", "--", "origin", repo, cwd=dest)
            _git("fetch", "--quiet", "--depth", "1", "origin", ref, cwd=dest)
            _git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=dest)
        else:
            _git("clone", "--quiet", "--depth", "1", "--single-branch", "--branch", ref, "--", repo, str(dest))
        _git("remote", "set-url", "origin", _scrub_git_url(repo), cwd=dest)
        commit = _git("rev-parse", "HEAD", cwd=dest).lower()
        if expect_commit and commit != expect_commit:
            raise PluginInstallError(f"{ref} resolved to {commit[:12]}, not the expected {expect_commit[:12]} "
                                     "(the ref moved between planning and building)")
    except PluginInstallError as exc:
        print(f"{TAG} ERROR: could not fetch {_scrub_git_url(repo)} at {ref}: {exc}", file=sys.stderr, flush=True)
        return 1
    manifest = fast_safe_load((dest / "plugin.yaml").read_text(encoding="utf-8")) if (dest / "plugin.yaml").is_file() else {}
    name = str((manifest or {}).get("name") or "").strip()
    if not name or "/" in name or name in {".", ".."}:
        print(f"{TAG} ERROR: {_scrub_git_url(repo)} at {ref} has no usable plugin.yaml name", file=sys.stderr, flush=True)
        return 1

    result = scan_plugin(dest, source=_scrub_git_url(repo))
    print(f"{TAG} Hermie plugin {ref} ({commit[:12]}) security scan report:", flush=True)
    print(format_scan_report(result), flush=True)
    allowed, reason = should_allow_plugin_install(result, force=True)
    if allowed is not True:
        print(f"{TAG} ERROR: the plugin security scan blocked the Hermie plugin: {reason}", file=sys.stderr, flush=True)
        return 1
    print(f"{TAG} scan decision: {reason}", flush=True)

    meta = {"schema": 1, "name": name, "source": _canonical_source(repo, None), "ref": ref,
            "commit": commit, "digest": tree_digest(dest)}
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    meta_path.chmod(0o444)
    print(f"{TAG} baked {name} {ref} ({commit[:12]}) into {dest}", flush=True)
    return 0


# ---------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------


def _warn_if_dashboard_ungated(environ: Mapping[str, str], cfg: dict) -> None:
    """The dashboard refuses to start on a non-loopback bind with no auth provider. Say so here,
    at the top of the log, instead of leaving it to a restart loop further down."""
    if _env(environ, "HERMES_DASHBOARD").lower() not in _TRUTHY:
        return
    host = _env(environ, DASHBOARD_HOST) or "0.0.0.0"
    if host in _LOOPBACK_HOSTS:
        return
    basic = _env(environ, BASIC_USERNAME) or _get_path(cfg, "dashboard.basic_auth.username")
    oidc = (_env(environ, OIDC_ISSUER) or _get_path(cfg, "dashboard.oauth.self_hosted.issuer")) and (
        _env(environ, OIDC_CLIENT_ID) or _get_path(cfg, "dashboard.oauth.self_hosted.client_id"))
    nous = _env(environ, "HERMES_DASHBOARD_OAUTH_CLIENT_ID") or _get_path(cfg, "dashboard.oauth.client_id")
    if not (basic or oidc or nous):
        _log(f"WARNING: the dashboard binds {host} but no auth provider is configured; it will refuse "
             f"to start. Set {BASIC_USERNAME} + {BASIC_PASSWORD}, or {OIDC_ISSUER} + {OIDC_CLIENT_ID}, "
             f"or bind {DASHBOARD_HOST}=127.0.0.1.")


def run(environ: Mapping[str, str], hermes_home: Path, *,
        hermie: Optional[Callable[[Plan, Path, list[Path]], list[_Enable]]] = None,
        profile_homes: Optional[list[Path]] = None) -> list[str]:
    """Validate, check config.yaml, install the plugin, then write config.yaml. Raises on any failure
    before the default profile's config.yaml is touched."""
    plan = parse_environment(environ)
    for note in plan.notes:
        _log(note)
    config_path = hermes_home / "config.yaml"
    # Fail on a broken config.yaml or incomplete basic auth BEFORE the plugin step touches the volume.
    preflight_config(config_path, plan)
    if profile_homes is None:
        profile_homes = _named_profile_homes() if plan.hermie_mode != "off" else []
    try:
        enables = (hermie or apply_hermie_plugin)(plan, hermes_home, profile_homes)
    except PluginInstallError as exc:
        raise EnvConfigError(f"  - {HERMIE_PLUGIN}: the Hermie plugin could not be installed: {exc}") from exc

    default_enable = tuple((name, mode == "reassert") for home, name, mode in enables
                           if home == hermes_home and mode != "none")
    changed = write_config(config_path, plan, enable_plugins=default_enable)
    # Only once the start has succeeded: a failed start leaves .env exactly as it was.
    for name in remove_shadowing_env_lines(environ, hermes_home):
        _log(f"removed {name} from {hermes_home / '.env'} (the container environment owns it)")
    for home, name, mode in enables:
        if home == hermes_home or mode == "none":
            continue
        try:
            for key in write_config(home / "config.yaml", Plan(), enable_plugins=((name, mode == "reassert"),)):
                changed.append(f"{key} in profile {home.name}")
        except Exception as exc:  # noqa: BLE001 — one broken profile config must not stop the gateway
            _log(f"WARNING: could not enable {name} in profile {home.name}: {_describe_error(exc)}")
    from hermes_cli.config import read_user_config_raw

    _warn_if_dashboard_ungated(environ, read_user_config_raw(config_path))
    return changed


def _describe_error(exc: BaseException) -> str:
    """A value-free description: the exception type, plus the line for a YAML error and the
    path/errno for an OS error. Never ``str(exc)``, which can quote file content."""
    parts = [type(exc).__name__]
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        mark = getattr(cur, "problem_mark", None)
        if mark is not None and getattr(mark, "line", None) is not None:
            parts.append(f"({type(cur).__name__} at line {mark.line + 1})")
            break
        if isinstance(cur, OSError) and cur.errno:
            parts.append(f"({os.strerror(cur.errno)}: {cur.filename})")
            break
        cur = cur.__cause__ or cur.__context__
    return " ".join(parts)


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["bake"]:
        parser = argparse.ArgumentParser(prog="container_env_config bake")
        parser.add_argument("--repo", default=HERMIE_PLUGIN_REPO)
        parser.add_argument("--ref", default="")
        parser.add_argument("--expect-commit", default="")
        parser.add_argument("--dest", type=Path, default=BAKED_PLUGIN_DIR)
        parser.add_argument("--meta", type=Path, default=BAKED_PLUGIN_META)
        opts = parser.parse_args(args[1:])
        return bake_plugin(opts.repo, opts.ref, opts.dest, opts.meta, expect_commit=opts.expect_commit)
    hermes_home = _hermes_home()
    try:
        # A snapshot: removing a key from .env also drops it from os.environ.
        changed = run(dict(os.environ), hermes_home)
    except EnvConfigError as exc:
        print(f"{TAG} ERROR: refusing to start with an invalid environment; config.yaml was not changed:\n"
              f"{exc}", file=sys.stderr, flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001 — surface anything else as a clean, value-free failure
        print(f"{TAG} ERROR: could not apply the environment to {hermes_home / 'config.yaml'}: "
              f"{_describe_error(exc)}", file=sys.stderr, flush=True)
        return 1
    if changed:
        for key in changed:
            _log(f"set {key}")
    else:
        _log("config.yaml already matches the environment; nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
