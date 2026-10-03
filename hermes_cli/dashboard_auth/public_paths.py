"""Shared allowlist of ``/api/*`` paths that bypass dashboard auth. Imported by BOTH gates —
``web_server.auth_middleware`` (loopback / ``--insecure``) and
``dashboard_auth.middleware.gated_auth_middleware`` (OAuth cookie) — so the lists cannot drift
again (a drift once 401'd ``/api/status`` and broke the portal's cookie-less liveness probe).
Keep minimal: every entry must be safe for external uptime probes, the pre-login SPA, and anyone
who ``curl``s the hostname; otherwise gate it and bootstrap after login."""
from __future__ import annotations

import threading

PUBLIC_API_PATHS: frozenset[str] = frozenset({
    # Minimal process liveness probe for desktop/backend boot handshakes; avoids
    # gateway config, platform discovery, MCP setup and cold plugin imports.
    "/api/health",
    # Portal wildcard liveness probe (``docs/agent-dashboard-public-url-contract.md``,
    # NAS side): version, gateway state, session count, auth-gate shape. No secrets.
    "/api/status",
    # Read-only config-defaults / schema feeds for the SPA's Config page.
    "/api/config/defaults",
    "/api/config/schema",
    # Read-only model metadata — same shape as public provider catalogs.
    "/api/model/info",
    # Read-only theme + plugin manifests for the dashboard skin engine.
    "/api/dashboard/themes",
    "/api/dashboard/plugins",
    # Chronos managed-cron fire webhook (NAS -> agent). NOT cookie-gated: it
    # carries its own short-lived NAS-minted JWT (purpose=cron_fire), which the
    # handler verifies — the JWT, not this allowlist, is the security boundary.
    "/api/cron/fire"})


# ── fork: paths a feature makes public while it is on ──────────────────────────────────────────
# A feature that answers on its own credentials (the MCP authorization server and endpoint: OAuth
# client authentication and its own bearer tokens) registers its exact paths here when it is
# enabled and removes them when it is not. Both gates read the registry; nothing is registered
# unless such a feature is on, so a gateway without it gates exactly as before. Exact paths only:
# registering ``/mcp`` never opens ``/mcp/consent``.
_registered_lock = threading.Lock()
_registered_paths: frozenset[str] = frozenset()


def register_public_path(path: str) -> None:
    """Let *path* (exactly; no prefix match) through both gates."""
    global _registered_paths
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError(f"not an absolute path: {path!r}")
    with _registered_lock:
        _registered_paths = _registered_paths | {path}


def unregister_public_path(path: str) -> None:
    global _registered_paths
    with _registered_lock:
        _registered_paths = _registered_paths - {path}


def registered_public_paths() -> frozenset[str]:
    return _registered_paths


def is_registered_public(path: str) -> bool:
    """True when a running feature registered exactly *path* as public."""
    return path in _registered_paths
