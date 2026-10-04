"""Audit log for dashboard-auth events: ``$HERMES_HOME/logs/dashboard-auth.log``, one JSON object
per line. Token-like fields are stripped before serialisation so refresh tokens / JWTs never
reach disk. Minimal import surface (no ``hermes_constants`` at import time) so early-loading
middleware can import it."""
from __future__ import annotations

import datetime as _dt
import enum
import json
import logging
import threading
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)
_write_lock = threading.Lock()

# Field names that must never appear in the log raw; matching kwargs are dropped.
_REDACTED_FIELDS: frozenset = frozenset({
    "access_token", "refresh_token", "code", "code_verifier",
    "state", "ticket", "cookie", "Authorization", "authorization",
    "client_secret", "token", "nonce"})


class AuditEvent(enum.Enum):
    """Event types; values are the literal ``event`` field on the JSON line."""
    LOGIN_START = "login_start"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    REFRESH_SUCCESS = "refresh_success"
    REFRESH_FAILURE = "refresh_failure"
    REVOKE = "revoke"
    SESSION_VERIFY_FAILURE = "session_verify_failure"
    SESSION_REJECTED = "session_rejected"
    WS_TICKET_MINTED = "ws_ticket_minted"
    WS_TICKET_REJECTED = "ws_ticket_rejected"
    TOKEN_AUTH_SUCCESS = "token_auth_success"
    TOKEN_AUTH_FAILURE = "token_auth_failure"
    # RFC 8252 native-app (system-browser + loopback + PKCE) flow.
    NATIVE_AUTHORIZE_START = "native_authorize_start"
    NATIVE_CODE_ISSUED = "native_code_issued"
    NATIVE_TOKEN_SUCCESS = "native_token_success"
    NATIVE_TOKEN_FAILURE = "native_token_failure"
    # Session access (tui_gateway/session_transports.py): a signed-in person joined a conversation another
    # login opened, or was throttled for failed resume lookups.
    SESSION_FOREIGN_ATTACH = "session_foreign_attach"
    SESSION_RESUME_THROTTLED = "session_resume_throttled"
    # The ``confirm`` server request (tui_gateway/confirm.py): who was asked and who answered, never the text.
    CONFIRM_REQUEST = "confirm_request"
    CONFIRM_OUTCOME = "confirm_outcome"
    # The interactive server requests (tui_gateway/interactive.py: input.form, input.file, review.draft): who was
    # asked and who answered, never a title, value, path, name or draft.
    INTERACTIVE_REQUEST = "interactive_request"
    INTERACTIVE_OUTCOME = "interactive_outcome"
    # Passkeys for the confirm level ``passkey`` (hermes_cli/dashboard_auth/passkeys): enrolment codes,
    # credentials, step-ups and verified answers. Fields name the user, the first 16 characters of the
    # credential id, the RP, the base URL, the request and a reason; never a code, text or signature.
    PASSKEY_INVITE_MINTED = "passkey_invite_minted"
    PASSKEY_INVITE_REFUSED = "passkey_invite_refused"
    PASSKEY_REGISTERED = "passkey_registered"
    PASSKEY_REGISTER_REFUSED = "passkey_register_refused"
    PASSKEY_REVOKED = "passkey_revoked"
    PASSKEY_STEPUP_REFUSED = "passkey_stepup_refused"
    PASSKEY_BASE_URLS_CHANGED = "passkey_base_urls_changed"
    CONFIRM_PASSKEY_VERIFIED = "confirm_passkey_verified"
    CONFIRM_PASSKEY_REFUSED = "confirm_passkey_refused"
    # An operator rule (confirm.passkey.require) forced a passkey confirmation (tools/passkey_policy.py): the
    # rule, the operator's pattern, session, user, outcome and reason; never the command text.
    CONFIRM_FORCED = "confirm_forced"
    # A dashboard or RPC config write that would have changed a protected section (confirm.passkey).
    PROTECTED_SETTING_REFUSED = "protected_setting_refused"
    # The remote MCP endpoint and its authorization server (hermes_cli/dashboard_auth/mcp): registrations,
    # consents, token issue/refresh/refusal, grant revocations, tool calls, chats opened and throttles.
    # Fields name the user, the grant, the client id and name, the address, the tool, the session, an
    # outcome and a reason; never a prompt, a reply, a token, a code or a client secret.
    MCP_CLIENT_REGISTERED = "mcp_client_registered"
    MCP_AUTHORIZE_START = "mcp_authorize_start"
    MCP_CONSENT_GRANTED = "mcp_consent_granted"
    MCP_CONSENT_DENIED = "mcp_consent_denied"
    MCP_TOKEN_ISSUED = "mcp_token_issued"
    MCP_TOKEN_REFRESHED = "mcp_token_refreshed"
    MCP_TOKEN_REJECTED = "mcp_token_rejected"
    MCP_GRANT_REVOKED = "mcp_grant_revoked"
    MCP_TOOL_CALL = "mcp_tool_call"
    MCP_CHAT_OPENED = "mcp_chat_opened"
    MCP_RATE_LIMITED = "mcp_rate_limited"
    # A write to the app's MCP routes (GET/POST /api/auth/mcp*) refused before it reached the store: a cookie
    # caller without a listed Origin. User, address, how the caller authenticated, path, reason.
    MCP_WRITE_REFUSED = "mcp_write_refused"
    # A server request answered from an agent's connection (tui_gateway/server_requests.py): a clarify answer
    # it gave (marked as the agent's before it reached the tool), or an answer refused because an agent may
    # answer nothing else. User, grant, client name, session, request id, method, outcome and reason; never
    # the question or the answer.
    MCP_REQUEST_ANSWERED = "mcp_request_answered"
    MCP_REQUEST_ANSWER_REFUSED = "mcp_request_answer_refused"


def _resolve_log_path() -> Path:
    """Lazy leaf import: honours profile overrides + the native-Windows ``%LOCALAPPDATA%`` fallback."""
    from hermes_constants import get_hermes_home
    return get_hermes_home() / "logs" / "dashboard-auth.log"


def audit_log(event: AuditEvent, **fields: Any) -> None:
    """Append one event; token-like fields dropped, log dir created. Write failures are logged at
    WARNING but never raise — auth must not fail because the audit logger broke."""
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "event": event.value,
        **{k: v for k, v in fields.items() if k not in _REDACTED_FIELDS}}
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    path = _resolve_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _write_lock, open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        _log.warning("dashboard-auth audit log write failed: %s", e)


# ---- BEGIN PLUGIN-COMPAT (revert-scheduled; see COMPAT_MANIFEST.md) ----
# Names external plugins imported from this module before the Sep 2026 decomposition.
# Internal code MUST NOT use these (scripts/check_compat_pointers.py fails CI if it does).
# The whole block is removed by reverting the commit that added it.
import os  # noqa: F401,E402
# ---- END PLUGIN-COMPAT ----
