"""``/mcp/consent``: the one place an MCP grant is born.

``/mcp/authorize`` opens a consent transaction and sends the browser here with ``?txn=<id>``. The route is
NOT public: the dashboard gate runs first, so a browser without a session goes through the normal sign-in
(``/login?next=/mcp/consent?txn=…``, which ``is_safe_next_path`` allows) and comes back.

    GET  /mcp/consent?txn=ID   the page: client name AND redirect host (a DCR name is attacker-chosen text),
                               the signed-in person, what the client may do, Allow / Deny
    POST /mcp/consent          form ``txn``, ``nonce``, ``decision`` (allow | deny): 303 back to the client
                               with a code, or with ``error=access_denied``

Rules:

- The identity is the gate's verified session and nothing in the form; without one (or the server's own
  internal identity) the answer is 403 ``no_identity``.
- A cookie-authenticated POST must carry ``Origin`` equal to the primary public origin (the only origin the
  page is served on); otherwise 403 ``origin_not_listed``. A bearer caller is exempt (a browser never
  attaches one on its own), as for the dashboard's other writes.
- The form's nonce is bound to the transaction by the store; an unknown, expired, decided or mismatched
  transaction is 404 ``not_found``. A person at the cap of live grants gets 409 ``too_many_grants`` and the
  transaction stays open (revoke one in Settings › MCP, then Allow again).
- Bodies of at most 16 KiB. The page is ``no-store``, cannot be framed, sends no referrer, and runs no script.
- Audit: ``mcp_consent_granted`` / ``mcp_consent_denied`` (``outcome`` ``denied`` for the person's no,
  ``refused`` with a ``reason`` for a request the gateway refused), with the user, client id and name,
  scopes and address; never the nonce or the code.

A browser (``Accept`` with ``text/html``) gets refusals as a short HTML page with the same status; any other
caller gets JSON ``{error, detail}``.
"""

from __future__ import annotations

import datetime as _dt
import html
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import Session
from hermes_cli.dashboard_auth.mcp import routes
from hermes_cli.dashboard_auth.mcp.store import ConsentInvalid, LimitReached
from hermes_cli.dashboard_auth.request_utils import client_ip, extract_bearer

#: What each scope lets the client do, as the page says it.
SCOPE_TEXT = {
    "bots:read": "See your bots, and the chats it opened or that you have open now.",
    "bots:prompt": "Send prompts to your bots as you and read their replies. Every message is marked as sent "
                   "by an agent, not by you.",
    "requests:read": "See what a bot is waiting for.",
    "requests:clarify": "Answer a bot's clarifying questions. Each answer is marked as the agent's.",
}
NEVER_TEXT = ("It can never approve commands, confirm with a passkey, provide secrets, change settings or "
              "delete chats. Those stay with you, in your own app.")

_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; "
                               "base-uri 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

_STYLE = """
  :root { color-scheme: light dark; --bg: #170d02; --fg: #fff; --accent: #ffac02;
          --line: color-mix(in srgb, #ffac02 30%, transparent); }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1.5rem;
         background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { width: 100%; max-width: 30rem; border: 1px solid var(--line); border-radius: 10px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  .client { color: var(--accent); overflow-wrap: anywhere; }
  .muted { opacity: .75; font-size: .9rem; }
  code { overflow-wrap: anywhere; }
  ul { padding-left: 1.2rem; }
  .actions { display: flex; gap: .75rem; margin-top: 1.25rem; }
  button { flex: 1; font: inherit; padding: .65rem 1rem; border-radius: 8px; cursor: pointer;
           border: 1px solid var(--line); background: transparent; color: var(--fg); }
  button.allow { background: var(--accent); color: #170d02; border-color: var(--accent); font-weight: 600; }
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex"><title>{_e(title)}</title><style>{_STYLE}</style></head>'
            f'<body><main>{body}</main></body></html>')


def _when(ts: int) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%H:%M UTC")


def render_consent(view: Any, *, person: str) -> str:
    """The consent page for *view* (a :class:`~.provider.ConsentView`); every value is escaped."""
    scopes = "".join(f"<li>{_e(SCOPE_TEXT.get(s, s))}</li>" for s in view.scopes)
    body = (
        f'<h1>Allow <span class="client">«{_e(view.client_name)}»</span> to work with your bots?</h1>'
        f"<p>An MCP client that calls itself <strong>«{_e(view.client_name)}»</strong> asks to act as "
        f"<strong>{_e(person)}</strong> on this gateway. That name is chosen by the client: check the address "
        f"below.</p>"
        f'<p>After you decide, your browser goes back to <code>{_e(view.redirect_host)}</code>. Only allow this if '
        f"you just connected an MCP client there.</p>"
        f"<p>If you allow it, it can:</p><ul>{scopes}</ul>"
        f"<p>{_e(NEVER_TEXT)} You can disconnect it at any time in Settings › MCP.</p>"
        f'<p class="muted">This request expires at {_e(_when(view.expires_at))}.</p>'
        f'<form method="post" action="/mcp/consent">'
        f'<input type="hidden" name="txn" value="{_e(view.txn_id)}">'
        f'<input type="hidden" name="nonce" value="{_e(view.nonce)}">'
        f'<div class="actions"><button type="submit" name="decision" value="deny">Deny</button>'
        f'<button class="allow" type="submit" name="decision" value="allow">Allow</button></div>'
        f"</form>")
    return _page("Allow an MCP client?", body)


def _refusal(request: Request, status: int, error: str, detail: str) -> Response:
    if "text/html" in request.headers.get("accept", ""):
        body = f"<h1>{_e(_TITLES.get(error, 'This request was refused'))}</h1><p>{_e(detail)}</p>"
        return HTMLResponse(_page("MCP sign-in", body), status_code=status, headers=_PAGE_HEADERS)
    return JSONResponse({"error": error, "detail": detail}, status_code=status, headers={"Cache-Control": "no-store"})


_TITLES = {
    "no_identity": "No signed-in person",
    "not_found": "This sign-in request is no longer open",
    "origin_not_listed": "This request did not come from this gateway's page",
    "too_many_grants": "Too many connected clients",
    "bad_request": "This request is not valid",
    "body_too_large": "This request is too large",
    "temporarily_unavailable": "Try again in a moment",
}


def _identity(request: Request) -> tuple[str, str, str]:
    """``(provider, provider user id, display name)`` of the gate's verified session, or empty strings."""
    from hermes_cli.dashboard_auth.ws_tickets import INTERNAL_PROVIDER, INTERNAL_USER_ID

    session = getattr(request.state, "session", None)
    if not isinstance(session, Session):
        return "", "", ""
    provider, user = str(session.provider or "").strip(), str(session.user_id or "").strip()
    if not provider or not user or (provider, user) == (INTERNAL_PROVIDER, INTERNAL_USER_ID):
        return "", "", ""
    return provider, user, str(session.display_name or session.email or "").strip()


async def consent_endpoint(request: Request) -> Response:
    rt = routes.runtime()
    provider, user, name = _identity(request)
    if not provider:
        return _refusal(request, 403, "no_identity",
                        "Connecting an MCP client needs a signed-in person; this connection has none.")
    user_id = f"{provider}:{user}"
    ip = client_ip(request)
    if request.method == "GET":
        shown = request.query_params.get("txn", "")
        response, _ = await routes.provider_call(request, lambda: _show(request, rt, shown, name or user))
        return response
    auth = "bearer" if extract_bearer(request) else "cookie"

    def refused(status: int, error: str, detail: str, reason: str, **fields: Any) -> Response:
        audit_log(AuditEvent.MCP_CONSENT_DENIED, user_id=user_id, ip=ip, auth=auth, outcome="refused",
                  reason=reason, **fields)
        return _refusal(request, status, error, detail)

    if auth == "cookie" and request.headers.get("origin", "") != rt.primary_origin:
        return refused(403, "origin_not_listed",
                       "A browser decision must come from this gateway's own consent page.", "origin_not_listed")
    try:
        await routes.read_capped_body(request)
    except routes.BodyTooLarge:
        return refused(413, "body_too_large", f"The body is larger than {routes.BODY_CAP} bytes.", "body_too_large")
    form = await request.form()
    txn, nonce, decision = form.get("txn"), form.get("nonce"), form.get("decision")
    if not isinstance(txn, str) or not isinstance(nonce, str) or decision not in ("allow", "deny"):
        return refused(400, "bad_request", "The form needs txn, nonce and decision (allow or deny).", "bad_form")

    async def decide() -> Response:
        try:
            if decision == "allow":
                outcome = await rt.provider.approve(txn, nonce, provider=provider, provider_user_id=user,
                                                    user_name=name)
            else:
                outcome = await rt.provider.deny(txn, nonce)
        except ConsentInvalid:
            return refused(404, "not_found", "This sign-in request is unknown, expired or already decided. "
                                             "Start the connection again from your MCP client.", "consent_invalid")
        except LimitReached as exc:
            return refused(409, "too_many_grants",
                           f"You already have {rt.settings.max_grants_per_user} connected MCP clients. Disconnect "
                           "one in Settings › MCP, then go back and press Allow again.", exc.reason)
        fields = {"client_id": outcome.client_id, "client_name": outcome.client_name,
                  "scopes": list(outcome.scopes)}
        if outcome.granted:
            audit_log(AuditEvent.MCP_CONSENT_GRANTED, user_id=user_id, ip=ip, auth=auth, **fields)
        else:
            audit_log(AuditEvent.MCP_CONSENT_DENIED, user_id=user_id, ip=ip, auth=auth, outcome="denied", **fields)
        return RedirectResponse(outcome.redirect_url, status_code=303, headers={"Cache-Control": "no-store"})

    response, _ = await routes.provider_call(request, decide)
    return response


async def _show(request: Request, rt: Any, txn: str, person: str) -> Response:
    view = await rt.provider.consent_view(txn) if txn and len(txn) <= 128 else None
    if view is None:
        return _refusal(request, 404, "not_found", "This sign-in request is unknown, expired or already decided. "
                                                   "Start the connection again from your MCP client.")
    return HTMLResponse(render_consent(view, person=person), headers=_PAGE_HEADERS)
