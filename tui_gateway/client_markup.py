"""Which Hermie blocks a connection draws (``client.capabilities {markup: [...]}``), per transport.

A Hermie client that draws a structured block in a reply (a ``hermie-chart`` or ``hermie-cards`` fence, a
GitHub alert quote) lists it under ``markup``. The gateway keeps the names it has a guide paragraph for
(:data:`VOCABULARY`) and echoes them; ``prompt.submit`` reads them on the SUBMITTING connection and the turn
tells the model about exactly those blocks (``tui_gateway/hermie_markup.py``). Nothing else reads them.

* The value is the client's own words and is never trusted beyond its shape: a list of at most
  :data:`MAX_NAMES` names of at most :data:`MAX_NAME_LENGTH` characters matching ``[a-z][a-z-]*``. Anything
  else (a string, a dict, too many names, one malformed name) is "none" and never fails the call; a
  well-formed name this gateway has no guide for is dropped silently.
* Each call REPLACES the connection's advertisement: a ``client.capabilities`` without ``markup`` clears it,
  as ``requests`` does. A client sends the key only in a second call, after a result that carried it: a
  gateway older than the key refuses it (4000) with the whole call.
* State lives per transport and goes with it (:func:`forget`, from ``server.unregister_live_transport``).
* An agent's connection (MCP) cannot send the key at all: ``agent_guard.AGENT_PARAMS`` allows it only
  ``server_requests``, and the bridge reads a reply as text, where a block is raw JSON. Its turns get no guide,
  and neither do the continuations of its turns or of a relayed bot message. The cost is accepted: in a chat
  where a person and an agent (or a relay) take turns, the system message changes between them, and the
  provider's prompt cache misses there.

A leaf (no gateway import): the split modules are re-created against ``server.py``'s globals, so callers
import from here inside the function that needs it.
"""

from __future__ import annotations

import contextvars
import re
import threading
from typing import Any, Iterable

#: The block names this gateway has a guide paragraph for (``hermie_markup.GUIDE``). Removing a name here is
#: the fastest way to stop telling bots about a block that misbehaves; no client release is needed.
VOCABULARY: frozenset[str] = frozenset({"chart", "cards", "alerts"})
MAX_NAMES = 16
MAX_NAME_LENGTH = 32
_NAME = re.compile(r"[a-z][a-z-]*")

_lock = threading.Lock()
# Identity-keyed like ``server_requests`` (a StdioTransport has __slots__ and cannot be weak-referenced).
_accepted: dict[Any, frozenset[str]] = {}

#: The names the running turn carries (:func:`resolve_turn_markup`), bound by ``prompt_turn`` in the same
#: try/finally as ``server._turn_auth_user``.
TURN_MARKUP: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "hermes_gateway_turn_markup", default=frozenset())


def accepted_names(value: Any) -> frozenset[str]:
    """The names of *value* this gateway accepts: empty unless *value* is a well-formed list (see the module
    docstring), then the ones in :data:`VOCABULARY`. Also re-checks a list read back from a queue envelope,
    a restart journal or a compute-host frame."""
    if value is UNGUIDED or not isinstance(value, (list, tuple, frozenset, set)) or len(value) > MAX_NAMES:
        return frozenset()
    names = []
    for name in value:
        if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH or not _NAME.fullmatch(name):
            return frozenset()
        names.append(name)
    return frozenset(names) & VOCABULARY


def advertise(transport: Any, value: Any) -> list[str]:
    """Replace *transport*'s advertisement with the accepted names of *value*; returns them sorted (what
    ``client.capabilities`` echoes as ``markup``)."""
    names = accepted_names(value)
    with _lock:
        if names:
            _accepted[transport] = names
        else:
            _accepted.pop(transport, None)
    return sorted(names)


def accepted(transport: Any) -> frozenset[str]:
    """What *transport* advertised and this gateway accepted (empty for None or a connection that never did)."""
    if transport is None:
        return frozenset()
    with _lock:
        return _accepted.get(transport, frozenset())


def forget(transport: Any) -> None:
    """Drop a disconnected transport's advertisement."""
    with _lock:
        _accepted.pop(transport, None)


# ── which connection a session's next unsubmitted turn follows ────────────────────────────────────────────
#
# A turn somebody submitted carries that connection's names. A turn nobody submitted that continues the same
# chat (a ``/goal`` continuation, an auto-continue, a wake-up) follows the connection that submitted the
# session's last turn, read live: while it is connected and still advertises the names, the continuation
# carries the same guide (so the system message, and the provider's prompt cache with it, does not flip
# between a person's turn and the continuation of it); once it is gone or advertises none, nothing. A turn the
# gateway dispatched for somebody else (a relayed bot message, a hosted room) and an MCP agent's turn name no
# such connection, so their continuations carry no guide either.

#: A turn the gateway dispatched for somebody other than a connection (a relayed bot message, a hosted-room
#: task): it carries no guide, and neither do the turns that follow from it (its ``/goal`` continuation). It
#: leaves the session's source alone, so the person's own unsubmitted turns afterwards follow their connection
#: again. Its reply goes back to whoever sent it, where a block would be raw JSON.
UNGUIDED = object()

#: ``session["_markup_source"]`` of a compute-host child: its only peer is the pipe, so it keeps the names its
#: last frame carried (``session["_markup_names"]``) instead of a connection. Known difference from an inline
#: session: the child cannot see the connection itself, so a continuation it runs keeps those names even when
#: that connection disconnected or changed its advertisement after the frame; the next frame corrects it. A
#: relayed turn's frame says ``turn_unguided`` and leaves the names alone, as an inline relay leaves the source.
FRAME_SOURCE = object()


def remember_source(session: dict, transport: Any) -> None:
    """The connection whose names the session's next unsubmitted turns follow (None: no connection's)."""
    session["_markup_source"] = transport


def remember_frame_names(session: dict, names: Iterable[str]) -> None:
    """In a compute-host child: the names the frame of the turn it is about to run carried."""
    session["_markup_source"] = FRAME_SOURCE
    session["_markup_names"] = accepted_names(list(names))


def resolve_turn_markup(session: dict | None, value: Any) -> frozenset[str]:
    """The names a turn carries: *value* re-checked when a submitter's names were handed in (an empty set
    included), or, for ``None`` (a turn nobody submitted), the names of the connection the session's last
    submitted turn came from, as that connection advertises them now."""
    if value is UNGUIDED:
        return frozenset()
    if value is not None:
        return accepted_names(value)
    source = session.get("_markup_source") if isinstance(session, dict) else None
    if source is FRAME_SOURCE:
        return accepted_names(list(session.get("_markup_names") or ()))
    return accepted(source)


def followup_markup(value: Any) -> Any:
    """What a turn's own follow-on turn (its ``/goal`` continuation) is handed, from what the turn itself was
    handed: :data:`UNGUIDED` stays unguided, anything else follows the session's source (``None``)."""
    return UNGUIDED if value is UNGUIDED else None


def wire(names: Iterable[str]) -> list[str]:
    """*names* as they travel in a queue envelope, its restart journal and a compute-host frame: sorted text."""
    return [] if names is UNGUIDED else sorted(accepted_names(list(names)))
