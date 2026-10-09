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
  ``server_requests``, and the bridge reads a reply as text, where a block is raw JSON. Its turns get no guide.

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

#: The accepted names of the connection that submitted the running turn, bound by ``prompt_turn`` in the
#: same try/finally as ``server._turn_auth_user``. Empty for a turn nobody submitted.
TURN_MARKUP: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "hermes_gateway_turn_markup", default=frozenset())


def accepted_names(value: Any) -> frozenset[str]:
    """The names of *value* this gateway accepts: empty unless *value* is a well-formed list (see the module
    docstring), then the ones in :data:`VOCABULARY`. Also re-checks a list read back from a queue envelope,
    a restart journal or a compute-host frame."""
    if not isinstance(value, (list, tuple, frozenset, set)) or len(value) > MAX_NAMES:
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


def wire(names: Iterable[str]) -> list[str]:
    """*names* as they travel in a queue envelope, its restart journal and a compute-host frame: sorted text."""
    return sorted(accepted_names(list(names)))
