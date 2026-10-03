"""Compatibility helper for explicit agent stop producers."""

from __future__ import annotations

import inspect
from typing import Any


def _accepts_keyword(callable_obj: Any, name: str) -> bool:
    """Return whether a callable explicitly supports a keyword argument."""
    try:
        parameters = inspect.signature(callable_obj).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        p.kind is inspect.Parameter.VAR_KEYWORD
        or (p.name == name and p.kind is not inspect.Parameter.POSITIONAL_ONLY)
        for p in parameters
    )


def request_hard_interrupt(
    agent: Any,
    message: str | None = None,
    *,
    tool_reason: str | None = None,
) -> bool:
    """Request an explicit stop, falling back to the legacy interrupt ABI.

    New agents expose ``hard_interrupt(message=None)``; third-party agents and old test
    doubles may only expose ``interrupt(message=None)`` and must not receive keyword
    arguments they do not know. ``tool_reason`` is a trusted, fixed category that may be
    exposed in model-visible tool cancellation output, forwarded only when the callable
    explicitly supports it. Returns ``False`` only when neither callable is available.
    """
    # Static lookup first: a dynamic ``__getattr__`` proxy (unspecced MagicMock, RPC
    # facade) must not be treated as genuinely implementing the new ABI.
    try:
        inspect.getattr_static(agent, "hard_interrupt")
    except AttributeError:
        interrupt = None
    else:
        interrupt = getattr(agent, "hard_interrupt", None)
    if not callable(interrupt):
        interrupt = getattr(agent, "interrupt", None)
    if not callable(interrupt):
        return False
    kwargs = {}
    if tool_reason is not None and _accepts_keyword(interrupt, "tool_reason"):
        kwargs["tool_reason"] = tool_reason
    if message is None:
        interrupt(**kwargs)
    else:
        interrupt(message, **kwargs)
    return True


# A stop the process asks for on its way out, not a person. Producers pass it as ``tool_reason`` to
# ``request_hard_interrupt``; the finalizer then closes an interrupted tool tail with a structured row
# (``display_metadata.interrupt_reason = "shutdown"``) instead of the "Operation interrupted" sentinel,
# because the turn is going to be continued after the restart, not abandoned.
DASHBOARD_SHUTDOWN_TOOL_REASON = "dashboard shutdown"
SHUTDOWN_TOOL_REASONS = frozenset({DASHBOARD_SHUTDOWN_TOOL_REASON})
SHUTDOWN_INTERRUPT_REASON = "shutdown"


def shutdown_interrupt_reason(agent: Any) -> str | None:
    """``"shutdown"`` when the pending interrupt came from a process shutdown, else None.

    Read before ``clear_interrupt()``: the reason lives only as long as the interrupt does."""
    reason = getattr(agent, "_tool_interrupt_reason", None)
    return SHUTDOWN_INTERRUPT_REASON if reason in SHUTDOWN_TOOL_REASONS else None
