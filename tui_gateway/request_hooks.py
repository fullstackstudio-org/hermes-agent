"""Plugin hooks for the requests the gateway asks of a person, and for background tasks that finish.

Three observer hooks, all fired on their own daemon thread so the request path never waits for a plugin, all
bounded by ``plugins.hook_callback_timeout`` (``plugins_dispatch._HOOK_TIMEOUT_BOUNDED_HOOKS``), all swallowing
every exception, and none of them ever carrying what the person is asked or answers (no question, choices,
prompt, command, site, answer, secret or task result):

- ``pre_server_request``: a ``clarify``, ``secret``, ``sudo`` or ``vault.*`` request was written to the
  session's clients (:func:`covers`). ``confirm`` is not announced here: it keeps ``pre_confirm_request``
  (``tui_gateway/confirm.py``), which also says the level and who the request is bound to.
- ``post_server_request``: that request stopped being open, for the methods above and for ``confirm``.
- ``on_background_complete``: a ``/background`` task finished (``methods_prompt._spawn_side_agent``).

The kwargs of each are the tuples below, pinned by a test against ``VALID_HOOKS`` and ``hooks.md``.

``session_id`` is the live runtime session id (the one a frame carries), ``session_key`` the conversation's
stored key; ``user_id`` is ``<provider>:<user id>`` of the login the turn acts for, or ``""`` when the gateway
cannot name one. Both are read on the calling thread (``bind_identity``): the acting user comes from the turn's
context, which a hook thread does not have.

A ``post_server_request`` is never delivered before the ``pre_server_request`` (or ``pre_confirm_request``) of
the same request has returned or ``ORDER_WAIT_SECONDS`` passed, so a plugin that clears what the first one
raised cannot see the clear first.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

#: ``pre_server_request`` kwargs (kept in step with ``VALID_HOOKS`` and hooks.md by a test).
PRE_KWARGS = ("session_id", "session_key", "request_id", "method", "user_id", "expires_at", "reached")
#: ``post_server_request`` kwargs.
POST_KWARGS = ("session_id", "session_key", "request_id", "method", "user_id", "reason")
#: ``on_background_complete`` kwargs.
BACKGROUND_KWARGS = ("session_id", "session_key", "task_id", "user_id")

#: The methods ``pre_server_request`` is fired for; ``vault.*`` is every method with that prefix.
METHODS = ("clarify", "secret", "sudo")
VAULT_PREFIX = "vault."
#: How long a ``post_server_request`` waits for the hook that announced the same request.
ORDER_WAIT_SECONDS = 5.0


def covers(method: str) -> bool:
    """Whether *method* is one ``pre_server_request`` is fired for (``confirm`` is not: it has its own hook)."""
    return method in METHODS or method.startswith(VAULT_PREFIX)


def settle_reason(outcome: Any) -> str:
    """The ``reason`` of ``post_server_request`` for a ``server_requests.RequestOutcome``: ``answered``,
    ``timeout``, the cancel reason (``interrupted``, ``session_closed``, ...), or why it never got an answer
    (``error_response``, ``too_many_attempts``). A short machine word, never user text."""
    status = str(getattr(outcome, "status", "") or "")
    if status in ("answered", "timeout"):
        return status
    return str(getattr(outcome, "reason", "") or status or "cancelled")


# ``identity(sid) -> (session_key, user_id)``, bound by server.py (importing it from here would pick a
# different module object under the test fixtures that patch ``sys.modules`` around the server import).
_identity: Callable[[str], tuple[str, str]] = lambda sid: (sid, "")  # noqa: E731


def bind_identity(identity: Callable[[str], tuple[str, str]]) -> None:
    global _identity
    _identity = identity


def identity(sid: str) -> tuple[str, str]:
    """``(session_key, user_id)`` for *sid*, never raising: the session id and ``""`` when unknown."""
    try:
        key, user = _identity(sid)
        return str(key or sid), str(user or "")
    except Exception:  # noqa: BLE001
        logger.debug("request hook identity unresolved", exc_info=True)
        return sid, ""


def _nobody_listens(hook: str) -> bool:
    """True only when plugins are already loaded and none registered *hook*: nothing to start a thread for.
    Before discovery it is False, so the hook's own thread triggers the (lazy) discovery, off the request."""
    try:
        from hermes_cli.plugins import get_plugin_manager
        manager = get_plugin_manager()
        return bool(getattr(manager, "_discovered", False)) and not manager.has_hook(hook)
    except Exception:  # noqa: BLE001
        return False


def _fire(hook: str, kwargs: dict, *, after: threading.Event | None = None) -> threading.Event:
    """Invoke *hook* on a daemon thread; the returned event is set once the hook returned (or failed). With no
    plugin registered for it, nothing is started and the event is already set."""
    done = threading.Event()
    if _nobody_listens(hook):
        done.set()
        return done

    def run() -> None:
        try:
            if after is not None:
                after.wait(ORDER_WAIT_SECONDS)
            from hermes_cli.plugins import invoke_hook
            invoke_hook(hook, **kwargs)
        except Exception:  # noqa: BLE001 - a plugin must not affect the request
            logger.debug("%s hook failed", hook, exc_info=True)
        finally:
            done.set()

    try:
        threading.Thread(target=run, name="request-hook", daemon=True).start()
    except Exception:  # noqa: BLE001 - no thread to spare: the request goes on without the hook
        logger.debug("%s hook not started", hook, exc_info=True)
        done.set()
    return done


class Tracked:
    """One open request a plugin was (or could be) told about. :meth:`settled` fires ``post_server_request``
    once; never raises."""

    __slots__ = ("sid", "key", "user_id", "method", "request_id", "_announced", "_lock", "_settled")

    def __init__(self, method: str, sid: str, request_id: str, key: str, user_id: str,
                 announced: threading.Event | None) -> None:
        self.method, self.sid, self.request_id, self.key, self.user_id = method, sid, request_id, key, user_id
        self._announced = announced
        self._lock = threading.Lock()
        self._settled = False

    def settled(self, reason: str) -> None:
        with self._lock:
            if self._settled:
                return
            self._settled = True
        try:
            _fire("post_server_request",
                  {"session_id": self.sid, "session_key": self.key, "request_id": self.request_id,
                   "method": self.method, "user_id": self.user_id, "reason": reason},
                  after=self._announced)
        except Exception:  # noqa: BLE001
            logger.debug("post_server_request not fired", exc_info=True)


def opened(method: str, sid: str, request_id: str, *, expires_at: int | None = None, reached: int = 0,
           announce: bool = True, session_key: str | None = None, user_id: str | None = None,
           announced: threading.Event | None = None) -> Tracked | None:
    """A request *request_id* of *method* is open in session *sid* (its frame is out). Fires
    ``pre_server_request`` when *announce*; *announced* is the event of a hook already fired for it
    (``pre_confirm_request``) that ``post_server_request`` should follow. *session_key* and *user_id* default
    to :func:`identity`. Returns the handle to call :meth:`Tracked.settled` on, or None if this could not be
    set up (nothing is raised)."""
    try:
        if session_key is None or user_id is None:
            key, user = identity(sid)
            session_key = key if session_key is None else session_key
            user_id = user if user_id is None else user_id
        if announce:
            announced = _fire("pre_server_request",
                              {"session_id": sid, "session_key": session_key, "request_id": request_id,
                               "method": method, "user_id": user_id, "expires_at": expires_at,
                               "reached": reached})
        return Tracked(method, sid, request_id, session_key, user_id, announced)
    except Exception:  # noqa: BLE001
        logger.debug("request hooks not set up", exc_info=True)
        return None


def background_complete(sid: str, task_id: str, *, session_key: str, user_id: str) -> None:
    """``on_background_complete``: the task *task_id* started from session *sid* finished. Never the result."""
    try:
        _fire("on_background_complete",
              {"session_id": sid, "session_key": session_key, "task_id": task_id, "user_id": user_id})
    except Exception:  # noqa: BLE001
        logger.debug("on_background_complete not fired", exc_info=True)
