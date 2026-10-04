"""The plugin hooks for server requests and background tasks (``tui_gateway/request_hooks.py``):
``pre_server_request``, ``post_server_request`` and ``on_background_complete``.

What is pinned here: the exact kwargs of each hook (and that they match ``VALID_HOOKS`` and ``hooks.md``);
that ``pre_server_request`` covers ``clarify``, ``secret``, ``sudo``, ``vault.*`` and the interactive requests
(announced with ``reached: 0`` while parked) and nothing else, and that
``confirm`` is announced by ``pre_confirm_request`` and ended by ``post_server_request``; every way a request
ends maps to a ``reason``; ``post`` never overtakes the hook that announced the same request; no kwarg ever
carries the question, prompt, command, site, answer or result; with no plugin registered nothing is started;
a callback that raises, hangs or fails to dispatch never changes what the request returns; a background task
fires ``on_background_complete`` when it finishes, also when it failed.
"""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

SECRET_TEXT = {
    "secret": {"prompt": "PROMPT-TEXT-7", "env_var": "ENV_TEXT_7"},
    "sudo": {"command": "COMMAND-TEXT-7"},
    "clarify": {"question": "QUESTION-TEXT-7", "choices": ["CHOICE-TEXT-7", "other"]},
    "vault.code": {"site": "SITE-TEXT-7", "hint": "HINT-TEXT-7"},
    "vault.unlock_prompt": {"backend": "BACKEND-TEXT-7", "display_name": "DISPLAY-TEXT-7"},
    "vault.save_login": {"origin": "https://origin-text-7.example", "site": "SITE-TEXT-7"},
}
ANSWER_TEXT = "ANSWER-TEXT-7"
ALICE = "oidc:alice"


class _Peer:
    """A client connection: records frames, never answers on its own."""

    def __init__(self, name: str, login: str | None = None):
        self.name = name
        self.frames: list[dict] = []
        self._closed = False
        self._peer = "10.0.0.1:5000"
        if login is not None:
            provider, user_id = login.split(":", 1)
            self.auth_identity = {"provider": provider, "user_id": user_id}

    def write(self, obj):
        self.frames.append(json.loads(json.dumps(obj)))
        return True

    def close(self):
        self._closed = True

    def requests(self, method):
        return [f for f in self.frames if f.get("method") == method]


@pytest.fixture(autouse=True)
def audit_records(monkeypatch):
    import tui_gateway.confirm as confirm_module
    monkeypatch.setattr(confirm_module, "_audit_sink", lambda event, **fields: None)


@pytest.fixture()
def server():
    import tui_gateway.confirm  # noqa: F401
    import tui_gateway.request_hooks  # noqa: F401
    import tui_gateway.server_requests  # noqa: F401
    import tui_gateway.transport  # noqa: F401
    with patch.dict("sys.modules", {
        "hermes_constants": MagicMock(get_hermes_home=MagicMock(return_value="/tmp/hermes_test")),
        "hermes_cli.env_loader": MagicMock(),
        "hermes_cli.banner": MagicMock(),
        "hermes_state": MagicMock(),
    }):
        import importlib
        mod = importlib.import_module("tui_gateway.server")
    methods = dict(mod._methods)
    yield mod
    mod._methods.clear()
    mod._methods.update(methods)
    for sid in list(mod._sessions):
        mod._sessions.pop(sid, None)
    from tui_gateway import confirm, server_requests
    server_requests.reset_for_tests()
    confirm.reset_for_tests()


@pytest.fixture()
def hooks(monkeypatch):
    """Record every call of the three hooks (in arrival order); each name gets an event set on its first call."""
    from hermes_cli.plugins import get_plugin_manager
    from tui_gateway import request_hooks
    manager = get_plugin_manager()
    saved, discovered = {k: list(v) for k, v in manager._hooks.items()}, manager._discovered
    manager._discovered = True  # the hooks below are the whole plugin set: nothing is left to discover
    monkeypatch.setattr(request_hooks, "ORDER_WAIT_SECONDS", 2.0)
    calls: list[tuple[str, dict]] = []
    seen = {name: threading.Event() for name in ("pre_server_request", "post_server_request",
                                                   "on_background_complete", "pre_confirm_request")}

    def recorder(name):
        def record(**kw):
            calls.append((name, {k: v for k, v in kw.items() if k != "telemetry_schema_version"}))
            seen[name].set()
        return record

    for name in seen:
        manager._hooks.setdefault(name, []).append(recorder(name))

    class Recorded:
        def of(self, name):
            return [kw for hook, kw in calls if hook == name]

        def wait(self, name, timeout=5):
            assert seen[name].wait(timeout), f"{name} never fired"
            return self.of(name)

        order = property(lambda self: [hook for hook, _ in calls])
        every_kwarg = property(lambda self: json.dumps([kw for _, kw in calls], default=str))

    yield Recorded()
    manager._hooks = saved
    manager._discovered = discovered


def _session(server, sid, *peers, creator=None):
    from tui_gateway.transport import FanoutTransport
    transport = peers[0] if len(peers) == 1 else FanoutTransport(*peers)
    server._sessions[sid] = {"session_key": f"key-{sid}", "transport": transport, "history": [],
                             "history_lock": threading.Lock(), "agent_ready": None, "auth_user_id": creator,
                             "auth_user_name": ""}
    return transport


def _as(peer, fn, *args, **kwargs):
    from tui_gateway.transport import bind_transport, reset_transport
    token = bind_transport(peer)
    try:
        return fn(*args, **kwargs)
    finally:
        reset_transport(token)


def _respond(server, peer, rid, result=None, error=None):
    frame = {"jsonrpc": "2.0", "id": rid, **({"error": error} if error is not None else {"result": result})}
    return _as(peer, server.dispatch, frame, peer)


def _ask_in_thread(server, method, sid="s1", *, timeout=10, params=None):
    """``server_requests.send_detailed`` on a thread, the way a turn asks; the box gets the outcome."""
    from tui_gateway import server_requests
    box: dict = {}

    def run():
        try:
            box["outcome"] = server_requests.send_detailed(method, sid, params or SECRET_TEXT[method], timeout=timeout)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def _wait_frame(peer, method, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if frames := peer.requests(method):
            return frames[0]
        time.sleep(0.01)
    raise AssertionError(f"no {method} frame reached the peer")


# ── pre_server_request ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", sorted(SECRET_TEXT))
def test_pre_server_request_fires_once_the_frame_is_out_without_the_text(server, hooks, method):
    from tui_gateway import request_hooks
    peer = _Peer("phone")
    _session(server, "s1", peer, creator=ALICE)
    before = int(time.time())
    thread, box = _ask_in_thread(server, method, timeout=60)
    frame = _wait_frame(peer, method)
    (fired,) = hooks.wait("pre_server_request")
    assert fired == {"session_id": "s1", "session_key": "key-s1", "request_id": frame["id"], "method": method,
                     "user_id": ALICE, "expires_at": fired["expires_at"], "reached": 1}
    assert before + 59 <= fired["expires_at"] <= int(time.time()) + 60
    assert tuple(fired) == request_hooks.PRE_KWARGS
    _respond(server, peer, frame["id"], {"value": ANSWER_TEXT, "answer": ANSWER_TEXT})
    thread.join(5)
    assert box["outcome"].status == "answered"
    texts = [t for value in SECRET_TEXT[method].values() for t in (value if isinstance(value, list) else [value])]
    assert not any(text in hooks.every_kwarg for text in [*texts, ANSWER_TEXT])


def test_pre_server_request_has_no_deadline_when_the_wait_has_none(server, hooks):
    peer = _Peer("phone")
    _session(server, "s1", peer)
    thread, _box = _ask_in_thread(server, "clarify", timeout=None)
    frame = _wait_frame(peer, "clarify")
    (fired,) = hooks.wait("pre_server_request")
    assert fired["expires_at"] is None and fired["user_id"] == ""
    _respond(server, peer, frame["id"], {"answer": "x"})
    thread.join(5)


def test_pre_server_request_reports_no_client_when_the_write_failed(server, hooks):
    peer = _Peer("phone")
    peer.write = lambda obj: False
    _session(server, "s1", peer)
    thread, _box = _ask_in_thread(server, "secret", timeout=0.3)
    thread.join(5)
    (fired,) = hooks.wait("pre_server_request")
    assert fired["reached"] == 0


def test_requests_without_a_hook_are_not_announced(server, hooks):
    from tui_gateway import server_requests
    peer = _Peer("phone")
    _session(server, "s1", peer)
    outcome = server_requests.send_detailed("window.read", "s1", {}, timeout=0.2)
    assert outcome.status == "timeout"
    assert hooks.order == []


def test_a_confirm_request_is_announced_by_its_own_hook_not_pre_server_request(server, hooks):
    from tui_gateway import confirm
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, creator=ALICE)
    _as(phone, server.handle_request, {"id": 1, "method": "client.capabilities",
                                       "params": {"server_requests": True, "confirm": ["plain"]}})
    box: dict = {}
    thread = threading.Thread(
        target=lambda: box.update(r=_as(phone, confirm.request, "s1", confirm.build_params(summary="SUMMARY-TEXT-7"))),
        daemon=True)
    thread.start()
    frame = _wait_frame(phone, "confirm")
    (announced,) = hooks.wait("pre_confirm_request")
    assert announced["request_id"] == frame["id"]
    assert hooks.of("pre_server_request") == []
    _respond(server, phone, frame["id"], {"decision": "declined", "method": "tap"})
    thread.join(5)
    (ended,) = hooks.wait("post_server_request")
    assert ended == {"session_id": "s1", "session_key": "key-s1", "request_id": frame["id"], "method": "confirm",
                     "user_id": announced["user_id"], "reason": "answered"}
    assert hooks.order == ["pre_confirm_request", "post_server_request"]
    assert "SUMMARY-TEXT-7" not in hooks.every_kwarg


DRAFT = {"v": 1, "title": "TITLE-TEXT-7", "summary": "SUMMARY-TEXT-7", "expires_at": 1_791_119_400,
         "optional": False, "kind": "mail", "text": "DRAFT-TEXT-7"}


def _ask_gated_in_thread(sid="s1", *, timeout=10, park_seconds=0):
    """``server_requests.send_gated`` for a ``review.draft`` on a thread; the box gets the outcome."""
    from tui_gateway import server_requests
    box: dict = {}

    def run():
        box["outcome"] = server_requests.send_gated(
            "review.draft", sid, DRAFT, timeout=timeout, park_seconds=park_seconds,
            validate=lambda result: None if result.get("decision") in ("approved", "rejected") else "bad_shape")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def test_an_interactive_request_is_announced_by_pre_server_request_without_the_text(server, hooks):
    from tui_gateway import server_requests
    phone = _Peer("phone", ALICE)
    _session(server, "s1", phone, creator=ALICE)
    server_requests.advertise(phone, True, None, requests=["review.draft"])
    before = int(time.time())
    thread, box = _ask_gated_in_thread(timeout=60)
    frame = _wait_frame(phone, "review.draft")
    (fired,) = hooks.wait("pre_server_request")
    assert fired == {"session_id": "s1", "session_key": "key-s1", "request_id": frame["id"],
                     "method": "review.draft", "user_id": ALICE, "expires_at": fired["expires_at"], "reached": 1}
    assert before + 59 <= fired["expires_at"] <= int(time.time()) + 60
    _respond(server, phone, frame["id"], {"decision": "approved", "text": ANSWER_TEXT})
    thread.join(5)
    assert box["outcome"].status == "answered"
    (ended,) = hooks.wait("post_server_request")
    assert ended["reason"] == "answered" and ended["method"] == "review.draft"
    assert not any(text in hooks.every_kwarg for text in ("TITLE-TEXT-7", "SUMMARY-TEXT-7", "DRAFT-TEXT-7",
                                                           ANSWER_TEXT))


def _fake_clock(monkeypatch):
    """Move ``server_requests``' method-gated clock by hand; ``advance`` wakes the waits (no sleeping)."""
    from tui_gateway import server_requests
    state = {"now": 1_000.0}
    monkeypatch.setattr(server_requests, "_monotonic", lambda: state["now"])

    def advance(seconds):
        state["now"] += seconds
        with server_requests._lock:
            for req in server_requests._open.values():
                if req.method_gated:
                    req.event.set()

    return advance


def test_a_parked_interactive_request_is_announced_with_nobody_reached(server, hooks, monkeypatch):
    """The push for a request no capable device was attached for: ``reached: 0``, the deadline is the park's."""
    from tui_gateway import server_requests
    advance = _fake_clock(monkeypatch)
    _session(server, "s1", _Peer("old app"), creator=ALICE)
    before = int(time.time())
    thread, box = _ask_gated_in_thread(timeout=300, park_seconds=60)
    (fired,) = hooks.wait("pre_server_request")
    assert fired["reached"] == 0 and fired["method"] == "review.draft" and fired["user_id"] == ALICE
    assert before + 59 <= fired["expires_at"] <= int(time.time()) + 61
    advance(61)
    thread.join(5)
    assert (box["outcome"].status, box["outcome"].reason) == ("unavailable", "no_capable_client")
    (ended,) = hooks.wait("post_server_request")
    assert ended["reason"] == "no_capable_client"
    assert server_requests.open_request_count() == 0


def test_a_parked_request_reached_later_is_announced_exactly_once(server, hooks):
    from tui_gateway import server_requests
    old = _Peer("old app")
    _session(server, "s1", old, creator=ALICE)
    thread, box = _ask_gated_in_thread(timeout=300, park_seconds=60)
    (fired,) = hooks.wait("pre_server_request")
    phone = _Peer("phone", ALICE)
    server._sessions["s1"]["transport"] = phone
    server_requests.advertise(phone, True, None, requests=["review.draft"])
    listed = _as(phone, server_requests.open_requests, "s1")
    assert [r["id"] for r in listed] == [fired["request_id"]]
    _respond(server, phone, fired["request_id"], {"decision": "approved", "text": ANSWER_TEXT})
    thread.join(5)
    assert box["outcome"].status == "answered"
    hooks.wait("post_server_request")
    assert hooks.order == ["pre_server_request", "post_server_request"]


# ── post_server_request ──────────────────────────────────────────────────────────────────────


def test_post_server_request_after_an_answer_without_the_answer(server, hooks):
    from tui_gateway import request_hooks
    peer = _Peer("phone")
    _session(server, "s1", peer, creator=ALICE)
    thread, _box = _ask_in_thread(server, "sudo")
    frame = _wait_frame(peer, "sudo")
    _respond(server, peer, frame["id"], {"value": ANSWER_TEXT})
    thread.join(5)
    (ended,) = hooks.wait("post_server_request")
    assert ended == {"session_id": "s1", "session_key": "key-s1", "request_id": frame["id"], "method": "sudo",
                     "user_id": ALICE, "reason": "answered"}
    assert tuple(ended) == request_hooks.POST_KWARGS
    assert ANSWER_TEXT not in hooks.every_kwarg and "COMMAND-TEXT-7" not in hooks.every_kwarg


def test_post_server_request_never_overtakes_a_slow_pre_server_request(server, hooks):
    from hermes_cli.plugins import get_plugin_manager
    release = threading.Event()
    order: list[str] = []

    def slow_pre(**kw):
        release.wait(5)
        order.append("pre")

    def post(**kw):
        order.append("post")

    manager = get_plugin_manager()
    manager._hooks["pre_server_request"] = [slow_pre]
    manager._hooks["post_server_request"] = [post]
    peer = _Peer("phone")
    _session(server, "s1", peer)
    thread, _box = _ask_in_thread(server, "secret")
    frame = _wait_frame(peer, "secret")
    _respond(server, peer, frame["id"], {"value": "x"})
    thread.join(5)  # the request is over while the push hook still runs
    time.sleep(0.2)
    assert order == []
    release.set()
    deadline = time.monotonic() + 5
    while len(order) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert order == ["pre", "post"]


def test_every_way_a_request_ends_has_a_reason(server, hooks):
    from tui_gateway import server_requests
    peer = _Peer("phone")
    _session(server, "s1", peer)

    def ended(count):
        deadline = time.monotonic() + 5
        while len(hooks.of("post_server_request")) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return [kw["reason"] for kw in hooks.of("post_server_request")]

    server_requests.send_detailed("secret", "s1", SECRET_TEXT["secret"], timeout=0.1)  # nobody answers
    assert ended(1) == ["timeout"]

    peer.frames.clear()
    thread, _box = _ask_in_thread(server, "secret")
    frame = _wait_frame(peer, "secret")
    server_requests.cancel("s1", reason="interrupted")
    thread.join(5)
    assert ended(2) == ["timeout", "interrupted"]

    peer.frames.clear()
    thread, _box = _ask_in_thread(server, "vault.code")
    frame = _wait_frame(peer, "vault.code")
    _respond(server, peer, frame["id"], error={"code": -32601, "message": "unknown method"})
    thread.join(5)
    assert ended(3) == ["timeout", "interrupted", "error_response"]


def test_post_server_request_fires_when_the_wait_itself_dies(server, hooks):
    from tui_gateway import server_requests
    peer = _Peer("phone")
    _session(server, "s1", peer)
    with patch.object(server_requests, "_await", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            server_requests.send_detailed("sudo", "s1", SECRET_TEXT["sudo"], timeout=5)
    (ended,) = hooks.wait("post_server_request")
    assert ended["reason"] == "interrupted"


# ── nothing registered, and a hook that misbehaves ───────────────────────────────────────────


def test_with_no_plugin_registered_nothing_is_started_and_the_request_is_unchanged(server, hooks):
    from hermes_cli.plugins import get_plugin_manager
    from tui_gateway import request_hooks
    manager = get_plugin_manager()
    for name in ("pre_server_request", "post_server_request", "on_background_complete", "pre_confirm_request"):
        manager._hooks.pop(name, None)
    peer = _Peer("phone")
    _session(server, "s1", peer)
    started: list = []
    real_thread = threading.Thread

    def spy(*args, **kwargs):
        if kwargs.get("name") == "request-hook":
            started.append(kwargs)
        return real_thread(*args, **kwargs)

    with patch.object(request_hooks.threading, "Thread", spy), \
            patch("hermes_cli.plugins.invoke_hook", side_effect=AssertionError("invoke_hook called")) as invoke:
        thread, box = _ask_in_thread(server, "secret")
        frame = _wait_frame(peer, "secret")
        _respond(server, peer, frame["id"], {"value": ANSWER_TEXT})
        thread.join(5)
        time.sleep(0.1)
    assert started == [] and not invoke.called
    assert "error" not in box
    assert box["outcome"].status == "answered" and box["outcome"].result == {"value": ANSWER_TEXT}


@pytest.mark.parametrize("broken", ["callback", "dispatch", "identity"])
def test_a_hook_that_fails_never_changes_what_the_request_returns(server, hooks, broken):
    from hermes_cli.plugins import get_plugin_manager
    from tui_gateway import request_hooks
    manager = get_plugin_manager()

    def boom(**kw):
        raise RuntimeError("plugin bug")

    patches = []
    if broken == "callback":
        manager._hooks["pre_server_request"] = [boom]
        manager._hooks["post_server_request"] = [boom]
    elif broken == "dispatch":
        patches.append(patch("hermes_cli.plugins.invoke_hook", side_effect=RuntimeError("dispatch bug")))
    else:
        patches.append(patch.object(request_hooks, "_identity", side_effect=RuntimeError("identity bug")))
    peer = _Peer("phone")
    _session(server, "s1", peer)
    for p in patches:
        p.start()
    try:
        thread, box = _ask_in_thread(server, "secret")
        frame = _wait_frame(peer, "secret")
        _respond(server, peer, frame["id"], {"value": ANSWER_TEXT})
        thread.join(5)
        time.sleep(0.1)
    finally:
        for p in patches:
            p.stop()
    assert "error" not in box
    assert box["outcome"].status == "answered" and box["outcome"].result == {"value": ANSWER_TEXT}


def test_a_hook_that_hangs_does_not_delay_the_request(server, hooks):
    from hermes_cli.plugins import get_plugin_manager
    release = threading.Event()
    manager = get_plugin_manager()
    manager._hooks["pre_server_request"] = [lambda **kw: release.wait(10)]
    peer = _Peer("phone")
    _session(server, "s1", peer)
    try:
        thread, box = _ask_in_thread(server, "secret")
        frame = _wait_frame(peer, "secret")
        started = time.monotonic()
        _respond(server, peer, frame["id"], {"value": "x"})
        thread.join(5)
        assert not thread.is_alive() and time.monotonic() - started < 2
        assert box["outcome"].status == "answered"
    finally:
        release.set()


# ── on_background_complete ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def side_server(monkeypatch, tmp_path):
    from tui_gateway import server
    monkeypatch.setattr(server, "_emit", lambda *a, **k: True)
    server._sessions["parent"] = {"session_key": "key-parent", "profile_home": str(tmp_path), "cwd": str(tmp_path),
                                  "auth_user_id": ALICE, "auth_user_name": ""}
    yield server
    server._sessions.pop("parent", None)


def _run_side(server, body, event="background.complete", tmp_path=None):
    session = server._sessions["parent"]
    server._spawn_side_agent("r", session, "bg_abc123", "parent", event, body, cwd=session["cwd"])
    for thread in threading.enumerate():
        if thread.name == "side-agent-bg_abc123":
            thread.join(10)


def test_on_background_complete_fires_after_the_task_without_its_result(side_server, hooks):
    from tui_gateway import request_hooks
    _run_side(side_server, lambda: "RESULT-TEXT-7")
    (fired,) = hooks.wait("on_background_complete")
    assert fired == {"session_id": "parent", "session_key": "key-parent", "task_id": "bg_abc123", "user_id": ALICE}
    assert tuple(fired) == request_hooks.BACKGROUND_KWARGS
    assert "RESULT-TEXT-7" not in hooks.every_kwarg


def test_on_background_complete_fires_for_a_failed_task_too(side_server, hooks):
    def failing():
        raise RuntimeError("ERROR-TEXT-7")

    _run_side(side_server, failing)
    (fired,) = hooks.wait("on_background_complete")
    assert fired["task_id"] == "bg_abc123"
    assert "ERROR-TEXT-7" not in hooks.every_kwarg


def test_other_side_agents_do_not_fire_it(side_server, hooks):
    _run_side(side_server, lambda: "x", event="btw.complete")
    time.sleep(0.2)
    assert hooks.of("on_background_complete") == []


def test_on_background_complete_survives_a_plugin_that_raises(side_server, hooks):
    from hermes_cli.plugins import get_plugin_manager

    def boom(**kw):
        raise RuntimeError("plugin bug")

    get_plugin_manager()._hooks["on_background_complete"] = [boom]
    emitted = []
    with patch.object(side_server, "_emit", lambda *a, **k: emitted.append(a)):
        _run_side(side_server, lambda: "done")
    assert emitted and emitted[0][0] == "background.complete" and emitted[0][2]["text"] == "done"


# ── declared, bounded, documented ────────────────────────────────────────────────────────────


def test_the_hooks_are_declared_bounded_and_documented_with_the_kwargs_they_fire():
    from pathlib import Path

    from hermes_cli.plugins import VALID_HOOKS
    from hermes_cli.plugins_dispatch import _HOOK_TIMEOUT_BOUNDED_HOOKS
    from tui_gateway import request_hooks
    root = Path(__file__).resolve().parents[2]
    hooks_md = (root / "website/docs/user-guide/features/hooks.md").read_text()
    plugins_md = (root / "website/docs/user-guide/features/plugins.md").read_text()
    for hook, kwargs in (("pre_server_request", request_hooks.PRE_KWARGS),
                         ("post_server_request", request_hooks.POST_KWARGS),
                         ("on_background_complete", request_hooks.BACKGROUND_KWARGS)):
        assert hook in VALID_HOOKS and hook in _HOOK_TIMEOUT_BOUNDED_HOOKS
        row = next(line for line in hooks_md.splitlines() if line.startswith(f"| `{hook}` |"))
        assert all(f"`{name}`" in row for name in kwargs)
        section = hooks_md.split(f"### `{hook}`", 1)[1].split("\n---\n", 1)[0]
        assert all(f"`{name}`" in section for name in kwargs)
        assert f"`{hook}`" in plugins_md


def test_covers_is_clarify_secret_sudo_the_vault_and_the_interactive_methods_only():
    from tui_gateway import request_hooks
    from tui_gateway.contracts import registry as contracts
    from tui_gateway.contracts.server_requests import INTERACTIVE_METHODS
    covered = {method for method in contracts.SERVER_REQUESTS if request_hooks.covers(method)}
    assert covered == {"clarify", "secret", "sudo", "vault.unlock_prompt", "vault.save_login", "vault.code",
                       *INTERACTIVE_METHODS}
    assert {"input.form", "input.file", "review.draft", "review.diff"} <= covered
    assert not request_hooks.covers("confirm") and not request_hooks.covers("approval")
