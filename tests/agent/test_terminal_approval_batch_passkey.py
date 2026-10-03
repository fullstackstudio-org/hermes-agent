"""The desktop terminal batch with an operator passkey rule (``tools/passkey_policy.py``), on the real batch.

The batch runs every command guard twice: once to prepare the approvals, once when the command runs. A
forced passkey confirmation is decided in the first pass and that WHOLE outcome lives on the batch's slot:
a stopped batch takes a confirmation with it (the same call later asks again), and a decline in the first
pass is the run pass's answer (never asked a second time, never run).
"""

import copy
import json
import queue
import threading
from contextlib import ExitStack
from types import SimpleNamespace

from gateway.session_context import clear_session_vars
from tests.agent.test_terminal_approval_batch import _agent, _call
from tools import approval, passkey_policy
from tools.thread_context import propagate_context_to_thread

PUSH = "printf pushed > pushed.txt"
FIRST = "rm -rf absent; printf first > first.txt"


class Phone:
    """The conversation's strong-confirm callback: answers the scripted outcomes in order."""

    def __init__(self, *outcomes: str):
        self.outcomes = list(outcomes)
        self.texts: list[dict] = []
        self.asked = queue.Queue()

    def __call__(self, text):
        self.texts.append(text)
        outcome = self.outcomes.pop(0)
        self.asked.put(outcome)
        return {"outcome": outcome, "verified": outcome == "confirmed",
                "method": "passkey" if outcome == "confirmed" else "tap"}


def test_a_prepared_passkey_outcome_lives_and_dies_with_its_batch(tmp_path, monkeypatch):
    from tools.terminal_scope import reset_terminal_scope, set_terminal_scope
    from tools.terminal_tool_lifecycle import cleanup_vm

    monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    monkeypatch.setattr("tools.approval_context._get_approval_mode", lambda: "manual")
    monkeypatch.setattr("tools.approval._tirith_scan", lambda command: {"action": "allow"})
    monkeypatch.setattr("agent.title_generator.maybe_auto_title", lambda *a, **kw: None)
    require = {"commands": ["printf pushed*"], "smart_denied": False, "approvals": False, "tools": []}
    monkeypatch.setattr(passkey_policy, "_config",
                        lambda: copy.deepcopy({"confirm": {"passkey": {"require": require}}}))
    key = "passkey-terminal-batch"
    published = queue.Queue()
    errors: list = []
    phone = Phone("confirmed", "confirmed", "declined")
    approval.register_gateway_notify(key, published.put)
    passkey_policy.register_strong_confirm(key, phone)
    from tui_gateway import server

    def run(target, batch_calls, rows):
        try:
            target._execute_tool_calls(SimpleNamespace(tool_calls=batch_calls), rows, key)
        except BaseException as exc:
            errors.append(exc)

    def start(target, batch_calls, rows):
        worker = threading.Thread(target=propagate_context_to_thread(lambda: run(target, batch_calls, rows)),
                                  daemon=True)
        worker.start()
        return worker

    agents = []

    def fresh_agent():
        agent = _agent()
        agent._flush_messages_to_session_db = lambda *a, **kw: True
        agents.append(agent)
        return agent

    first_agent = fresh_agent()
    monkeypatch.setattr(server, "_sessions", {key: {
        "session_key": key, "source": "desktop", "agent": first_agent, "cwd": str(tmp_path)}})
    tokens = server._set_session_context(key)
    workers = []
    with ExitStack() as scope:
        scope.callback(reset_terminal_scope, set_terminal_scope({"TERMINAL_ENV": "local",
                                                                 "TERMINAL_CWD": str(tmp_path)}))
        try:
            # 1. The batch prepares: the ordinary approval for the first call is published, the second call's
            #    passkey is confirmed. Then the person stops the turn before anything runs.
            rows: list = []
            workers.append(start(first_agent, [_call("first", FIRST), _call("second", PUSH)], rows))
            published.get(timeout=10)
            assert phone.asked.get(timeout=10) == "confirmed"
            first_agent.interrupt("stop")
            workers[-1].join(10)
            assert not workers[-1].is_alive() and errors == []
            assert not (tmp_path / "pushed.txt").exists() and not (tmp_path / "first.txt").exists()

            # 2. The same call later, on its own: the stopped batch's confirmation is gone; it asks again.
            single = fresh_agent()
            server._sessions[key]["agent"] = single
            rows = []
            workers.append(start(single, [_call("second", PUSH)], rows))
            workers[-1].join(15)
            assert phone.asked.get(timeout=1) == "confirmed"
            assert len(phone.texts) == 2 and (tmp_path / "pushed.txt").exists()
            # Where it runs: resolved when run on its own; unknown yet while a batch prepares.
            assert phone.texts[1]["summary"].startswith(f"In {tmp_path}: ")
            assert "the directory the session is in when" in phone.texts[0]["summary"]
            (tmp_path / "pushed.txt").unlink()

            # 3. The same batch again: the passkey is declined while preparing; the run pass takes that
            #    decline (the person is not asked a second time) and the push never runs.
            again = fresh_agent()
            server._sessions[key]["agent"] = again
            rows = []
            workers.append(start(again, [_call("first", FIRST), _call("second", PUSH)], rows))
            request = published.get(timeout=10)
            assert phone.asked.get(timeout=10) == "declined"
            assert approval.resolve_gateway_approval(key, "once", request_id=request["request_id"]) == 1
            workers[-1].join(15)
            assert not workers[-1].is_alive() and errors == []
            assert len(phone.texts) == 3
            assert (tmp_path / "first.txt").exists() and not (tmp_path / "pushed.txt").exists()
            pushed_row = next(r for r in rows if r["tool_call_id"] == "second")
            assert "declined" in json.dumps(json.loads(pushed_row["content"]))
            assert approval.list_gateway_approvals(key) == []
        finally:
            for agent in agents:
                agent.interrupt("test cleanup")
            approval.unregister_gateway_notify(key)
            passkey_policy.unregister_strong_confirm(key)
            for worker in workers:
                worker.join(5)
            cleanup_vm(key)
            clear_session_vars(tokens)
