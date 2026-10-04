"""The MCP tools over the real gateway handlers, without HTTP: what each tool may see and do (plan D7-D11).

Pinned here: a chat-scoped tool acts only on chats this person opened through MCP, and ``chats_list`` shows
no other person's chats; ``bot_interrupt`` leaves a turn the agent did not start alone; a turn the gateway no
longer knows (a restart) is waited on again or reported without claiming a reply; a new chat that expired
before its first prompt is ``not_found``; a submit during a restart is ``gateway_restarting``; the running-turn
limit, scopes, the wait cap, the result size cap, and what ``instructions`` and the tool descriptions say.
Every payload is a harmless marker.
"""

from __future__ import annotations

import json
import time

import anyio
import pytest

from hermes_cli.dashboard_auth.mcp.settings import SCOPES, MCPSettings
from hermes_cli.dashboard_auth.mcp.store import MCPStore
from tui_gateway.mcp_bridge import limits, server as bridge_server, tools, turns
from tui_gateway.mcp_bridge.tools import Bridge, Caller, ToolFailure
import tui_gateway.server as server

from .conftest import AppPeer, CLIENT

ROBIN = Caller(login="oidc:user-a", provider="oidc", user_id="user-a", name="Robin", client=CLIENT,
               grant_id="grant-g1", scopes=frozenset(SCOPES), ip="203.0.113.7")
SAM = Caller(login="oidc:user-b", provider="oidc", user_id="user-b", name="Sam", client=CLIENT,
             grant_id="grant-g2", scopes=frozenset(SCOPES), ip="203.0.113.8")


@pytest.fixture
def bridge(tmp_path, live_gateway):
    audits: list = []
    store = MCPStore(tmp_path / "mcp.db")
    b = Bridge(store=store, settings=MCPSettings(enabled=True), endpoint_url="https://gw.example.invalid/mcp",
               audit=lambda event, **fields: audits.append((event, fields)))
    b.audits = audits
    b.live = live_gateway
    bridge_server.reset_for_tests()
    yield b
    bridge_server.reset_for_tests()


def _fail(fn, *args, **kwargs) -> ToolFailure:
    with pytest.raises(ToolFailure) as caught:
        fn(*args, **kwargs)
    return caught.value


def _app_turn(bridge, chat_id, text="marker gated", user=("oidc:user-a", "Robin")):
    """The person's own app opens the chat and starts a turn in it."""
    app = AppPeer(user=user)
    resumed = app.call("session.resume", {"session_id": chat_id, "profile": "default", "omit_messages": True})
    sid = resumed["result"]["session_id"]
    answer = app.call("prompt.submit", {"session_id": sid, "text": text})
    assert answer["result"]["status"] == "streaming", answer
    return app, sid


# ── what the agent may see (D10) ────────────────────────────────────────────────────────────


def test_chat_tools_act_only_on_chats_this_person_opened_through_mcp(bridge):
    robins = tools.bot_prompt(bridge, ROBIN, "default", "marker reply")
    assert robins["status"] == "done"
    for fn, args in ((tools.chat_history, ()), (tools.requests_open, ()), (tools.bot_interrupt, ()),
                     (tools.clarify_answer, ("rq", "x"))):
        assert _fail(fn, bridge, SAM, robins["chat_id"], *args).code == "not_found"
    # Sam's own listing has none of Robin's chats, MCP-opened or live.
    assert tools.chats_list(bridge, SAM)["chats"] == []
    listed = tools.chats_list(bridge, ROBIN)["chats"]
    assert [c["chat_id"] for c in listed] == [robins["chat_id"]]


def test_chat_open_runs_the_apps_access_rule_and_is_audited(bridge):
    robins = tools.bot_prompt(bridge, ROBIN, "default", "marker reply")
    opened = tools.chat_open(bridge, ROBIN, "default", robins["chat_id"])
    assert opened["chat_id"] == robins["chat_id"] and opened["open_requests"] == []
    events = [fields for event, fields in bridge.audits if event == "mcp_chat_opened"]
    assert [e["how"] for e in events] == ["new", "open"]
    assert all("text" not in e for e in events)
    assert _fail(tools.chat_open, bridge, ROBIN, "default", "20990101_000000_nochat").code == "not_found"
    assert _fail(tools.chat_open, bridge, ROBIN, "no-such-bot", robins["chat_id"]).code == "not_found"


# ── turns ───────────────────────────────────────────────────────────────────────────────────


def test_bot_interrupt_leaves_a_turn_the_agent_did_not_start_alone(bridge):
    chat = tools.chat_new(bridge, ROBIN, "default")["chat_id"]
    _app, sid = _app_turn(bridge, chat)
    agent = bridge.live.agent_of(chat)
    assert tools.bot_interrupt(bridge, ROBIN, chat) == {
        "ok": False, "was_running": True, "reason": "the running turn was not started by this agent"}
    assert agent._interrupt_requested is False
    agent.gate.set()


def test_a_turn_the_gateway_no_longer_knows_is_waited_on_or_reported_without_claiming_a_reply(bridge):
    first = tools.bot_prompt(bridge, ROBIN, "default", "marker gated", wait_seconds=0)
    assert first["status"] == "running"
    turns.reset_for_tests()  # what a restart leaves: no watch knows the turn
    again = tools.bot_wait(bridge, ROBIN, first["chat_id"], first["turn_id"], wait_seconds=0)
    assert (again["status"], again["turn_known"], again["retry_after_seconds"]) == ("restarted", False, 5)
    bridge.live.agent_of(first["chat_id"]).gate.set()
    deadline = time.monotonic() + 5
    while bridge.live.session_of(first["chat_id"])[1].get("running") and time.monotonic() < deadline:
        time.sleep(0.01)
    ended = tools.bot_wait(bridge, ROBIN, first["chat_id"], first["turn_id"], wait_seconds=0)
    assert (ended["status"], ended["turn_known"]) == ("done", False)
    assert "reply_text" not in ended and "latest_reply" in ended


def test_a_new_chat_that_expired_before_its_first_prompt_is_not_found(bridge):
    chat = tools.chat_new(bridge, ROBIN, "default", title="marker title")["chat_id"]
    tools._drop_draft((ROBIN.login, chat))
    sid, _session = bridge.live.session_of(chat)
    server._sessions.pop(sid)  # what the reaper does to a clientless chat with no stored row
    failure = _fail(tools.bot_prompt, bridge, ROBIN, "default", "marker reply", chat_id=chat)
    assert failure.code == "not_found" and "no longer exists" in failure.message
    # And it is not listed.
    assert chat not in [c["chat_id"] for c in tools.chats_list(bridge, ROBIN)["chats"]]


def test_a_new_chat_is_held_open_until_its_first_prompt(bridge):
    chat = tools.chat_new(bridge, ROBIN, "default")["chat_id"]
    assert (ROBIN.login, chat) in tools._drafts
    done = tools.bot_prompt(bridge, ROBIN, "default", "marker reply", chat_id=chat)
    assert (done["status"], done["chat_id"]) == ("done", chat)
    assert (ROBIN.login, chat) not in tools._drafts


def test_a_submit_while_the_gateway_restarts_is_gateway_restarting(bridge, monkeypatch):
    from tui_gateway import shutdown_drain

    from .test_turns import _refuse_admission

    chat = tools.chat_new(bridge, ROBIN, "default")["chat_id"]
    monkeypatch.setattr(server, "_shutdown_drain_active", lambda: True)
    monkeypatch.setattr(shutdown_drain, "_shutdown_drain_active", lambda: True)
    monkeypatch.setattr(server, "_session_turn_admission", _refuse_admission)
    failure = _fail(tools.bot_prompt, bridge, ROBIN, "default", "marker reply", chat_id=chat)
    assert failure.code == "gateway_restarting" and failure.extra["retry_after_seconds"] > 0


def test_clarify_answer_answers_only_a_clarify_of_this_chat(bridge):
    waiting = tools.bot_prompt(bridge, ROBIN, "default", "marker clarify")
    other = tools.chat_new(bridge, ROBIN, "default")["chat_id"]
    [request] = waiting["open_requests"]
    assert _fail(tools.clarify_answer, bridge, ROBIN, other, request["request_id"], "one").code == "not_found"
    assert _fail(tools.clarify_answer, bridge, ROBIN, waiting["chat_id"], request["request_id"], 3).code == "bad_request"
    assert tools.clarify_answer(bridge, ROBIN, waiting["chat_id"], request["request_id"], "one")["ok"] is True


# ── limits and scopes ─────────────────────────────────────────────────────────────────────────


def test_the_running_turn_limit_counts_the_grants_unfinished_turns(bridge):
    first = tools.bot_prompt(bridge, ROBIN, "default", "marker gated", wait_seconds=0)
    assert limits.running_turns(ROBIN.grant_id) == 1
    refusal = limits.check_running(ROBIN.grant_id, 1)
    assert refusal is not None and refusal.code == "busy"
    assert limits.check_running(SAM.grant_id, 1) is None
    bridge.live.agent_of(first["chat_id"]).gate.set()
    assert tools.bot_wait(bridge, ROBIN, first["chat_id"], first["turn_id"])["status"] == "done"
    assert limits.check_running(ROBIN.grant_id, 1) is None


def test_prompts_are_limited_per_grant(monkeypatch):
    monkeypatch.setattr(limits, "PROMPTS", limits.WindowLimiter(2, 600.0))
    assert limits.check_prompt("g1") is None and limits.check_prompt("g1") is None
    refusal = limits.check_prompt("g1")
    assert refusal.code == "rate_limited" and 1 <= refusal.retry_after_seconds <= 600
    assert limits.check_prompt("g2") is None


def test_a_tool_outside_the_grants_scopes_is_forbidden(bridge, monkeypatch):
    reader = Caller(**{**ROBIN.__dict__, "scopes": frozenset({"bots:read"})})
    monkeypatch.setattr(bridge_server, "caller_from_token", lambda: reader)
    endpoint = bridge_server.Endpoint(bridge)
    result = anyio.run(lambda: endpoint.run(None, "bot_prompt", "bots:prompt", tools.bot_prompt, "default", "x"))
    assert result.is_error and json.loads(result.content[0].text)["error"]["code"] == "forbidden"
    [(event, fields)] = [a for a in bridge.audits if a[0] == "mcp_tool_call"]
    assert (fields["outcome"], fields["reason"], fields["tool"]) == ("refused", "forbidden", "bot_prompt")


def test_without_a_verified_token_a_tool_is_unauthenticated(bridge, monkeypatch):
    monkeypatch.setattr(bridge_server, "caller_from_token", lambda: None)
    result = anyio.run(lambda: bridge_server.Endpoint(bridge).run(None, "whoami", None, tools.whoami))
    assert json.loads(result.content[0].text)["error"]["code"] == "unauthenticated"


def test_wait_seconds_is_capped_at_90():
    assert tools._wait_seconds(500) == 90 and tools._wait_seconds(-3) == 0 and tools._wait_seconds("x") == 60


def test_a_result_is_cut_to_one_mebibyte():
    rows = [{"row_id": i, "text": "m" * 8000} for i in range(200)]
    text = bridge_server._fit({"rows": rows, "has_more": False})
    data = json.loads(text)
    assert len(text.encode()) <= bridge_server.RESULT_MAX_BYTES
    assert data["result_truncated"] is True and data["has_more"] is True and data["rows"][-1]["row_id"] == 199


# ── what the agent is told ────────────────────────────────────────────────────────────────────


def test_instructions_and_descriptions_say_what_mcp_cannot_do():
    text = bridge_server.INSTRUCTIONS
    for phrase in ("untrusted", "cannot do through MCP", "restarted", "bot_wait again", "at most 90",
                   "provide secrets", "approve", "passkey"):
        assert phrase in text, phrase
    assert "example" not in text and "Robin" not in text
    server_ = bridge_server.build_server(bridge_server.Endpoint(None))
    described = {t.name: t.description for t in server_._tool_manager.list_tools()}
    assert set(described) == {"whoami", "bots_list", "chats_list", "chat_new", "chat_open", "chat_history",
                              "bot_prompt", "bot_wait", "bot_interrupt", "requests_open", "clarify_answer"}
    for name in ("bots_list", "chats_list", "chat_open", "chat_history", "requests_open", "bot_prompt", "bot_wait"):
        assert "untrusted" in described[name], name
    assert "restarted" in described["bot_wait"] and "at most 90" in described["bot_prompt"]
