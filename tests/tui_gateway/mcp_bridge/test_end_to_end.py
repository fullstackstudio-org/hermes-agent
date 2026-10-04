"""The MCP endpoint end to end: the SDK's own client, over ASGI, against the real dashboard app.

A token is minted through the real authorization server (registration, authorize, consent behind the
signed-in cookie, code, token: the F2 fixtures), the dashboard's lifespan runs the MCP server's session
manager, and every tool reaches the real gateway handlers as the person with the agent marker, with a
scripted agent behind each chat. Every payload is a harmless marker.
"""

from __future__ import annotations

import json
import threading
import time

import anyio
import anyio.to_thread
import httpx2
import pytest
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from hermes_cli import web_server
from hermes_cli.dashboard_auth.mcp import mount
from tests.hermes_cli.dashboard_auth.mcp.test_routes import (  # noqa: F401 - fixtures
    BASE, CLIENT_NAME, audit_lines, make_gateway)
from tui_gateway.mcp_bridge import limits, server as bridge_server
import tui_gateway.server as server

PERSON = ("stub:alice", "Alice")
PREFIX = f"[Answered by the agent «{CLIENT_NAME}» through MCP, not by «Alice»] "


@pytest.fixture
def endpoint(make_gateway, live_gateway):  # noqa: F811
    bridge_server.reset_for_tests()
    gw = make_gateway()
    flow = gw.connect()
    yield gw, flow, live_gateway
    bridge_server.reset_for_tests()


def _payload(result) -> dict:
    return json.loads(result.content[0].text)


class Session:
    """One SDK client session over ASGI to the dashboard app, with the lifespan's session manager running."""

    def __init__(self, client: Client, http: httpx2.AsyncClient):
        self.client, self.http = client, http

    async def call(self, name, arguments=None, **kw):
        result = await self.client.call_tool(name, arguments or {}, **kw)
        return result.is_error, _payload(result)


def run(token: str, body, *, mode: str = "auto"):
    """Run ``await body(session)`` with a connected client; returns what it returns."""

    async def main():
        async with mount.lifespan(web_server.app):
            http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=web_server.app), base_url=BASE,
                                      headers={"Authorization": f"Bearer {token}"}, timeout=30)
            async with http:
                transport = streamable_http_client(f"{BASE}/mcp", http_client=http, terminate_on_close=False)
                async with Client(transport, mode=mode) as client:
                    return await body(Session(client, http))

    return anyio.run(main)


def _in_thread(fn, *args):
    worker = threading.Thread(target=fn, args=args, daemon=True)
    worker.start()
    return worker


# ── the flow ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_an_agent_lists_bots_starts_a_chat_and_gets_a_reply(endpoint, mode):
    gw, flow, live = endpoint

    async def body(s: Session):
        tools = {tool.name for tool in (await s.client.list_tools()).tools}
        assert tools == {"whoami", "bots_list", "chats_list", "chat_new", "chat_open", "chat_history", "bot_prompt",
                         "bot_wait", "bot_interrupt", "requests_open", "clarify_answer"}
        error, me = await s.call("whoami")
        assert not error and me["person"] == {"id": PERSON[0], "name": PERSON[1]}
        assert me["agent"]["client"] == CLIENT_NAME and me["gateway"]["endpoint_url"] == f"{BASE}/mcp"
        error, bots = await s.call("bots_list")
        assert not error and [b["bot"] for b in bots["bots"]] == ["default"]
        error, chat = await s.call("chat_new", {"bot": "default", "title": "marker title"})
        assert not error, chat
        error, reply = await s.call("bot_prompt", {"bot": "default", "chat_id": chat["chat_id"], "text": "marker reply"})
        assert not error, reply
        return chat["chat_id"], reply

    chat_id, reply = run(flow.tokens["access_token"], body, mode=mode)
    assert (reply["status"], reply["reply_text"], reply["chat_id"]) == ("done", "marker reply done", chat_id)
    [row] = [r for r in live.db.get_messages(chat_id) if r["role"] == "user"]
    assert row["display_metadata"]["author"] == {"id": PERSON[0], "name": PERSON[1],
                                                 "via": {"kind": "mcp", "client": CLIENT_NAME}}


def test_history_rows_carry_via_and_chats_list_shows_the_chat(endpoint):
    gw, flow, live = endpoint

    async def body(s: Session):
        _, reply = await s.call("bot_prompt", {"bot": "default", "text": "marker reply"})
        error, history = await s.call("chat_history", {"chat_id": reply["chat_id"]})
        assert not error, history
        error, chats = await s.call("chats_list", {"bot": "default"})
        assert not error, chats
        return reply, history, chats

    reply, history, chats = run(flow.tokens["access_token"], body)
    [user] = [row for row in history["rows"] if row["role"] == "user"]
    assert user["text"] == "marker reply"
    assert user["author"] == {"id": PERSON[0], "name": PERSON[1], "via": {"kind": "mcp", "client": CLIENT_NAME}}
    assert [c["chat_id"] for c in chats["chats"]] == [reply["chat_id"]]
    assert chats["chats"][0]["opened_via_mcp"] is True


def test_a_clarify_is_answered_through_mcp_with_the_agents_prefix(endpoint):
    gw, flow, live = endpoint

    async def body(s: Session):
        _, waiting = await s.call("bot_prompt", {"bot": "default", "text": "marker clarify"})
        assert waiting["status"] == "waiting_for_person", waiting
        [request] = waiting["open_requests"]
        assert request["kind"] == "clarify" and request["answerable_via_mcp"] is True
        error, answered = await s.call("clarify_answer", {"chat_id": waiting["chat_id"],
                                                          "request_id": request["request_id"], "answers": "one"})
        assert not error and answered["ok"] is True, answered
        _, done = await s.call("bot_wait", {"chat_id": waiting["chat_id"], "turn_id": waiting["turn_id"]})
        return waiting, done

    waiting, done = run(flow.tokens["access_token"], body)
    assert (done["status"], done["reply_text"]) == ("done", "marker clarified")
    assert live.agents[waiting["chat_id"]].clarify_answers == [PREFIX + "one"]


def test_an_approval_waits_for_the_person_and_cannot_be_answered_through_mcp(endpoint):
    gw, flow, live = endpoint
    from .conftest import AppPeer

    app = AppPeer(user=(PERSON[0], PERSON[1]))

    async def body(s: Session):
        _, waiting = await s.call("bot_prompt", {"bot": "default", "text": "marker approval"})
        assert waiting["status"] == "waiting_for_person", waiting
        [request] = waiting["open_requests"]
        assert (request["kind"], request["answerable_via_mcp"]) == ("approval", False)
        assert request["command"] == "echo marker"
        error, listed = await s.call("requests_open", {"chat_id": waiting["chat_id"]})
        assert not error and [r["request_id"] for r in listed["requests"]] == [request["request_id"]]
        error, refused = await s.call("clarify_answer", {"chat_id": waiting["chat_id"],
                                                         "request_id": request["request_id"], "answers": "once"})
        assert error and refused["error"]["code"] == "not_answerable"
        # The person answers in their own app.
        resumed = await anyio.to_thread.run_sync(app.call, "session.resume", {
            "session_id": waiting["chat_id"], "profile": "default", "omit_messages": True})
        assert "error" not in resumed, resumed
        server.dispatch({"jsonrpc": "2.0", "id": request["request_id"], "result": {"choice": "once"}}, app)
        _, done = await s.call("bot_wait", {"chat_id": waiting["chat_id"], "turn_id": waiting["turn_id"]})
        return waiting, done

    waiting, done = run(flow.tokens["access_token"], body)
    assert (done["status"], done["reply_text"]) == ("done", "marker approved")
    assert live.agents[waiting["chat_id"]].approval_results == [{"choice": "once"}]


def test_progress_reaches_a_client_that_asked_and_the_agent_stops_its_turn(endpoint):
    gw, flow, live = endpoint
    seen: list = []

    async def progress(value, total, message):
        seen.append((value, message))

    async def body(s: Session):
        _, running = await s.call("bot_prompt", {"bot": "default", "text": "marker gated", "wait_seconds": 2},
                                  progress_callback=progress)
        assert running["status"] == "running", running
        assert running["partial_text"].startswith("marker partial")
        error, stopped = await s.call("bot_interrupt", {"chat_id": running["chat_id"]})
        assert not error and stopped == {"ok": True, "was_running": True}, stopped
        _, ended = await s.call("bot_wait", {"chat_id": running["chat_id"], "turn_id": running["turn_id"]})
        return ended

    ended = run(flow.tokens["access_token"], body)
    assert ended["status"] == "interrupted", ended
    assert seen and seen[0][1].startswith("marker partial"), seen


def test_a_busy_chat_queues_the_prompt_and_never_reports_the_persons_turn(endpoint):
    gw, flow, live = endpoint
    from .conftest import AppPeer

    app = AppPeer(user=(PERSON[0], PERSON[1]))

    async def body(s: Session):
        _, chat = await s.call("chat_new", {"bot": "default"})
        chat_id = chat["chat_id"]
        sid, _session = live.session_of(chat_id)
        await anyio.to_thread.run_sync(app.call, "session.resume", {
            "session_id": chat_id, "profile": "default", "omit_messages": True})
        agent = live.agent_of(chat_id)
        # The person's own turn runs (gated) when the agent's prompt arrives.
        answer = await anyio.to_thread.run_sync(app.call, "prompt.submit", {"session_id": sid, "text": "marker gated"})
        assert answer["result"]["status"] == "streaming", answer
        _, queued = await s.call("bot_prompt", {"bot": "default", "chat_id": chat_id, "text": "marker reply",
                                                "wait_seconds": 1})
        assert (queued["status"], queued["queue_position"]) == ("queued", 1), queued
        assert "partial_text" not in queued  # the person's partial reply is not the agent's
        agent.gate.set()
        _, done = await s.call("bot_wait", {"chat_id": chat_id, "turn_id": queued["turn_id"]})
        return done

    done = run(flow.tokens["access_token"], body)
    assert (done["status"], done["reply_text"]) == ("done", "marker reply done"), done


# ── limits and revocation ─────────────────────────────────────────────────────────────────────


def test_too_many_calls_are_rate_limited(endpoint, monkeypatch):
    gw, flow, live = endpoint
    monkeypatch.setattr(limits, "TOOL_CALLS", limits.WindowLimiter(2, 60.0))

    async def body(s: Session):
        return [await s.call("whoami") for _ in range(3)]

    calls = run(flow.tokens["access_token"], body)
    assert [error for error, _ in calls] == [False, False, True]
    refused = calls[2][1]["error"]
    assert refused["code"] == "rate_limited" and 1 <= refused["retry_after_seconds"] <= 60
    events = [line for line in audit_lines() if line["event"] == "mcp_rate_limited"]
    assert events and events[-1]["tool"] == "whoami" and events[-1]["grant_id"]


def test_a_revoked_grant_gets_401_and_the_log_holds_no_text_or_token(endpoint):
    gw, flow, live = endpoint

    async def body(s: Session):
        error, reply = await s.call("bot_prompt", {"bot": "default", "text": "marker reply"})
        assert not error
        [grant] = gw.store.grants_for(PERSON[0])
        gw.store.revoke_grant(grant.id, by="operator")
        response = await s.http.post("/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "tools/list"},
                                     headers={"Accept": "application/json, text/event-stream"})
        return response

    response = run(flow.tokens["access_token"], body)
    assert response.status_code == 401
    assert 'resource_metadata="' in response.headers["www-authenticate"]
    log = json.dumps(audit_lines())
    calls = [line for line in audit_lines() if line["event"] == "mcp_tool_call"]
    assert {line["tool"] for line in calls} >= {"bot_prompt"}
    assert all(line["user_id"] == PERSON[0] and line["client_name"] == CLIENT_NAME for line in calls)
    for secret in ("marker reply", "marker reply done", flow.tokens["access_token"], flow.tokens["refresh_token"]):
        assert secret not in log


def test_a_dashboard_whose_lifespan_did_not_start_the_server_answers_503(endpoint):
    gw, flow, live = endpoint
    response = gw.client.post("/mcp", headers={"Authorization": f"Bearer {flow.tokens['access_token']}",
                                               "Accept": "application/json, text/event-stream"},
                              json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert (response.status_code, response.json()["error"]) == (503, "bridge_not_ready")
    time.sleep(0)
