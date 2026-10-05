"""``account.usage``: provider account limits as fields, scoped to the profile the call names.

The view (shape, cache, bound) has its own tests in ``tests/agent/test_account_usage_view.py``; here the RPC:
which providers a profile's config names, whose credentials the fetch runs under, the contract, the refusals.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

import tui_gateway.server as server
from agent import account_usage, account_usage_view as view
from agent.account_usage import AccountUsageSnapshot, AccountUsageWindow
from agent.secret_scope import get_secret, set_multiplex_active
from hermes_constants import get_hermes_home
from tui_gateway.transport import bind_transport, reset_transport

MARKER = "harmless-usage-marker-0001"


class _WS:
    def __init__(self, identity=None):
        if identity is not None:
            self.auth_identity = identity

    def write(self, obj):
        return True

    def close(self):
        pass


def _rpc(params, method="account.usage", transport=None):
    token = bind_transport(transport) if transport is not None else None
    try:
        return server.handle_request({"id": 1, "method": method, "params": params})
    finally:
        if token is not None:
            reset_transport(token)


@pytest.fixture
def homes(tmp_path, monkeypatch):
    launch = tmp_path / ".hermes"
    work = launch / "profiles" / "work"
    for home, provider, fallbacks, key in ((launch, "anthropic", [], "launch-key"),
                                           (work, "openai-codex", [{"provider": "openrouter", "model": "m"}], "work-key")):
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.yaml").write_text(yaml.safe_dump(
            {"model": {"provider": provider, "default": "m"}, "fallback_providers": fallbacks}), encoding="utf-8")
        (home / ".env").write_text(f"USAGE_PROBE_KEY={key}\n", encoding="utf-8")
    monkeypatch.setattr(server, "_hermes_home", launch)
    monkeypatch.setenv("HERMES_HOME", str(launch))
    monkeypatch.setenv("USAGE_PROBE_KEY", "launch-key")
    monkeypatch.setattr(server, "_profile_home", lambda name: work if (name or "").strip() == "work" else None)
    monkeypatch.setattr(server, "profile_name_for_home", lambda home: "work" if home and Path(home) == work else None)
    monkeypatch.setattr(server, "_current_profile_name", lambda: "default")
    server._cfg_cache = server._cfg_sig = server._cfg_path = None
    view.reset_for_tests()
    set_multiplex_active(True)
    yield launch, work
    set_multiplex_active(False)
    view.reset_for_tests()
    server._cfg_cache = server._cfg_sig = server._cfg_path = None


def _fetcher(calls):
    """A fetch that reports the home and secret it ran under, in the plan field."""
    def fetch(provider):
        calls.append(provider)
        plan = f"{get_hermes_home().name}|{get_secret('USAGE_PROBE_KEY')}"
        return AccountUsageSnapshot(provider=provider, source="test", fetched_at=datetime(2026, 10, 5, tzinfo=timezone.utc),
                                    plan=plan, windows=(AccountUsageWindow("Week", 10.0),))
    return fetch


def test_the_result_matches_the_contract_and_names_the_launch_profile(homes, monkeypatch):
    calls: list = []
    monkeypatch.setattr(view, "default_fetch", _fetcher(calls))
    response = _rpc({})
    assert "error" not in response, response
    result = response["result"]
    assert result["ok"] is True and result["profile"] == "default"
    assert [p["provider"] for p in result["providers"]] == ["anthropic"]
    assert result["providers"][0]["windows"][0] == {"id": "week", "label": "Week", "used_percent": 10.0,
                                                    "reset_at": None, "detail": None}


def test_a_named_profile_uses_its_own_config_home_and_secrets(homes, monkeypatch):
    launch, work = homes
    calls: list = []
    monkeypatch.setattr(view, "default_fetch", _fetcher(calls))
    default = _rpc({})["result"]
    scoped = _rpc({"profile": "work"})["result"]
    assert default["profile"] == "default" and scoped["profile"] == "work"
    # The providers come from THAT profile's config, in model-then-fallback order ...
    assert [p["provider"] for p in default["providers"]] == ["anthropic"]
    assert [p["provider"] for p in scoped["providers"]] == ["openai-codex", "openrouter"]
    # ... and the fetch ran under its home and its .env, not the launch profile's (worker threads included).
    assert default["providers"][0]["plan"] == ".hermes|launch-key"
    assert {p["plan"] for p in scoped["providers"]} == {"work|work-key"}
    # Back on the launch profile afterwards: nothing leaked into the process.
    assert get_hermes_home() == launch
    assert _rpc({})["result"]["providers"][0]["plan"] == ".hermes|launch-key"


def test_profiles_do_not_share_cache_entries(homes, monkeypatch):
    calls: list = []
    monkeypatch.setattr(view, "default_fetch", _fetcher(calls))
    _rpc({})
    _rpc({"profile": "work"})
    _rpc({})
    _rpc({"profile": "work"})
    assert sorted(calls) == ["anthropic", "openai-codex", "openrouter"]  # each pair fetched once


def test_cache_and_refresh_through_the_rpc(homes, monkeypatch):
    calls: list = []
    monkeypatch.setattr(view, "default_fetch", _fetcher(calls))
    _rpc({})
    _rpc({})
    _rpc({"refresh": False})
    assert calls == ["anthropic"]
    _rpc({"refresh": True})  # inside the 15 s floor: still the cached entry
    assert calls == ["anthropic"]


def test_an_unknown_profile_is_refused_not_answered_for_the_launch_profile(homes, monkeypatch):
    def unknown(name):
        from tui_gateway.server import ProfileUnavailableError
        raise ProfileUnavailableError(f"Profile '{name}' does not exist.")
    monkeypatch.setattr(server, "_profile_home", unknown)
    monkeypatch.setattr(view, "default_fetch", lambda provider: pytest.fail("fetched for a profile that does not exist"))
    assert _rpc({"profile": "ghost"})["error"]["code"] == 4064


def test_params_are_checked_and_the_method_runs_on_the_pool(homes):
    assert _rpc({"surprise": 1})["error"]["code"] == 4000
    assert "account.usage" in server._LONG_HANDLERS


def test_nothing_secret_in_the_response_whatever_the_providers_return(homes, monkeypatch):
    def fetch(provider):
        return AccountUsageSnapshot(
            provider=provider, source="test", fetched_at=datetime(2026, 10, 5, tzinfo=timezone.utc), plan="Max",
            windows=(AccountUsageWindow("Week", 1.0, None, f"Bearer {MARKER}abcdefghij"),),
            raw={"access_token": MARKER, "headers": {"Authorization": f"Bearer {MARKER}"}})
    monkeypatch.setattr(view, "default_fetch", fetch)
    response = _rpc({"profile": "work"})
    assert MARKER not in json.dumps(response) and "raw" not in json.dumps(response)


def test_a_failing_fetch_answers_unavailable_not_an_rpc_error(homes, monkeypatch):
    def boom(provider):
        raise RuntimeError(f"upstream said {MARKER}")
    monkeypatch.setattr(view, "default_fetch", boom)
    result = _rpc({})["result"]
    assert result["ok"] is True and result["providers"][0]["available"] is False
    assert MARKER not in json.dumps(result)


def test_a_provider_without_a_usage_source_is_not_listed(homes, monkeypatch):
    (homes[0] / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "no-such-provider-xyz"}}), encoding="utf-8")
    server._cfg_cache = server._cfg_sig = server._cfg_path = None
    monkeypatch.setattr(view, "default_fetch", lambda provider: pytest.fail("no source, no fetch"))
    assert _rpc({})["result"]["providers"] == []


def test_an_mcp_agent_may_not_read_account_usage(homes):
    agent = _WS({"provider": "self_hosted", "user_id": "alice", "agent": {"kind": "mcp", "client": "tool"}})
    assert _rpc({}, transport=agent)["error"]["code"] == 4033


def test_the_real_view_is_what_the_handler_calls(homes, monkeypatch):
    """No patched ``default_fetch``: the strict fetcher of ``agent.account_usage`` is what runs."""
    seen: list = []

    def strict(provider, **kwargs):
        seen.append((provider, kwargs))
        return None
    monkeypatch.setattr(account_usage, "fetch_account_usage_strict", strict)
    result = _rpc({})["result"]
    assert seen == [("anthropic", {})]
    assert result["providers"][0]["unavailable_reason"] == "Not signed in to this provider in this profile."
