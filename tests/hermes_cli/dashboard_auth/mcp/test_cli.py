"""``hermes dashboard mcp`` (``hermes_cli/dashboard_auth/mcp/cli.py``): the operator lists and revokes grants on
the gateway host. Pinned: list shows live grants (``--all`` the ended ones too), revoke by id or unique prefix
ends every token of the grant, ``--user`` revokes all of one person's, each revocation is audited
``by: operator``, ambiguity and misuse are refused, and the parser is wired under ``hermes dashboard``."""

from __future__ import annotations

import argparse
import io
import json

import pytest

from hermes_cli.dashboard_auth.mcp import cli
from hermes_cli.dashboard_auth.mcp.settings import parse
from hermes_cli.dashboard_auth.mcp.store import MCPStore


class Clock:
    def __init__(self, t: float = 1_790_000_000):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _grant(store: MCPStore, user: str, client: str = "Claude Code") -> tuple[str, str]:
    """A grant minted the way the routes mint one: register, consent, approve, take, exchange."""
    client_id = f"client-{user}-{len(store.grants(include_inactive=True))}"
    store.add_client(client_id=client_id, client_secret=None, client_name=client,
                     redirect_uris=["http://127.0.0.1:1/cb"], token_endpoint_auth_method="none", metadata={},
                     created_ip="203.0.113.1")
    consent = store.open_consent(client_id=client_id, params={
        "scopes": ["bots:read"], "code_challenge": "c" * 43, "redirect_uri": "http://127.0.0.1:1/cb",
        "redirect_uri_provided_explicitly": True, "resource": "https://gw.example.invalid/mcp", "state": None})
    code, _ = store.issue_code(txn_id=consent.txn_id, nonce=consent.nonce, user_id=user, user_name=user.title(),
                               provider=user.split(":")[0], max_grants=5)
    taken = store.take_code(code, client_id=client_id)
    issued = store.exchange_code(code=code, grant_id=taken.grant_id, client_id=client_id, access_ttl=3600,
                                 refresh_ttl=86400, grant_max_age=86400 * 90, max_grants=5)
    return issued.grant.id, issued.access_token


@pytest.fixture
def store(tmp_path) -> MCPStore:
    return MCPStore(tmp_path / "dashboard_auth" / "mcp.db", clock=Clock())


def run(store: MCPStore, *argv: str) -> tuple[int, str, str]:
    """Parse through the real ``hermes dashboard`` parser, then run with the test's store."""
    from hermes_cli.subcommands.dashboard import build_dashboard_parser

    root = argparse.ArgumentParser()
    build_dashboard_parser(root.add_subparsers(dest="command"), cmd_dashboard=lambda a: None,
                           cmd_dashboard_register=lambda a: None)
    args = root.parse_args(["dashboard", "mcp", *argv])
    assert args.func is cli.cmd_dashboard_mcp
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(args, out=out, err=err, store=store, settings=parse({"dashboard": {"mcp": {"enabled": True}}}))
    return code, out.getvalue(), err.getvalue()


def audit_lines() -> list[dict]:
    from hermes_constants import get_hermes_home

    path = get_hermes_home() / "logs" / "dashboard-auth.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_list_and_revoke_one_grant_by_prefix(store):
    alice, alice_token = _grant(store, "stub:alice")
    bob, _ = _grant(store, "stub:bob")
    code, out, _ = run(store, "list")
    assert code == 0 and alice in out and bob in out and "Claude Code" in out

    code, out, _ = run(store, "revoke", "--id", alice[:8])  # an id may start with "-"
    assert code == 0 and f"Revoked grant {alice}" in out
    assert store.verify_access(alice_token) is None
    code, out, _ = run(store, "list")
    assert alice not in out and bob in out
    code, out, _ = run(store, "list", "--all", "--user", "stub:alice")
    assert alice in out and "revoked by operator" in out
    [line] = [line for line in audit_lines() if line["event"] == "mcp_grant_revoked"]
    assert (line["by"], line["grant_id"], line["user_id"]) == ("operator", alice, "stub:alice")

    code, out, _ = run(store, "revoke", f"--id={alice}")
    assert code == 0 and "already revoked" in out


def test_revoke_every_grant_of_one_person(store):
    one, _ = _grant(store, "stub:alice")
    two, _ = _grant(store, "stub:alice", client="Another client")
    keep, _ = _grant(store, "stub:bob")
    code, out, _ = run(store, "revoke", "--user", "stub:alice")
    assert code == 0 and "Revoked 2 grant(s)" in out
    assert [g.id for g in store.grants()] == [keep]
    assert {line["grant_id"] for line in audit_lines() if line["event"] == "mcp_grant_revoked"} == {one, two}


def test_misuse_is_refused(store):
    _grant(store, "stub:alice")
    assert run(store, "revoke")[0] == 2
    assert run(store, "revoke", "abc")[0] == 2  # too short to be a prefix
    assert run(store, "revoke", "zzzzzzzzzz")[0] == 1
    assert run(store, "revoke", "x" * 10, "--user", "stub:alice")[0] == 2
    assert not [line for line in audit_lines() if line["event"] == "mcp_grant_revoked"]


def test_status_and_prune_never_create_the_store(tmp_path):
    store = MCPStore(tmp_path / "dashboard_auth" / "mcp.db")
    code, out, _ = run(store, "status")
    assert code == 0 and "enabled in config" in out and "not created yet" in out
    assert run(store, "prune")[0] == 0 and run(store, "list")[0] == 0
    assert not store.exists()
