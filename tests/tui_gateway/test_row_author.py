"""``author.via`` on a row (``tui_gateway/row_author.py``; contract ``contract/gateway/mcp.md``).

A row an agent sent for the person through MCP keeps the person as its author and says how it was sent:
``via: {kind: "mcp", client}``. Only a valid marker beside a person is written; the client name is one
cleaned line of at most 80 code points; the grant id never reaches a row. ``replayed_by`` carries the
presser's own ``via``, and is written when the presser is somebody else or an agent.
"""

from __future__ import annotations

import pytest

from tui_gateway.row_author import (
    ReplayedTurn, agent_from_row_author, agent_marker, deliver_correction, replayed_row_metadata,
    resubmitted_row_identity, row_author, with_row_author,
)

ROBIN = ("oidc:robin", "Robin")
SAM = ("oidc:sam", "Sam")
VIA = {"kind": "mcp", "client": "Claude Code"}


@pytest.mark.parametrize("client, shown", [
    ("Claude Code", "Claude Code"),
    ("  Claude\n\tCode  ", "Claude Code"),                   # Cc and whitespace collapse to one space
    ("Claude Code ", "Claude Code"),                # line / paragraph separators
    ("Cla​ude‮ Code⁦", "Claude Code"),         # format characters (zero-width, bidi) go
    ("x" * 120, "x" * 80),                                    # at most 80 code points
])
def test_the_client_name_is_one_clean_line(client, shown):
    assert agent_marker({"kind": "mcp", "client": client, "grant": "grant-g1"}) == {"kind": "mcp", "client": shown}


@pytest.mark.parametrize("value", [None, "mcp", {"kind": "other", "client": "x"}, {"kind": "mcp"},
                                   {"kind": "mcp", "client": "​‮"}, {"kind": "mcp", "client": 7}])
def test_any_other_shape_is_no_marker(value):
    assert agent_marker(value) is None


def test_a_row_names_the_person_and_how_it_was_sent_never_the_grant():
    assert row_author(ROBIN, {**VIA, "grant": "grant-g1"}) == {"id": "oidc:robin", "name": "Robin", "via": VIA}
    assert row_author(ROBIN) == {"id": "oidc:robin", "name": "Robin"}
    assert row_author(ROBIN, {"kind": "other", "client": "x"}) == {"id": "oidc:robin", "name": "Robin"}
    assert row_author((None, ""), VIA) is None and row_author(None, VIA) is None
    assert with_row_author({"title_preview": "t"}, ROBIN, VIA) == {
        "title_preview": "t", "author": {"id": "oidc:robin", "name": "Robin", "via": VIA}}
    assert agent_from_row_author(row_author(ROBIN, VIA)) == VIA
    assert agent_from_row_author({"id": "oidc:robin", "via": {"kind": "mcp", "client": ""}}) is None


def test_replayed_by_carries_the_pressers_via():
    # An agent asks for the person's own words again: replayed_by is written although the id matches.
    assert replayed_row_metadata(None, ROBIN, ROBIN, agent=VIA) == {
        "author": {"id": "oidc:robin", "name": "Robin"},
        "replayed_by": {"id": "oidc:robin", "name": "Robin", "via": VIA}}
    # The person pressing Retry on their agent's words: the words stay the agent's, nothing else is said.
    assert replayed_row_metadata(None, ROBIN, ROBIN, author_agent=VIA) == {
        "author": {"id": "oidc:robin", "name": "Robin", "via": VIA}}
    # Somebody else, as before.
    assert replayed_row_metadata(None, ROBIN, SAM) == {
        "author": {"id": "oidc:robin", "name": "Robin"}, "replayed_by": {"id": "oidc:sam", "name": "Sam"}}


def test_a_replayed_turn_keeps_a_presser_agent_only_beside_a_presser():
    assert ReplayedTurn(None, ROBIN, {**VIA, "grant": "g"}).presser_agent == VIA
    assert ReplayedTurn(None, None, VIA).presser_agent is None
    assert ReplayedTurn(None, ROBIN, {"kind": "x"}).presser_agent is None


@pytest.mark.parametrize("text, original, agent, expected", [
    ("same words", {"id": "oidc:robin", "name": "Robin", "via": VIA}, None,
     (ROBIN, ("oidc:robin", "Robin"), True, VIA)),
    ("new words", {"id": "oidc:robin", "name": "Robin", "via": VIA}, None, (ROBIN, ROBIN, False, None)),
    ("new words", {"id": "oidc:robin", "name": "Robin"}, VIA, (ROBIN, ROBIN, False, VIA)),
    ("new words", {"id": "oidc:sam", "name": "Sam"}, VIA, (ROBIN, None, False, None)),
], ids=["replay_keeps_the_rows_via", "own_row_by_hand", "own_row_by_the_agent", "somebody_elses_row"])
def test_a_resubmit_over_a_stored_row(text, original, agent, expected):
    row = {"role": "user", "content": "same words", "display_metadata": {"author": original}}
    assert resubmitted_row_identity(text, row, {"content": "same words"}, ROBIN, agent) == expected


def test_a_correction_hands_the_agent_its_author_with_via():
    received = []

    class _Agent:
        def steer(self, text, author=None):
            received.append((text, author))
            return True

    assert deliver_correction(_Agent(), "steer", "marker", ROBIN, VIA)
    assert deliver_correction(_Agent(), "steer", "marker", ROBIN)
    assert received == [("marker", {"id": "oidc:robin", "name": "Robin", "via": VIA}),
                        ("marker", {"id": "oidc:robin", "name": "Robin"})]
