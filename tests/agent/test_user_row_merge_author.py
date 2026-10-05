"""Joining two user rows into one keeps an author only when both rows had that same author.

Providers need roles to alternate, so two user rows in a row are joined: the pre-call repair
(``repair_message_sequence``), a micro-compaction supersede, the per-call sanitizer copies and a
compaction restatement merged onto the handoff carrier. Every one of them used to keep the FIRST row's
``display_metadata`` -- and with it the first sender's name on the second sender's words. Once the
joined row is written back (compaction, an edit or regenerate) that wrong name is stored for good. A
joined row now names its author only when both rows named the same one; otherwise it names nobody.

The pre-call repair goes further: it does not join two people's rows at all (nor a named row with an
unnamed one), because the turn note on the joined row would then credit one person's words to the
other. The request copy separates them with an assistant placeholder instead.
"""
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent.agent_runtime_helpers import drop_thinking_only_and_merge_users, repair_message_sequence
from agent.conversation_loop import _apply_active_turn_redirect
from agent.micro_compaction import MicroCompactionMixin
from agent.moa_alternation import merge_same_role_messages

ROBIN = {"id": "oidc:user-a", "name": "Robin"}
SAM = {"id": "oidc:user-b", "name": "Sam"}


def _row(text, author, **extra):
    return {"role": "user", "content": text, "display_metadata": {"author": author, **extra}}


def _author(row):
    return (row.get("display_metadata") or {}).get("author")


def _history_ending_in(*rows):
    """A short answered exchange, then the rows under test back to back."""
    return [_row("hello", ROBIN), {"role": "assistant", "content": "hi"}, *rows]


def test_the_repair_merge_joins_one_persons_rows_and_keeps_their_author():
    messages = _history_ending_in(
        _row("stop, use last year", ROBIN, title_preview="kept"), _row("what about Q3?", ROBIN))

    assert repair_message_sequence(None, messages) == 1

    merged = messages[-1]
    assert merged["content"] == "stop, use last year\n\nwhat about Q3?"
    assert _author(merged) == ROBIN
    assert merged["display_metadata"]["title_preview"] == "kept"  # only the author is at stake


@pytest.mark.parametrize("first, second", [(SAM, ROBIN), (SAM, None), (None, ROBIN)],
                         ids=["two_people", "second_unknown", "first_unknown"])
def test_the_repair_never_joins_rows_it_cannot_credit_to_one_person(first, second):
    messages = _history_ending_in(_row("stop, use last year", first), _row("what about Q3?", second))

    assert repair_message_sequence(None, messages) == 0

    assert [(m["content"], _author(m)) for m in messages[-2:]] == [
        ("stop, use last year", first), ("what about Q3?", second)]


def test_a_redirect_row_is_not_joined_with_the_next_persons_prompt():
    """Sam redirects Robin's turn; the model call fails before any assistant row follows, and Robin's
    next prompt lands straight after Sam's stamped correction."""
    agent = SimpleNamespace(_strip_think_blocks=lambda text: text, _current_streamed_assistant_text="")
    messages = [_row("summarise the report", ROBIN), {"role": "assistant", "content": "working"}]
    _apply_active_turn_redirect(agent, messages, "stop, use last year", author=SAM)
    assert _author(messages[-1]) == SAM
    messages.append(_row("what about Q3?", ROBIN))

    repair_message_sequence(None, messages)

    assert (messages[-1]["content"], _author(messages[-1])) == ("what about Q3?", ROBIN)
    assert _author(messages[-2]) == SAM  # the correction stays Sam's own row


def _agent(db, session_id):
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
        from run_agent import AIAgent

        agent = AIAgent(api_key="test-key", base_url="https://openrouter.ai/api/v1", model="test/model",
                        quiet_mode=True, session_db=db, session_id=session_id,
                        skip_context_files=True, skip_memory=True)
    agent.compression_in_place = True
    return agent


def _stored_merged_row(db, session_id):
    return [r for r in db.get_messages_as_conversation(session_id)
            if r.get("role") == "user" and "what about Q3?" in str(r.get("content"))]


@pytest.mark.parametrize("first, second, expected", [(SAM, ROBIN, ROBIN), (ROBIN, ROBIN, ROBIN)],
                         ids=["two_people_stay_apart", "same_person"])
def test_a_merged_row_written_back_by_compaction_keeps_the_merge_rule(first, second, expected):
    from agent.conversation_compression import compress_context
    from hermes_state import SessionDB

    with tempfile.TemporaryDirectory() as tmp:
        db = SessionDB(db_path=Path(tmp) / "state.db")
        sid = "20260924_140000_merge"
        db.create_session(sid, "desktop", model="test/model")
        messages = []
        for i in range(30):
            messages += [_row(f"question {i} " + "x" * 400, ROBIN),
                         {"role": "assistant", "content": f"answer {i} " + "y" * 400}]
        messages += [_row("stop, use last year", first), _row("what about Q3?", second)]
        repair_message_sequence(None, messages)
        agent = _agent(db, sid)
        summary = MagicMock()
        summary.choices[0].message.content = "## Active Task\nkeep going"
        with patch("agent.context_compressor.call_llm", return_value=summary), \
                patch("agent.context_compressor.get_model_context_length", return_value=8000):
            agent.context_compressor.context_length = 8000
            compress_context(agent, messages, approx_tokens=100_000, system_message="sys")

        [stored] = _stored_merged_row(db, agent.session_id)
        assert _author(stored) == expected
        db.close()


@pytest.mark.parametrize("first, second, expected", [(SAM, ROBIN, ROBIN), (ROBIN, ROBIN, ROBIN)],
                         ids=["two_people_stay_apart", "same_person"])
def test_a_merged_row_written_back_by_replace_messages_keeps_the_merge_rule(first, second, expected):
    """An edit or regenerate writes the in-memory history back with ``replace_messages``."""
    from hermes_state import SessionDB

    with tempfile.TemporaryDirectory() as tmp:
        db = SessionDB(db_path=Path(tmp) / "state.db")
        sid = "20260924_140500_merge"
        db.create_session(sid, "desktop", model="test/model")
        messages = _history_ending_in(_row("stop, use last year", first), _row("what about Q3?", second))
        repair_message_sequence(None, messages)
        db.replace_messages(sid, messages, archive_dropped=True)

        [stored] = _stored_merged_row(db, sid)
        assert _author(stored) == expected
        db.close()


@pytest.mark.parametrize("merge", [
    lambda rows: drop_thinking_only_and_merge_users(rows),
    lambda rows: merge_same_role_messages(rows),
], ids=["pre_call_sanitizer_copy", "aggregator_copy"])
@pytest.mark.parametrize("second, expected", [(ROBIN, None), (SAM, SAM)], ids=["two_people", "same_person"])
def test_every_request_copy_join_follows_the_same_rule(merge, second, expected):
    """Joins on a REQUEST copy. The wire builder has already put an assistant placeholder between two
    people's rows by then (``build_api_messages``), so two people's rows only meet here when a caller
    hands them in directly; the joined row then names nobody."""
    rows = _history_ending_in(_row("stop, use last year", SAM), _row("what about Q3?", second))

    merged = merge(rows)

    assert merged[-1]["content"] == "stop, use last year\n\nwhat about Q3?"
    assert _author(merged[-1]) == expected


@pytest.mark.parametrize("first, second", [(SAM, ROBIN), (SAM, None), (None, ROBIN)],
                         ids=["two_people", "second_unknown", "first_unknown"])
def test_a_micro_compaction_supersede_never_joins_rows_it_cannot_credit_to_one_person(first, second):
    """Micro-compaction joins the user rows a superseded marker leaves adjacent in the LIVE history, and
    its join drops both rows' sidecars -- the genuine turn notes with them. Two people's rows stay two
    rows, as the pre-call repair keeps them; the wire builder separates them with a placeholder (HERM-127)."""
    agent = SimpleNamespace()
    rows = _history_ending_in(_row("stop, use last year", first), _row("what about Q3?", second))

    merged = MicroCompactionMixin._merge_adjacent_user_turns(agent, rows)

    assert [(m["content"], _author(m)) for m in merged[-2:]] == [
        ("stop, use last year", first), ("what about Q3?", second)]
    assert not getattr(agent, "_flush_scan_cursor_invalidated", False)


def test_a_micro_compaction_supersede_still_joins_one_persons_rows():
    rows = _history_ending_in(_row("stop, use last year", SAM), _row("what about Q3?", SAM))

    merged = MicroCompactionMixin._merge_adjacent_user_turns(SimpleNamespace(), rows)

    assert merged[-1]["content"] == "stop, use last year\n\nwhat about Q3?"
    assert _author(merged[-1]) == SAM


@pytest.mark.parametrize("inflight_author, expected", [(ROBIN, None), (SAM, SAM)], ids=["two_people", "same_person"])
def test_an_in_flight_task_restated_onto_the_handoff_carrier_follows_the_same_rule(inflight_author, expected):
    """Compaction restates an unfinished task after the handoff; when the transcript already ends on a
    user row it is merged onto the carrier -- which may be a person's own tail row the summary was
    folded into."""
    from agent.context_compressor import (
        COMPRESSED_SUMMARY_METADATA_KEY, ContextCompressor, _SUMMARY_END_MARKER)

    with patch("agent.context_compressor.get_model_context_length", return_value=8000):
        compressor = ContextCompressor(model="test-model", quiet_mode=True, config_context_length=8000)
    carrier = {**_row("stop, use last year\n\n[CONTEXT COMPACTION] summary\n\n" + _SUMMARY_END_MARKER, SAM),
               COMPRESSED_SUMMARY_METADATA_KEY: True}
    compressed = [{"role": "system", "content": "sys"}, carrier]

    out = compressor._reappend_inflight_user_task(compressed, _row("finish the Q3 numbers", inflight_author))

    assert "finish the Q3 numbers" in out[-1]["content"]
    assert _author(out[-1]) == expected


@pytest.mark.parametrize("force_user_leading", [False, True], ids=["summary_after", "summary_first"])
def test_a_summary_folded_into_a_persons_row_leaves_it_naming_nobody(force_user_leading):
    """A summary merged into a tail row makes that row partly the model's paraphrase of everyone."""
    from agent.context_compressor import COMPRESSED_SUMMARY_METADATA_KEY, ContextCompressor

    with patch("agent.context_compressor.get_model_context_length", return_value=8000):
        compressor = ContextCompressor(model="test-model", quiet_mode=True, config_context_length=8000)
    row = _row("what about Q3?", ROBIN, title_preview="kept")

    compressor._merge_summary_into_tail_row(row, "[CONTEXT COMPACTION] summary", "user", force_user_leading)

    assert row[COMPRESSED_SUMMARY_METADATA_KEY] is True
    assert _author(row) is None
    assert row["display_metadata"] == {"title_preview": "kept"}


def test_metadata_read_back_as_json_text_is_judged_by_what_it_says():
    import json

    from agent.message_metadata import keep_shared_author

    joined = {"role": "user", "content": "a\n\nb", "display_metadata": json.dumps({"author": SAM, "x": 1})}
    keep_shared_author(joined, _row("b", ROBIN))
    assert joined["display_metadata"] == {"x": 1}
