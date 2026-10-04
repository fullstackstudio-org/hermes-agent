"""An uploaded image lives on disk: the conversation keeps its path, never its base64 bytes.

The turn an image is sent in carries it inline (unless ``images.inline_current_turn`` is false); stored
rows, later turns and the history clients read carry the ``[Image attached at: <path>]`` handle only.
"""

from __future__ import annotations

import copy
import json

import pytest

from agent.image_routing import build_native_content_parts
from agent.inline_images import (
    INLINE_IMAGE_NOTE,
    drop_inline_images_in_place,
    inline_current_turn_enabled,
    inline_images_for_display,
    strip_inline_images,
    strip_replayed_inline_images,
)
from agent.replay_cleanup import canonicalize_replay_history
from agent.turn_context import build_api_messages
from hermes_state import SessionDB

_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000a49444154789c6360000002000100ffff0300000600"
    "0557bfabd40000000049454e44ae426082"
)


@pytest.fixture
def upload(tmp_path):
    img = tmp_path / "images" / "upload_20261004_120000_1.png"
    img.parent.mkdir()
    img.write_bytes(_PNG)
    return img


@pytest.fixture
def native_parts(upload):
    parts, skipped = build_native_content_parts("what is in this photo?", [str(upload)])
    assert not skipped and any(p.get("type") == "image_url" for p in parts)
    return parts


def _has_data_url(value) -> bool:
    return "data:image" in json.dumps(value)


class _SendAgent:
    api_mode = "chat_completions"
    ephemeral_system_prompt = None
    _compression_warning = None
    _current_turn_timestamp = 10_000.0

    @staticmethod
    def _copy_reasoning_content_for_api(_source, _target):
        return None

    @staticmethod
    def _should_sanitize_tool_calls():
        return False


def _send(history, idx):
    request, _ = build_api_messages(
        _SendAgent(), history, current_turn_user_idx=idx,
        ext_prefetch_cache="", plugin_user_context="", moa_config=None, active_system_prompt="",
    )
    return request


# ── persistence ──────────────────────────────────────────────────────────────


def test_stored_rows_never_hold_an_inline_image(tmp_path, upload, native_parts):
    """Every writer goes through the same encoding: append, batch append and a full rewrite
    (edit/regenerate, compaction) store the handle, never the data URL."""
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        for sid in ("append", "batch", "replace"):
            db.create_session(session_id=sid, source="tui")
        db.append_message("append", role="user", content=native_parts)
        db.append_messages_batch("batch", [{"role": "user", "content": native_parts}])
        db.replace_messages("replace", [
            {"role": "user", "content": native_parts}, {"role": "assistant", "content": "a cat"}])

        for sid in ("append", "batch", "replace"):
            stored = db.get_messages_as_conversation(sid)[0]["content"]
            assert not _has_data_url(stored), sid
            assert f"[Image attached at: {upload}]" in json.dumps(stored), sid
            raw = db._conn.execute(
                "SELECT content FROM messages WHERE session_id = ? AND role = 'user'", (sid,)).fetchone()[0]
            assert "base64" not in raw, sid
    finally:
        db.close()


def test_kept_prefix_still_matches_after_the_image_was_dropped(tmp_path, native_parts):
    """A rewrite compares the live history to the stored rows through the same encoding, so the
    stored (stripped) user row still counts as the same message as its live (inline) original."""
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session(session_id="s", source="tui")
        live = [{"role": "user", "content": native_parts}, {"role": "assistant", "content": "a cat"}]
        db.replace_messages("s", live)
        first_ids = [m["_row_id"] for m in db.get_messages_as_conversation("s", include_row_ids=True)]
        db.replace_messages("s", live + [{"role": "user", "content": "thanks"}], archive_dropped=True)
        second = db.get_messages_as_conversation("s", include_row_ids=True)
        assert [m["_row_id"] for m in second[:2]] == first_ids
    finally:
        db.close()


def test_flushed_turn_row_names_the_file_without_a_placeholder(native_parts, upload):
    """The agent's own flush projects list content to text: a named image adds no ``[screenshot]``."""
    from agent.session_persistence import _durable_content

    persisted = [{"type": "text", "text": f"what is in this photo?\n@image:{upload}"}, native_parts[1]]
    assert _durable_content(persisted) == f"what is in this photo?\n@image:{upload}"
    # An image nothing names keeps its placeholder.
    assert _durable_content([{"type": "text", "text": "look"}, native_parts[1]]) == "look\n[screenshot]"


# ── replay ───────────────────────────────────────────────────────────────────


def test_later_turns_replay_the_handle_and_the_current_turn_keeps_the_pixels(upload, native_parts):
    earlier = [
        {"role": "user", "content": native_parts},
        {"role": "assistant", "content": "a cat"},
        {"role": "user", "content": "and its colour?"},
    ]
    frozen = copy.deepcopy(earlier)
    request = _send(earlier, idx=2)
    assert earlier == frozen  # the send path never rewrites the live list
    assert not _has_data_url(request)
    assert f"[Image attached at: {upload}]" in json.dumps(request[0]["content"])

    current = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"},
               {"role": "user", "content": native_parts}]
    request = _send(current, idx=2)
    assert any(p.get("type") == "image_url" for p in request[2]["content"])


def test_replay_matches_what_a_resumed_session_sends(tmp_path, native_parts):
    """Resume surfaces and the send path serialize the same prefix bytes."""
    history = [{"role": "user", "content": native_parts}, {"role": "assistant", "content": "a cat"}]
    replay = canonicalize_replay_history(history, now=10_000.0)
    request = _send(history + [{"role": "user", "content": "more"}], idx=2)
    assert request[0]["content"] == replay[0]["content"]
    assert history[0]["content"] is native_parts  # pure


def test_an_inline_image_no_handle_names_stays_for_the_model_and_shows_as_a_note(tmp_path):
    """An OpenAI-compatible client sending a data: URL has no file on disk: the model keeps the image
    (stored, replayed), and a client reading the history sees ``[image]``."""
    unnamed = [{"type": "text", "text": "look"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]
    assert strip_inline_images(unnamed) is unnamed
    history = [{"role": "user", "content": unnamed}, {"role": "assistant", "content": "ok"}]
    assert strip_replayed_inline_images(history) is history
    assert inline_images_for_display(unnamed) == [{"type": "text", "text": "look"}, {"type": "text", "text": INLINE_IMAGE_NOTE}]

    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session(session_id="api", source="api_server")
        db.append_message("api", role="user", content=unnamed)
        assert db.get_messages_as_conversation("api")[0]["content"] == unnamed
    finally:
        db.close()


def test_a_flattened_copy_of_a_named_turn_replays_without_the_data_url(upload):
    text = f"look\n\n[Image attached at: {upload}]\ndata:image/png;base64," + "A" * 64
    replay = strip_replayed_inline_images([{"role": "user", "content": text, "api_content": text}])
    assert replay[0]["content"] == f"look\n\n[Image attached at: {upload}]\n{INLINE_IMAGE_NOTE}"
    assert replay[0]["api_content"] == replay[0]["content"]
    unnamed = [{"role": "user", "content": "data:image/png;base64," + "A" * 64}]
    assert strip_replayed_inline_images(unnamed) is unnamed


def test_remote_image_urls_and_other_roles_are_left_alone():
    remote = [{"type": "text", "text": "x"}, {"type": "image_url", "image_url": {"url": "https://e.x/a.png"}}]
    assert strip_inline_images(remote) is remote
    tool = {"role": "tool", "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}
    assert strip_replayed_inline_images([tool])[0] is tool


# ── the turn itself (run_conversation) ───────────────────────────────────────


def _run(monkeypatch, user_message, cfg):
    import agent.conversation_loop as loop

    seen = {}

    def _fake_turn(agent, message, **_kw):
        seen["message"] = message
        return {"messages": [{"role": "user", "content": message}, {"role": "assistant", "content": "a cat"}],
                "completed": True}

    monkeypatch.setattr(loop, "_run_conversation_turn", _fake_turn)
    monkeypatch.setattr("agent.inline_images.inline_current_turn_enabled", lambda cfg_=None: inline_current_turn_enabled(cfg))
    result = loop.run_conversation(type("A", (), {})(), user_message)
    return seen["message"], result


def test_the_current_turn_carries_the_image_and_its_history_drops_it(monkeypatch, upload, native_parts):
    sent, result = _run(monkeypatch, native_parts, {})
    assert any(p.get("type") == "image_url" for p in sent)
    # The finished turn's history (what the next turn starts from) carries the handle only.
    assert not _has_data_url(result["messages"])
    assert f"[Image attached at: {upload}]" in json.dumps(result["messages"][0]["content"])


def test_inline_current_turn_false_sends_the_handle_only(monkeypatch, upload, native_parts):
    sent, _ = _run(monkeypatch, native_parts, {"images": {"inline_current_turn": False}})
    assert not _has_data_url(sent)
    assert f"[Image attached at: {upload}]" in json.dumps(sent)


def test_inline_current_turn_config_parsing():
    assert inline_current_turn_enabled({}) is True
    assert inline_current_turn_enabled({"images": {"inline_current_turn": False}}) is False
    assert inline_current_turn_enabled({"images": {"inline_current_turn": "false"}}) is False
    assert inline_current_turn_enabled({"images": {"inline_current_turn": True}}) is True
    assert inline_current_turn_enabled({"images": None}) is True


def test_inline_current_turn_reads_the_profile_config(tmp_path, monkeypatch):
    """Through the real loader: a profile's config.yaml turns the inline image off."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert inline_current_turn_enabled() is True
    (home / "config.yaml").write_text("images:\n  inline_current_turn: false\n")
    assert inline_current_turn_enabled() is False


def test_drop_in_place_keeps_identity_and_markers(native_parts):
    msg = {"role": "user", "content": native_parts, "_row_id": 7}
    messages = [msg]
    assert drop_inline_images_in_place(messages) == 1
    assert messages[0] is msg and msg["_row_id"] == 7 and not _has_data_url(msg)


def test_vision_guidance_names_the_handle_an_attachment_writes(native_parts):
    """The model is told how an earlier attachment is named: the handle build_native_content_parts
    writes is the one vision_analyze's image_url guidance describes."""
    from tools.vision_tools import VISION_ANALYZE_SCHEMA

    handle_line = native_parts[0]["text"].splitlines()[-1]
    handle_prefix = handle_line.split(": ", 1)[0]  # "[Image attached at"
    guidance = VISION_ANALYZE_SCHEMA["parameters"]["properties"]["image_url"]["description"]
    assert handle_prefix in guidance and "@image:" in guidance


# ── handles name images one by one ───────────────────────────────────────────

_UNNAMED = {"type": "image_url", "image_url": {"url": "data:image/png;base64," + "B" * 64}}


def test_a_handle_names_one_image_and_an_extra_inline_image_is_kept(tmp_path, upload, native_parts):
    """A delegated goal puts the caller's data: URL after the file images: one handle, two inline parts;
    only the named one goes."""
    mixed = [*native_parts, _UNNAMED]
    stripped = strip_inline_images(mixed)
    assert stripped == [native_parts[0], _UNNAMED]
    assert strip_replayed_inline_images([{"role": "user", "content": mixed}])[0]["content"] == stripped

    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session(session_id="mixed", source="tui")
        db.append_message("mixed", role="user", content=mixed)
        assert db.get_messages_as_conversation("mixed")[0]["content"] == stripped
    finally:
        db.close()
    shown = inline_images_for_display(mixed)
    assert shown == [native_parts[0], {"type": "text", "text": INLINE_IMAGE_NOTE}]


def test_two_handles_drop_the_first_two_inline_images(tmp_path):
    a, b = tmp_path / "a.png", tmp_path / "b.png"
    for f in (a, b):
        f.write_bytes(_PNG)
    parts, _ = build_native_content_parts("compare", [str(a), str(b)])
    assert [p["type"] for p in strip_inline_images([*parts, _UNNAMED])] == ["text", "image_url"]


def test_prose_that_mentions_image_is_not_a_handle():
    for text in ("see foo@image:bar", "the hint `[Image attached at: x]` looks like this"):
        content = [{"type": "text", "text": text}, _UNNAMED]
        assert strip_inline_images(content) is content, text


def test_assistant_and_tool_rows_are_stored_as_they_are(tmp_path, native_parts):
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session(session_id="roles", source="tui")
        db.append_message("roles", role="user", content="hi")
        db.append_message("roles", role="assistant", content=native_parts)
        db.append_message("roles", role="tool", content=native_parts, tool_call_id="c1", tool_name="vision_analyze")
        rows = db.get_messages_as_conversation("roles")
        assert rows[1]["content"] == native_parts and rows[2]["content"] == native_parts
    finally:
        db.close()
    assert strip_replayed_inline_images([{"role": "assistant", "content": native_parts}])[0]["content"] is native_parts


# ── attached image files ─────────────────────────────────────────────────────


def test_image_files_get_distinct_names_and_are_created_exclusively(tmp_path, monkeypatch):
    from agent import inline_images

    first = inline_images.create_image_file(tmp_path / "images", "upload", ".png", b"one")
    second = inline_images.create_image_file(tmp_path / "images", "upload", ".png", b"two")
    assert first != second and first.read_bytes() == b"one" and second.read_bytes() == b"two"

    # A name already taken (or a link planted under it) is never written: the next random name is used.
    tokens = iter(["aaaaaaaaaaaa", "bbbbbbbbbbbb"])
    monkeypatch.setattr(inline_images.secrets, "token_hex", lambda _n: next(tokens))
    monkeypatch.setattr(inline_images, "datetime", type("D", (), {"now": staticmethod(
        lambda: __import__("datetime").datetime(2026, 10, 4, 12, 0, 0))}))
    taken = tmp_path / "images" / "upload_20261004_120000_aaaaaaaaaaaa.png"
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    taken.symlink_to(victim)
    made = inline_images.create_image_file(tmp_path / "images", "upload", ".png", b"new")
    assert made.name == "upload_20261004_120000_bbbbbbbbbbbb.png" and victim.read_bytes() == b"keep"

    monkeypatch.setattr(inline_images.secrets, "token_hex", lambda _n: "aaaaaaaaaaaa")
    with pytest.raises(FileExistsError):
        inline_images.create_image_file(tmp_path / "images", "upload", ".png", b"x")


def test_two_sessions_of_one_profile_never_share_an_upload(tmp_path):
    """Same profile, same second, both at their first image: two files, each with its own bytes."""
    from tui_gateway import server

    a = {"profile_home": str(tmp_path)}
    b = {"profile_home": str(tmp_path)}
    path_a = server._queue_attached_image(a, b"from a", ".png", prefix="upload")
    path_b = server._queue_attached_image(b, b"from b", ".png", prefix="upload")
    assert path_a != path_b
    assert path_a.read_bytes() == b"from a" and path_b.read_bytes() == b"from b"
    assert a["attached_images"] == [str(path_a)] and b["attached_images"] == [str(path_b)]


@pytest.mark.parametrize("umask, mode", [(0o022, 0o644), (0o077, 0o600)])
def test_image_files_are_readable_as_the_umask_allows(tmp_path, umask, mode):
    """0644 less the umask, as write_bytes made them: a sandbox running as another uid reads uploads."""
    import os
    import stat

    from agent.inline_images import create_image_file

    previous = os.umask(umask)
    try:
        made = create_image_file(tmp_path / "images", "upload", ".png", b"x")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(made).st_mode) == mode
