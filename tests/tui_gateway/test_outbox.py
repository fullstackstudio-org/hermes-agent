"""The outbox: what may be shared, how the copy is made, how it is read back and when it goes.

``tui_gateway/outbox.py`` copies a file a bot names into ``<home>/outbox/<token>/`` for the person's client.
Nothing the delivery denylist or the read guard refuses is copied, no link is followed, only regular files up to
the size cap are taken, every copy gets a new random token, and retention and the size cap remove the oldest.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from tui_gateway import outbox, outbox_share, upload_dirs

pytestmark = pytest.mark.skipif(not upload_dirs.supported(), reason="needs O_NOFOLLOW and dir_fd")

_MP3 = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 64
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
_HTML = b"<!doctype html><script>alert(1)</script>"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A profile home with a work folder; HOME is the temp dir so ``~/.ssh`` is inside it."""
    hermes = tmp_path / ".hermes"
    (hermes / "cache" / "audio").mkdir(parents=True)
    (hermes / "work").mkdir()
    (tmp_path / "work").mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("HERMES_MEDIA_DELIVERY_STRICT", raising=False)
    return hermes


def _share(home: Path, path: Path | str, **kwargs):
    return outbox.share_file(str(path), home=home, session_id="s1", logins=["oidc:a"], **kwargs)


def _entries(home: Path) -> list[str]:
    root = home / "outbox"
    return sorted(n for n in os.listdir(root) if n not in (outbox.LOCK_NAME, outbox.STAGING_NAME)) if root.exists() else []


def test_a_shared_file_is_a_private_copy_under_a_random_token(home):
    source = home / "cache" / "audio" / "tts_20261004_225730_989324.mp3"
    source.write_bytes(_MP3)
    first, second = _share(home, source), _share(home, source)

    assert first["id"] != second["id"]
    for record in (first, second):
        assert outbox.TOKEN_RE.match(record["id"])
        assert record["name"] == source.name
        assert (record["mime"], record["kind"], record["inline"]) == ("audio/mpeg", "audio", True)
        assert record["size"] == len(_MP3) and record["logins"] == ["oidc:a"] and record["session_id"] == "s1"
        entry = home / "outbox" / record["id"]
        assert (entry / "blob").read_bytes() == _MP3
        assert stat.S_IMODE((entry / "blob").stat().st_mode) == 0o600
        assert stat.S_IMODE(entry.stat().st_mode) == 0o700
        assert json.loads((entry / "record.json").read_text())["sha256"] == record["sha256"]
    # The agent's own file is untouched and stays where it was.
    assert source.read_bytes() == _MP3


def test_the_client_shape_carries_no_path_session_or_login(home):
    source = home / "work" / "report final.pdf"
    source.write_bytes(b"%PDF-1.7\n")
    attachment = outbox.attachment_of(_share(home, source))
    assert set(attachment) == set(outbox.ATTACHMENT_KEYS)
    assert attachment["url"] == f"/api/files/outbox/{attachment['id']}/report%20final.pdf"
    assert attachment["kind"] == "pdf"
    assert str(home) not in json.dumps(attachment) and "oidc:a" not in json.dumps(attachment)


def test_a_new_token_never_reuses_an_existing_folder(home, monkeypatch):
    source = home / "work" / "a.txt"
    source.write_text("hi")
    taken = "A" * 32
    (home / "outbox" / taken).mkdir(parents=True)
    tokens = iter([taken, "B" * 32])
    monkeypatch.setattr(outbox.secrets, "token_urlsafe", lambda _n: next(tokens))
    record = _share(home, source)
    assert record["id"] == "B" * 32
    assert not os.listdir(home / "outbox" / taken)


@pytest.mark.parametrize("make", [
    lambda h: h / ".env",
    lambda h: h / "auth.json",
    lambda h: h / "config.yaml",
    lambda h: h / "state.db",
    lambda h: h / "mcp-tokens" / "server.json",
    lambda h: h.parent / ".ssh" / "id_ed25519",
    lambda h: h.parent / "work" / ".env.production",
    lambda h: h.parent / "work" / ".git-credentials",
], ids=["env", "auth", "config", "state-db", "mcp-tokens", "ssh-key", "project-env", "git-credentials"])
def test_sensitive_files_are_never_shared(home, make):
    target = make(home)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("SECRET=1")
    with pytest.raises(outbox.ShareRefused) as refused:
        _share(home, target)
    assert refused.value.reason == "denied"
    assert _entries(home) == []


def test_a_link_to_a_sensitive_file_is_judged_by_its_target(home):
    (home / ".env").write_text("SECRET=1")
    link = home / "work" / "innocent.txt"
    link.symlink_to(home / ".env")
    with pytest.raises(outbox.ShareRefused):
        _share(home, link)
    assert _entries(home) == []


def test_traversal_to_a_sensitive_file_is_refused(home):
    (home / ".env").write_text("SECRET=1")
    with pytest.raises(outbox.ShareRefused):
        _share(home, f"{home}/cache/audio/../../.env")


def test_a_link_to_an_ordinary_file_shares_that_file_under_its_own_name(home):
    real = home / "work" / "clip.mp3"
    real.write_bytes(_MP3)
    link = home / "work" / "latest.mp3"
    link.symlink_to(real)
    record = _share(home, link)
    assert record["name"] == "clip.mp3" and record["source"] == str(real.resolve())


@pytest.mark.parametrize("kind", ["directory", "fifo", "missing", "system", "relative", "control"])
def test_only_an_existing_regular_file_is_shared(home, kind):
    if kind == "directory":
        path = str(home / "work")
    elif kind == "fifo":
        fifo = home / "work" / "pipe.mp3"
        os.mkfifo(fifo)
        path = str(fifo)
    elif kind == "missing":
        path = str(home / "work" / "nope.mp3")
    elif kind == "system":
        path = "/etc/hosts"
    elif kind == "relative":
        path = "work/a.mp3"
    else:
        path = str(home / "work" / "a\nb.mp3")
    with pytest.raises(outbox.ShareRefused):
        _share(home, path)
    assert _entries(home) == []


def test_a_file_over_the_size_cap_is_refused(home):
    big = home / "work" / "big.bin"
    big.write_bytes(b"x" * 2048)
    settings = outbox.OutboxSettings(max_file_bytes=1024)
    with pytest.raises(outbox.ShareRefused) as refused:
        _share(home, big, settings=settings)
    assert refused.value.reason == "too_large"
    assert _entries(home) == []


def test_an_outbox_folder_that_is_a_link_is_never_written_through(home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / "outbox").symlink_to(elsewhere)
    source = home / "work" / "a.txt"
    source.write_text("hi")
    with pytest.raises(outbox.ShareRefused):
        _share(home, source)
    assert os.listdir(elsewhere) == []


@pytest.mark.parametrize(("name", "data", "expected"), [
    ("a.png", _PNG, ("image/png", "image", True)),
    ("a.png", _HTML, ("application/octet-stream", "file", False)),
    ("a.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", ("image/svg+xml", "file", False)),
    ("a.html", _HTML, ("text/html", "file", False)),
    ("a.mp4", b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16, ("video/mp4", "video", True)),
    ("a.m4a", b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 16, ("audio/mp4", "audio", True)),
    ("a.ogg", b"OggS" + b"\x00" * 16, ("audio/ogg", "audio", True)),
    ("a.opus", b"OggS" + b"\x00" * 16, ("audio/ogg", "audio", True)),
    ("a.wav", b"RIFF\x00\x00\x00\x00WAVEfmt ", ("audio/wav", "audio", True)),
    ("a.mp3", b"\xff\xfb\x90\x00" + b"\x00" * 16, ("audio/mpeg", "audio", True)),
    ("a.pdf", b"%PDF-1.4", ("application/pdf", "pdf", True)),
    ("a.zip", b"PK\x03\x04", ("application/zip", "file", False)),
    ("noext", _MP3, ("audio/mpeg", "audio", True)),
    ("noext", b"plain words", ("application/octet-stream", "file", False)),
])
def test_type_comes_from_name_and_bytes_together(name, data, expected):
    assert outbox.classify(name, data[:64]) == expected


def test_active_types_are_served_as_bytes():
    assert outbox.served_type("text/html") == "application/octet-stream"
    assert outbox.served_type("image/svg+xml") == "application/octet-stream"
    assert outbox.served_type("audio/mpeg") == "audio/mpeg"


def test_display_names_are_one_safe_component():
    assert outbox.display_name("tts_1.mp3") == "tts_1.mp3"
    assert outbox.display_name("a\x00b\nc.txt") == "a_b_c.txt"
    assert outbox.display_name("..") == "file"
    long = outbox.display_name("x" * 400 + ".pdf")
    assert len(long) == 180 and long.endswith(".pdf")


def test_open_shared_serves_only_the_recorded_copy(home):
    source = home / "work" / "a.txt"
    source.write_text("hello")
    record = _share(home, source)
    shared = outbox.open_shared(home, record["id"], "a.txt")
    assert shared is not None
    try:
        assert os.pread(shared.fd, 100, 0) == b"hello"
    finally:
        shared.close()
    assert outbox.open_shared(home, record["id"], "b.txt") is None  # another name
    assert outbox.open_shared(home, "Z" * 32, "a.txt") is None  # another token
    assert outbox.open_shared(home, "../" + record["id"][3:], "a.txt") is None  # not a token


def test_a_blob_replaced_by_a_link_or_a_hard_link_is_not_served(home):
    secret = home / ".env"
    secret.write_text("SECRET=12345")
    source = home / "work" / "a.txt"
    source.write_text("hello world!")
    record = _share(home, source)
    blob = home / "outbox" / record["id"] / "blob"
    blob.unlink()
    blob.symlink_to(secret)
    assert outbox.open_shared(home, record["id"], "a.txt") is None
    blob.unlink()
    os.link(secret, blob)  # same size as the recorded copy
    assert outbox.open_shared(home, record["id"], "a.txt") is None


def test_retention_and_size_cap_remove_the_oldest(home):
    now = time.time()
    records = []
    for index in range(4):
        source = home / "work" / f"f{index}.bin"
        source.write_bytes(b"x" * 100)
        records.append(_share(home, source, now=now - (4 - index)))
    # f0 has aged to 40 days: past the 30-day retention.
    old = now - 40 * 86400
    os.utime(home / "outbox" / records[0]["id"] / "blob", (old, old))
    assert outbox.prune_outbox(home, outbox.OutboxSettings(), now=now) == 1
    assert _entries(home) == sorted(r["id"] for r in records[1:])
    # A 250-byte cap keeps the two newest (one conversation allowed the whole cap: the profile cap at work).
    whole = outbox.OutboxSettings(max_total_bytes=250, conversation_share=1.0)
    assert outbox.prune_outbox(home, whole, now=now) == 1
    assert _entries(home) == sorted(r["id"] for r in records[2:])


def test_sharing_makes_room_by_evicting_the_oldest(home):
    settings = outbox.OutboxSettings(max_total_bytes=250, conversation_share=1.0)
    ids = []
    for index in range(3):
        source = home / "work" / f"f{index}.bin"
        source.write_bytes(b"x" * 100)
        ids.append(_share(home, source, settings=settings, now=time.time() + index)["id"])
    assert _entries(home) == sorted(ids[1:])


def test_pruning_removes_what_is_planted_but_never_follows_it(home, tmp_path):
    keep = tmp_path / "keep.txt"
    keep.write_text("mine")
    (home / "outbox").mkdir()
    (home / "outbox" / "not-a-token").symlink_to(keep)
    outbox.prune_outbox(home, outbox.OutboxSettings())
    assert _entries(home) == [] and keep.read_text() == "mine"


def test_settings_come_from_the_files_section():
    settings = outbox.settings_from({"files": {
        "outbox_max_file_mb": 5, "outbox_max_total_mb": 50, "outbox_retention_days": 2,
        "outbox_sources": ["Hermie", "desktop"]}})
    assert settings.max_file_bytes == 5 * 1024 * 1024 and settings.max_total_bytes == 50 * 1024 * 1024
    assert settings.retention_seconds == 2 * 86400 and settings.sources == {"hermie", "desktop"}
    defaults = outbox.settings_from({"files": {"outbox_max_file_mb": "x", "outbox_retention_days": -1}})
    assert defaults == outbox.OutboxSettings()


def test_may_fetch_is_for_the_people_of_the_conversation():
    record = {"logins": ["oidc:a"]}
    assert outbox.may_fetch(record, None)  # no per-person identity: one trust domain
    assert outbox.may_fetch(record, "oidc:a")
    assert not outbox.may_fetch(record, "oidc:b")
    assert outbox.may_fetch(record, "oidc:b", live_logins={"oidc:b"})
    assert not outbox.may_fetch({"logins": []}, "oidc:a")


# ── outbox_share ─────────────────────────────────────────────────────────────────────────────────────────────


def test_sharing_is_only_for_the_listed_sources():
    settings = outbox.OutboxSettings()
    assert outbox_share.session_shares_files({"source": "hermie"}, settings)
    assert not outbox_share.session_shares_files({"source": "desktop"}, settings)
    assert not outbox_share.session_shares_files({"source": "tui"}, settings)
    # A resume that did not pass its source falls back to the stored row's.
    assert outbox_share.session_shares_files({"source": "tui"}, settings, lambda: "hermie")
    assert not outbox_share.session_shares_files({"source": "hermie"}, outbox.OutboxSettings(sources=frozenset()))


def test_a_turn_shares_its_directives_and_its_tts_result_once(home):
    clip = home / "cache" / "audio" / "tts_1.mp3"
    clip.write_bytes(_MP3)
    chart = home / "work" / "chart.png"
    chart.write_bytes(_PNG)
    text = f"Here is the chart.\nMEDIA:{chart}\nAnd `MEDIA:/example/in/code.png` stays."
    tool_messages = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "text_to_speech", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": json.dumps({
            "success": True, "file_path": str(clip), "media_tag": f"MEDIA:{clip}", "voice_compatible": False})},
    ]
    shared = outbox_share.share_turn_files(text, tool_messages, home=home, session_id="s1", logins=["oidc:a"],
                                           settings=outbox.OutboxSettings())
    assert [(a["name"], a["kind"]) for a in shared.attachments] == [("chart.png", "image"), ("tts_1.mp3", "audio")]
    assert str(home) not in shared.text and "MEDIA:" in shared.text  # the example in code is kept
    assert shared.text.startswith("Here is the chart.")


def test_a_refused_file_leaves_no_path_and_no_attachment(home):
    (home / "auth.json").write_text("{}")
    shared = outbox_share.share_turn_files(f"Look: MEDIA:{home}/auth.json", [], home=home, session_id="s1",
                                           logins=[], settings=outbox.OutboxSettings())
    assert shared.named and shared.attachments == [] and shared.refused == ["denied"]
    assert shared.text == "Look:\n\n(1 file could not be shared.)"
    assert str(home) not in shared.text


def test_the_stream_never_shows_a_directive():
    stream = outbox_share.MediaDeltaFilter()
    deltas = ["Here it is\nME", "DIA:/home/u/.hermes/cache/audio/tts", "_1.mp3\nDone", " now.\n**MEDIA:/x/y.png**",
              "\nI AM", " ok"]
    shown = "".join(stream.feed(d) for d in deltas)
    assert "MEDIA:" not in shown and "/home/u" not in shown
    assert shown == "Here it is\nDone now.\nI AM ok"


def test_history_shows_attachments_instead_of_directives():
    attachment = {"id": "A" * 32, "name": "tts_1.mp3", "mime": "audio/mpeg", "kind": "audio", "size": 3,
                  "sha256": "0" * 64, "created_at": 1.0, "url": "/api/files/outbox/" + "A" * 32 + "/tts_1.mp3"}
    planted = {**attachment, "source": "/secret/path", "id": "B" * 32}
    text, attachments, meta = outbox_share.project_row(
        "assistant", "Listen.\nMEDIA:/root/.hermes/cache/audio/tts_1.mp3",
        {"attachments": [attachment, planted, {"id": "../x"}], "turn_id": "t"})
    assert text == "Listen."
    assert attachments[0] == attachment and set(attachments[1]) == set(outbox.ATTACHMENT_KEYS)
    assert len(attachments) == 2 and meta == {"turn_id": "t"}
    # A row without the key, or a user row, is untouched.
    assert outbox_share.project_row("assistant", "MEDIA:/x.png", {"turn_id": "t"}) == (
        "MEDIA:/x.png", None, {"turn_id": "t"})
    assert outbox_share.project_row("user", "MEDIA:/x.png", {"attachments": []})[1] is None


# ── review round: re-sharing, per-turn caps, eviction, deletion, previews ────────────────────────────────────


def test_a_shared_copy_or_an_upload_is_never_shared_again(home, tmp_path):
    """Login B in a chat of the same profile must not get A's copy by asking the bot to send its blob."""
    source = home / "work" / "a.txt"
    source.write_text("for A only")
    record = _share(home, source)
    blob = home / "outbox" / record["id"] / "blob"
    for path in (blob, home / "outbox" / record["id"] / "record.json"):
        with pytest.raises(outbox.ShareRefused) as refused:
            outbox.share_file(str(path), home=home, session_id="s2", logins=["oidc:b"])
        assert refused.value.reason == "denied"
    # Another profile's outbox too, and a link into one.
    other = home / "profiles" / "lloyd" / "outbox" / ("Q" * 32)
    other.mkdir(parents=True)
    (other / "blob").write_text("lloyd's")
    link = home / "work" / "innocent.txt"
    link.symlink_to(other / "blob")
    for path in (other / "blob", link):
        with pytest.raises(outbox.ShareRefused):
            _share(home, path)
    upload = tmp_path / "work" / "uploads" / "hermie" / "2026-10-04" / "0123456789abcdef-scan.pdf"
    upload.parent.mkdir(parents=True)
    upload.write_bytes(b"%PDF-1.7\n")
    with pytest.raises(outbox.ShareRefused):
        _share(home, upload)
    assert _entries(home) == [record["id"]]


def test_the_read_guard_and_native_delivery_refuse_the_outbox(home):
    from agent.file_safety import get_read_block_error
    from gateway.platforms.base import validate_media_delivery_path
    source = home / "work" / "a.txt"
    source.write_text("x")
    blob = home / "outbox" / _share(home, source)["id"] / "blob"
    assert get_read_block_error(str(blob)) is not None
    assert validate_media_delivery_path(str(blob)) is None


def test_a_hard_linked_source_is_refused(home):
    (home / "work" / "original.txt").write_text("plain")
    alias = home / "work" / "notes.txt"
    os.link(home / "work" / "original.txt", alias)
    with pytest.raises(outbox.ShareRefused) as refused:
        _share(home, alias)
    assert refused.value.reason == "linked"
    # A hard link to a credential store is the store itself to the guards (same file), whatever its name.
    (home / "auth.json").write_text("{}")
    os.link(home / "auth.json", home / "work" / "auth-notes.txt")
    with pytest.raises(outbox.ShareRefused) as refused:
        _share(home, home / "work" / "auth-notes.txt")
    assert refused.value.reason == "denied"


def test_a_source_swapped_for_a_link_after_the_check_is_not_read(home, tmp_path, monkeypatch):
    """The checks judge the resolved path; the open walks it without following a link."""
    secret = home / ".env"
    secret.write_text("SECRET=1")
    folder = home / "work" / "out"
    folder.mkdir()
    (folder / "a.txt").write_text("fine")
    real_check = outbox.check_source

    def check_then_swap(path, **kwargs):
        resolved = real_check(path, **kwargs)
        moved = home / "work" / "moved"
        folder.rename(moved)
        folder.symlink_to(home)  # .../out now points at the home
        (moved / "a.txt").unlink()
        (home / "a.txt").symlink_to(secret)
        return resolved

    monkeypatch.setattr(outbox, "check_source", check_then_swap)
    with pytest.raises(outbox.ShareRefused):
        _share(home, folder / "a.txt")
    assert _entries(home) == []


def _big(home, name, size):
    path = home / "work" / name
    with open(path, "wb") as handle:
        handle.truncate(size)
    return path


def test_one_conversation_cannot_evict_anothers_recent_files(home):
    """The reviewer's scenario, scaled down (x200 MB -> x200 B): A shares one file; then a reply in B names
    eleven files that do not all fit. A's file stays; B's turn gets what fits in B's half of the outbox and the
    rest is refused."""
    settings = outbox.OutboxSettings(max_total_bytes=2000, max_file_bytes=200, max_turn_bytes=100_000)
    a = outbox.share_file(str(_big(home, "a.bin", 200)), home=home, session_id="A", logins=["oidc:a"],
                          settings=settings)
    text = "\n".join(f"MEDIA:{_big(home, f'b{i}.bin', 200)}" for i in range(11))
    shared = outbox_share.share_turn_files(text, [], home=home, session_id="B", logins=["oidc:b"],
                                           settings=settings)
    assert a["id"] in _entries(home)
    assert len(shared.attachments) == 5 and shared.refused == ["no_room"] * 6
    assert all(att["id"] in _entries(home) for att in shared.attachments)
    # A later turn of B may push out B's own oldest, still never A's.
    later = outbox.share_file(str(_big(home, "b-late.bin", 200)), home=home, session_id="B", settings=settings,
                              now=time.time() + 60)
    assert a["id"] in _entries(home) and later["id"] in _entries(home)
    assert shared.attachments[0]["id"] not in _entries(home)


def test_room_is_made_from_the_same_conversations_oldest_but_never_this_turns(home):
    settings = outbox.OutboxSettings(max_total_bytes=450, max_file_bytes=200, conversation_share=1.0)
    old = outbox.share_file(str(_big(home, "o.bin", 200)), home=home, session_id="A", settings=settings)
    first = outbox.share_file(str(_big(home, "f.bin", 200)), home=home, session_id="A", settings=settings,
                              now=time.time() + 1)
    # The same conversation's oldest goes to make room ...
    second = outbox.share_file(str(_big(home, "s.bin", 200)), home=home, session_id="A", settings=settings,
                               now=time.time() + 2)
    assert _entries(home) == sorted([first["id"], second["id"]])
    # ... but never a file of the turn being shared.
    with pytest.raises(outbox.ShareRefused) as refused:
        outbox.share_file(str(_big(home, "t.bin", 200)), home=home, session_id="A", settings=settings,
                          protect={first["id"], second["id"]})
    assert refused.value.reason == "no_room"
    assert old["id"] not in _entries(home)


def test_per_turn_caps_on_count_and_bytes(home):
    paths = [_big(home, f"f{i}.bin", 100) for i in range(5)]
    text = "\n".join(f"MEDIA:{p}" for p in paths)
    settings = outbox.OutboxSettings(max_turn_files=3)
    shared = outbox_share.share_turn_files(text, [], home=home, session_id="s", logins=[], settings=settings)
    assert len(shared.attachments) == 3 and shared.refused == ["turn_limit", "turn_limit"]
    assert shared.text == "(2 files could not be shared.)"
    settings = outbox.OutboxSettings(max_turn_bytes=250)
    shared = outbox_share.share_turn_files(text, [], home=home, session_id="t", logins=[], settings=settings)
    assert len(shared.attachments) == 2 and set(shared.refused) == {"too_large"}


def test_a_slow_copy_is_abandoned_and_removed(home, monkeypatch):
    """The turn waits a bounded time; a copy still running then is cancelled and leaves nothing behind."""
    import threading
    path = _big(home, "slow.bin", 100)
    release = threading.Event()
    real_fill = outbox._fill_entry

    def slow_fill(*args, **kwargs):
        release.wait(5)
        return real_fill(*args, **kwargs)

    monkeypatch.setattr(outbox, "_fill_entry", slow_fill)
    settings = outbox.OutboxSettings(turn_timeout_seconds=0.3)
    started = time.monotonic()
    shared = outbox_share.share_turn_files(f"MEDIA:{path}", [], home=home, session_id="s", logins=[],
                                           settings=settings)
    assert time.monotonic() - started < 3
    assert shared.attachments == [] and shared.refused == ["timeout"]
    release.set()
    deadline = time.monotonic() + 5
    while _entries(home) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _entries(home) == []


def test_deleting_a_session_removes_its_copies(home, tmp_path):
    from hermes_state import SessionDB
    home = tmp_path / "store"  # the outbox lives beside the store (a profile home)
    home.mkdir()
    (home / "work").mkdir()
    db = SessionDB(db_path=home / "state.db")
    try:
        for sid in ("keep", "gone"):
            db.create_session(session_id=sid, source="hermie", model="m")
        kept = outbox.share_file(str(_big(home, "k.bin", 10)), home=home, session_id="keep")
        outbox.share_file(str(_big(home, "g.bin", 10)), home=home, session_id="gone")
        assert db.delete_session("gone")
        assert _entries(home) == [kept["id"]]
        outbox.share_file(str(_big(home, "g2.bin", 10)), home=home, session_id="bulk")
        db.create_session(session_id="bulk", source="hermie", model="m")
        assert db.delete_sessions(["bulk"]) == 1
        assert _entries(home) == [kept["id"]]
    finally:
        db.close()


def test_previews_never_show_a_media_path():
    from hermes_state_common import _shape_preview, strip_media_for_preview
    assert strip_media_for_preview("Here you go MEDIA:/root/.hermes/cache/audio/tts_1.mp3 enjoy") == \
        "Here you go enjoy"
    assert strip_media_for_preview('**MEDIA:"/a b/c.png"** [[audio_as_voice]]') == ""
    assert strip_media_for_preview(">>>MEDIA:/root/.hermes/ca...") == ">>>"
    assert _shape_preview("look MEDIA:/x/y.pdf") == "look"


def test_the_stream_keeps_examples_in_code_and_flushes_at_the_end():
    stream = outbox_share.MediaDeltaFilter()
    shown = "".join(stream.feed(d) for d in ["```\nMEDIA:/ex.png\n```\n", "done MEDIA:/a.p", "ng"])
    shown += stream.flush()
    assert shown == "```\nMEDIA:/ex.png\n```\ndone "
    long = outbox_share.MediaDeltaFilter()
    shown = long.feed("x MEDIA:/" + "a" * 9000) + long.feed("b.png rest") + long.flush()
    assert "MEDIA:" not in shown and shown.endswith("rest")


def test_project_row_adds_the_note_for_refused_files():
    text, attachments, meta = outbox_share.project_row(
        "assistant", "Here.\nMEDIA:/etc/passwd", {"attachments": [], "attachments_refused": 1})
    assert text == "Here.\n\n(1 file could not be shared.)" and attachments == [] and meta is None


def test_every_preview_surface_strips_media_paths(tmp_path):
    """Session list previews, the roster preview, the live session item, timeline entries and search snippets."""
    from hermes_state import SessionDB
    from hermes_state_timeline import get_session_timeline
    from tui_gateway.methods_profiles import _latest_message_preview
    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session(session_id="s", source="hermie", model="m")
        db.append_message("s", role="user", content="send MEDIA:/root/.hermes/secret/plan.pdf please")
        db.append_message("s", role="assistant", content="Done.\nMEDIA:/root/.hermes/cache/audio/tts_1.mp3")
        assert "MEDIA:" not in _latest_message_preview(db, "s")
        rows = db.list_sessions_rich(limit=5)
        assert rows and all("MEDIA:" not in (row.get("preview") or "") for row in rows)
        entries = get_session_timeline(db, "s")["entries"]
        assert entries and all("MEDIA:" not in e["preview"] for e in entries)
    finally:
        db.close()
    import tui_gateway.server as server
    item = server._session_live_item("x", {"history": [{"role": "assistant", "content": "Here MEDIA:/a/b.png"}],
                                           "session_key": "x"})
    assert item["preview"] == "Here"


# ── review round 2: paths by identity, per-conversation share, prose, staging, compaction ────────────────────

from agent import path_identity  # noqa: E402

@pytest.fixture
def case_insensitive_tmp(tmp_path):
    if not path_identity.case_insensitive(tmp_path):
        pytest.skip("needs a case-insensitive temp volume (macOS default); the simulated tests cover the logic")


@pytest.fixture
def secrets_on_disk(home, tmp_path):
    """A shared copy, a store, a credential under ~/.config and a person's upload: each a harmless marker."""
    source = home / "work" / "a.txt"
    source.write_text("marker")
    record = _share(home, source)
    (home / "state.db").write_text("marker")
    (home / "auth.json").write_text("{}")
    (tmp_path / ".config" / "gh").mkdir(parents=True)
    (tmp_path / ".config" / "gh" / "hosts.yml").write_text("marker")
    (tmp_path / ".ssh").mkdir()
    upload = tmp_path / "work" / "uploads" / "hermie" / "2026-10-05"
    upload.mkdir(parents=True)
    (upload / "0123456789abcdef-scan.pdf").write_bytes(b"%PDF-1.7\n")
    return record


def test_a_case_variant_of_a_denied_path_is_never_shared(home, tmp_path, case_insensitive_tmp, secrets_on_disk):
    """realpath keeps the spelling it is given; on a case-insensitive volume these open the denied files."""
    token = secrets_on_disk["id"]
    for variant in (home / "OUTBOX" / token / "blob", home / "Outbox" / token / "record.json",
                    home / "STATE.DB", home / "Auth.Json", tmp_path / ".CONFIG" / "gh" / "hosts.yml",
                    tmp_path / "work" / "Uploads" / "Hermie" / "2026-10-05" / "0123456789abcdef-scan.pdf"):
        assert variant.exists()
        with pytest.raises(outbox.ShareRefused) as refused:
            outbox.share_file(str(variant), home=home, session_id="s2", logins=["oidc:b"])
        assert refused.value.reason == "denied", variant
    assert _entries(home) == [token]


def test_native_delivery_and_the_file_guards_see_through_case(home, tmp_path, case_insensitive_tmp,
                                                              secrets_on_disk):
    from agent.file_safety import get_read_block_error, get_write_denied_error
    from gateway.platforms.base import validate_media_delivery_path
    blob = home / "OUTBOX" / secrets_on_disk["id"] / "blob"
    for variant in (blob, home / "STATE.DB", tmp_path / ".CONFIG" / "gh" / "hosts.yml"):
        assert validate_media_delivery_path(str(variant)) is None, variant
    assert get_read_block_error(str(blob)) is not None
    assert get_read_block_error(str(home / "AUTH.JSON")) is not None
    assert get_write_denied_error(str(tmp_path / ".SSH" / "authorized_keys")) is not None
    assert get_write_denied_error(str(home / "State.db")) is not None
    # An ordinary file in any spelling is still fine.
    (home / "work" / "Report.txt").write_text("marker")
    assert validate_media_delivery_path(str(home / "work" / "REPORT.TXT")) is not None


def test_the_opened_file_is_judged_by_the_path_the_kernel_reports(home, monkeypatch):
    """Simulated canonicaliser (any platform): an innocent spelling whose descriptor resolves to the store."""
    (home / "state.db").write_text("marker")
    source = home / "work" / "notes.txt"
    source.write_text("marker")
    monkeypatch.setattr(path_identity, "fd_path", lambda fd: str(home / "state.db"))
    with pytest.raises(outbox.ShareRefused) as refused:
        _share(home, source)
    assert refused.value.reason == "denied"
    # The stored spelling is what the copy is recorded under.
    renamed = home / "work" / "Notes.TXT"
    monkeypatch.setattr(path_identity, "fd_path", lambda fd: str(renamed))
    record = _share(home, source)
    assert record["name"] == "Notes.TXT" and record["source"] == str(renamed)


def test_folded_comparison_covers_names_that_do_not_exist_yet(home, tmp_path, monkeypatch):
    """Simulated case-insensitive volume: a name not on disk has no inode, so it is compared folded."""
    from agent.file_safety import get_read_block_error, get_write_denied_error
    monkeypatch.setattr(path_identity, "case_insensitive", lambda path: True)
    assert get_read_block_error(str(home / "MCP-Tokens" / "server.json")) is not None
    assert get_write_denied_error(str(tmp_path / ".NETRC")) is not None
    probe = path_identity.PathProbe(home / "OUTBOX" / "x")
    assert probe.within(home / "outbox") and not probe.within(home / "outbox2")
    monkeypatch.setattr(path_identity, "case_insensitive", lambda path: False)
    assert not path_identity.PathProbe(home / "OUTBOX" / "x").within(home / "outbox")


def test_a_hard_link_to_a_store_is_not_delivered_natively_either(home):
    from gateway.platforms.base import validate_media_delivery_path
    (home / "state.db").write_text("marker")
    alias = home / "work" / "history.txt"
    os.link(home / "state.db", alias)
    assert validate_media_delivery_path(str(alias)) is None


def test_a_conversation_holds_at_most_half_the_outbox(home):
    """A's shares never take more than half; past that A's own oldest go, and B still has room."""
    settings = outbox.OutboxSettings(max_total_bytes=1000, max_file_bytes=200)
    a = [outbox.share_file(str(_big(home, f"a{i}.bin", 200)), home=home, session_id="A", settings=settings,
                           now=time.time() + i)["id"] for i in range(4)]
    assert _entries(home) == sorted(a[2:])  # 400 of 500: the third and fourth pushed out A's oldest
    b = [outbox.share_file(str(_big(home, f"b{i}.bin", 200)), home=home, session_id="B", settings=settings,
                           now=time.time() + 10 + i)["id"] for i in range(2)]
    assert _entries(home) == sorted(a[2:] + b)
    with pytest.raises(outbox.ShareRefused) as refused:  # bigger than a conversation's share
        outbox.share_file(str(_big(home, "huge.bin", 600)), home=home, session_id="C",
                          settings=outbox.OutboxSettings(max_total_bytes=1000, max_file_bytes=1000))
    assert refused.value.reason == "too_large"


def test_another_conversations_files_go_only_after_the_grace_period(home):
    """The outbox full of A and B (each within its half): C's share waits out the grace period, then takes the
    oldest of theirs, never one of this reply's or a file younger than the grace."""
    settings = outbox.OutboxSettings(max_total_bytes=800, max_file_bytes=200, evict_grace_seconds=3600)
    start = time.time()
    held = {}
    for index, sid in enumerate(("A", "A", "B", "B")):
        held[f"{sid}{index}"] = outbox.share_file(str(_big(home, f"{sid}{index}.bin", 200)), home=home,
                                                  session_id=sid, settings=settings, now=start + index)["id"]
    with pytest.raises(outbox.ShareRefused) as refused:
        outbox.share_file(str(_big(home, "c0.bin", 200)), home=home, session_id="C", settings=settings,
                          now=start + 60)
    assert refused.value.reason == "no_room"
    assert _entries(home) == sorted(held.values())
    later = start + 2 * 3600
    c = outbox.share_file(str(_big(home, "c1.bin", 200)), home=home, session_id="C", settings=settings, now=later)
    assert held["A0"] not in _entries(home)
    assert _entries(home) == sorted([held["A1"], held["B2"], held["B3"], c["id"]])


def test_a_conversation_holds_at_most_half_the_entry_count(home, monkeypatch):
    """Tiny files cannot exhaust the entry count for the others: a conversation keeps half of it, its own
    oldest go first, and a reply that has already shared that many is refused."""
    monkeypatch.setattr(outbox, "MAX_ENTRIES", 6)
    start = time.time()
    a = [outbox.share_file(str(_big(home, f"a{i}.bin", 1)), home=home, session_id="A", now=start + i)["id"]
         for i in range(5)]
    assert _entries(home) == sorted(a[2:])  # three of six
    b = [outbox.share_file(str(_big(home, f"b{i}.bin", 1)), home=home, session_id="B", now=start + 10 + i)["id"]
         for i in range(3)]
    assert _entries(home) == sorted(a[2:] + b)
    with pytest.raises(outbox.ShareRefused) as refused:  # A's reply already shares three: nothing may go
        outbox.share_file(str(_big(home, "a9.bin", 1)), home=home, session_id="A", now=start + 20,
                          protect=set(a[2:]))
    assert refused.value.reason == "no_room"
    assert _entries(home) == sorted(a[2:] + b)


def test_a_share_that_cannot_fit_evicts_nobody(home):
    """Refused anyway (the outbox is full of this reply's files and files within the grace period): other
    conversations' old files stay, they are not deleted for nothing."""
    settings = outbox.OutboxSettings(max_total_bytes=1000, max_file_bytes=500, evict_grace_seconds=3600)
    start = time.time()

    def share(sid, size, name, at, **kwargs):
        return outbox.share_file(str(_big(home, name, size)), home=home, session_id=sid, settings=settings,
                                 now=at, **kwargs)["id"]

    old = share("B", 100, "b.bin", start - 7200)  # evictable: shared more than the grace period ago
    c = share("C", 400, "c.bin", start)
    d = share("D", 300, "d.bin", start)
    mine = share("A", 200, "a0.bin", start)
    with pytest.raises(outbox.ShareRefused) as refused:  # 400 + 300 + 200 stay, 150 more does not fit
        share("A", 150, "a1.bin", start + 10, protect={mine})
    assert refused.value.reason == "no_room"
    assert _entries(home) == sorted([old, c, d, mine])
    # A share that fits once the old file goes still takes it.
    fits = share("A", 100, "a2.bin", start + 20, protect={mine})
    assert old not in _entries(home) and fits in _entries(home)


def test_the_periodic_pass_holds_each_conversation_to_its_share(home):
    """A cap lowered under what a conversation holds: its oldest go until it is within half the new cap."""
    ids = [outbox.share_file(str(_big(home, f"a{index}.bin", 100)), home=home, session_id="A",
                             now=time.time() + index)["id"] for index in range(4)]
    assert outbox.prune_outbox(home, outbox.OutboxSettings(max_total_bytes=500)) == 2  # 250 each: two stay
    assert _entries(home) == sorted(ids[2:])


def test_prose_that_names_the_convention_is_left_alone(home):
    text = "Use the MEDIA: directive to attach files."
    shared = outbox_share.share_turn_files(text, [], home=home, session_id="s", logins=[],
                                           settings=outbox.OutboxSettings())
    assert shared.text == text and shared.refused == [] and not shared.named
    assert outbox_share.strip_directives(text) == text
    from hermes_state_common import strip_media_for_preview
    assert strip_media_for_preview(text) == text
    assert strip_media_for_preview("Say MEDIA: then a path, e.g. MEDIA:notes") == \
        "Say MEDIA: then a path, e.g. MEDIA:notes"


def test_a_directive_at_a_line_start_with_a_relative_name_is_still_hidden(home):
    text = "Here it is.\n  **MEDIA:out/chart.png**\nMEDIA:/no/such/file.weird"
    shared = outbox_share.share_turn_files(text, [], home=home, session_id="s", logins=[],
                                           settings=outbox.OutboxSettings())
    assert "MEDIA:" not in shared.text and "chart.png" not in shared.text and "/no/such" not in shared.text
    assert shared.text.startswith("Here it is.") and len(shared.refused) == 2


def test_a_hung_copy_does_not_hold_the_outbox(home, monkeypatch):
    """The copy runs outside the lock: another conversation's share completes while one read is stuck."""
    import threading
    release, entered = threading.Event(), threading.Event()
    real_fill = outbox._fill_entry
    slow = home / "work" / "slow.bin"
    slow.write_bytes(b"x" * 10)

    def stuck_fill(entry_dir_fd, token, src_fd, name, *args, **kwargs):
        if name == "slow.bin":
            entered.set()
            release.wait(10)
        return real_fill(entry_dir_fd, token, src_fd, name, *args, **kwargs)

    monkeypatch.setattr(outbox, "_fill_entry", stuck_fill)
    stuck = threading.Thread(target=lambda: outbox.share_file(str(slow), home=home, session_id="A"), daemon=True)
    stuck.start()
    assert entered.wait(5)
    try:
        fast = outbox.share_file(str(_big(home, "fast.bin", 10)), home=home, session_id="B", lock_timeout=1.0)
        assert fast["id"] in _entries(home)
        assert len(os.listdir(home / "outbox" / outbox.STAGING_NAME)) == 1  # the stuck copy, not published
    finally:
        release.set()
        stuck.join(10)
    assert len(_entries(home)) == 2 and os.listdir(home / "outbox" / outbox.STAGING_NAME) == []


def test_abandoned_staging_copies_are_cleaned_but_a_fresh_one_is_kept(home, tmp_path):
    staging = home / "outbox" / outbox.STAGING_NAME
    old, fresh = staging / ("O" * 32), staging / ("F" * 32)
    for entry in (old, fresh):
        entry.mkdir(parents=True)
        (entry / "blob").write_text("marker")
    long_ago = time.time() - outbox.STAGING_MAX_AGE_SECONDS - 60
    for path in (old / "blob", old):
        os.utime(path, (long_ago, long_ago))
    keep = tmp_path / "keep.txt"
    keep.write_text("mine")
    (staging / "planted").symlink_to(keep)
    outbox.prune_outbox(home, outbox.OutboxSettings())
    assert sorted(os.listdir(staging)) == ["F" * 32] and keep.read_text() == "mine"


def test_a_link_planted_as_the_staging_folder_is_replaced_not_followed(home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / "outbox").mkdir()
    (home / "outbox" / outbox.STAGING_NAME).symlink_to(elsewhere)
    record = _share(home, _big(home, "a.bin", 10))
    assert record["id"] in _entries(home) and os.listdir(elsewhere) == []
    assert not (home / "outbox" / outbox.STAGING_NAME).is_symlink()


def test_a_compacted_conversation_still_owns_what_it_shared_before(home, tmp_path):
    """Compaction moves the conversation to a new session id; its copies are keyed on the lineage root, so its
    own quota covers both segments and its newer shares push out its older ones, not someone else's."""
    from hermes_state import SessionDB
    from tui_gateway.prompt_turn import _outbox_conversation
    db = SessionDB(db_path=tmp_path / "lineage.db")
    try:
        db.create_session(session_id="S1", source="hermie", model="m")
        db.end_session("S1", "compression")
        db.create_session(session_id="S2", source="hermie", model="m", parent_session_id="S1")

        class Agent:
            _session_db = db

        assert _outbox_conversation(Agent(), "S2") == "S1"
        assert _outbox_conversation(Agent(), "S1") == "S1"
        assert _outbox_conversation(object(), "S2") == "S2"
    finally:
        db.close()
    settings = outbox.OutboxSettings(max_total_bytes=500, max_file_bytes=200)
    first = outbox.share_file(str(_big(home, "s1.bin", 200)), home=home, session_id="S1", conversation_id="S1",
                              settings=settings, now=time.time())
    assert first["conversation_id"] == "S1"
    second = outbox.share_file(str(_big(home, "s2.bin", 200)), home=home, session_id="S2", conversation_id="S1",
                               settings=settings, now=time.time() + 1)
    assert _entries(home) == [second["id"]]  # one conversation, 250 bytes: the older segment's copy went
    # Deleting a segment removes the copies its rows show; the conversation's other segment keeps its own.
    assert outbox.remove_session_files(home, ["S1"]) == 0
    assert outbox.remove_session_files(home, ["S2"]) == 1


# ── review round 3: the real fd_path on macOS, and the operator allowlist by what the paths name ─────────────

import sys  # noqa: E402
import unicodedata  # noqa: E402

_darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="F_GETPATH is macOS-only")


@_darwin_only
def test_fd_path_reports_the_spelling_the_volume_stores(tmp_path, case_insensitive_tmp):
    """The real ``F_GETPATH`` (no stub): a case variant and an NFD spelling both come back as stored."""
    folder = tmp_path.resolve()
    stored = folder / "Report.txt"
    stored.write_text("marker")
    nfc = "café.txt"
    (folder / nfc).write_text("marker")
    for opened, expected in ((folder / "REPORT.TXT", stored),
                             (folder / unicodedata.normalize("NFD", nfc), folder / nfc)):
        fd = os.open(opened, os.O_RDONLY)
        try:
            reported = path_identity.fd_path(fd)
        finally:
            os.close(fd)
        assert reported is not None, opened
        assert unicodedata.normalize("NFC", reported) == unicodedata.normalize("NFC", str(expected))
        assert Path(reported).name == expected.name  # the stored spelling, not the one that was opened


@_darwin_only
def test_a_case_variant_of_a_denied_file_is_refused_by_the_opened_file_check(home, case_insensitive_tmp):
    """With the real ``fd_path`` the descriptor of ``STATE.DB`` is re-judged as ``state.db`` (denied), even
    where the up-front checks were given an innocent spelling."""
    (home / "state.db").write_text("marker")
    fd = os.open(home / "STATE.DB", os.O_RDONLY)
    try:
        with pytest.raises(outbox.ShareRefused) as refused:
            outbox._judge_opened(fd, home / "work" / "innocent.txt", home)
    finally:
        os.close(fd)
    assert refused.value.reason == "denied"


def _strict_old_file(root: Path, name: str = "scan.txt") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text("marker")
    old = time.time() - 30 * 86400  # long outside any recency window
    os.utime(path, (old, old))
    return path


def test_an_allowlist_root_holds_for_the_stored_spelling_when_the_case_differs(home, tmp_path, monkeypatch):
    """Simulated case-insensitive volume: the root is written ``WORK/Shared`` and the kernel reports
    ``work/shared``; the operator allowlist must contain by what the paths name, as the denylist does."""
    from gateway.platforms.base import media_delivery_resolved_path_allowed
    monkeypatch.setenv("HERMES_MEDIA_DELIVERY_STRICT", "1")
    monkeypatch.setenv("HERMES_MEDIA_ALLOW_DIRS", str(tmp_path / "WORK" / "Shared"))
    stored = _strict_old_file(tmp_path / "work" / "shared")
    monkeypatch.setattr(path_identity, "case_insensitive", lambda path: True)
    assert media_delivery_resolved_path_allowed(stored)
    assert not media_delivery_resolved_path_allowed(_strict_old_file(tmp_path / "work" / "shared2"))


@_darwin_only
def test_strict_mode_keeps_sharing_a_file_under_a_differently_cased_allowlist_root(home, tmp_path,
                                                                                    case_insensitive_tmp,
                                                                                    monkeypatch):
    """Real volume and real ``fd_path``: the agent spells the file as the operator spelled the root; the copy is
    recorded under the stored spelling and strict mode must still allow it."""
    monkeypatch.setenv("HERMES_MEDIA_DELIVERY_STRICT", "1")
    stored = _strict_old_file(tmp_path / "work" / "shared")
    spelled = tmp_path / "WORK" / "SHARED" / "scan.txt"
    monkeypatch.setenv("HERMES_MEDIA_ALLOW_DIRS", str(tmp_path / "WORK" / "SHARED"))
    record = _share(home, spelled)
    assert record["name"] == stored.name and (home / "outbox" / record["id"] / "blob").read_bytes() == b"marker"
    # Without the allowlist, strict mode refuses the same old file: the allowlist is what lets it through.
    monkeypatch.delenv("HERMES_MEDIA_ALLOW_DIRS")
    with pytest.raises(outbox.ShareRefused):
        _share(home, spelled)


def test_the_conversation_is_looked_up_once_and_only_when_a_file_is_shared(home):
    looked_up = []

    def conversation() -> str:
        looked_up.append(1)
        return "root-session"

    kwargs = dict(home=home, session_id="s-new", logins=["oidc:a"], settings=outbox.OutboxSettings(),
                  conversation_id=conversation)
    plain = outbox_share.share_turn_files("Nothing to attach.", [], **kwargs)
    assert plain.attachments == [] and not plain.named and looked_up == []
    one, two = home / "work" / "one.txt", home / "work" / "two.txt"
    one.write_text("marker")
    two.write_text("marker")
    shared = outbox_share.share_turn_files(f"Here.\nMEDIA:{one}\nMEDIA:{two}", [], **kwargs)
    assert len(shared.attachments) == 2 and looked_up == [1]
    records = [json.loads((home / "outbox" / a["id"] / "record.json").read_text()) for a in shared.attachments]
    assert {r["conversation_id"] for r in records} == {"root-session"}
    assert {r["session_id"] for r in records} == {"s-new"}
