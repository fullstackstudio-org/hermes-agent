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
    return sorted(os.listdir(root)) if root.exists() else []


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
    # A 250-byte cap keeps the two newest.
    assert outbox.prune_outbox(home, outbox.OutboxSettings(max_total_bytes=250), now=now) == 1
    assert _entries(home) == sorted(r["id"] for r in records[2:])


def test_sharing_makes_room_by_evicting_the_oldest(home):
    settings = outbox.OutboxSettings(max_total_bytes=250)
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
    assert shared.text == "Look:"


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
