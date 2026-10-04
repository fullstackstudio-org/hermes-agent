"""``tui_gateway/diff_hunks.py``: a unified diff as the bounded hunks of a ``review.diff`` request, and the patch put
back together from the approved ones. The round trips run on diffs real git made (a modified file, a new one, a deleted
one, a rename with edits, a file without a final newline) and are applied with ``git apply``; the refusals pin the
bounds and every way a diff cannot be shown as it is.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tui_gateway import diff_hunks as dh

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

OLD = "".join(f"line {n}\n" for n in range(1, 41))


def _modified(*changes: tuple[int, str]) -> str:
    lines = OLD.splitlines(keepends=True)
    for number, text in changes:
        lines[number - 1] = text + "\n"
    return "".join(lines)


# ── real diffs, applied again ───────────────────────────────────────────────────────────────────


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
                    "GIT_COMMITTER_EMAIL": "t@example.com"}
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        done = subprocess.run(["git", *args], cwd=self.root, env=self.env,
                              input=None if stdin is None else stdin.encode(), capture_output=True)
        if check and done.returncode:
            raise AssertionError(f"git {' '.join(args)}: {done.stderr.decode()}")
        return done.stdout.decode()   # bytes in, bytes out: a CRLF in the diff stays a CRLF

    def write(self, name: str, text: str | bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode())

    def commit(self) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "x")

    def diff(self, *args: str) -> str:
        return self.git("diff", "--no-color", "--no-ext-diff", *args)

    def apply(self, patch: str) -> None:
        self.git("apply", "--whitespace=nowarn", "-", stdin=patch)


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path)


def _compose(parsed: dh.ParsedDiff, approved) -> str:
    return dh.compose_patch(parsed.head, [h.as_dict() for h in parsed.hunks], approved)


@needs_git
def test_a_modified_file_round_trips_through_every_hunk(repo):
    repo.write("a.txt", OLD)
    repo.commit()
    new = _modified((3, "line three"), (20, "line twenty"), (38, "line thirty-eight"))
    repo.write("a.txt", new)
    text = repo.diff()
    parsed = dh.parse(text)
    assert parsed.head == dh.FileHead("modify", "a.txt", "a.txt") and parsed.path == "a.txt"
    assert [h.id for h in parsed.hunks] == ["h1", "h2", "h3"]
    assert all(h.header.startswith("@@ -") for h in parsed.hunks)
    patch = _compose(parsed, {"h1", "h2", "h3"})
    assert patch == "\n".join(line for line in text.split("\n") if not line.startswith("index "))   # git's own
    repo.git("checkout", "--", "a.txt")
    repo.apply(patch)
    assert (repo.root / "a.txt").read_text() == new


EDITS = {   # hunk id -> (first line index, end index, replacement), on the 40 lines of OLD
    "h1": (2, 3, ["line three", "an added line", "another"]),   # +2 lines
    "h2": (19, 20, ["line twenty"]),                            # +-0
    "h3": (37, 38, ["line thirty-eight", "extra"]),             # +1
}


def _edited(ids) -> list[str]:
    lines = OLD.splitlines()
    for hunk_id in sorted(ids, reverse=True):       # from the end, so the indexes above stay what they are
        first, end, new = EDITS[hunk_id]
        lines[first:end] = new
    return lines


@needs_git
@pytest.mark.parametrize("approved", [{"h1"}, {"h2"}, {"h3"}, {"h1", "h3"}, {"h2", "h3"}, {"h1", "h2"}])
def test_a_subset_of_the_hunks_applies_alone(repo, approved):
    """Hunks that add lines move the ones after them; the new-side start is corrected when an earlier hunk is left
    out, and ``git apply`` takes the result."""
    repo.write("a.txt", OLD)
    repo.commit()
    repo.write("a.txt", "\n".join(_edited(EDITS)) + "\n")
    parsed = dh.parse(repo.diff())
    assert len(parsed.hunks) == 3
    patch = _compose(parsed, approved)
    repo.git("checkout", "--", "a.txt")
    repo.apply(patch)
    assert (repo.root / "a.txt").read_text().splitlines() == _edited(approved)


def test_the_new_side_start_follows_the_rejected_hunks():
    hunks = [{"id": "h1", "header": "@@ -3,1 +3,3 @@", "lines": [" a", "+b", "+c"]},
             {"id": "h2", "header": "@@ -20 +22 @@ def f():", "lines": ["-x", "+y"]},
             {"id": "h3", "header": "@@ -38,2 +40,1 @@", "lines": [" k", "-z"]}]
    only_second = dh.compose_patch(None, hunks, {"h2"}, path="f.py")
    assert only_second.splitlines()[3] == "@@ -20 +20 @@ def f():"
    only_third = dh.compose_patch(None, hunks, {"h3"}, path="f.py")
    assert only_third.splitlines()[3] == "@@ -38,2 +38,1 @@"   # h1 added two lines and is left out: 40 - 2
    both_later = dh.compose_patch(None, hunks, {"h2", "h3"}, path="f.py").splitlines()
    assert "@@ -20 +20 @@ def f():" in both_later and "@@ -38,2 +38,1 @@" in both_later
    everything = dh.compose_patch(None, hunks, {"h1", "h2", "h3"}, path="f.py").splitlines()
    assert [line for line in everything if line.startswith("@@")] == [h["header"] for h in hunks]   # nothing moved
    last_alone = dh.compose_patch(None, hunks, {"h3"}, path="f.py")
    assert last_alone.startswith("diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n@@ -38,2 +38,1 @@\n")
    assert dh.compose_patch(None, hunks, set(), path="f.py") == ""
    assert dh.compose_patch(None, hunks, {"h9"}, path="f.py") == ""


@needs_git
def test_a_file_without_a_final_newline_keeps_its_marker_lines(repo):
    repo.write("a.txt", "one\ntwo\nthree")
    repo.commit()
    repo.write("a.txt", "one\ntwo\nthree\nfour")
    text = repo.diff()
    assert "\\ No newline at end of file" in text
    parsed = dh.parse(text)
    assert parsed.hunks[0].lines == (" one", " two", "-three", dh.NO_NEWLINE, "+three", "+four", dh.NO_NEWLINE)
    patch = _compose(parsed, {"h1"})
    repo.git("checkout", "--", "a.txt")
    repo.apply(patch)
    assert (repo.root / "a.txt").read_bytes() == b"one\ntwo\nthree\nfour"


@needs_git
def test_the_marker_after_both_sides_round_trips(repo):
    repo.write("a.txt", "one\ntwo")
    repo.commit()
    repo.write("a.txt", "one\n2")
    parsed = dh.parse(repo.diff())
    assert parsed.hunks[0].lines.count(dh.NO_NEWLINE) == 2
    repo.git("checkout", "--", "a.txt")
    repo.apply(_compose(parsed, {"h1"}))
    assert (repo.root / "a.txt").read_bytes() == b"one\n2"


@needs_git
def test_a_new_file_round_trips(repo):
    repo.write("keep.txt", "x\n")
    repo.commit()
    repo.write("docs/new.txt", "first\nsecond\n")
    repo.git("add", "-A")
    text = repo.diff("--cached")
    assert "new file mode 100644" in text
    parsed = dh.parse(text)
    assert parsed.head == dh.FileHead("new", None, "docs/new.txt", mode="100644")
    assert parsed.path == "docs/new.txt" and parsed.hunks[0].header == "@@ -0,0 +1,2 @@"
    patch = _compose(parsed, {"h1"})
    assert patch.startswith("diff --git a/docs/new.txt b/docs/new.txt\nnew file mode 100644\n--- /dev/null\n"
                            "+++ b/docs/new.txt\n@@ -0,0 +1,2 @@\n+first\n+second\n")
    repo.git("reset", "-q", "--hard")
    repo.git("clean", "-fdq")
    assert not (repo.root / "docs" / "new.txt").exists()
    repo.apply(patch)
    assert (repo.root / "docs" / "new.txt").read_text() == "first\nsecond\n"


@needs_git
def test_a_deleted_file_round_trips(repo):
    repo.write("gone.txt", "bye\nnow\n")
    repo.commit()
    (repo.root / "gone.txt").unlink()
    parsed = dh.parse(repo.diff())
    assert parsed.head == dh.FileHead("deleted", "gone.txt", None, mode="100644") and parsed.path == "gone.txt"
    patch = _compose(parsed, {"h1"})
    assert "deleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n@@ -1,2 +0,0 @@\n" in patch
    repo.git("checkout", "--", "gone.txt")
    repo.apply(patch)
    assert not (repo.root / "gone.txt").exists()


@needs_git
def test_a_rename_with_edits_round_trips(repo):
    repo.write("old name.txt", OLD)
    repo.write("other.txt", "keep\n")
    repo.commit()
    (repo.root / "new").mkdir()
    repo.git("mv", "old name.txt", "new/name.txt")
    new = _modified((5, "line five"))
    repo.write("new/name.txt", new)
    repo.git("add", "-A")
    text = repo.diff("--cached", "-M")
    assert "rename from old name.txt" in text and "rename to new/name.txt" in text
    parsed = dh.parse(text)
    assert parsed.head.kind == "rename" and (parsed.head.old, parsed.head.new) == ("old name.txt", "new/name.txt")
    assert parsed.path == "old name.txt -> new/name.txt"
    assert parsed.head.similarity is not None and parsed.head.similarity > 50
    patch = _compose(parsed, {"h1"})
    assert "rename from old name.txt\nrename to new/name.txt\n--- a/old name.txt\n+++ b/new/name.txt\n" in patch
    repo.git("reset", "-q", "--hard")
    repo.apply(patch)
    assert not (repo.root / "old name.txt").exists()
    assert (repo.root / "new" / "name.txt").read_text() == new


@needs_git
def test_a_diff_with_the_crlf_line_ending_of_the_diff_itself_is_read_like_the_lf_one(repo):
    repo.write("a.txt", OLD)
    repo.commit()
    repo.write("a.txt", _modified((3, "three"), (30, "thirty")))
    text = repo.diff()
    assert dh.parse(text.replace("\n", "\r\n")) == dh.parse(text)
    assert dh.parse(text.replace("\n", "\r\n").rstrip("\r\n")) == dh.parse(text)


@needs_git
def test_content_with_a_carriage_return_is_refused_not_rewritten(repo):
    """A CRLF file's lines end in CR: the CR is part of the content and cannot be shown, so the diff is refused (the
    contract's verbatim rule), never repaired."""
    repo.write("w.txt", "a\r\nb\r\nc\r\n")
    repo.commit()
    repo.write("w.txt", "a\r\nB\r\nc\r\n")
    with pytest.raises(dh.DiffError, match=r"Hunk h1, line 1 .*U\+000D"):
        dh.parse(repo.diff())


@needs_git
def test_a_binary_diff_is_refused(repo):
    repo.write("img.bin", bytes(range(256)))
    repo.commit()
    repo.write("img.bin", bytes(range(255, -1, -1)))
    for text in (repo.diff(), repo.diff("--binary")):
        with pytest.raises(dh.DiffError, match="binary"):
            dh.parse(text)


@needs_git
def test_a_diff_of_two_files_is_refused(repo):
    repo.write("a.txt", "1\n")
    repo.write("b.txt", "1\n")
    repo.commit()
    repo.write("a.txt", "2\n")
    repo.write("b.txt", "2\n")
    with pytest.raises(dh.DiffError, match="more than one file"):
        dh.parse(repo.diff())


# ── the head ────────────────────────────────────────────────────────────────────────────────────

HUNK = "@@ -1,2 +1,2 @@\n a\n-b\n+c\n"


def test_bare_hunks_take_the_agents_path():
    parsed = dh.parse(HUNK, "src/f.py")
    assert parsed.head == dh.FileHead("modify", "src/f.py", "src/f.py") and parsed.path == "src/f.py"
    assert dh.compose_patch(parsed.head, [h.as_dict() for h in parsed.hunks], {"h1"}) == (
        "diff --git a/src/f.py b/src/f.py\n--- a/src/f.py\n+++ b/src/f.py\n" + HUNK)
    bare = dh.parse(HUNK)
    assert bare.path is None
    assert dh.compose_patch(bare.head, [h.as_dict() for h in bare.hunks], {"h1"}) == HUNK


def test_plain_diff_u_headers_without_prefixes_and_with_timestamps():
    text = "--- f.py\t2026-10-03 10:00:00.000000000 +0200\n+++ f.py\t2026-10-03 10:01:00.000000000 +0200\n" + HUNK
    parsed = dh.parse(text)
    assert parsed.head == dh.FileHead("modify", "f.py", "f.py")
    assert dh.compose_patch(parsed.head, [h.as_dict() for h in parsed.hunks], {"h1"}).startswith(
        "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n@@")


def test_the_patch_is_written_from_the_stored_head_never_from_the_agents_header_text():
    """The headers the agent wrote are read into a structure and thrown away: the patch names the path the person was
    shown, whatever else the text of the header said (a ``diff --git`` line, an ``index`` line, a timestamp)."""
    text = ("diff --git a/shown.txt b/elsewhere.txt\nindex 1234567..89abcde 100644\n--- a/shown.txt\t2026\n"
            "+++ b/shown.txt\n" + HUNK)
    parsed = dh.parse(text)
    patch = dh.compose_patch(parsed.head, [h.as_dict() for h in parsed.hunks], {"h1"})
    assert "elsewhere" not in patch and "index" not in patch and "2026" not in patch
    assert patch.splitlines()[:3] == ["diff --git a/shown.txt b/shown.txt", "--- a/shown.txt", "+++ b/shown.txt"]


@pytest.mark.parametrize("text, match", [
    ("--- a/x\n+++ b/y\n" + HUNK, "two different files"),
    ("--- /dev/null\n+++ /dev/null\n" + HUNK, "both sides"),
    ("--- a/../x\n+++ b/../x\n" + HUNK, r"\.\. segment"),
    ("--- /etc/passwd\n+++ /etc/passwd\n" + HUNK, "absolute"),
    ('--- "a/x y"\n+++ "b/x y"\n' + HUNK, "quoted"),
    ("--- a/x\n" + HUNK, "followed by"),
    ("--- a/x\n+++ b/x\n--- a/x\n+++ b/x\n" + HUNK, "followed by"),
    ("diff --git a/x b/x\n" + HUNK, "no '--- '"),
    ("new file mode 100644\n--- a/x\n+++ b/x\n" + HUNK, "new, deleted or renamed"),
    ("deleted file mode 100644\n--- /dev/null\n+++ b/x\n" + HUNK, "new but also deleted"),
    ("rename from x\nrename to y\n--- a/x\n+++ b/x\n" + HUNK, "new, deleted or renamed"),
    ("new file mode 10064\n--- /dev/null\n+++ b/x\n" + HUNK, "six octal"),
    ("similarity index 190%\n--- a/x\n+++ b/y\n" + HUNK, "similarity"),
    ("old mode 100644\nnew mode 100755\n--- a/x\n+++ b/x\n" + HUNK, "not part of a unified diff"),
    ("```diff\n" + HUNK + "```\n", "not part of a unified diff"),
    ("", "required"), ("   \n\n", "required"), ("--- a/x\n+++ b/x\n", "no hunk"),
])
def test_what_the_head_may_not_say(text, match):
    with pytest.raises(dh.DiffError, match=match):
        dh.parse(text)


def test_the_agents_path_must_be_the_file_the_diff_changes():
    text = "--- a/x.txt\n+++ b/x.txt\n" + HUNK
    assert dh.parse(text, "x.txt").path == "x.txt"
    with pytest.raises(dh.DiffError, match="not the file the diff changes"):
        dh.parse(text, "y.txt")
    with pytest.raises(dh.DiffError, match="cannot be used"):
        dh.parse(HUNK, "../etc/passwd")
    with pytest.raises(dh.DiffError, match="cannot be used"):
        dh.parse(HUNK, "p" * 301)
    renamed = "similarity index 80%\nrename from a.txt\nrename to b.txt\n--- a/a.txt\n+++ b/b.txt\n" + HUNK
    assert dh.parse(renamed, "b.txt").path == "a.txt -> b.txt"
    with pytest.raises(dh.DiffError, match="not the file"):
        dh.parse(renamed, "a.txt")
    deleted = "deleted file mode 100644\n--- a/a.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n"
    assert dh.parse(deleted, "a.txt").head.kind == "deleted"


# ── the hunks ───────────────────────────────────────────────────────────────────────────────────


def _hunk(*lines: str, header: str | None = None) -> str:
    old = sum(1 for line in lines if line[:1] in (" ", "-"))
    new = sum(1 for line in lines if line[:1] in (" ", "+"))
    return (header or f"@@ -1,{old} +1,{new} @@") + "\n" + "".join(line + "\n" for line in lines)


def test_a_hunk_is_read_by_its_counts_so_a_dashed_line_is_content():
    text = _hunk(" keep", "--- not a header", "+++ not a header either", "+added", header="@@ -1,2 +1,3 @@")
    parsed = dh.parse(text)
    assert parsed.hunks[0].lines == (" keep", "--- not a header", "+++ not a header either", "+added")


def test_two_hunks_and_a_section_text():
    text = _hunk(" a", "-b", "+c", header="@@ -1,2 +1,2 @@ def f(x):") + _hunk(" z", "+y", header="@@ -9 +9,2 @@")
    parsed = dh.parse(text)
    assert [h.header for h in parsed.hunks] == ["@@ -1,2 +1,2 @@ def f(x):", "@@ -9 +9,2 @@"]
    assert [h.id for h in parsed.hunks] == ["h1", "h2"]
    assert dh.parse(text + "\n\n").hunks == parsed.hunks   # blank lines at the end of the text are not a hunk


def test_a_blank_context_line_is_one_space_or_an_empty_line():
    spaced = "@@ -1,3 +1,3 @@\n a\n \n-b\n+c\n"
    empty = "@@ -1,3 +1,3 @@\n a\n\n-b\n+c\n"
    assert dh.parse(spaced).hunks[0].lines == (" a", " ", "-b", "+c")
    assert dh.parse(empty) == dh.parse(spaced)


@pytest.mark.parametrize("text, match", [
    ("@@ -1,2 +1,2 @@\n a\n-b\n", "the diff ends first"),
    ("@@ -1,1 +1,1 @@\n a\n b\n", "not part of a hunk"),
    ("@@ -1,1 +1,1 @@\n a\n-b\n+c\n", "not part of a hunk"),
    ("@@ -1,2 +1,0 @@\n-a\n+b\n", "does not fit the header's counts"),
    ("@@ -1,2 +1,0 @@\n a\n", "does not fit the header's counts"),
    ("@@ -1 +1 @@\n-a\n+b\nstray\n", "not part of a hunk"),
    ("@@ -1 +1 @@\n-a\n+b\n\\ No newline\n", "not part of a hunk"),
    ("@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+b\n", "must follow a line"),
    ("@@ -1,2 +1,2 @@\n a\n\\ No newline at end of file\n\\ No newline at end of file\n-b\n+c\n", "must follow a line"),
    ("@@@ -1,2 -1,2 +1,2 @@@\n a\n", "not of the form"),
    ("@@ -1,2 +1,2\n a\n", "not of the form"),
    ("@@ -1 +1 @@\n?a\n+b\n", "does not fit"),
    ("@@ -1 +1 @@ \u202ebidi\n-a\n+b\n", "cannot be shown"),
    ("@@ -1 +1 @@ tab\t\n-a\n+b\n", "whitespace at the end"),
])
def test_a_hunk_whose_counts_or_lines_do_not_fit_is_refused(text, match):
    with pytest.raises(dh.DiffError, match=match):
        dh.parse(text)


# ── bounds ──────────────────────────────────────────────────────────────────────────────────────


def test_the_bounds_are_the_contracts():
    assert (dh.MAX_DIFF_BYTES, dh.MAX_HUNKS, dh.MAX_HUNK_LINES, dh.MAX_LINE_CHARS, dh.MAX_HEADER_CHARS,
            dh.MAX_PATH_CHARS) == (65_536, 200, 400, 500, 200, 300)


def _many(count: int) -> str:
    return "".join(f"@@ -{n * 3 + 1} +{n * 3 + 1} @@\n-a\n+b\n" for n in range(count))


def test_at_most_two_hundred_hunks():
    assert len(dh.parse(_many(200)).hunks) == 200
    with pytest.raises(dh.DiffError, match="more than 200 hunks"):
        dh.parse(_many(201))


def test_at_most_four_hundred_lines_in_a_hunk():
    def hunk(count: int) -> str:
        return f"@@ -1,{count} +1,{count} @@\n" + " x\n" * count

    assert len(dh.parse(hunk(400)).hunks[0].lines) == 400
    with pytest.raises(dh.DiffError, match="Hunk h1: it has more than 400 lines"):
        dh.parse(hunk(401))
    marked = "@@ -1,400 +1,400 @@\n" + " x\n" * 400 + dh.NO_NEWLINE + "\n"
    with pytest.raises(dh.DiffError, match="more than 400 lines"):
        dh.parse(marked)


def test_at_most_five_hundred_characters_in_a_line_its_marker_included():
    assert dh.parse(_hunk("+" + "x" * 499)).hunks[0].lines[0] == "+" + "x" * 499
    with pytest.raises(dh.DiffError, match=r"it is 501 characters \(at most 500\)"):
        dh.parse(_hunk("+" + "x" * 500))


def test_a_header_has_at_most_two_hundred_characters():
    ok = "@@ -1 +1 @@ " + "f" * (200 - len("@@ -1 +1 @@ "))
    assert len(ok) == 200 and dh.parse(_hunk("-a", "+b", header=ok)).hunks[0].header == ok
    long = "@@ -1 +1 @@ " + "f" * 200
    with pytest.raises(dh.DiffError, match="at most 200"):
        dh.parse(_hunk("-a", "+b", header=long))
    assert dh.header_problem(ok) == ""


def test_at_most_64_kib_of_diff():
    # 130 hunks of 500 bytes is under the hunk count and over the byte limit.
    hunk = "@@ -1,2 +1,2 @@\n a\n-" + "b" * 480 + "\n+" + "c" * 480 + "\n"
    one = len(hunk.encode())
    count = dh.MAX_DIFF_BYTES // one + 1
    assert count <= dh.MAX_HUNKS
    with pytest.raises(dh.DiffError, match="the limit is 65536"):
        dh.parse(hunk * count)
    assert len(dh.parse(hunk * (dh.MAX_DIFF_BYTES // one)).hunks) == dh.MAX_DIFF_BYTES // one
    multi = "@@ -1 +1 @@\n-é\n+" + "é" * 40_000 + "\n"
    with pytest.raises(dh.DiffError, match="bytes"):
        dh.parse(multi)   # the limit counts bytes, not characters


# ── every line passes the verbatim rules ────────────────────────────────────────────────────────


@pytest.mark.parametrize("line, why", [
    ("+trailing tab\t", "whitespace at the end"),
    ("-\t", "whitespace at the end"),
    ("+tab\t then spaces" + " " * 17 + "y", "17 spaces in a row"),
    ("+" + " " * 33 + "\tx", "indented 33 spaces"),
    ("+bidi ‮ text", "U+202E"),
    ("+zero​width", "U+200B"),
    ("+nbsp here", "U+00A0"),
    ("+soft­hyphen", "U+00AD"),
    ("+trailing space ", "whitespace at the end"),
    ("-trailing　", "U+3000"),
    ("+x" + " " * 17 + "y", "17 spaces in a row"),
    ("+" + " " * 33 + "x", "indented 33 spaces"),
    ("+   ", "whitespace at the end"),
    ("+bell\x07", "U+0007"),
    ("+cr\rinside", "U+000D"),
    ("+line sep", "U+2028"),
    ("+privateuse", "U+E000"),
    ("+" + "́" * 5, "too many combining marks"),
])
def test_a_line_that_cannot_be_shown_as_it_is_is_refused(line, why):
    marker = line[0]
    other = "-a" if marker == "+" else "+a"
    text = _hunk(other, line)
    with pytest.raises(dh.DiffError, match=re.escape(why)):
        dh.parse(text)


def test_the_marker_is_not_part_of_the_rule_and_the_rest_is_a_line_of_text():
    assert dh.line_problem(" ") == "" and dh.line_problem("+") == "" and dh.line_problem("-") == ""
    assert dh.line_problem("  ") != "" and dh.line_problem("+ ") != ""   # spaces after the marker are invisible
    assert dh.line_problem(" " + " " * 32 + "x") == ""
    assert dh.line_problem("+" + " " * 32 + "x") == "" and dh.line_problem("+" + " " * 33 + "x") != ""
    assert dh.line_problem("+x" + " " * 16 + "y") == "" and dh.line_problem("+x" + " " * 17 + "y") != ""
    assert dh.line_problem("?x") != "" and dh.line_problem("") != ""
    assert dh.line_problem(dh.NO_NEWLINE) == "" and dh.line_problem("\\ No newline") != ""
    assert dh.line_problem("+déjà vu \U0001f600") == ""


def test_an_error_names_the_hunk_and_the_line_and_quotes_little():
    text = _hunk(" a", " b", "+" + "x\u202ey" + "z" * 100)
    with pytest.raises(dh.DiffError) as caught:
        dh.parse(text)
    message = str(caught.value)
    assert message.startswith("Hunk h1, line 3 (line 4 of the diff)") and len(message) < 300
    assert "..." in message


def test_a_diff_that_is_not_text_is_refused():
    for bad in (None, 3, b"@@ -1 +1 @@\n-a\n+b\n", ["@@"]):
        with pytest.raises(dh.DiffError, match="required"):
            dh.parse(bad)
    with pytest.raises(dh.DiffError, match="surrogate"):
        dh.parse("@@ -1 +1 @@\n-a\n+\ud800\n")


# ── tabs ────────────────────────────────────────────────────────────────────────────────────────


def test_a_tab_is_allowed_leading_and_inside_a_line_and_counts_as_one_character():
    for line in ("+\tif x {", " \t\treturn a\tb", "-\t\t// comment\twith a tab", "+a\tb"):
        assert dh.line_problem(line) == "", line
    assert dh.line_problem("+\t") != ""                   # a tab at the end is whitespace nobody sees
    assert dh.line_problem("+" + "\t" * 499) != ""        # all tabs: nothing visible, whitespace at the end
    assert dh.line_problem("+" + "\t" * 498 + "x") == ""  # 500 code points
    assert dh.line_problem("+" + "\t" * 499 + "x") != ""   # 501: over the limit, a tab counts as one
    # A tab is not a space: it ends the indent and a run of spaces (README §6.3 counts spaces only).
    assert dh.line_problem("+" + " " * 32 + "\t" + " " * 16 + "x") == ""     # 32 of indent, then a run of 16
    assert dh.line_problem("+" + " " * 32 + "\t" + " " * 17 + "x") != ""     # the run after the tab is a run, not indent
    assert dh.line_problem("+x" + " " * 16 + "\t" + " " * 16 + "y") == ""
    assert dh.line_problem("+x" + " " * 17 + "\ty") != ""
    # Every other character the README refuses stays refused.
    for bad in ("+\x0b", "+a\x0cb", "+a\rb", "+a\u00a0b", "+a\u202eb", "+a\u200bb", "+a\x00b"):
        assert dh.line_problem(bad) != "", repr(bad)


GO = """package main

import "fmt"

func main() {
\tfor i := 0; i < 3; i++ {
\t\tfmt.Println(i)
\t}
}
"""


@needs_git
def test_a_tab_indented_go_diff_round_trips(repo):
    repo.write("main.go", GO)
    repo.write("Makefile", "all:\n\tgo build ./...\n")
    repo.commit()
    new = GO.replace("i < 3", "i < 5").replace("\t\tfmt.Println(i)", "\t\tfmt.Println(i)\n\t\tfmt.Println(i * 2)")
    repo.write("main.go", new)
    text = repo.diff("--", "main.go")
    assert "\t\tfmt.Println(i * 2)" in text
    parsed = dh.parse(text)
    assert any(line.startswith("+\t\tfmt.Println(i * 2)") for h in parsed.hunks for line in h.lines)
    assert parsed.hunks[0].header.startswith("@@ -")
    repo.git("checkout", "--", "main.go")
    repo.apply(_compose(parsed, {h.id for h in parsed.hunks}))
    assert (repo.root / "main.go").read_text() == new
    repo.write("Makefile", "all:\n\tgo build ./...\n\tgo test ./...\n")
    make = dh.parse(repo.diff("--", "Makefile"))
    assert make.hunks[0].lines[-1] == "+\tgo test ./..."


def test_a_tab_in_a_hunk_header_s_section_text_is_allowed():
    parsed = dh.parse("@@ -1 +1 @@ func\t(a int)\n-a\n+b\n")
    assert parsed.hunks[0].header == "@@ -1 +1 @@ func\t(a int)"
