"""A unified diff as the bounded hunks of a ``review.diff`` request, and the patch put back together from the hunks the
person approved (plan ``request-types-v2``, contract ``contract/requests`` §7).

:func:`parse` reads the agent's diff of ONE file and returns a :class:`ParsedDiff`: the file's head (what the diff
says about the file: modified, new, deleted or renamed) and the hunks, ids ``h1``, ``h2``, ... Nothing is guessed and
nothing is repaired; a diff that cannot be shown as it is raises :class:`DiffError` with a sentence for the agent:

- bounds: at most :data:`MAX_DIFF_BYTES` (64 KiB) of text, :data:`MAX_HUNKS` hunks, :data:`MAX_HUNK_LINES` lines in
  one, :data:`MAX_LINE_CHARS` characters in a line (its marker included), :data:`MAX_HEADER_CHARS` in a hunk header;
- a hunk is read by its header's counts (``@@ -a,b +c,d @@``: ``b`` old and ``d`` new lines), the way ``patch`` does,
  so a removed line that looks like ``--- x`` is content; counts that do not match the lines refuse the diff. Starting
  line numbers are not checked;
- every line passes the verbatim rules of README §6.2 and §7.1 (:func:`line_problem`): the marker (space, ``+`` or
  ``-``) is taken off first and the rest is checked as one line of text (:func:`text_problem`: a tab is the one
  exception to README §6.2, so Go and Makefile diffs can be reviewed; the layout limits are a diff's own, in columns
  with a tab stop every 8: indent at most 96, any other run of spaces and tabs at most 32), so a carriage return that is part of
  the line (CRLF content), a hidden character, whitespace at the end of a line or a wide run of whitespace refuses the
  diff, never rewrites it. A blank context line is one space (an empty line inside a hunk is read as that);
- the line ending of the DIFF itself may be CRLF (every line, the last one aside, ends in CR: they are all removed);
  a CR on only some lines is a CR in the content and refused;
- ``\\ No newline at end of file`` is kept as a line of its hunk (exactly that text) only in the LAST hunk, once per
  side, directly after the last ``-`` line and/or the last ``+`` line of the hunk, never after a context line:
  anywhere else ``git apply`` would join the line to the next one of the file, invisibly;
- a binary diff (``Binary files ... differ``, ``GIT binary patch``), a diff of several files, a diff without a hunk and
  header lines this module does not know (mode changes, copies) are refused.

The file head is read into a structure and put back by :func:`compose_patch` from that structure and the hunks the
GATEWAY stored, never from the agent's own header text: the person is shown ``path`` and the hunks, so the patch the
agent gets back names exactly that path (paths are relative, without ``..``) and contains exactly the approved
hunks. Its form is git's (``diff --git a/<path> b/<path>``, ``--- a/``, ``+++ b/``; apply it with ``git apply``).
Rejecting an earlier hunk shifts the new-side start of the hunks after it; :func:`compose_patch` corrects it.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Sequence
from dataclasses import dataclass

from tui_gateway.request_text import verbatim_problem

MAX_DIFF_BYTES = 65_536
MAX_HUNKS = 200
MAX_HUNK_LINES = 400
MAX_LINE_CHARS = 500
MAX_HEADER_CHARS = 200
MAX_PATH_CHARS = 300
NO_NEWLINE = "\\ No newline at end of file"
#: ``@@ -a,b +c,d @@`` and, after a space, the section text git adds (the function the hunk is in). A count left out is 1.
HEADER = re.compile(r"@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@((?: .*)?)")
_MODE = re.compile(r"[0-7]{6}")
_INDEX = re.compile(r"index [0-9a-fA-F]{4,64}\.\.[0-9a-fA-F]{4,64}(?: ([0-7]{6}))?")
#: The one mode of a file the gateway lets a diff create or delete: a regular, non-executable file.
REGULAR_MODE = "100644"
#: A tab stop every this many columns, for the two limits below (README §7.1).
TAB_STOP = 8
#: The layout limits of a diff line, in columns (README §7.1): wider than a draft's 32 and 16 (§6.3) because code nests.
MAX_DIFF_INDENT = 96
MAX_DIFF_SPACE_RUN = 32
#: All the spaces and tabs of one line together, indent included (a tab is a stop every 8 columns): runs separated by
#: a nearly invisible character would otherwise add up without limit.
MAX_DIFF_WHITESPACE = 160
_WHITESPACE_RUN = re.compile(r"[ \t]+")
_SIMILARITY = re.compile(r"(\d{1,3})%")
_SHORT = 60


class DiffError(ValueError):
    """The diff cannot be reviewed as given: the message says what to change (it is shown to the agent)."""


@dataclass(frozen=True)
class FileHead:
    """What the diff says about its one file. ``kind`` is ``modify``, ``new``, ``delete`` or ``rename``; ``old`` and
    ``new`` are relative paths (``None`` for the side that does not exist); ``similarity`` is a rename's index
    (percent). A new or deleted file is always a regular file of mode 100644: any other mode is refused."""

    kind: str
    old: str | None = None
    new: str | None = None
    similarity: int | None = None

    @property
    def path(self) -> str:
        """The path the person is shown: the file's own (the new path of a rename; ``old_path`` is the other)."""
        return (self.old if self.kind == "delete" else self.new) or ""

    @property
    def old_path(self) -> str | None:
        """A rename's previous path, else ``None``."""
        return self.old if self.kind == "rename" else None


@dataclass(frozen=True)
class Hunk:
    id: str
    header: str
    lines: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"id": self.id, "header": self.header, "lines": list(self.lines)}


@dataclass(frozen=True)
class ParsedDiff:
    head: FileHead
    hunks: tuple[Hunk, ...]

    @property
    def path(self) -> str:
        return self.head.path


# ── one line ──────────────────────────────────────────────────────────────────────────────────


def text_problem(text: str) -> str:
    """Why *text*, one line of a hunk without its marker (or a header), cannot be shown as it is, or "". README §6.2
    (characters) with ONE difference for a diff: U+0009 is allowed, leading and inside the line. The layout limits
    are a diff's own, wider than a draft's because code nests deeper (README §7.1): a tab is a fixed stop every
    :data:`TAB_STOP` columns and a run of spaces and tabs is measured in columns, the indent against
    :data:`MAX_DIFF_INDENT` (96), any other run against :data:`MAX_DIFF_SPACE_RUN` (32) and all of them together
    against :data:`MAX_DIFF_WHITESPACE` (160). That keeps padding from pushing the text far out of view; it cannot make
    a long row fit, so a client shows an overflow indicator for a row wider than its view. A combining mark directly
    after a space or a tab, or at the start of the text, is refused (it would only keep two runs apart). A tab counts
    as one code point for the length of the line. A client shows a tab visibly (a marker or such a tab stop), never
    hidden. Whitespace at the end of the line, a tab included, is still refused: no rendering shows it."""
    # Every run of spaces and tabs is measured below; for the characters, a run stands in as one visible character.
    if problem := verbatim_problem(_WHITESPACE_RUN.sub("x", text)):
        return problem
    if text != text.rstrip():
        return "whitespace at the end of a line or of the text cannot be seen"
    for at, ch in enumerate(text):
        if unicodedata.category(ch) in ("Mn", "Me") and (at == 0 or text[at - 1] in " \t"):
            return f"character U+{ord(ch):04X} is a combining mark after a space or at the start of the text"
    column, position, total = 0, 0, 0
    for run in _WHITESPACE_RUN.finditer(text):
        column += run.start() - position
        start = column
        for ch in run.group():
            column = (column // TAB_STOP + 1) * TAB_STOP if ch == "\t" else column + 1
        position = run.end()
        total += column - start
        if run.start() == 0 and column > MAX_DIFF_INDENT:
            return (f"it is indented {column} columns (a tab is a stop every {TAB_STOP}; at most {MAX_DIFF_INDENT}), "
                    "which can put part of it out of view; present it without padding")
        if run.start() != 0 and column - start > MAX_DIFF_SPACE_RUN:
            return (f"it has {column - start} columns of spaces and tabs in a row (a tab is a stop every {TAB_STOP}; "
                    f"at most {MAX_DIFF_SPACE_RUN}), which can put part of it out of view; present it without padding")
        if total > MAX_DIFF_WHITESPACE:
            return (f"it has more than {MAX_DIFF_WHITESPACE} columns of spaces and tabs in all (a tab is a stop every "
                    f"{TAB_STOP}), which can put part of it out of view; present it without padding")
    return ""


def line_problem(line: str) -> str:
    """Why the hunk line *line* (marker included) cannot be shown as it is, or "". The rule of README §7: at most
    :data:`MAX_LINE_CHARS` code points; the line is the ``\\ No newline at end of file`` marker or starts with a space,
    ``+`` or ``-``; the rest, taken as one line of text, passes :func:`text_problem` (§6.2 with tabs allowed, and §7.1's layout limits)."""
    if len(line) > MAX_LINE_CHARS:
        return f"it is {len(line)} characters (at most {MAX_LINE_CHARS})"
    if line == NO_NEWLINE:
        return ""
    if line[:1] not in (" ", "+", "-"):
        return "it does not start with a space, + or -"
    return text_problem(line[1:])


def header_problem(header: str) -> str:
    """Why the hunk header *header* is not one this module shows, or ""."""
    if len(header) > MAX_HEADER_CHARS:
        return f"it is {len(header)} characters (at most {MAX_HEADER_CHARS})"
    if HEADER.fullmatch(header) is None:
        return "it is not of the form @@ -a,b +c,d @@"
    return text_problem(header)


def _short(line: str) -> str:
    return repr(line if len(line) <= _SHORT else line[:_SHORT] + "...")


# ── paths ─────────────────────────────────────────────────────────────────────────────────────


def path_problem(path: str) -> str:
    """Why *path* is not a path to name a file by, or "": it must be relative, without empty, ``.``, ``..`` or ``.git``
    (any case) segments or segments that start with a space or end with a space or a dot, at most
    :data:`MAX_PATH_CHARS` characters, free of control characters (a line break would
    inject header lines into the patch) and text that can be shown as it is."""
    if not path:
        return "it is empty"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return "it has a control character"
    if len(path) > MAX_PATH_CHARS:
        return f"it is {len(path)} characters (at most {MAX_PATH_CHARS})"
    if path.startswith("/"):
        return "it is absolute: use a path relative to the repository"
    if any(segment in ("", ".", "..") for segment in path.split("/")):
        return "it has an empty, . or .. segment"
    if any(segment.lower() == ".git" for segment in path.split("/")):
        return "it has a .git segment"
    if any(segment[0] == " " or segment[-1] in " ." for segment in path.split("/")):
        return "a segment starts with a space or ends with a space or a dot"
    if "\\" in path:
        return "it has a backslash"
    return verbatim_problem(path)


def _file_name(token: str, what: str) -> str | None:
    """The path a ``---`` or ``+++`` line names (``None`` for ``/dev/null``), without the tab and timestamp some
    tools append."""
    name = token.split("\t", 1)[0]
    if name.startswith('"'):
        raise DiffError(f"{what}: a quoted file name is not supported; use a plain relative path.")
    return None if name == "/dev/null" else name


def _checked(path: str, what: str) -> str:
    if problem := path_problem(path):
        raise DiffError(f"{what} {_short(path)} cannot be used: {problem}.")
    return path


# ── the head ──────────────────────────────────────────────────────────────────────────────────


@dataclass
class _Preamble:
    git: bool = False
    old_name: str | None = None
    new_name: str | None = None
    has_files: bool = False
    new_file: bool = False
    deleted_file: bool = False
    similarity: int | None = None
    rename_from: str | None = None
    rename_to: str | None = None


def _read_preamble(lines: list[str]) -> tuple[_Preamble, int]:
    """The header lines before the first hunk, and the index of that hunk's header."""
    pre, i = _Preamble(), 0
    while i < len(lines) and not lines[i].startswith("@@"):
        line = lines[i]
        number = i + 1
        if line.startswith("diff --git "):
            if pre.git or pre.has_files:
                raise DiffError("The diff names more than one file; review one file at a time (one call each).")
            pre.git = True
        elif line.startswith("index "):
            match = _INDEX.fullmatch(line)
            if match is None:
                raise DiffError(f"Line {number}: an index line looks like 'index 1234567..89abcde 100644'.")
            if match.group(1) is not None:
                _mode(match.group(1), number)
        elif line.startswith("new file mode "):
            _mode(line[len("new file mode "):], number)
            pre.new_file = True
        elif line.startswith("deleted file mode "):
            _mode(line[len("deleted file mode "):], number)
            pre.deleted_file = True
        elif line.startswith("old mode ") or line.startswith("new mode "):
            raise DiffError(f"Line {number}: a change of a file's mode cannot be reviewed; only the content of regular "
                            "files (mode 100644) can.")
        elif line.startswith("similarity index "):
            match = _SIMILARITY.fullmatch(line[len("similarity index "):])
            if match is None or int(match.group(1)) > 100:
                raise DiffError(f"Line {number}: a similarity index looks like 'similarity index 90%'.")
            pre.similarity = int(match.group(1))
        elif line.startswith("rename from "):
            pre.rename_from = _checked(line[len("rename from "):], f"Line {number}: the path")
        elif line.startswith("rename to "):
            pre.rename_to = _checked(line[len("rename to "):], f"Line {number}: the path")
        elif line.startswith("--- "):
            if pre.has_files or not (i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
                raise DiffError(f"Line {number}: a '--- ' line must be followed by a '+++ ' line, once.")
            pre.old_name = _file_name(line[4:], f"Line {number}")
            pre.new_name = _file_name(lines[i + 1][4:], f"Line {number + 1}")
            pre.has_files = True
            i += 1
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            raise DiffError("A binary diff cannot be reviewed: only text hunks can be shown to the person.")
        else:
            raise DiffError(f"Line {number} is not part of a unified diff of one file: {_short(line)}. Send the "
                            "diff as it is (git diff or diff -u), without anything around it.")
        i += 1
    return pre, i


def _mode(text: str, number: int) -> str:
    """*text* when it is :data:`REGULAR_MODE`; any other mode is refused with the reason: only regular, non-executable
    files can be created or deleted through a review (a link or a submodule would write something other than what
    the hunks show, and an executable bit is not in a hunk at all)."""
    if _MODE.fullmatch(text) is None:
        raise DiffError(f"Line {number}: a file mode is six octal digits (100644).")
    if text != REGULAR_MODE:
        what = {"120000": "a symbolic link", "160000": "a submodule (gitlink)", "100755": "an executable file"}.get(
            text, "not a regular file")
        raise DiffError(f"Line {number}: mode {text} is {what}; only regular files of mode {REGULAR_MODE} can be "
                        "reviewed.")
    return text


def _head(pre: _Preamble, path: str | None) -> FileHead:
    """The :class:`FileHead` the header lines and the agent's ``path`` say; refuses what contradicts. A diff without
    ``---`` and ``+++`` lines (bare hunks) needs the agent's ``path``: the person must see which file it is."""
    if path is not None:
        _checked(path, "path")
    if not pre.has_files:
        if pre.git or pre.new_file or pre.deleted_file or pre.rename_from or pre.rename_to:
            raise DiffError("The diff has file header lines but no '--- ' and '+++ ' lines.")
        if path is None:
            raise DiffError("path is required: the diff has no '--- ' and '+++ ' lines, so say which file it changes "
                            "(a relative path) or send the diff with its header lines.")
        return FileHead("modify", path, path)
    old, new = pre.old_name, pre.new_name
    # git writes a/ and b/ in front of both names; strip them as a pair (or from the one that exists).
    if (old is None or old.startswith("a/")) and (new is None or new.startswith("b/")):
        old = old[2:] if old else None
        new = new[2:] if new else None
    for name, side in ((old, "'---'"), (new, "'+++'")):
        if name is not None:
            _checked(name, f"The {side} path")
    if old is None and new is None:
        raise DiffError("The diff has /dev/null on both sides.")
    if old is None:
        if pre.deleted_file or pre.rename_from or pre.rename_to:
            raise DiffError("The header says the file is new but also deleted or renamed.")
        head = FileHead("new", None, new)
    elif new is None:
        if pre.new_file or pre.rename_from or pre.rename_to:
            raise DiffError("The header says the file is deleted but also new or renamed.")
        head = FileHead("delete", old, None)
    elif old == new:
        if pre.new_file or pre.deleted_file or pre.rename_from or pre.rename_to:
            raise DiffError("The header says the file is new, deleted or renamed but names one path on both sides.")
        head = FileHead("modify", old, new)
    else:
        if pre.new_file or pre.deleted_file:
            raise DiffError("The header says the file is renamed but also new or deleted.")
        if (pre.rename_from, pre.rename_to) != (old, new):
            raise DiffError("The diff names two different files without 'rename from' and 'rename to' lines that "
                            "say so; review one file at a time.")
        head = FileHead("rename", old, new, similarity=pre.similarity)
    if path is not None and path != head.path:
        raise DiffError(f"path {_short(path)} is not the file the diff changes ({_short(head.path)}); leave "
                        "path out or name that file.")
    return head


# ── the hunks ─────────────────────────────────────────────────────────────────────────────────


def _count(text: str | None) -> int:
    return 1 if text is None else int(text)


def _read_hunk(lines: list[str], i: int, number: int) -> tuple[Hunk, int]:
    """The hunk whose header is ``lines[i]`` and the index of the line after it."""
    hid = f"h{number}"
    header = lines[i]
    if problem := header_problem(header):
        raise DiffError(f"Hunk {hid} (line {i + 1}): the header {_short(header)} cannot be shown: {problem}.")
    match = HEADER.fullmatch(header)
    old_left, new_left = _count(match.group(2)), _count(match.group(4))
    body: list[str] = []
    marked: set[str] = set()
    i += 1

    def fail(message: str) -> DiffError:
        return DiffError(f"Hunk {hid}: {message}")

    def check_marker(number: int) -> None:
        """``\\ No newline at end of file`` says the line before it has no newline. It is allowed only after a ``-``
        or ``+`` line that is the last of its side in the hunk (git apply would otherwise join that line to the next
        one in the file, invisibly), once per side; the last hunk is checked by the caller."""
        if not body or body[-1] == NO_NEWLINE:
            raise fail(f"line {number}: '{NO_NEWLINE}' must follow a line.")
        side = body[-1][0]
        if side == " ":
            raise fail(f"line {number}: '{NO_NEWLINE}' after a context line is refused: show the change of the final "
                       "newline as - and + lines of that line.")
        if (old_left if side == "-" else new_left) > 0 or side in marked:
            raise fail(f"line {number}: '{NO_NEWLINE}' is allowed only once after the last "
                       f"{'old (-)' if side == '-' else 'new (+)'} line of the hunk.")
        marked.add(side)

    while old_left > 0 or new_left > 0:
        if i >= len(lines):
            raise fail(f"the header counts {_count(match.group(2))} old and {_count(match.group(4))} new lines but "
                       "the diff ends first.")
        line = lines[i]
        if line == "":
            line = " "  # an editor may have stripped the space of a blank context line
        if line == NO_NEWLINE:
            check_marker(i + 1)
        elif line[0] == " " and old_left > 0 and new_left > 0:
            old_left, new_left = old_left - 1, new_left - 1
        elif line[0] == "-" and old_left > 0:
            old_left -= 1
        elif line[0] == "+" and new_left > 0:
            new_left -= 1
        else:
            raise fail(f"line {i + 1} {_short(line)} does not fit the header's counts "
                       f"({_count(match.group(2))} old and {_count(match.group(4))} new lines).")
        _check_line(line, hid, len(body) + 1, i + 1)
        body.append(line)
        i += 1
        if len(body) > MAX_HUNK_LINES:
            raise fail(f"it has more than {MAX_HUNK_LINES} lines; split the change into smaller hunks.")
    if i < len(lines) and lines[i] == NO_NEWLINE:
        check_marker(i + 1)
        body.append(NO_NEWLINE)
        i += 1
        if len(body) > MAX_HUNK_LINES:
            raise fail(f"it has more than {MAX_HUNK_LINES} lines; split the change into smaller hunks.")
    if not body:
        raise fail("it has no lines.")
    start, count = int(match.group(1)), _count(match.group(2))
    if not any(line[0] == " " for line in body) and (start > 1 or (count == 0 and start == 1)):
        raise fail(f"it has no context line and starts at line {start}: git apply puts a hunk without context at the "
                   "end of the file, not at that line, so the person would see one place and the change would land "
                   "elsewhere. Include unchanged lines around the change (git diff -U3, never -U0).")
    return Hunk(hid, header, tuple(body)), i


def _check_line(line: str, hid: str, index: int, number: int) -> None:
    if problem := line_problem(line):
        raise DiffError(f"Hunk {hid}, line {index} (line {number} of the diff) {_short(line)} cannot be shown as it "
                        f"is: {problem}.")


def parse(diff: object, path: str | None = None) -> ParsedDiff:
    """The one-file unified diff *diff* as a :class:`ParsedDiff`; *path* is the agent's name for the file (a diff of
    bare hunks, without ``---`` and ``+++`` lines, needs it). Raises :class:`DiffError`, the sentence to give the agent."""
    if not isinstance(diff, str):
        raise DiffError("diff is required: a unified diff of one file, as text.")
    try:
        size = len(diff.encode("utf-8"))
    except UnicodeEncodeError:
        raise DiffError("The diff is not valid text (it has a lone surrogate).") from None
    if size > MAX_DIFF_BYTES:
        raise DiffError(f"The diff is {size} bytes; the limit is {MAX_DIFF_BYTES} (64 KiB). Review a smaller change.")
    if not diff.strip():
        raise DiffError("diff is required: a unified diff of one file, as text.")
    lines = diff.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > 1 and all(line.endswith("\r") for line in lines[:-1]):
        # The diff's own line ending is CRLF: take it off every line.
        lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    pre, i = _read_preamble(lines)
    head = _head(pre, path)
    hunks: list[Hunk] = []
    while i < len(lines):
        if not lines[i].startswith("@@"):
            if lines[i].startswith("diff --git ") or (
                    lines[i].startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
                raise DiffError("The diff names more than one file; review one file at a time (one call each).")
            if all(line == "" for line in lines[i:]):
                break
            raise DiffError(f"Line {i + 1} is not part of a hunk: {_short(lines[i])}. After a hunk's last line "
                            "only another hunk may follow.")
        if len(hunks) >= MAX_HUNKS:
            raise DiffError(f"The diff has more than {MAX_HUNKS} hunks; review a smaller change.")
        if hunks and NO_NEWLINE in hunks[-1].lines:
            raise DiffError(f"Hunk {hunks[-1].id}: '{NO_NEWLINE}' is allowed only in the last hunk (the end of the "
                            "file).")
        hunk, i = _read_hunk(lines, i, len(hunks) + 1)
        hunks.append(hunk)
    if not hunks:
        raise DiffError("The diff has no hunk (a line starting with @@): there is nothing to review.")
    if head.kind in ("new", "delete"):
        wanted, what = ("+", "added (+)") if head.kind == "new" else ("-", "removed (-)")
        for hunk in hunks:
            if any(line[0] not in (wanted, "\\") for line in hunk.lines):
                raise DiffError(f"Hunk {hunk.id}: the file is {'new' if head.kind == 'new' else 'deleted'}, so every "
                                f"line must be {what}, with no context or opposite line.")
    return ParsedDiff(head, tuple(hunks))


# ── the patch the person approved ─────────────────────────────────────────────────────────────


def _head_lines(head: FileHead) -> list[str]:
    """The header of the recomposed patch, from the stored head."""
    old, new = head.old, head.new
    if head.kind == "modify":
        return [f"diff --git a/{old} b/{new}", f"--- a/{old}", f"+++ b/{new}"]
    if head.kind == "new":
        return [f"diff --git a/{new} b/{new}", f"new file mode {REGULAR_MODE}", "--- /dev/null", f"+++ b/{new}"]
    if head.kind == "delete":
        return [f"diff --git a/{old} b/{old}", f"deleted file mode {REGULAR_MODE}", f"--- a/{old}", "+++ /dev/null"]
    similarity = [] if head.similarity is None else [f"similarity index {head.similarity}%"]
    return [f"diff --git a/{old} b/{new}", *similarity, f"rename from {old}", f"rename to {new}", f"--- a/{old}",
            f"+++ b/{new}"]


def _shifted(header: str, shift: int) -> str:
    """*header* with its new-side start moved by *shift* lines (the net change of rejected hunks before it)."""
    if not shift:
        return header
    match = HEADER.fullmatch(header)
    if match is None:
        return header
    start = int(match.group(3)) + shift
    if start < 0:
        return header
    old = match.group(1) + ("" if match.group(2) is None else f",{match.group(2)}")
    new = f"{start}" + ("" if match.group(4) is None else f",{match.group(4)}")
    return f"@@ -{old} +{new} @@{match.group(5)}"


def compose_patch(head: FileHead, hunks: Sequence[dict], approved: Collection[str]) -> str:
    """The patch of exactly the *approved* hunk ids, in order: the head the gateway stored, then each approved hunk's
    header and lines as the gateway stored them. A rejected hunk before an
    approved one moves that one's new-side start back by its net line change. Empty when no hunk is approved."""
    out: list[str] = []
    shift = 0
    for hunk in hunks:
        match = HEADER.fullmatch(hunk["header"])
        net = (_count(match.group(4)) - _count(match.group(2))) if match else 0
        if hunk["id"] in approved:
            out.extend([_shifted(hunk["header"], -shift), *hunk["lines"]])
        else:
            shift += net
    if not out:
        return ""
    return "\n".join([*_head_lines(head), *out]) + "\n"
