"""``contract/requests/README.md`` §6: a client that follows the README mirrors the gateway exactly.

The README states the stripping, the refused characters and the layout limits of a draft's verbatim text with
their exact numbers, and says clients MUST refuse the same set. Here a second implementation is written from the
README ALONE (:func:`mirror`: the numbers and the default-ignorable table are parsed out of the README, never read
from ``tui_gateway/request_text.py``) and compared with the gateway's own ``strip_line_ends`` and
``verbatim_problem`` on the boundary cases and on a seeded random corpus. A drifting number, a changed table or a
rule the README does not carry fails here.
"""

from __future__ import annotations

import random
import re
import unicodedata
from pathlib import Path

import pytest

from tui_gateway import request_text
from tui_gateway.interactive_validate import strip_line_ends

README = (Path(__file__).resolve().parents[3] / "contract" / "requests" / "README.md").read_text(encoding="utf-8")
SECTION = README[README.index("## 6. `review.draft`"):README.index("## 7. Versioning")]


def _limits() -> dict[str, int]:
    found = dict(re.findall(r"^\| `(MAX_[A-Z_]+)` \| (\d+) \|", SECTION, re.MULTILINE))
    return {name: int(value) for name, value in found.items()}


def _table() -> list[tuple[int, int]]:
    block = re.search(r"Default-ignorable table.*?```text\n(.*?)```", SECTION, re.DOTALL).group(1)
    ranges = []
    for line in block.split():
        low, _, high = line.partition("-")
        ranges.append((int(low, 16), int(high or low, 16)))
    return ranges


MAX_MARKS = int(re.search(r"`MAX_COMBINING_MARKS` = (\d+) combining marks", SECTION).group(1))
LIMITS = _limits()
TABLE = _table()
INVISIBLE_LETTERS = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x1D159}  # README §6.2 item 4


def test_the_readme_numbers_are_the_codes():
    assert LIMITS == {"MAX_SPACE_RUN": request_text.MAX_SPACE_RUN, "MAX_INDENT": request_text.MAX_INDENT,
                      "MAX_BLANK_LINES": request_text.MAX_BLANK_LINES, "MAX_LINE_CHARS": request_text.MAX_LINE_CHARS}
    assert (request_text.MAX_SPACE_RUN, request_text.MAX_INDENT, request_text.MAX_BLANK_LINES,
            request_text.MAX_LINE_CHARS, request_text.MAX_COMBINING_MARKS) == (16, 32, 3, 2000, 4)
    assert re.search(r"`MAX_COMBINING_MARKS` = (\d+) combining marks", SECTION).group(1) == "4"
    assert TABLE == [tuple(pair) for pair in request_text.DEFAULT_IGNORABLE]
    assert {ord(c) for c in request_text._INVISIBLE_LETTERS} == INVISIBLE_LETTERS


def _ignorable(code: int) -> bool:
    return any(low <= code <= high for low, high in TABLE)


def mirror(text: str) -> str:
    """What a client builds from README §6.1 to §6.3 alone: the stripped text, or "" when it is refused."""
    lines = [line.rstrip() for line in text.split("\n")]  # §6.1: LF only, str.isspace at the end of each line
    stripped = "\n".join(lines).rstrip()
    if not stripped:
        return ""
    marks = 0
    for ch in stripped:  # §6.2
        category = unicodedata.category(ch)
        if category == "Cn" or _ignorable(ord(ch)):
            return ""
        if category in ("Mn", "Me"):
            marks += 1
            if marks > MAX_MARKS:
                return ""
            continue
        marks = 0
        if ch in "\n ":
            continue
        if category in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp", "Zs") or ord(ch) in INVISIBLE_LETTERS or ch.isspace():
            return ""
    blank = 0
    for line in stripped.split("\n"):  # §6.3
        if not line:
            blank += 1
            if blank > LIMITS["MAX_BLANK_LINES"]:
                return ""
            continue
        blank = 0
        body = line.lstrip(" ")
        if (len(line) > LIMITS["MAX_LINE_CHARS"] or len(line) - len(body) > LIMITS["MAX_INDENT"]
                or any(len(run) > LIMITS["MAX_SPACE_RUN"] for run in re.findall(" +", body))):
            return ""
    return stripped


def gateway(text: str) -> str:
    stripped = strip_line_ends(text)
    return "" if not stripped or request_text.verbatim_problem(stripped) else stripped


@pytest.mark.parametrize("text, ok", [
    ("git status", True),
    ("x" + " " * 16 + "y", True), ("x" + " " * 17 + "y", False),            # MAX_SPACE_RUN
    (" " * 32 + "x", True), (" " * 33 + "x", False),                       # MAX_INDENT
    (" " * 32 + "x" + " " * 16 + "y", True),                                # the indent is not also a run
    ("a" + "\n" * 4 + "b", True), ("a" + "\n" * 5 + "b", False),            # MAX_BLANK_LINES (3 empty lines)
    ("\n" * 4 + "x", False), ("\n" * 3 + "x", True),                        # leading blank lines count
    ("a\n" * 3 + "x" * 2000, True), ("x" * 2000, True), ("x" * 2001, False),  # MAX_LINE_CHARS
    (" " * 32 + "x" * 1968, True), (" " * 32 + "x" * 1969, False),         # the indent counts in the length
    ("e" + "́" * 4, True), ("e" + "́" * 5, False),                # combining marks
    ("́" * 5, False), ("e" + "́" * 4 + "e" + "́" * 4, True),  # the count resets at a base
    ("e" + "́" * 4 + " " + "́" * 4, True),                        # ... at a space
    ("é́́́ः́", True),                        # Mc resets the count
    ("a\tb", False), ("a\rb", False), ("a\x1fb", False), ("a\x85b", False), ("a\x7fb", False),
    ("a b", False), ("a　b", False), ("a b", False), ("a b", False), ("a b", False),
    ("a​b", False), ("a‮b", False), ("a­b", False), ("a﻿b", False),
    ("a\ud800b", False), ("ab", False), ("a͸b", False),         # Cs, Co, Cn
    ("a️b", False), ("a͏b", False), ("aㅤb", False), ("a⠀b", False), ("a\U0001d159b", False),
    ("a᠎b", False), ("a\U000e0100b", False), ("a឴b", False),
    ("trailing\t", True), ("trailing 　", True), ("a  \nb", True), ("a\r\nb", True),  # stripped, not refused
    ("a\n   \nb", True), ("a" + "\n" * 9, True), ("", False), (" \t\n", False),
    ("中" * 2000, True), ("\U0001f600" * 2000, True), ("\U0001f600" * 2001, False),  # code points, not UTF-16
])
def test_boundaries(text, ok):
    assert bool(gateway(text)) is ok, repr(text)
    assert bool(mirror(text)) is ok, repr(text)
    if ok:
        assert mirror(text) == gateway(text)


def test_a_random_corpus_agrees():
    pieces = ["a", "b", "e", " ", " ", "  ", "\n", "\n", "\n\n", "\t", "\r", "́", "ः", " ", "​",
              " ", "　", "️", "͏", "ㅤ", "⠀", "͸", "", "\x00", "\x1f", "\x7f",
              " " * 16, " " * 17, " " * 32, " " * 33, "中", "\U0001f600", "́" * 4, "́" * 5]
    rng = random.Random(20261004)
    agreed_ok = agreed_refused = 0
    for _ in range(20_000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 14)))
        want = gateway(text)
        assert mirror(text) == want, repr(text)
        agreed_ok += bool(want)
        agreed_refused += not want
    assert agreed_ok > 500 and agreed_refused > 500  # the corpus exercises both sides
