"""``tui_gateway.request_text``: the text rules shared by ``confirm`` and the requests built on it."""

from __future__ import annotations

import pytest

from tui_gateway import confirm, request_text
from tui_gateway.request_text import MAX_COMBINING_MARKS, clean_text, verbatim_problem


def test_clean_strips_bidi_overrides_and_isolates():
    assert clean_text("a‮b‭c⁦d⁩e", multiline=False) == "abcde"


def test_clean_strips_zero_width_characters():
    assert clean_text("pa​y‌‍me﻿nt⁠", multiline=False) == "payment"


def test_clean_strips_invisible_letters():
    assert clean_text("aᅟᅠㅤﾠ⠀\U0001d159b", multiline=False) == "ab"
    # Text made only of them is empty, not blank-looking.
    assert clean_text("ㅤㅤ", multiline=True) == ""


def test_clean_caps_combining_marks_per_base_character():
    kept = "e" + "́" * MAX_COMBINING_MARKS
    assert MAX_COMBINING_MARKS == 4
    assert clean_text("e" + "́" * 5, multiline=False) == kept
    assert clean_text("e" + "́" * 40 + "f", multiline=False) == kept + "f"
    # The count restarts on the next base character.
    assert clean_text("e" + "́" * 4 + "e" + "́" * 4, multiline=False) == kept * 2


def test_clean_normalises_crlf_and_line_separators():
    assert clean_text("a\r\nb\rc d e", multiline=True) == "a\nb\nc\nd\ne"
    assert clean_text("a\r\nb c", multiline=False) == "a b c"


def test_clean_keeps_one_blank_line_and_trims_the_ends():
    assert clean_text("\n\n\na\n\n\n\nb\n  \n\n", multiline=True) == "a\n\nb"


def test_clean_collapses_whitespace_and_tabs():
    assert clean_text("  a \t  b  ", multiline=False) == "a b"
    assert clean_text("a\t\tb   c\n  d  ", multiline=True) == "a b c\nd"


def test_clean_drops_other_control_characters_and_none():
    assert clean_text("a\x00b\x07c\x1bd", multiline=False) == "abcd"
    assert clean_text(None, multiline=True) == ""


@pytest.mark.parametrize("text, code", [
    ("a\tb", "U+0009"),
    ("a b", "U+2028"),
    ("a b", "U+00A0"),
    ("a​b", "U+200B"),
    ("aㅤb", "U+3164"),
    ("a͏b", "U+034F"),
])
def test_verbatim_refuses_characters_that_cannot_be_shown_as_they_are(text, code):
    assert verbatim_problem(text) == f"character {code} cannot be shown as it is"


def test_verbatim_refuses_trailing_whitespace():
    assert "end of a line" in verbatim_problem("ls \nmore")
    assert "end of a line" in verbatim_problem("ls ")
    assert "end of a line" in verbatim_problem("ls\n")


def test_verbatim_refuses_too_many_combining_marks_and_padding():
    assert verbatim_problem("e" + "́" * 5) == "too many combining marks on one character"
    assert "17 spaces in a row" in verbatim_problem("ls" + " " * 17 + "x")
    assert "blank lines in a row" in verbatim_problem("a\n\n\n\n\nb")


def test_verbatim_accepts_ordinary_text():
    assert verbatim_problem("git status\n    indented\n\n\nend") == ""
    assert verbatim_problem("café \U0001f600") == ""


def test_confirm_re_exports_the_moved_names():
    assert confirm.verbatim_problem is request_text.verbatim_problem
    assert confirm.DEFAULT_IGNORABLE is request_text.DEFAULT_IGNORABLE
    assert confirm.default_ignorable is request_text.default_ignorable
    assert confirm.MAX_COMBINING_MARKS == request_text.MAX_COMBINING_MARKS
