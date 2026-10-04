"""Text hygiene for what the gateway shows a person verbatim: ``confirm``, and the interactive requests that
follow it (forms, files, draft review).

- :func:`clean_text` makes agent text safe to show: control and format characters (bidi overrides,
  zero-width characters), invisible letters and over-long stacks of combining marks go, line separators
  become newlines, whitespace collapses.
- :func:`verbatim_problem` decides whether a text can be shown EXACTLY as it is (a command the person signs
  as it runs): it returns why not, or "", and never rewrites anything.

``tui_gateway/confirm.py`` re-exports the names it and its tests used before the split;
``tools/passkey_policy.py`` keeps its own copy of :data:`DEFAULT_IGNORABLE` and a test keeps the two in step.
"""

from __future__ import annotations

import bisect
import re
import unicodedata

# Letters and symbols that render as nothing (Hangul fillers, the blank Braille pattern, the musical null
# notehead): text built from them looks empty or hides where a line really ends.
_INVISIBLE_LETTERS = frozenset({"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800", "\U0001d159"})
_LINE_BREAKS = frozenset({"\n", "\u2028", "\u2029"})
#: ``Default_Ignorable_Code_Point`` as Unicode publishes it (``DerivedCoreProperties.txt``; unchanged
#: from 14.0, which added U+180F, through 16.0): code points a renderer shows as nothing. ``unicodedata``
#: does not expose the property, so the ranges are copied here (``tools/passkey_policy.py`` holds the same
#: table; a test keeps the two and the running Unicode database's ``Cf`` in step). Most are ``Cf`` and
#: refused as such; the rest are variation selectors, the combining grapheme joiner, the Khmer inherent
#: vowels (``Mn``), the Hangul fillers (``Lo``) and reserved ranges (``Cn``). Refused in a VERBATIM
#: detail; :func:`clean_text` keeps the ``Mn`` ones under :data:`MAX_COMBINING_MARKS` (an emoji's U+FE0F).
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_IGNORABLE_STARTS = [low for low, _ in DEFAULT_IGNORABLE]


def default_ignorable(ch: str) -> bool:
    """Whether *ch* is a ``Default_Ignorable_Code_Point`` (:data:`DEFAULT_IGNORABLE`)."""
    code = ord(ch)
    at = bisect.bisect_right(_IGNORABLE_STARTS, code) - 1
    return at >= 0 and code <= DEFAULT_IGNORABLE[at][1]

#: At most this many combining marks (Mn, Me) on one base character; more stack into unreadable glyphs.
MAX_COMBINING_MARKS = 4

# The layout of a VERBATIM detail (:func:`verbatim_problem`). Clients show it monospaced with every space
# kept and scroll long lines sideways instead of wrapping them (web: ``white-space: pre``); a phone in
# portrait shows about 40 columns and a dozen lines of it. Spacing beyond these bounds is padding that
# can park a second command outside that view (``git status`` + 300 spaces + ``; curl … | sh``, or 80
# blank lines before it); ordinary code stays well inside them. The text is refused, never rewritten:
# the passkey challenge covers the exact characters.
#: Spaces in a row after a line's first non-space character. Column-aligned comments and arguments
#: rarely need more than a few; 16 still leaves the next word on a 40-column screen after a short command.
MAX_SPACE_RUN = 16
#: Spaces at the start of a line: 8 levels of 4-space Python, 16 levels of 2-space YAML or JSON (a
#: Kubernetes manifest's secret reference sits at 18). Deeper is a jump to the right, not structure.
MAX_INDENT = 32
#: Empty lines in a row. PEP 8 puts two between top-level definitions; more than three only pushes what
#: follows down the sheet.
MAX_BLANK_LINES = 3
#: Characters on one line, whatever the detail's own bound (``CONFIRM_DETAIL_MAX``) becomes.
MAX_LINE_CHARS = 2_000
# These bounds LIMIT padding; they cannot by themselves keep everything in view. Gaps just under them,
# repeated, still run a line off the screen, as do many short lines, a long visible prefix or wide glyphs
# (U+FDFD three hundred times). That is the clients' part: an overflow marker on the detail, and Confirm
# disabled until it has been scrolled to its end (``website/docs/guides/confirm-sensitive-actions.md``).
_SPACE_RUN = re.compile(" +")


def clean_text(text: object, *, multiline: bool) -> str:
    """Plain text safe to show verbatim: line/paragraph separators become newlines, every other control
    (Cc), format (Cf: bidi overrides and isolates, zero-width characters), surrogate (Cs) and private-use
    (Co) code point is dropped, as are invisible letters, and combining marks beyond
    :data:`MAX_COMBINING_MARKS` per base character. A single-line field collapses all whitespace to single
    spaces."""
    raw = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    out = []
    marks = 0
    for ch in raw:
        category = unicodedata.category(ch)
        if category in ("Mn", "Me"):
            marks += 1
            if marks <= MAX_COMBINING_MARKS:
                out.append(ch)
            continue
        marks = 0
        if ch in _LINE_BREAKS:
            out.append("\n" if multiline else " ")
        elif ch == "\t":
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co") or ch in _INVISIBLE_LETTERS:
            continue
        else:
            out.append(ch)
    cleaned = "".join(out)
    if not multiline:
        return " ".join(cleaned.split())
    lines = [" ".join(line.split()) for line in cleaned.split("\n")]
    # At most one blank line in a row, none at either end.
    kept: list[str] = []
    for line in lines:
        if line or (kept and kept[-1]):
            kept.append(line)
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept)


def layout_problem(text: str, *, json_strings: bool = False) -> str:
    """Why the spacing of *text* could hide part of it from the person confirming it, or "" (see
    :data:`MAX_SPACE_RUN`, :data:`MAX_INDENT`, :data:`MAX_BLANK_LINES`, :data:`MAX_LINE_CHARS`). Tabs and
    every other kind of whitespace are refused before this runs, so only spaces and newlines count.

    *json_strings* (a tool call's detail: its name, then its arguments as indented JSON): a string value
    keeps its line breaks as the visible escape ``\\n``, so the indentation of each line of code in it
    shows as a run of spaces right after that escape. Such a run is that line's indentation and may be up
    to :data:`MAX_INDENT`; every other run keeps :data:`MAX_SPACE_RUN`."""
    blank = 0
    for number, line in enumerate(text.split("\n"), start=1):
        if not line.strip(" "):
            blank += 1
            if blank > MAX_BLANK_LINES:
                return f"line {number - blank + 1} starts more than {MAX_BLANK_LINES} blank lines in a row"
            continue
        blank = 0
        if len(line) > MAX_LINE_CHARS:
            return f"line {number} is {len(line)} characters (at most {MAX_LINE_CHARS})"
        body = line.lstrip(" ")
        if (indent := len(line) - len(body)) > MAX_INDENT:
            return f"line {number} is indented {indent} spaces (at most {MAX_INDENT})"
        for run in _SPACE_RUN.finditer(body):
            size = run.end() - run.start()
            if size <= MAX_SPACE_RUN:
                continue
            if json_strings and size <= MAX_INDENT and body[max(0, run.start() - 2):run.start()] == "\\n":
                continue
            return f"line {number} has {size} spaces in a row (at most {MAX_SPACE_RUN})"
    return ""


def verbatim_problem(text: str, *, json_strings: bool = False) -> str:
    """Why *text* cannot be shown VERBATIM (no cleaning at all), or "": a character :func:`clean_text` would
    drop or rewrite (a control character other than newline, a tab, a format, surrogate or private-use
    character, a line or paragraph separator, whitespace other than space, an invisible letter, more than
    :data:`MAX_COMBINING_MARKS` combining marks on one character), an unassigned code point (``Cn``: the
    running Unicode database does not know it, so neither does this check) or a default-ignorable one
    (:data:`DEFAULT_IGNORABLE`, which renders as nothing), whitespace at the end of a line or of the text,
    which no rendering shows, or spacing that could push part of it out of view (:func:`layout_problem`,
    with *json_strings* for a tool call's detail)."""
    marks = 0
    for ch in text:
        category = unicodedata.category(ch)
        if category == "Cn" or default_ignorable(ch):
            return f"character U+{ord(ch):04X} cannot be shown as it is"
        if category in ("Mn", "Me"):
            marks += 1
            if marks > MAX_COMBINING_MARKS:
                return "too many combining marks on one character"
            continue
        marks = 0
        if ch in ("\n", " "):
            continue
        if category in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp", "Zs") or ch in _INVISIBLE_LETTERS or ch.isspace():
            return f"character U+{ord(ch):04X} cannot be shown as it is"
    if any(line != line.rstrip() for line in text.split("\n")) or text != text.rstrip():
        return "whitespace at the end of a line or of the text cannot be seen"
    if problem := layout_problem(text, json_strings=json_strings):
        return f"{problem}, which can put part of it out of view; present it without padding"
    return ""
