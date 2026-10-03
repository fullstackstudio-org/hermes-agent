"""Context demotions for plugin install-scan findings (``tools.plugin_guard``).

The threat regexes in ``tools.skills_guard`` are written for a SKILL.md the agent will execute
verbatim. A plugin repository is a codebase: the same text sits in READMEs, test fixtures, JSON
scenery, denylists and regex literals, where it cannot run on the host at install time. Each
helper here recognises one such *class* of inert context and lowers the finding one step or to
informational. Nothing is deleted — every finding stays in the report with file and line — and
nothing here applies to a bundled skill's own ``SKILL.md`` / ``skills/`` tree, which the agent
does read as instructions. Every function is a pure predicate on (finding, line, path).
"""
from __future__ import annotations

import base64
import binascii
import bisect
import re
from pathlib import Path
from typing import Optional

from tools.skills_guard import _COMPILED_THREAT_PATTERNS, Finding

# pattern id -> compiled regex, to locate a finding's token on its full source line.
_PATTERN_BY_ID = {pid: rx for rx, pid, *_ in _COMPILED_THREAT_PATTERNS}

# One severity step down; ``medium``/``low`` are already informational (verdict-neutral).
STEP_DOWN = {"critical": "high", "high": "medium"}

# ── (1) documentation prose ──────────────────────────────────────────────────────────────────
# A README/AGENTS.md/docs page describing a command, a refused path (``~/.ssh`` in a denylist
# table) or an uninstall step is not the plugin's runtime behaviour. Command- and path-shaped
# findings there step down once (critical→high, high→medium): a doc line can never on its own
# hard-block an install. Agent-facing shapes keep full severity because the prose IS the
# payload for them: every ``injection`` pattern, the Markdown exfil/context patterns, the
# agent-config edits, ``curl | sh`` install one-liners (a README is where those live), an
# ``authorized_keys`` append, and a leaked provider key (a real secret is a real leak anywhere).
DOC_PROSE_EXTENSIONS = {".md", ".txt", ".rst", ".html"}
_PROSE_KEEPS_FULL_SEVERITY_CATEGORIES = {"injection", "credential_exposure"}
_PROSE_KEEPS_FULL_SEVERITY_IDS = {
    "context_exfil", "send_to_url", "md_image_exfil", "md_link_exfil", "ssh_backdoor",
    "curl_pipe_shell", "wget_pipe_shell", "curl_pipe_python",
    "agent_config_mod", "agent_config_mod_shell", "agent_config_contract", "agent_config_ref",
    "hermes_config_mod", "hermes_config_mod_shell", "hermes_config_ref",
    "other_agent_config_mod", "other_agent_config_mod_shell", "other_agent_config_ref",
}
# Agent instruction surfaces inside a plugin — a bundled skill tree and the post-install note
# the agent is shown — are executed as instructions, so they get no prose cap.
_AGENT_INSTRUCTION_DIRS = {"skills", "optional-skills"}
_AGENT_INSTRUCTION_FILES = {"skill.md", "after-install.md"}


def is_doc_prose(rel_path: str) -> bool:
    """A documentation file that the loader never executes and the agent never runs as a skill."""
    p = Path(rel_path)
    if p.suffix.lower() not in DOC_PROSE_EXTENSIONS or p.name.lower() in _AGENT_INSTRUCTION_FILES:
        return False
    return not any(part.lower() in _AGENT_INSTRUCTION_DIRS for part in p.parts[:-1])


# A repository's CI pipeline (``.github/workflows/*.yml``) runs on the forge's runner, never on the
# host that installs the plugin, and the agent never reads it as instructions. Its ``os.environ``
# reads (``RUNNER_TEMP``, ``GITHUB_ENV``) and ``pip install`` steps are the CI's own plumbing, so
# it takes the same one-step prose cap as a README: visible, confirmable, never a hard block on
# its own. Only the workflow directory proper — a ``.github/scripts/*.py`` is real code.
_CI_WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def is_ci_workflow(rel_path: str) -> bool:
    """A forge CI workflow definition (``.github/workflows/<name>.yml``)."""
    p = Path(rel_path)
    return (len(p.parts) == 3 and p.parts[0].lower() == ".github" and p.parts[1].lower() == "workflows"
            and p.suffix.lower() in _CI_WORKFLOW_SUFFIXES)


def is_agent_facing(finding: Finding) -> bool:
    """A shape whose prose IS the payload (injection, agent-config edit, install one-liner, leaked key)."""
    return (finding.category in _PROSE_KEEPS_FULL_SEVERITY_CATEGORIES
            or finding.pattern_id in _PROSE_KEEPS_FULL_SEVERITY_IDS)


def prose_cap(finding: Finding) -> Optional[str]:
    """Stepped-down severity for a command/path-shaped finding in documentation, else None."""
    return None if is_agent_facing(finding) else STEP_DOWN.get(finding.severity)


# A README "Uninstall" section removing the plugin's OWN install directory
# (``rm -rf "$HOME/.hermes/plugins/<name>"``) is the one destructive shape that is harmless by
# construction: one ``rm``, one argument rooted at ``$HOME/.hermes/plugins/`` or ``skills/``
# with a plain leaf — no glob, no ``..``, nothing chained. It lands at medium (a note). Any
# wider target (``$HOME``, ``$HOME/.hermes``, ``$HOME/.hermes/plugins/*``) only gets the
# generic prose step (high, caution) and the same line in a ``.sh`` stays critical (#115353).
_SELF_UNINSTALL_RM = re.compile(
    r'^(?:\$\s*)?rm\s+(?:-[a-zA-Z]+\s+)*'
    r'(?P<q>["\']?)\$HOME/\.hermes/(?:plugins|skills)/[A-Za-z0-9][A-Za-z0-9._-]*/?(?P=q)'
    r'\s*(?:#.*)?$'
)


def is_self_uninstall_doc(finding: Finding, line: str) -> bool:
    return finding.pattern_id == "destructive_home_rm" and _SELF_UNINSTALL_RM.match(line.strip()) is not None


# ── (2) test trees and fixtures ──────────────────────────────────────────────────────────────
# Test code and fixtures deliberately hold hostile strings (``rm -rf /`` in a DENY table,
# ``/etc/passwd`` in a traversal probe, a fake ``sk-`` key in a redaction corpus) to prove the
# plugin rejects them. They are still scanned — ``from .tests import evil`` would run — but a
# finding there steps down once, so a fixture cannot hard-block and a string-only fixture is
# a note. A root-level test dir (``tests/``, ``fixtures/``) or the unambiguous dunder names at any
# depth (``src/__tests__/``), plus test-file naming (``foo.test.js``, ``test_foo.py``, and the
# plural ``tests_state.py`` / ``state_tests.py`` a single-module plugin uses when it has no
# ``tests/`` dir); a nested ``src/spec/handler.py`` is runtime code and gets no cap.
TEST_TREE_DIRS = {"tests", "test", "testing", "spec", "specs", "fixtures"}
_TEST_DIRS_ANY_DEPTH = {"__tests__", "__fixtures__", "__mocks__"}
_TEST_FILE_NAME = re.compile(r"^(?:tests?_[^/]*|[^/]*_tests?\.[^./]+|[^/]*\.(?:test|spec)\.[^./]+)$", re.IGNORECASE)


# In a test file, a hostile string that is only DATA — quoted, with no exec verb on the line
# (``verdict_for("rm -rf /")``, ``("/etc/passwd", "DENY")``) — is a note; a fixture file that is
# not code at all (``corpus.json``) likewise. ``os.system('rm -rf /')`` or ``open('/etc/passwd')``
# in a test still steps down only once: the line executes when imported.
_EXEC_ON_LINE = re.compile(
    r"\b(?:system|popen|run|call|check_output|check_call|Popen|exec|execv\w*|spawn\w*|eval|execSync|execFile\w*"
    r"|spawnSync|child_process|source|os\.startfile|open)\s*\(|\$\(|(?<![\w\\])`", re.IGNORECASE)


def is_inert_fixture_line(finding: Finding, line: str, is_code: bool) -> bool:
    """The finding's text is quoted test data on a line that does not execute anything."""
    if not is_code:
        return True
    if _EXEC_ON_LINE.search(line):
        return False
    rx = _PATTERN_BY_ID.get(finding.pattern_id)
    hits = list(rx.finditer(line)) if rx else []
    spans = [m.span() for m in _LITERAL_SPANS.finditer(line)]
    return bool(hits) and all(any(a <= h.start() and h.end() <= b for a, b in spans) for h in hits)


def is_test_tree(rel_path: str) -> bool:
    p = Path(rel_path)
    return (
        (len(p.parts) > 1 and p.parts[0].lower() in TEST_TREE_DIRS)
        or any(part.lower() in _TEST_DIRS_ANY_DEPTH for part in p.parts[:-1])
        or _TEST_FILE_NAME.match(p.name) is not None
    )


# ── (3) base64 media data ────────────────────────────────────────────────────────────────────
# ``encoded_exfil`` (``base64 … env``) fires on a data URI whose payload happens to contain the
# letters "env" (PNG scenery, embedded fonts). Decode the head of the blob and sniff it: a
# known image/font/audio/document magic number means the bytes are an asset, not an encoder
# call, and the finding drops to informational (kept in the report).
_BASE64_RUN = re.compile(r"(?:base64,)?([A-Za-z0-9+/]{24,}={0,2})")
_MEDIA_MAGIC = (
    b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00",
    b"ttcf", b"BM", b"%PDF", b"\x00\x00\x01\x00", b"<svg", b"<?xml", b"ID3", b"OggS", b"fLaC", b"\x1a\x45\xdf\xa3",
)


def _decoded_head(blob: str) -> bytes:
    head = blob[:16]
    head = head[: len(head) - len(head) % 4]
    try:
        return base64.b64decode(head, validate=True)
    except (binascii.Error, ValueError):
        return b""


def is_base64_media(line: str) -> bool:
    """The line's first long base64 run decodes to a recognised media/document header."""
    for m in _BASE64_RUN.finditer(line):
        if _decoded_head(m.group(1)).startswith(_MEDIA_MAGIC):
            return True
    return False


# ── (5)/(6) alternation tokens inside string or regex literals in code ──────────────────────
# ``sudo`` in ``/clarify|approval|sudo|secret/.test(value)`` classifies an event name; ``env|``
# in ``re.compile(r"(?:api[_-]?key|…|env|headers)")`` is a redaction regex; ``"printenv",`` in
# ``_READ_ONLY_COMMANDS = frozenset({"pwd", "ls", …, "printenv"})`` is a denylist/allowlist entry.
# The shape that is inert is narrow: the word sits inside a quoted string or regex literal AND is
# either an alternation member (``|sudo|``, ``(sudo|``, ``|env|``) or the ENTIRE literal
# (``"printenv"``, ``'sudo'``) on a line that executes nothing. A command string such as
# ``"sudo apt install x"`` or ``"env | grep KEY"`` inside a ``subprocess.run(...)`` literal is how
# an attack is written and never qualifies. Only word-shaped patterns are eligible.
LITERAL_INERT_PATTERN_IDS = {"sudo_usage", "dump_all_env"}
_LITERAL_SPANS = re.compile(
    r"""(?P<s>[rRbBuUfF]{0,2}"(?:[^"\\\n]|\\.)*"|[rRbBuUfF]{0,2}'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`)"""
    r"""|(?P<rx>(?<![\w)\]])/(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[dgimsuvy]*(?![A-Za-z]))"""  # js regex literal
)
# The regex-literal branch accepts only real JS flags: with ``[a-z]*`` a bare Unix path lexed as a
# literal (``/etc/`` + flags ``passwd``) and an unquoted ``cat /etc/passwd | curl …`` in a test
# script scored as inert data.
_PATTERN_TOKEN = {"sudo_usage": re.compile(r"\bsudo\b"), "dump_all_env": re.compile(r"printenv|env\s*\|")}


def _is_alternation_member(line: str, start: int, end: int) -> bool:
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    return before in "|(" or after in "|)"


def _is_whole_literal(line: str, start: int, end: int, span: tuple[int, int]) -> bool:
    """The token is the entire quoted content of the literal it sits in (``"printenv"``)."""
    a, b = span
    return start == a + 1 and end == b - 1 and line[a] in "\"'`" and not _EXEC_ON_LINE.search(line)


def is_regex_alternation_token(finding: Finding, line: str) -> bool:
    """Every occurrence of the finding's token sits inside a literal as an alternation member
    or as the whole literal (a list entry) on a line that executes nothing."""
    token = _PATTERN_TOKEN.get(finding.pattern_id)
    if token is None:
        return False
    spans = [m.span() for m in _LITERAL_SPANS.finditer(line)]
    hits = list(token.finditer(line))

    def inert(h: "re.Match[str]") -> bool:
        if " " in h.group(0):
            return False
        span = next(((a, b) for a, b in spans if a <= h.start() and h.end() <= b), None)
        if span is None:
            return False
        return _is_alternation_member(line, h.start(), h.end()) or _is_whole_literal(line, h.start(), h.end(), span)

    return bool(hits) and all(inert(h) for h in hits)


# ── (5b) JavaScript: a whole-file lexer, and a finding judged by its own token ──────────────
# Two word-shaped patterns misfire on a built web client:
#   - ``sudo_usage``: a client that relays Hermes' secure prompts names the gateway's ``sudo``
#     server request (the masked sudo-password prompt) as data: ``{secret:"secret",sudo:"sudo"}``,
#     ``{sudo:12e4}``, ``case"sudo":``, ``kind!=="sudo"``;
#   - ``exec_string``: a syntax highlighter calls ``RegExp.prototype.exec`` with a string,
#     ``re.exec("")``, ``/x/.exec(s)``, ``this.matcherRe.exec(…)``.
# Minified, such code sits on lines kilobytes long that always hold a template literal or a
# ``.call(``, and a line often begins inside a template a previous line opened, so the per-line
# tests of (5)/(6) can neither lex the line nor find one that "executes nothing".
#
# For ``.js``/``.mjs``/``.cjs`` the file is lexed whole (strings, templates spanning lines with
# nested ``${…}``, comments, regex literals by the usual "a regex may follow an operator, an
# opener or a keyword" rule; where that rule cannot decide, or the file is otherwise doubtful,
# the lexer raises and nothing changes) and each hit is judged by its token. The finding drops
# to ``low`` (still reported) only when EVERY hit of the pattern on the line qualifies:
#   ``sudo_usage``
#     1. The token is an object key (``{sudo:`` / ``,"sudo":``), a whole quoted string compared
#        with ``===``/``!==``/``==``/``!=`` or after ``case``, or a whole quoted string that is the
#        entire value of a property whose key is not command-shaped (``kind:"sudo"``; never
#        ``cmd:``/``shell:``/``args:``). Never a template, a comment, an assignment to a
#        variable, an array element or a module specifier.
#     2. No bracket around it hands it on: no enclosing call whose callee runs or loads code
#        (``spawn``, ``exec*``, ``run*``, ``call``/``apply``/``bind``, ``eval``, ``Function``,
#        ``require``, ``import``, ``open``, ``setTimeout`` …) or is computed (``x[y](``,
#        ``f()(``), no enclosing ``${…}``, no enclosing array/object bound to a command name.
#     3. No JavaScript in the plugin can run anything (``JsSinkInventory``, below).
#   ``exec_string``
#     - ``/x/.exec("…")``: the receiver is a regex literal, so this is ``RegExp.prototype.exec``;
#     - ``re.exec("…")``, ``this.matcherRe.exec("…")``, ``new RegExp(s).exec("…")``: a member
#       call on any other receiver, and no JavaScript in the plugin can run anything, so there
#       is no ``child_process`` binding for the receiver to be.
#     A bare ``exec("…")`` (an imported ``child_process.exec``) is never judged.
# ``JsSinkInventory`` answers "can any JavaScript in this plugin run something". Lexed files are
# judged by token, so a keyword list in a string (a highlighter's ``"eval require …"``) is not a
# sink: a sink-named identifier (``eval``, ``require``, ``Function``, ``spawn``, ``execSync``,
# ``child_process``, ``importScripts``, ``Worker`` …), a bare ``exec(`` call, a module specifier
# naming a process module (``"child_process"``, ``"node:vm"``, ``"zx"``, ``"execa"`` …), a
# non-literal ``import(``, a string handed to ``setTimeout``, computed access on a global
# (``globalThis[…]``), ``constructor.constructor`` / ``["constructor"]``, ``process.binding``
# and a ``$`…```/``sh`…``` shell tag. Every other JS/TS/HTML file is searched as raw text,
# strings and comments included, and a ``\u`` escape there is a doubt. An unreadable file, a
# symlink or a lexing error anywhere is a doubt too, and one doubt answers "yes".
# What stays out of reach is a sink built without any of those names (and so a value that
# flows through a variable into such a disguised call). Like every rule here this one only
# ever lowers a finding, and only to ``low``: it stays in the report.
JS_DATA_PATTERN_IDS = {"sudo_usage", "exec_string"}
JS_LEXED_SUFFIXES = {".js", ".mjs", ".cjs"}
JS_FAMILY_SUFFIXES = JS_LEXED_SUFFIXES | {".jsx", ".ts", ".mts", ".cts", ".tsx", ".html", ".htm", ".svg"}


class JsLexError(ValueError):
    """The file is not JavaScript this lexer can read with confidence."""


class _Tok:
    """One token. ``parent``: index of the innermost open ``(``/``[``/``{``/``${`` (-1 at top
    level). Openers carry ``block`` (a ``{`` that opens a block, a ``(`` after if/while/for/with);
    closers carry ``match`` (their opener) and ``regex_after`` (a regex may follow)."""
    __slots__ = ("kind", "start", "end", "text", "parent", "match", "block", "regex_after")

    def __init__(self, kind: str, start: int, end: int, text: str) -> None:
        self.kind, self.start, self.end, self.text = kind, start, end, text
        self.parent, self.match, self.block, self.regex_after = -1, -1, False, False


_JS_IDENT = re.compile(r"[A-Za-z_$\u0080-￿][\w$\u0080-￿]*")
_JS_NUMBER = re.compile(r"0[xXbBoO][\da-fA-F_]+n?|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?n?")
_JS_PUNCT = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.(?!\d)"
    r"|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\*\*|<<|>>|[{}()\[\];,<>+\-*/%&|^!~?:=.@]")
_JS_SPACE = frozenset(" \t\r\n\v\f﻿      　") | frozenset(
    chr(c) for c in range(0x2000, 0x200b))
_RE_AFTER_KEYWORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                                "case", "do", "else", "yield", "await", "extends"})
_OBJECT_AFTER_KEYWORDS = _RE_AFTER_KEYWORDS - {"do", "else", "extends"}
_REGEX_FLAGS = re.compile(r"[A-Za-z]*")


def _template_chunk(text: str, i: int) -> tuple[int, bool]:
    """From just after a backtick or a substitution's ``}``: (end, opens a ``${``)."""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "`":
            return i + 1, False
        elif c == "$" and text.startswith("{", i + 1):
            return i + 2, True
        else:
            i += 1
    raise JsLexError("unterminated template literal")


def _regex_allowed(toks: list, prev: Optional[_Tok]) -> bool:
    if prev is None:
        return True
    if prev.kind == "p":
        if prev.text in (")", "]", "}"):
            return prev.regex_after
        return prev.text not in ("++", "--")
    if prev.kind == "id":
        if prev.text not in _RE_AFTER_KEYWORDS:
            return False
        before = toks[-2] if len(toks) > 1 else None    # ``x.return / 2`` is a property, then a division
        return not (before is not None and before.kind == "p" and before.text in (".", "?."))
    if prev.kind == "tpl":
        return prev.text.endswith("${")
    return False


# Where a ``/`` cannot be told apart without a parser, the lexer stops instead of guessing: after a
# ``}`` (a block ends and a regex may follow; an object literal ends and a division may follow), and
# after ``of``/``yield``/``await``, which are keywords in some places and plain names in others.
# Neither occurs in the bundles this rule was written for; a file that has one is "unsure".
_CONTEXTUAL_KEYWORDS = frozenset({"of", "yield", "await"})


def _slash_is_ambiguous(toks: list, prev: Optional[_Tok]) -> bool:
    if prev is None:
        return False
    if prev.kind == "p":
        return prev.text == "}"
    if prev.kind == "id" and prev.text in _CONTEXTUAL_KEYWORDS:
        before = toks[-2] if len(toks) > 1 else None
        return not (before is not None and before.kind == "p" and before.text in (".", "?."))
    return False


def _brace_opens_block(prev: Optional[_Tok]) -> bool:
    if prev is None:
        return True
    if prev.kind == "p":
        return prev.text in (")", ";", "{", "}", "=>")
    if prev.kind == "id":
        return prev.text not in _OBJECT_AFTER_KEYWORDS
    return False


def lex_js(text: str) -> list:
    """Tokens of a whole JavaScript file (comments dropped). Raises ``JsLexError`` on anything it
    cannot read with confidence: an unterminated string/template/regex/comment, a bracket that
    does not match, a backslash outside a literal (identifier escapes hide names), a ``/`` it
    cannot classify, an HTML-like comment."""
    toks: list = []
    stack: list = []
    n = len(text)
    i = text.find("\n") if text.startswith("#!") else 0
    i = n if i < 0 else i
    prev: Optional[_Tok] = None

    def emit(tok: _Tok) -> _Tok:
        tok.parent = stack[-1] if stack else -1
        toks.append(tok)
        return tok

    while i < n:
        c = text[i]
        if c in _JS_SPACE:
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise JsLexError("unterminated comment")
            i = j + 2
            continue
        if c in "'\"":
            j = i + 1
            while True:
                if j >= n:
                    raise JsLexError("unterminated string")
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if d == c:
                    break
                if d in "\r\n":
                    raise JsLexError("newline in a string")
                j += 1
            prev = emit(_Tok("str", i, j + 1, text[i:j + 1]))
            i = j + 1
            continue
        if c == "`" or (c == "}" and stack and toks[stack[-1]].kind == "tpl"):
            if c == "}":
                stack.pop()
            j, opens = _template_chunk(text, i + 1)
            prev = emit(_Tok("tpl", i, j, text[i:j]))
            if opens:
                stack.append(len(toks) - 1)
            i = j
            continue
        if c == "/" and _slash_is_ambiguous(toks, prev):
            raise JsLexError("a '/' that may be a regex or a division")
        if c == "/" and _regex_allowed(toks, prev):
            j, in_class = i + 1, False
            while True:
                if j >= n or text[j] in "\r\n":
                    raise JsLexError("unterminated regex literal")
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if in_class:
                    in_class = d != "]"
                elif d == "[":
                    in_class = True
                elif d == "/":
                    break
                j += 1
            j = _REGEX_FLAGS.match(text, j + 1).end()
            prev = emit(_Tok("re", i, j, text[i:j]))
            i = j
            continue
        if c.isdigit() or (c == "." and text[i + 1:i + 2].isdigit()):
            m = _JS_NUMBER.match(text, i)
            prev = emit(_Tok("num", i, m.end(), m.group(0)))
            i = m.end()
            continue
        m = _JS_IDENT.match(text, i + 1 if c == "#" else i)
        if m and (c != "#" or m.start() == i + 1):
            prev = emit(_Tok("id", i, m.end(), text[i:m.end()]))
            i = m.end()
            continue
        m = _JS_PUNCT.match(text, i)
        if m is None:
            raise JsLexError(f"unexpected character {c!r}")
        t = m.group(0)
        # Annex B: in a classic script ``<!--`` and a line-leading ``-->`` open a comment the
        # engine skips and this lexer would read as code (and as the start of a template).
        if (t == "<" and text.startswith("!--", i + 1)) or (
                t == "--" and text.startswith(">", i + 2) and (prev is None or "\n" in text[prev.end:i])):
            raise JsLexError("an HTML-like comment")
        tok = _Tok("p", i, i + len(t), t)
        if t in ("(", "[", "{"):
            if t == "{":
                tok.block = _brace_opens_block(prev)
            elif t == "(":
                tok.block = prev is not None and prev.kind == "id" and prev.text in ("if", "while", "for", "with")
            emit(tok)
            stack.append(len(toks) - 1)
        elif t in (")", "]", "}"):
            if not stack or toks[stack[-1]].kind != "p" or {"(": ")", "[": "]", "{": "}"}[toks[stack[-1]].text] != t:
                raise JsLexError(f"unbalanced {t!r}")
            tok.match = stack.pop()
            tok.regex_after = t != "]" and toks[tok.match].block
            emit(tok)
        else:
            emit(tok)
        prev = tok
        i += len(t)
    if stack:
        raise JsLexError("unclosed bracket at end of file")
    return toks


# Callees that run or load code (the last name of the member chain): a value inside their
# arguments, at any depth, is handed on. ``call``/``apply``/``bind``/``open`` are generic on
# purpose: a lexer cannot tell ``child.exec`` from ``RegExp.exec``, so it never tries.
_JS_RUNS = re.compile(
    r"^(?:system|popen|run\w*|call|apply|bind|check_output|check_call|exec\w*|spawn\w*|eval|fork|child_process"
    r"|source|startfile|open|require|import|Function|Worker|SharedWorker|importScripts|setTimeout|setInterval"
    r"|setImmediate|sh|\$)$", re.IGNORECASE)
_JS_COMMAND_NAME = re.compile(
    r"cmd|command|script|exec|run|shell|install|hook|arg|entry|bin|start|setup|prog|file|spawn", re.IGNORECASE)
_JS_NOT_A_CALL = frozenset({"if", "while", "for", "with", "switch", "catch", "function", "return", "typeof", "await",
                            "yield", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "instanceof"})
_JS_EQUALITY = frozenset({"===", "!==", "==", "!="})
_JS_BINDING = frozenset({":", "=", "+=", "||=", "&&=", "??="})


def _is_p(tok: Optional[_Tok], *texts: str) -> bool:
    return tok is not None and tok.kind == "p" and tok.text in texts


def _name(tok: _Tok) -> str:
    return tok.text[1:-1] if tok.kind == "str" else tok.text


def _member_chain(toks: list, end: int) -> list:
    """Names of ``a.b?.c`` ending at token ``end`` (an identifier), first to last."""
    names = [toks[end].text]
    k = end - 1
    while k >= 1 and _is_p(toks[k], ".", "?.") and toks[k - 1].kind == "id":
        names.insert(0, toks[k - 1].text)
        k -= 2
    return names


def _chain_runs(names: list) -> bool:
    return _JS_RUNS.match(names[-1]) is not None or any(_JS_COMMAND_NAME.search(x) for x in names[:-1])


def _call_runs(toks: list, p: int) -> bool:
    """The ``(`` at ``p`` calls something that runs code, or something this lexer cannot name."""
    b = toks[p - 1] if p > 0 else None
    if b is None:
        return False
    if b.kind == "id":
        return b.text not in _JS_NOT_A_CALL and _chain_runs(_member_chain(toks, p - 1))
    if _is_p(b, ")"):
        inner = toks[b.match + 1:p - 1]    # esbuild's ``(0,x.y)(…)``: judge ``x.y``
        if (len(inner) >= 3 and inner[0].kind == "num" and _is_p(inner[1], ",") and inner[-1].kind == "id"
                and all((t.kind == "id") if k % 2 == 0 else _is_p(t, ".", "?.") for k, t in enumerate(inner[2:]))):
            return _chain_runs([t.text for t in inner[2::2]])
        return True
    if _is_p(b, "]") or (b.kind == "tpl" and not b.text.endswith("${")) or b.kind in ("str", "re", "num"):
        return True
    return False


def _bound_to_command(toks: list, k: int) -> bool:
    """Token ``k`` is the value of ``<command-shaped name> :``/``=`` (``args:[``, ``cmd=``)."""
    return (k >= 2 and _is_p(toks[k - 1], *_JS_BINDING) and toks[k - 2].kind in ("id", "str")
            and _JS_COMMAND_NAME.search(_name(toks[k - 2])) is not None)


def _handed_on(toks: list, k: int) -> bool:
    if _bound_to_command(toks, k):
        return True
    p = toks[k].parent
    while p >= 0:
        o = toks[p]
        if o.kind == "tpl" or (o.text == "(" and _call_runs(toks, p)) or _bound_to_command(toks, p):
            return True
        p = o.parent
    return False


def _is_data_token(toks: list, k: int, start: int, end: int) -> bool:
    tok = toks[k]
    prev = toks[k - 1] if k > 0 else None
    nxt = toks[k + 1] if k + 1 < len(toks) else None
    in_object = tok.parent >= 0 and _is_p(toks[tok.parent], "{")
    is_key = in_object and _is_p(prev, "{", ",") and _is_p(nxt, ":")
    if tok.kind == "id":
        if (tok.start, tok.end) != (start, end) or not is_key:
            return False
    elif tok.kind == "str":
        if (tok.start + 1, tok.end - 1) != (start, end):
            return False
        compared = (_is_p(prev, *_JS_EQUALITY) or _is_p(nxt, *_JS_EQUALITY)
                    or (prev is not None and prev.kind == "id" and prev.text == "case" and _is_p(nxt, ":")))
        is_value = (in_object and _is_p(prev, ":") and _is_p(nxt, ",", "}") and k >= 3
                    and toks[k - 2].kind in ("id", "str") and _is_p(toks[k - 3], "{", ",")
                    and _JS_COMMAND_NAME.search(_name(toks[k - 2])) is None)
        if not (is_key or compared or is_value):
            return False
    else:
        return False
    return not _handed_on(toks, k)


# Files this module does not lex (TS, JSX, HTML) are searched as raw text, strings included.
_JS_SINK_TEXT = re.compile(
    r"\b(?:eval|require|child_process|worker_threads|spawn|spawnSync|execSync|execFile|execFileSync|fork"
    r"|createRequire|dlopen|importScripts|runInNewContext|runInThisContext|runInContext|compileFunction"
    r"|execa|shelljs|Deno|Bun)\b(?!-[A-Za-z])"    # not `require-trusted-types-for` in a CSP
    r"|(?<![.\w$])exec\s*\(|\bFunction\s*\(|\bnew\s+Function\b|\b(?:Shared)?Worker\s*\("
    r"|\bprocess\s*\.\s*(?:binding|dlopen|mainModule)\b|\bconstructor\s*\.\s*constructor\b"
    r"|\[\s*[\"'`]constructor[\"'`]\s*\]"
    r"|\b(?:globalThis|window|self|global|top|parent|frames)\s*\["
    r"|\bset(?:Timeout|Interval|Immediate)\s*\(\s*[\"'`]"
    r"|\bimport\s*\(\s*(?![\"'][^\"'`\\\n]*[\"']\s*[,)])"
    r"|[\"'`](?:node:(?:vm|cluster|module|child_process|worker_threads)|vm|cluster|zx(?:/[\w-]+)?|sudo-prompt"
    r"|@vscode/sudo-prompt|cross-spawn)[\"'`]")
_JS_ESCAPE = re.compile(r"\\u[0-9a-fA-F{]")

# Lexed files are judged by token.
_JS_SINK_IDS = frozenset({
    "eval", "require", "Function", "child_process", "worker_threads", "spawn", "spawnSync", "execSync", "execFile",
    "execFileSync", "fork", "createRequire", "dlopen", "importScripts", "runInNewContext", "runInThisContext",
    "runInContext", "compileFunction", "execa", "shelljs", "Deno", "Bun", "Worker", "SharedWorker"})
_JS_PROCESS_MODULES = re.compile(
    r"^(?:node:)?(?:child_process|vm|cluster|module|worker_threads)$|^(?:zx(?:/[\w-]+)?|execa|shelljs|cross-spawn"
    r"|sudo|sudo-prompt|@vscode/sudo-prompt)$")
_JS_GLOBALS = frozenset({"globalThis", "window", "self", "global", "top", "parent", "frames"})


def _is_method_definition(toks: list, k: int, closer_of: dict) -> bool:
    """``exec(s){…}`` in a class body or an object literal defines a method; it calls nothing."""
    close = closer_of.get(k + 1, -1)
    before = toks[k - 1] if k else None
    return (close >= 0 and _is_p(toks[close + 1] if close + 1 < len(toks) else None, "{")
            and toks[k].parent >= 0 and _is_p(toks[toks[k].parent], "{")
            and (_is_p(before, "{", "}", ",", ";", "*")
                 or (before is not None and before.kind == "id" and before.text in ("static", "async", "get", "set"))))


def _js_token_sink(toks: list) -> bool:
    """A lexed file names or reaches something that runs code (see the inventory above)."""
    closer_of = {t.match: j for j, t in enumerate(toks) if t.match >= 0}
    for k, t in enumerate(toks):
        prev = toks[k - 1] if k else None
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if t.kind == "id":
            if t.text in _JS_SINK_IDS:
                return True
            member = _is_p(prev, ".", "?.")
            if t.text == "exec" and not member and _is_p(nxt, "(") and not _is_method_definition(toks, k, closer_of):
                return True
            if t.text == "import" and _is_p(nxt, "("):
                arg = toks[k + 2] if k + 2 < len(toks) else None
                after = toks[k + 3] if k + 3 < len(toks) else None
                if not (arg is not None and arg.kind == "str" and _is_p(after, ")", ",")):
                    return True
            if t.text in _JS_GLOBALS and not member and _is_p(nxt, "["):
                return True
            if t.text in ("setTimeout", "setInterval", "setImmediate") and _is_p(nxt, "("):
                arg = toks[k + 2] if k + 2 < len(toks) else None
                if arg is not None and arg.kind in ("str", "tpl"):
                    return True
            if t.text == "constructor" and member and k >= 2 and toks[k - 2].kind == "id" and (
                    toks[k - 2].text == "constructor"):
                return True
            if t.text == "process" and _is_p(nxt, ".", "?.") and k + 2 < len(toks) and toks[k + 2].text in (
                    "binding", "dlopen", "mainModule"):
                return True
            if t.kind == "id" and nxt is not None and nxt.kind == "tpl" and nxt.text.startswith("`") and (
                    t.text not in (_JS_NOT_A_CALL | _RE_AFTER_KEYWORDS)) and _chain_runs(_member_chain(toks, k)):
                return True    # a shell tag: zx's $`…`, Bun.$`…`, sh`…`
        elif t.kind == "str":
            value = t.text[1:-1]
            if value == "constructor" and _is_p(prev, "["):
                return True
            specifier = (prev is not None and prev.kind == "id" and prev.text in ("from", "import")) or (
                _is_p(prev, "(") and k >= 2 and toks[k - 2].kind == "id" and toks[k - 2].text in ("require", "import"))
            if specifier and _JS_PROCESS_MODULES.match(value):
                return True
    return False


class JsSinkInventory:
    """Per plugin scan: can any JavaScript in the plugin run something, and the tokens of each
    lexed file. Built lazily on the first candidate finding; one doubt answers "yes"."""

    def __init__(self, plugin_dir: Path, excluded_dirs: frozenset = frozenset()) -> None:
        self.plugin_dir = plugin_dir
        self.excluded_dirs = excluded_dirs
        self._unsafe: Optional[bool] = None
        self._tokens: dict = {}

    def _files(self):
        for f in sorted(self.plugin_dir.rglob("*")):
            try:
                parts = f.relative_to(self.plugin_dir).parts
            except ValueError:
                continue
            if any(p in self.excluded_dirs for p in parts) or f.suffix.lower() not in JS_FAMILY_SUFFIXES:
                continue
            if f.is_symlink() or f.is_file():
                yield f, "/".join(parts)

    def tokens(self, rel_path: str) -> Optional[tuple]:
        """``(text, tokens, token starts)`` of a lexed file, or None when it cannot be lexed."""
        if rel_path not in self._tokens:
            try:
                text = (self.plugin_dir / rel_path).read_text(encoding="utf-8-sig")
                toks = lex_js(text)
                self._tokens[rel_path] = (text, toks, [t.start for t in toks])
            except (OSError, UnicodeDecodeError, JsLexError, RecursionError):
                self._tokens[rel_path] = None
        return self._tokens[rel_path]

    def anything_runs(self) -> bool:
        if self._unsafe is None:
            self._unsafe = self._scan()
        return self._unsafe

    def _scan(self) -> bool:
        for f, rel in self._files():
            if f.is_symlink():
                return True
            if f.suffix.lower() in JS_LEXED_SUFFIXES:
                lexed = self.tokens(rel)
                if lexed is None or _js_token_sink(lexed[1]):
                    return True
                continue
            try:
                text = f.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError):
                return True
            if _JS_SINK_TEXT.search(text) or _JS_ESCAPE.search(text):
                return True
        return False

    def js_data(self, finding: Finding, rel_path: str, line_no: int, line: str) -> bool:
        """Every hit of the finding's pattern on line ``line_no`` is data (see the rule above)."""
        if finding.pattern_id not in JS_DATA_PATTERN_IDS or Path(rel_path).suffix.lower() not in JS_LEXED_SUFFIXES:
            return False
        rx = _PATTERN_BY_ID.get(finding.pattern_id)
        hits = list(rx.finditer(line)) if rx else []
        lexed = self.tokens(rel_path) if hits else None
        if lexed is None:
            return False
        text, toks, starts = lexed
        lines = text.split("\n")
        if not 0 < line_no <= len(lines) or lines[line_no - 1] != line:
            return False
        base = sum(len(x) + 1 for x in lines[:line_no - 1])
        judge = _is_sudo_data if finding.pattern_id == "sudo_usage" else _is_regex_exec
        for h in hits:
            s, e = base + h.start(), base + h.end()
            k = bisect.bisect_right(starts, s) - 1
            if k < 0 or not toks[k].start <= s < toks[k].end:
                return False
            verdict = judge(toks, k, s, e)
            if verdict is False or (verdict is None and self.anything_runs()):
                return False
        return True


def _is_regex_exec(toks: list, k: int, start: int, end: int) -> Optional[bool]:
    """An ``exec_string`` hit (``exec("``): True for ``/re/.exec("…")``, None (data unless some
    JavaScript in the plugin can run code) for a member ``.exec("…")`` on any other receiver,
    False for anything else, a bare ``exec("…")`` above all."""
    tok = toks[k]
    if tok.kind != "id" or tok.text != "exec" or tok.start != start:
        return False
    nxt = toks[k + 1] if k + 1 < len(toks) else None
    arg = toks[k + 2] if k + 2 < len(toks) else None
    if not (_is_p(nxt, "(") and arg is not None and arg.kind == "str") or k < 2 or not _is_p(toks[k - 1], ".", "?."):
        return False
    receiver = toks[k - 2]
    if receiver.kind == "re":
        return True
    return None if receiver.kind == "id" or _is_p(receiver, ")", "]") else False


def _is_sudo_data(toks: list, k: int, start: int, end: int) -> Optional[bool]:
    """A ``sudo_usage`` hit in a data position: data unless some JavaScript in the plugin runs code."""
    return None if _is_data_token(toks, k, start, end) else False


# ── (6) base64 decode piped to a non-interpreter ────────────────────────────────────────────
# ``base64_decode_pipe`` describes "decodes and pipes to execution". ``gh api … | base64 -d |
# grep '^sha:'`` decodes data for a text filter; the shape is only execution when the consumer
# is a shell/interpreter or ``eval``/``source``/``exec``. A data consumer steps down to medium.
_DECODE_CONSUMER = re.compile(r"base64\s+(?:-d|--decode)\s*\|\s*(?:\w+=\S*\s+)*(?:\S*/)?(?P<cmd>[A-Za-z0-9_.+-]+)")
_INTERPRETERS = re.compile(r"^(?:sh|bash|zsh|dash|ksh|fish|python[\d.]*|perl|ruby|node|nodejs|php|eval|source|exec|xargs|env|sudo)$")


def is_data_decode(line: str) -> bool:
    """``base64 -d`` whose pipe target is a non-interpreter command (grep, jq, tee, tar …)."""
    m = _DECODE_CONSUMER.search(line)
    return m is not None and _INTERPRETERS.match(m.group("cmd")) is None


# ── (7) loopback address with port ───────────────────────────────────────────────────────────
# ``hardcoded_ip_port`` is the "network" family's egress tripwire, yet ``127.0.0.1:12306`` in a
# README, an ``.mcp.json`` or a client default is a LOCAL service the plugin talks to on the same
# machine — nothing leaves the host. When every IP:port on the line is loopback the finding is
# informational; a routable address anywhere on the line keeps the pattern's severity.
_LOOPBACK_IP_PORT = re.compile(r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}")


def is_loopback_only(finding: Finding, line: str) -> bool:
    """Every ``hardcoded_ip_port`` hit on the line is a 127.0.0.0/8 address."""
    if finding.pattern_id != "hardcoded_ip_port":
        return False
    rx = _PATTERN_BY_ID.get(finding.pattern_id)
    hits = list(rx.finditer(line)) if rx else []
    return bool(hits) and all(_LOOPBACK_IP_PORT.match(line, h.start()) for h in hits)


# ── (8) ``pip install`` as words inside a message string ─────────────────────────────────────
# ``unpinned_pip_install`` describes a dependency the plugin pulls at runtime. In code, the same
# two words inside a quoted literal at a NON-command position — ``"... no pip install is
# needed"``, ``f"(no pip install is suggested)"`` — are prose the plugin shows a user. A literal
# that starts with the command (``"pip install requests"``), or names it after ``python -m`` /
# ``uv`` / ``pipx`` / ``sudo`` / a shell separator, is a command string and never qualifies, nor
# does any line that executes something (``subprocess.run("pip install x", shell=True)``).
_PIP_INSTALL_TOKEN = re.compile(r"pip\s+install\b", re.IGNORECASE)
_PIP_COMMAND_POSITION = re.compile(r"(?:^|[;&|`(]|\b(?:uv|pipx|sudo|python[\d.]*\s+-m))\s*$", re.IGNORECASE)


def is_pip_install_in_prose_literal(finding: Finding, line: str) -> bool:
    """Every ``pip install`` on a code line sits mid-sentence inside a string literal, and the
    line executes nothing."""
    if finding.pattern_id != "unpinned_pip_install" or _EXEC_ON_LINE.search(line):
        return False
    spans = [m.span() for m in _LITERAL_SPANS.finditer(line)]
    hits = list(_PIP_INSTALL_TOKEN.finditer(line))

    def prose(h: "re.Match[str]") -> bool:
        span = next(((a, b) for a, b in spans if a <= h.start() and h.end() <= b), None)
        if span is None:
            return False
        content_start = next((i for i in range(span[0], span[1]) if line[i] in "\"'`/"), span[0]) + 1
        return _PIP_COMMAND_POSITION.search(line[content_start:h.start()]) is None

    return bool(hits) and all(prose(h) for h in hits)


__all__ = [
    "STEP_DOWN", "DOC_PROSE_EXTENSIONS", "TEST_TREE_DIRS", "LITERAL_INERT_PATTERN_IDS", "JS_DATA_PATTERN_IDS",
    "JsLexError", "JsSinkInventory", "lex_js",
    "is_doc_prose", "is_ci_workflow", "is_agent_facing", "prose_cap", "is_self_uninstall_doc", "is_test_tree",
    "is_inert_fixture_line", "is_base64_media",
    "is_regex_alternation_token", "is_data_decode", "is_loopback_only", "is_pip_install_in_prose_literal",
]
