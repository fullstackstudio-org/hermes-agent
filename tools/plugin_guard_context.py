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
DOC_PROSE_EXTENSIONS = {".md", ".txt", ".rst", ".html", ".htm", ".xhtml"}
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
# opener or a keyword" rule). Where the lexer cannot decide or the text is doubtful (a ``/``
# after ``}`` or after of/yield/await, an HTML-like comment, U+2028/U+2029 outside a string or
# template, an identifier escape, an unterminated literal, an unbalanced bracket, a character it
# cannot read) it raises, and the finding keeps the severity the line rules give it. Every
# failure of this code, of any kind, counts as a doubt: it never lowers on an error and never
# raises into the scan.
#
# A finding drops to ``low`` (still reported) only when EVERY hit of the pattern on the line
# qualifies AND ``JsSinkInventory`` finds nothing in the plugin's JavaScript that can run code:
#   ``sudo_usage``: the token is an object key (``{sudo:`` / ``,"sudo":``), a whole quoted string
#     compared with ``===``/``!==``/``==``/``!=`` or after ``case``, or a whole quoted string that
#     is the entire value of a property whose key is not command-shaped (``kind:"sudo"``; never
#     ``cmd:``/``shell:``/``args:``); never a template, a comment, an assignment to a variable, an
#     array element or a module specifier. No bracket around it hands it on: no enclosing call
#     whose callee runs or loads code (``spawn``, ``exec*``, ``run*``, ``call``/``apply``/``bind``,
#     ``eval``, ``Function``, ``require``, ``import``, ``open``, ``setTimeout`` …; ``f?.(`` is
#     judged by ``f``) or is computed (``x[y](``, ``f()(``), no enclosing ``${…}``, no enclosing
#     array/object bound to a command name.
#   ``exec_string``: a member call ``.exec("…")``, on a regex literal or any other receiver. A
#     bare ``exec("…")`` (an imported ``child_process.exec``) is never judged.
#
# ``JsSinkInventory`` answers "can any JavaScript in this plugin run something". Lexed files are
# judged by token, so a keyword list in a string (a highlighter's ``"eval require …"``) is not a
# sink. Sinks: a sink-named identifier (``eval``, ``require``, ``Function``, ``spawn``,
# ``execSync``, ``child_process``, ``importScripts``, ``Worker``, ``getBuiltinModule``, ``_load``
# …), a bare ``exec(`` call that is not a method definition, a module specifier naming a process
# or code-loading module (``child_process``, ``vm``, ``worker_threads``, ``inspector``, ``wasi``,
# ``module``, ``zx``, ``execa`` …, with or without ``node:``) or a ``data:``/``blob:``/
# ``http(s):`` URL, a non-literal ``import(``, a string handed to ``setTimeout``, computed
# access on a global (``globalThis[…]``), ``constructor.constructor``, ``module.constructor``,
# ``["constructor"]``, ``process.binding``, a ``$`…```/``sh`…``` shell tag, and any replacement
# of ``exec`` (``X.prototype.exec =``, ``x["exec"]``, ``defineProperty(…, "exec", …)``). Every
# other JS/TS/HTML file is searched as raw text, strings and comments included, and a ``\u``
# escape there is a doubt. An unreadable file, a symlink or a lexing error anywhere is a doubt
# too, and one doubt answers "yes".
#
# Reaching ``constructor`` or replacing ``exec`` indirectly is a doubt too: a ``"constructor"``
# string anywhere, ``{constructor: F}``, ``.constructor`` on a call result, and a computed member
# whose key is not a literal when it is indexed again, sits on a call result, a function or an
# array, is called with a string, or is assigned on a ``prototype`` (``_computed_key_doubt``). A key
# that is provably a number (``Number(…)``, ``i - 1``, a ``const`` bound to one) names an index and
# is no doubt, as a literal ``0`` never was (``_NumericKeys``).
#
# The inventory answers for the whole plugin on purpose, not per file or per module graph: the
# chunks of a web bundle share one realm, so a ``RegExp.prototype.exec`` replaced in one makes
# every ``/re/.exec("…")`` in another a call of it, and a sink in one chunk runs data another chunk
# hands it (a bundle's chunks usually reach each other through its entry).
#
# The inventory is a DENYLIST with known gaps, not a proof that nothing can run. It only ever
# decides whether ``sudo_usage`` and a member ``exec_string`` may drop to ``low``; every other
# finding is untouched. Known gaps it does not try to close: the browser's own code-from-string
# routes (a ``<script>`` element built and inserted, a ``javascript:`` URL, ``setAttribute("on…")``,
# ``innerHTML``/``outerHTML``/``insertAdjacentHTML``, ``document.write``), which run in the page and
# not on the host, and any route built without a name the list knows.
#
# Accepted limits (the rule only ever lowers, and only to a ``low`` that stays in the report):
#   - The inventory reads JavaScript only. A Python or shell file of the plugin that hands JS
#     data to a process is not counted; those files are judged by their own rules.
#   - Directories the scanner never reads (``EXCLUDED_DIRS``: ``node_modules``, ``.venv`` …) are
#     invisible to the inventory as they are to the scan.
#   - A sink built without any of the names above, and a value that reaches such a disguised
#     call through a variable, cannot be seen. So "can run it" means "can run it by a route the
#     inventory names".
#   - A numeric key trusts ``Number``/``parseInt``/``parseFloat`` unless the plugin rebinds them by
#     a route the checks name (a declaration or parameter, a function or method of that name,
#     ``x.Number =``, a quoted name in an argument list, a computed member or an object key, a
#     ``with`` statement). A global object reached through an alias and a built name
#     (``g[k] = f``) is not seen, as ``g["Fun"+"ction"]`` is not.
#   - This rule is not the only demotion: the per-line rule (5) already lowers a whole-literal
#     ``"sudo"`` on a line that executes nothing to ``medium``, with no inventory at all.
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
_JS_SPACE = frozenset(" \t\r\n\v\f\ufeff\xa0\u1680\u202f\u205f\u3000") | frozenset(
    chr(c) for c in range(0x2000, 0x200b))
_RE_AFTER_KEYWORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                                "case", "do", "else", "yield", "await", "extends", "default"})
_OBJECT_AFTER_KEYWORDS = _RE_AFTER_KEYWORDS - {"do", "else", "extends"}
_REGEX_FLAGS = re.compile(r"[A-Za-z]*")
_ASCII_DIGITS = frozenset("0123456789")
# U+2028/U+2029 end a line for the engine (a ``//`` comment, an Annex B ``-->``) but not for
# ``str.split("\n")``; outside a string or template they are a doubt, never whitespace.
_SEPARATORS = frozenset("\u2028\u2029")
_LINE_END = re.compile(r"[\n\r\u2028\u2029]")
_NOT_IN_A_NAME = re.compile("[" + re.escape("".join(sorted(_JS_SPACE | _SEPARATORS))) + "]")


def _line_comment_end(text: str, i: int) -> int:
    """Where a ``//`` (or ``#!``) comment starting at ``i`` ends: at ``\n`` or ``\r``."""
    m = _LINE_END.search(text, i)
    if m is None:
        return len(text)
    if m.group(0) in _SEPARATORS:
        raise JsLexError("a line or paragraph separator outside a string")
    return m.start()


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
    i = _line_comment_end(text, 0) if text.startswith("#!") else 0
    prev: Optional[_Tok] = None

    def emit(tok: _Tok) -> _Tok:
        tok.parent = stack[-1] if stack else -1
        toks.append(tok)
        return tok

    while i < n:
        c = text[i]
        if c in _SEPARATORS:
            raise JsLexError("a line or paragraph separator outside a string")
        if c in _JS_SPACE:
            i += 1
            continue
        if text.startswith("//", i):
            i = _line_comment_end(text, i)
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise JsLexError("unterminated comment")
            if any(sep in text[i:j] for sep in _SEPARATORS):
                raise JsLexError("a line or paragraph separator outside a string")
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
                if j >= n or text[j] in "\r\n\u2028\u2029":
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
        if c in _ASCII_DIGITS or (c == "." and i + 1 < n and text[i + 1] in _ASCII_DIGITS):
            m = _JS_NUMBER.match(text, i)
            if m is None:
                raise JsLexError("unreadable number")
            prev = emit(_Tok("num", i, m.end(), m.group(0)))
            i = m.end()
            continue
        m = _JS_IDENT.match(text, i + 1 if c == "#" else i)
        if m and (c != "#" or m.start() == i + 1):
            end = m.end()
            stop = _NOT_IN_A_NAME.search(text, i, end)    # a space or separator ends a name
            if stop is not None:
                if text[stop.start()] in _SEPARATORS:
                    raise JsLexError("a line or paragraph separator outside a string")
                end = stop.start()
            prev = emit(_Tok("id", i, end, text[i:end]))
            i = end
            continue
        m = _JS_PUNCT.match(text, i)
        if m is None:
            raise JsLexError(f"unexpected character {c!r}")
        t = m.group(0)
        # Annex B: in a classic script ``<!--`` and a line-leading ``-->`` open a comment the
        # engine skips and this lexer would read as code (and as the start of a template).
        if (t == "<" and text.startswith("!--", i + 1)) or (
                t == "--" and text.startswith(">", i + 2) and (prev is None or any(nl in text[prev.end:i] for nl in "\n\r"))):
            raise JsLexError("an HTML-like comment")
        tok = _Tok("p", i, i + len(t), t)
        if t in ("(", "[", "{"):
            if t == "{":
                tok.block = _brace_opens_block(prev)
            elif t == "(":
                # ``if (`` opens a statement head; ``x.if(`` is a call of a property named ``if``.
                tok.block = (prev is not None and prev.kind == "id" and prev.text in ("if", "while", "for", "with")
                             and not (len(toks) >= 2 and _is_p(toks[-2], ".", "?.")))
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


_JS_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
                      "'": "'", '"': '"', "\\": "\\"}
_HEX = frozenset("0123456789abcdefABCDEF")


def _decode_js_string(text: str) -> Optional[str]:
    """The value of a quoted string token: ``\\xNN``, ``\\uXXXX``, ``\\u{…}``, the single-letter escapes,
    identity escapes and line continuations decoded. ``None`` when unsure (a legacy octal or
    ``\\8``/``\\9`` escape, a malformed hex or unicode escape): callers treat that as a doubt."""
    body = text[1:-1]
    out: list = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            return None
        e = body[i]
        if e == "0" and not (i + 1 < n and body[i + 1].isdigit()):
            out.append("\0")
            i += 1
        elif e.isdigit():
            return None    # legacy octal, \8, \9
        elif e in _JS_SIMPLE_ESCAPES:
            out.append(_JS_SIMPLE_ESCAPES[e])
            i += 1
        elif e == "x":
            h = body[i + 1:i + 3]
            if len(h) != 2 or not set(h) <= _HEX:
                return None
            out.append(chr(int(h, 16)))
            i += 3
        elif e == "u":
            if body.startswith("{", i + 1):
                j = body.find("}", i + 2)
                h = body[i + 2:j] if j > 0 else ""
                if not h or not set(h) <= _HEX or int(h, 16) > 0x10FFFF:
                    return None
                out.append(chr(int(h, 16)))
                i = j + 1
            else:
                h = body[i + 1:i + 5]
                if len(h) != 4 or not set(h) <= _HEX:
                    return None
                out.append(chr(int(h, 16)))
                i += 5
        elif e in "\r\n\u2028\u2029":    # a line continuation
            i += 2 if e == "\r" and body.startswith("\n", i + 1) else 1
        else:
            out.append(e)    # an identity escape: \q is q
            i += 1
    return "".join(out)


def _name(tok: _Tok) -> Optional[str]:
    """An identifier's text or a string's decoded value (``None`` when the string is doubtful)."""
    return _decode_js_string(tok.text) if tok.kind == "str" else tok.text


def _is_member_name(toks: list, k: int) -> bool:
    """Token ``k`` follows ``.``/``?.``: a property name, even when it spells a keyword."""
    return k >= 1 and _is_p(toks[k - 1], ".", "?.")


def _command_shaped(name: Optional[str]) -> bool:
    return name is None or _JS_COMMAND_NAME.search(name) is not None


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
    """The ``(`` at ``p`` calls something that runs code, or something this lexer cannot name.
    ``f?.(…)`` is judged by ``f``."""
    bi = p - 1
    if bi >= 1 and _is_p(toks[bi], "?."):
        bi -= 1
    b = toks[bi] if bi >= 0 else None
    if b is None:
        return False
    if b.kind == "id":
        if b.text in _JS_NOT_A_CALL and not _is_member_name(toks, bi):
            return False    # ``if (``, ``typeof (``: not a call; ``x.if(`` is one
        return _chain_runs(_member_chain(toks, bi))
    if _is_p(b, ")"):
        inner = toks[b.match + 1:bi]    # esbuild's ``(0,x.y)(…)``: judge ``x.y``
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
            and _command_shaped(_name(toks[k - 2])))


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
                    and not _command_shaped(_name(toks[k - 2])))
        if not (is_key or compared or is_value):
            return False
    else:
        return False
    return not _handed_on(toks, k)


# Files this module does not lex (TS, JSX, HTML) are searched as raw text, strings included.
_REMOTE_SPECIFIER = r"[\"'`](?:data|blob|https?):"
_JS_SINK_TEXT = re.compile(
    r"\b(?:eval|require|child_process|worker_threads|spawn|spawnSync|execSync|execFile|execFileSync|fork"
    r"|createRequire|dlopen|importScripts|runInNewContext|runInThisContext|runInContext|compileFunction"
    r"|getBuiltinModule|_load|execa|shelljs|Deno|Bun)\b(?!-[A-Za-z])"    # not `require-trusted-types-for` (CSP)
    r"|(?<![.\w$])exec\s*\(|\bFunction\s*\(|\bnew\s+Function\b|\b(?:Shared)?Worker\s*\("
    r"|\bprocess\s*\.\s*(?:binding|dlopen|mainModule)\b|\bconstructor\s*\.\s*constructor\b"
    r"|\b[Mm]odule\s*\.\s*(?:constructor|_\w+)\b|\[\s*[\"'`](?:constructor|exec)[\"'`]\s*\]"
    r"|\bprototype\s*\.\s*exec\s*=(?!=)|\bdefine(?:Property|Properties)\b[^;\n]*[\"'`]exec[\"'`]"
    r"|\b(?:globalThis|window|self|global|top|parent|frames)\s*\["
    r"|\bset(?:Timeout|Interval|Immediate)\s*\(\s*[\"'`]"
    r"|\bimport\s*\(\s*(?![\"'][^\"'`\\\n]*[\"']\s*[,)])|\bimport\s*\(\s*" + _REMOTE_SPECIFIER
    + r"|\b(?:from|import)\s*" + _REMOTE_SPECIFIER
    + r"|[\"'`](?:node:(?:vm|cluster|module|child_process|worker_threads|inspector|wasi)|vm|cluster|inspector|wasi"
    r"|worker_threads|zx(?:/[\w-]+)?|sudo-prompt|@vscode/sudo-prompt|cross-spawn)[\"'`]")
_JS_ESCAPE = re.compile(r"\\u[0-9a-fA-F{]")

# Lexed files are judged by token.
_JS_SINK_IDS = frozenset({
    "eval", "require", "Function", "child_process", "worker_threads", "spawn", "spawnSync", "execSync", "execFile",
    "execFileSync", "fork", "createRequire", "dlopen", "importScripts", "runInNewContext", "runInThisContext",
    "runInContext", "compileFunction", "getBuiltinModule", "_load", "execa", "shelljs", "Deno", "Bun", "Worker",
    "SharedWorker"})
_JS_PROCESS_MODULES = re.compile(
    r"^(?:node:)?(?:child_process|vm|cluster|module|worker_threads|inspector|wasi)$"
    r"|^(?:zx(?:/[\w-]+)?|execa|shelljs|cross-spawn|sudo|sudo-prompt|@vscode/sudo-prompt)$"
    r"|^(?:data|blob|https?):", re.IGNORECASE)
_JS_GLOBALS = frozenset({"globalThis", "window", "self", "global", "top", "parent", "frames"})
_JS_DEFINERS = frozenset({"defineProperty", "defineProperties", "__defineGetter__", "__defineSetter__", "set"})


def _is_method_definition(toks: list, k: int, closer_of: dict) -> bool:
    """``exec(s){…}`` in a class body or an object literal defines a method; it calls nothing."""
    close = closer_of.get(k + 1, -1)
    before = toks[k - 1] if k else None
    return (close >= 0 and _is_p(toks[close + 1] if close + 1 < len(toks) else None, "{")
            and toks[k].parent >= 0 and _is_p(toks[toks[k].parent], "{")
            and (_is_p(before, "{", "}", ",", ";", "*")
                 or (before is not None and before.kind == "id" and before.text in ("static", "async", "get", "set"))))


# Words after which ``[`` opens an array literal or a destructuring pattern, not a computed member
# (``this[`` and ``super[`` index a value and are not here).
_JS_KEYWORDS = frozenset({
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
    "export", "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new",
    "of", "return", "static", "switch", "throw", "try", "typeof", "var", "void", "while", "with", "yield",
    "await", "async"})


def _computed_member(toks: list, k: int) -> bool:
    """The ``[`` at ``k`` indexes a value (``x["exec"]``), not an array literal."""
    b = toks[k - 1] if k else None
    return b is not None and ((b.kind == "id" and (b.text not in _JS_KEYWORDS or _is_member_name(toks, k - 1)))
                              or _is_p(b, ")", "]") or b.kind == "str")


def _literal_value(tok: _Tok) -> Optional[str]:
    """The value of a string, a template without substitutions, or a number; None otherwise."""
    if tok.kind == "str":
        return _decode_js_string(tok.text)
    if tok.kind == "tpl" and tok.text.startswith("`") and tok.text.endswith("`") and len(tok.text) >= 2:
        return _decode_js_string(tok.text)
    if tok.kind == "num":
        return tok.text
    return None


# A key that is always a number (or a BigInt) names an index, never ``constructor`` or ``exec``:
# ``f()[Number(s)]`` can reach no more than ``f()[0]``, which was never a doubt. Proven by token:
# ``Number(…)``/``parseInt(…)``/``parseFloat(…)`` as the whole key while no JavaScript in the plugin
# rebinds those names (``JsSinkInventory._numeric_builtins_untouched``); an expression whose top
# level holds only operands, ``.``/``?.``, groups, the prefixes ``-``/``~``/``!``/``typeof``/
# ``void``/``new``/``await``/``delete``, and at least one numeric binary operator (``-``, ``*``,
# ``/``, ``%``, ``**``, ``|``, ``&``, ``^``, ``<<``, ``>>``, ``>>>``) or a leading ``-``/``+``/
# ``~``/``++``/``--`` (``n.length - 1``, ``i | 0``, ``-1``); or a name bound by ``const name = <one
# of those>`` earlier in the same block, on one line, with nothing between that can bind the name
# again for the key (``for``, ``with``, ``catch``, ``function``, ``class``, ``=>``). ``+``, ``,``,
# ``?:``, ``||``/``&&``/``??``, assignments, comparisons, ``yield`` and every other keyword are not
# numeric. The receiver must not name a reflective or global route (``Object.keys(o)[i - 1]``,
# ``Reflect.ownKeys(f)[n]``, ``window``…): those keep the old rule.
_JS_NUMERIC_BUILTINS = frozenset({"Number", "parseInt", "parseFloat"})
_JS_NUMERIC_BINARY = frozenset({"-", "*", "/", "%", "**", "|", "&", "^", "<<", ">>", ">>>"})
_JS_NUMERIC_PREFIX = frozenset({"-", "+", "~", "++", "--"})
_JS_KEY_PREFIX_WORDS = frozenset({"typeof", "void", "new", "await", "delete"})
_JS_REFLECTIVE = frozenset({
    "Object", "Reflect", "Function", "getPrototypeOf", "getOwnPropertyNames", "getOwnPropertyDescriptor",
    "getOwnPropertyDescriptors", "getOwnPropertySymbols", "keys", "values", "entries", "ownKeys", "fromEntries",
    "constructor", "prototype", "__proto__", "__lookupGetter__", "__lookupSetter__", "arguments"}) | _JS_GLOBALS
_JS_SCOPE_WORDS = frozenset({"for", "with", "catch", "function", "class"})


_MAX_RECEIVER_TOKENS = 512    # a longer receiver (or ancestor chain) is not read: it keeps the old rule


class _NumericKeys:
    """Per lexed file: which computed keys are provably numbers (see above). Every walk is bounded:
    an expression is read by its top-level tokens only, a ``const`` is found through an index
    built once, and a receiver longer than ``_MAX_RECEIVER_TOKENS`` is not read."""

    def __init__(self, toks: list, closer_of: dict, builtins_ok: bool, text: str) -> None:
        self.toks, self.closer_of, self.builtins_ok, self.text = toks, closer_of, builtins_ok, text
        self._next_same: Optional[list] = None
        self._decls: dict = {}       # (depth, name) -> indices of ``const name =``, ascending
        self._barriers: dict = {}    # depth -> indices of for/with/catch/function/class/=> there
        self._terms: dict = {}       # declaration index -> its ``,``/``;`` at the same depth
        self._const_memo: dict = {}

    def _index(self) -> None:
        toks = self.toks
        n = len(toks)
        nxt = [n] * n
        last: dict = {}
        for i in range(n - 1, -1, -1):
            t = toks[i]
            nxt[i] = last.get(t.parent, n)
            last[t.parent] = i
        self._next_same = nxt
        for i, t in enumerate(toks):
            if t.kind == "p" and t.text == "=>":
                self._barriers.setdefault(t.parent, []).append(i)
            elif t.kind == "id" and not _is_member_name(toks, i):
                if t.text in _JS_SCOPE_WORDS:
                    self._barriers.setdefault(t.parent, []).append(i)
                elif (i >= 1 and toks[i - 1].kind == "id" and toks[i - 1].text == "const"
                      and not _is_member_name(toks, i - 1) and i + 1 < n and _is_p(toks[i + 1], "=")):
                    self._decls.setdefault((t.parent, t.text), []).append(i)
                    e = nxt[i + 1]
                    while e < n and not _is_p(toks[e], ",", ";"):
                        e = nxt[e]
                    self._terms[i] = e

    def expression(self, lo: int, hi: int, depth: int) -> bool:
        """``toks[lo:hi]``, one expression whose top-level tokens have parent ``depth``, always
        evaluates to a number or a BigInt (see above). Anything it does not know answers False."""
        toks = self.toks
        if lo >= hi:
            return False
        if self._next_same is None:
            self._index()
        first = toks[lo]
        if (self.builtins_ok and first.kind == "id" and first.text in _JS_NUMERIC_BUILTINS and hi - lo >= 3
                and _is_p(toks[lo + 1], "(") and self.closer_of.get(lo + 1) == hi - 1):
            return True
        binary = False
        after_operand = False    # the previous top-level token ends an operand
        i = lo
        while i < hi:
            t = toks[i]
            if t.kind == "p":
                x = t.text
                if x in ("(", "["):
                    pass    # a group, or a call/index of the operand before; its closer ends an operand
                elif x == "{":
                    if after_operand:
                        return False
                elif x in (")", "]", "}"):
                    after_operand = True
                elif x in (".", "?."):
                    after_operand = False
                elif after_operand and x in _JS_NUMERIC_BINARY:
                    binary, after_operand = True, False
                elif i == lo and x in _JS_NUMERIC_PREFIX:
                    pass
                elif not after_operand and x in ("-", "~", "!"):
                    pass
                else:
                    return False
            elif t.kind == "id":
                member = _is_member_name(toks, i)
                if not member and t.text in _JS_KEY_PREFIX_WORDS:
                    if after_operand:
                        return False
                elif after_operand and not member:
                    return False    # two operands in a row: not one expression
                elif not member and (t.text in _JS_KEYWORDS or t.text == "yield"):
                    return False
                else:
                    after_operand = True
            elif t.kind == "tpl":
                after_operand = True    # a template, or a tag's call
            else:    # num, str, re
                if after_operand:
                    return False
                after_operand = True
            i = self._next_same[i]    # the next token at this level: groups and substitutions are skipped
        return binary or (first.kind == "p" and first.text in _JS_NUMERIC_PREFIX)

    def const(self, k: int, name: str) -> bool:
        """The key ``[name]`` at *k* reads ``const name = <numeric>`` declared earlier in the same
        block, on one line (no automatic semicolon can cut it short), and nothing between can bind
        ``name`` again for the key: a ``for``/``with``/``catch``/``function``/``class`` or an arrow
        at that level. A second ``const``/``let``/``var`` of the name in the block is an early error."""
        if self._next_same is None:
            self._index()
        depth = self.toks[k].parent
        decls = self._decls.get((depth, name), [])
        at = bisect.bisect_left(decls, k) - 1
        if at < 0:
            return False
        d = decls[at]
        barriers = self._barriers.get(depth, [])
        b = bisect.bisect_right(barriers, d)
        if b < len(barriers) and barriers[b] < k:
            return False
        e = self._terms[d]
        if e >= k:
            return False    # the key is inside the declaration's own value
        if d not in self._const_memo:
            toks = self.toks
            self._const_memo[d] = (not any(c in self.text[toks[d - 1].start:toks[e].end] for c in "\n\r")
                                   and self.expression(d + 2, e, depth))
        return self._const_memo[d]

    def reflective_receiver(self, k: int) -> bool:
        """The receiver of the computed member at *k* (its member chain, calls and their
        arguments) names ``Object``, ``Reflect``, a ``getOwnProperty…``/``keys``/``entries`` route,
        ``prototype``, ``constructor`` or a global object, holds a string with such a name or one
        this lexer will not decode, or is too long to read."""
        toks = self.toks
        depth = toks[k].parent
        i = k - 1
        while i > depth:
            if k - i > _MAX_RECEIVER_TOKENS:
                return True
            t = toks[i]
            if t.kind == "id" and t.text in _JS_REFLECTIVE:
                return True
            if t.kind == "str":
                value = _decode_js_string(t.text)
                if value is None or value in _JS_REFLECTIVE:
                    return True
            if t.parent == depth:
                if t.kind == "id" and t.text in _JS_KEYWORDS and not _is_member_name(toks, i):
                    return False
                if t.kind == "p" and t.text not in (".", "?.", "(", ")", "[", "]", "{", "}"):
                    return False
            i -= 1
        return False

    def key(self, k: int, j: int) -> bool:
        """The key of the computed member ``[`` at *k* (closed at *j*) is always a number and the
        receiver names no reflective route (see above)."""
        if self.reflective_receiver(k):
            return False
        if self.expression(k + 1, j, k):
            return True
        return j == k + 2 and self.toks[k + 1].kind == "id" and self.const(k, self.toks[k + 1].text)


def _computed_key_doubt(toks: list, k: int, closer_of: dict, numeric: Optional[_NumericKeys] = None) -> bool:
    """The computed member ``[`` at *k* could reach ``constructor`` or replace ``exec``: its key is
    ``"constructor"``/``"exec"`` (a string or a plain template), or its key is neither a literal
    (``"constr"+"uctor"``, ``k``, a template with substitutions) nor provably a number
    (``_NumericKeys``) and the member is indexed again (``x[a][b]``), sits on a call result, a
    function or an array (``f()[k]``, ``(()=>{})[k]``, ``[][k]``; a plain parenthesised value ``(a ?? b)[k]`` does not count), is called with a string
    (``x[k]("code")``), or is assigned on a ``prototype`` (``RegExp.prototype[k] = …``)."""
    j = closer_of.get(k, -1)
    if j < 0:
        return True
    inner = toks[k + 1:j]
    value = _literal_value(inner[0]) if len(inner) == 1 else None
    if value is not None:
        return value in ("constructor", "exec")
    if numeric is not None and numeric.key(k, j):
        return False
    after = toks[j + 1] if j + 1 < len(toks) else None
    receiver = toks[k - 1]
    if _is_p(after, "[") or _is_p(receiver, "]"):
        return True
    if _is_p(receiver, ")"):
        o = receiver.match
        callee = toks[o - 1] if o > 0 else None
        is_call = callee is not None and ((callee.kind == "id" and callee.text not in _JS_KEYWORDS)
                                          or _is_p(callee, ")", "]"))
        holds_function = any((t.kind == "id" and t.text == "function") or _is_p(t, "=>") for t in toks[o + 1:k - 1])
        if is_call or holds_function:
            return True    # getPrototypeOf(f)[k], (()=>{})[k]
    if _is_p(after, "(") and j + 2 < len(toks) and toks[j + 2].kind in ("str", "tpl"):
        return True
    return receiver.kind == "id" and receiver.text == "prototype" and _is_p(after, *_JS_BINDING)


def _name_string_inert(toks: list, k: int, closer_of: dict) -> bool:
    """A string at *k* that may spell ``Number``/``parseInt``/``parseFloat`` sits where it cannot
    name what is rebound: not an object key, and between it and its block no argument list, no
    computed member and no computed object key (``defineProperty(g, "Number", …)``,
    ``g["Number"] = f``, ``{["Number"]: f}``, ``Reflect.set(g, …["Number"], f)`` are not inert)."""
    prev = toks[k - 1] if k else None
    nxt = toks[k + 1] if k + 1 < len(toks) else None
    if _is_p(prev, "{", ",") and _is_p(nxt, ":"):
        return False
    p = toks[k].parent
    for _ in range(_MAX_RECEIVER_TOKENS):
        if p < 0:
            return True
        o = toks[p]
        if o.kind == "p":
            if o.text == "(":
                return False
            if o.text == "[":
                close = closer_of.get(p, -1)
                if _computed_member(toks, p) or (close >= 0 and _is_p(toks[close + 1] if close + 1 < len(toks)
                                                                       else None, ":")):
                    return False
            if o.text == "{" and o.block:
                return True
        p = o.parent
    return False    # nested deeper than this walk reads: not inert


def _numeric_builtins_untouched(toks: list, closer_of: dict) -> bool:
    """No token of this lexed file can rebind ``Number``, ``parseInt`` or ``parseFloat``: each such
    name is called (and is not a function or method being defined), read as ``Number.x``, or passed
    as a call argument (``.map(Number)``); a ``.Number`` member is only called or read on; a string
    spelling one of them (or one this lexer will not decode) is inert (``_name_string_inert``);
    no ``with`` statement can put another binding in front of them."""
    n = len(toks)
    for k, t in enumerate(toks):
        prev = toks[k - 1] if k else None
        nxt = toks[k + 1] if k + 1 < n else None
        if (t.kind == "id" and t.text == "with" and _is_p(nxt, "(") and not _is_p(prev, ".", "?.")
                and not _is_method_definition(toks, k, closer_of)):
            return False    # with (o) Number(x): the name resolves on o first
        if t.kind == "id" and t.text in _JS_NUMERIC_BUILTINS:
            if _is_p(prev, ".", "?."):
                if not _is_p(nxt, "(", ".", "?."):
                    return False
                continue
            if _is_p(nxt, "("):
                close = closer_of.get(k + 1, -1)
                after = toks[close + 1] if 0 <= close < n - 1 else None
                if close < 0 or _is_p(after, "{", "=>"):
                    return False    # function Number(){}, {Number(){…}}
                continue
            if _is_p(nxt, ".", "?."):
                continue
            if _is_p(prev, "(", ",") and _is_p(nxt, ")", ",") and t.parent >= 0 and _is_p(toks[t.parent], "("):
                o = t.parent
                close = closer_of.get(o, -1)
                after = toks[close + 1] if 0 <= close < n - 1 else None
                callee = toks[o - 1] if o >= 1 else None
                if (close >= 0 and not _is_p(after, "{", "=>") and callee is not None
                        and ((callee.kind == "id" and (callee.text not in _JS_KEYWORDS or _is_member_name(toks, o - 1)))
                             or _is_p(callee, ")", "]"))):
                    continue    # .map(Number): passed as a value
            return False
        if t.kind == "str" or (t.kind == "tpl" and t.text.startswith("`") and t.text.endswith("`") and len(t.text) >= 2):
            value = _decode_js_string(t.text)
            if (value is None or value in _JS_NUMERIC_BUILTINS) and not _name_string_inert(toks, k, closer_of):
                return False
    return True


# Raw-text files (TS, JSX, HTML): every ``Number``/``parseInt``/``parseFloat`` must be called or
# read on (``Number(``, ``Number.isNaN``), never quoted, and no ``Number(…){`` method is defined.
_JS_NUMERIC_NAME_TEXT = re.compile(r"(?<![\w$])(?:Number|parseInt|parseFloat)(?![\w$])")
_JS_NUMERIC_NAME_USE = re.compile(r"\s*(?:\(|\??\.)")
_JS_NUMERIC_NAME_DEFINED = re.compile(r"(?<![\w$])(?:Number|parseInt|parseFloat)\s*\([^()]*\)\s*(?:\{|=>)")


def _numeric_builtins_untouched_text(text: str) -> bool:
    if _JS_NUMERIC_NAME_DEFINED.search(text):
        return False
    for m in _JS_NUMERIC_NAME_TEXT.finditer(text):
        before = text[m.start() - 1] if m.start() else ""
        if (before and before in "\"'`") or not _JS_NUMERIC_NAME_USE.match(text, m.end()):
            return False
    return True


def _js_token_sink(toks: list, builtins_ok: bool = False, text: Optional[str] = None) -> bool:
    """A lexed file names or reaches something that runs code (see the inventory above).
    ``builtins_ok``: no JavaScript in the plugin rebinds ``Number``/``parseInt``/``parseFloat``;
    ``text``: the file's source, to see that a ``const`` a key reads is on one line."""
    closer_of = {t.match: j for j, t in enumerate(toks) if t.match >= 0}
    numeric = _NumericKeys(toks, closer_of, builtins_ok, text) if text is not None else None
    for k, t in enumerate(toks):
        prev = toks[k - 1] if k else None
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if _is_p(t, "[") and _computed_member(toks, k) and _computed_key_doubt(toks, k, closer_of, numeric):
            return True
        if t.kind == "id":
            if t.text in _JS_SINK_IDS:
                return True
            member = _is_p(prev, ".", "?.")
            if t.text == "exec" and not member and _is_p(nxt, "(") and not _is_method_definition(toks, k, closer_of):
                return True
            if t.text == "exec" and member and k >= 2 and toks[k - 2].kind == "id" and toks[k - 2].text == "prototype" \
                    and _is_p(nxt, *_JS_BINDING):
                return True    # RegExp.prototype.exec = … : every /re/.exec("…") would call it
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
                    toks[k - 2].text in ("constructor", "module", "Module")):
                return True
            if t.text == "process" and not member and _is_p(nxt, "["):
                return True    # process["bin"+"ding"]
            if t.text == "process" and _is_p(nxt, ".", "?.") and k + 2 < len(toks) and toks[k + 2].text in (
                    "binding", "dlopen", "mainModule"):
                return True
            if t.text == "constructor" and member and _is_p(nxt, "(") and k + 2 < len(toks) and (
                    toks[k + 2].kind in ("str", "tpl")):
                return True    # (()=>{}).constructor("code"): the Function constructor by another name
            if t.text == "constructor" and member and k >= 2 and _is_p(toks[k - 2], ")", "]"):
                return True    # Object.getPrototypeOf(function(){}).constructor
            if t.text == "constructor" and not member and _is_p(prev, "{", ",") and _is_p(nxt, ":", ",", "}", "="):
                return True    # const {constructor: F} = fn
            if nxt is not None and nxt.kind == "tpl" and nxt.text.startswith("`") and (
                    t.text not in (_JS_NOT_A_CALL | _RE_AFTER_KEYWORDS) or member) \
                    and _chain_runs(_member_chain(toks, k)):
                return True    # a shell tag: zx's $`…`, Bun.$`…`, sh`…`
        elif t.kind == "tpl" and _literal_value(t) == "constructor":
            return True
        elif t.kind == "str":
            value = _decode_js_string(t.text)    # None: an escape this lexer will not guess at
            if value == "constructor":
                return True    # Reflect.get(fn, "constructor"), {"constructor": F} = fn
            computed = _is_p(prev, "[") and _computed_member(toks, k - 1)
            if computed and (value is None or value in ("constructor", "exec")):
                return True
            definer = t.parent >= 1 and _is_p(toks[t.parent], "(") and toks[t.parent - 1].kind == "id" \
                and toks[t.parent - 1].text in _JS_DEFINERS
            if definer and (value is None or value == "exec"):
                return True    # Object.defineProperty(RegExp.prototype, "exec", …)
            specifier = (prev is not None and prev.kind == "id" and prev.text in ("from", "import")) or (
                _is_p(prev, "(") and k >= 2 and toks[k - 2].kind == "id" and toks[k - 2].text in ("require", "import"))
            if specifier and (value is None or _JS_PROCESS_MODULES.match(value)):
                return True
    return False


class JsSinkInventory:
    """Per plugin scan: can any JavaScript in the plugin run something, and the tokens of each
    lexed file. Built lazily on the first candidate finding; one doubt answers "yes"."""

    def __init__(self, plugin_dir: Path, excluded_dirs: frozenset = frozenset(), walk=None) -> None:
        self.plugin_dir = plugin_dir
        self.excluded_dirs = excluded_dirs
        self._walk = walk    # the scan's own walk (tracked-aware); without it, excluded_dirs are skipped
        self._unsafe: Optional[bool] = None
        self._tokens: dict = {}

    def _files(self):
        if self._walk is not None:
            for f, rel in sorted(self._walk()):
                if f.suffix.lower() in JS_FAMILY_SUFFIXES and (f.is_symlink() or f.is_file()):
                    yield f, rel
            return
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
        """``(tokens, token starts, lines, line offsets)`` of a lexed file, or None when it cannot
        be read or lexed, or anything at all goes wrong: a doubt, never an exception."""
        if rel_path not in self._tokens:
            try:
                text = (self.plugin_dir / rel_path).read_text(encoding="utf-8-sig")
                toks = lex_js(text)
                lines = text.split("\n")
                offsets = [0] * len(lines)
                for i in range(1, len(lines)):
                    offsets[i] = offsets[i - 1] + len(lines[i - 1]) + 1
                self._tokens[rel_path] = (toks, [t.start for t in toks], lines, offsets)
            except Exception:    # noqa: BLE001 - any failure is a doubt: nothing is lowered
                self._tokens[rel_path] = None
        return self._tokens[rel_path]

    def anything_runs(self) -> bool:
        if self._unsafe is None:
            try:
                self._unsafe = self._scan()
            except Exception:    # noqa: BLE001 - a scan that fails answers "yes"
                self._unsafe = True
        return self._unsafe

    def _numeric_builtins_untouched(self, files: list) -> bool:
        """No JavaScript in the plugin rebinds ``Number``, ``parseInt`` or ``parseFloat`` by a
        route these checks name (a global reached through an alias and a computed name is not
        seen, like every such route in the inventory). Anything unreadable answers False."""
        for f, rel in files:
            if f.is_symlink():
                return False
            if f.suffix.lower() in JS_LEXED_SUFFIXES:
                lexed = self.tokens(rel)
                if lexed is None:
                    return False
                toks = lexed[0]
                if not _numeric_builtins_untouched(toks, {t.match: j for j, t in enumerate(toks) if t.match >= 0}):
                    return False
                continue
            try:
                text = f.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError):
                return False
            if not _numeric_builtins_untouched_text(text):
                return False
        return True

    def _scan(self) -> bool:
        files = list(self._files())
        builtins_ok = self._numeric_builtins_untouched(files)
        for f, rel in files:
            if f.is_symlink():
                return True
            if f.suffix.lower() in JS_LEXED_SUFFIXES:
                lexed = self.tokens(rel)
                if lexed is None or _js_token_sink(lexed[0], builtins_ok, "\n".join(lexed[2])):
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
        """Every hit of the finding's pattern on line ``line_no`` is data (see the rule above).
        Any failure answers False: the finding keeps its severity."""
        try:
            return self._js_data(finding, rel_path, line_no, line)
        except Exception:    # noqa: BLE001 - never lower on an error, never raise into the scan
            return False

    def _js_data(self, finding: Finding, rel_path: str, line_no: int, line: str) -> bool:
        if finding.pattern_id not in JS_DATA_PATTERN_IDS or Path(rel_path).suffix.lower() not in JS_LEXED_SUFFIXES:
            return False
        rx = _PATTERN_BY_ID.get(finding.pattern_id)
        hits = list(rx.finditer(line)) if rx else []
        lexed = self.tokens(rel_path) if hits else None
        if lexed is None:
            return False
        toks, starts, lines, offsets = lexed
        if not 0 < line_no <= len(lines) or lines[line_no - 1] != line:
            return False
        base = offsets[line_no - 1]
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
    """An ``exec_string`` hit (``exec("``): None (data unless some JavaScript in the plugin can run
    code) for a member ``.exec("…")``, whether the receiver is a regex literal or anything else;
    False for anything else, a bare ``exec("…")`` above all. A regex receiver is not enough on its
    own: ``RegExp.prototype.exec`` can be replaced."""
    tok = toks[k]
    if tok.kind != "id" or tok.text != "exec" or tok.start != start:
        return False
    nxt = toks[k + 1] if k + 1 < len(toks) else None
    arg = toks[k + 2] if k + 2 < len(toks) else None
    if not (_is_p(nxt, "(") and arg is not None and arg.kind == "str") or k < 2 or not _is_p(toks[k - 1], ".", "?."):
        return False
    receiver = toks[k - 2]
    return None if receiver.kind in ("re", "id") or _is_p(receiver, ")", "]") else False


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
