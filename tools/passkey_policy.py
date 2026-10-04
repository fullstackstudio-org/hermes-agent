"""Operator rules that force a passkey confirmation (``confirm.passkey.require``).

The agent can ask for a passkey confirmation (``confirm_action(level="passkey")``); these rules are where
the gateway's operator forces one, whatever the agent, the session or the approval settings say. Four
rules, read by ``hermes_cli/dashboard_auth/passkeys/settings.py`` (a section a dashboard session cannot
write):

- ``commands``: shell-command globs, matched like ``approvals.deny`` (case-insensitive ``fnmatch`` over the
  same normalised and de-obfuscated variants of the command) plus the commands handed to ``eval``, a
  here-string or ``xargs`` (:func:`command_variants`). Not reordered options or a script run by name;
  ``tools: ["terminal"]`` is the hard guarantee;
- ``approvals``: every dangerous-command approval. A command the dangerous-command detector flags is
  decided at the floor (below), like a ``commands`` match; every other approval the gateway would ask a
  person for in the command and ``execute_code`` gates (a security-scanner finding, an ``execute_code``
  script) is asked as a passkey confirmation instead, at the place it would have been asked;
- ``smart_denied``: an owner override of a guardian (smart approval) DENY;
- ``tools``: tool-name globs (case-insensitive ``fnmatch``), for every call of a matching tool.

Where they are decided, so no session setting skips them:

- ``commands`` and the detector part of ``approvals``: :func:`command_floor`, called from
  ``tools.approval._user_deny_block``, which every command guard runs before yolo (process or session),
  ``approvals.mode: off``, cron and single-query approve modes, the permanent allowlist, session
  approvals and the smart guardian. It is also the one check the isolated-container fast path runs, so a
  rule holds on every terminal backend (a command can reach the network from a container too). The
  Codex app-server runtime runs the same floor on every exec approval request before its auto-accept
  (``agent/transports/codex_app_server_session._exec_floor``).
- the rest of ``approvals``, and ``smart_denied``: :func:`human_decision`, called from
  ``tools.approval._human_decision`` where an ordinary approval would be asked. Yolo and ``mode: off``
  skip those approvals altogether, and with them this part.
- ``tools``: :func:`tool_call_block`, called at tool dispatch (``hermes_cli.plugins.
  _dispatch_pre_tool_call_hooks``) after the plugin hooks, and on its own when the hook pipeline raises,
  for every tool call in every mode.

A forced confirmation is a ``confirm`` request at level ``passkey`` that the gateway builds itself
(:func:`forced_text`: title "Approve a command", summary the redacted description plus the security
scanner's findings, detail the command AS IT WILL RUN). A detail the secret redactor would change, one
over the contract's 2,000 characters, one with characters a confirmation cannot show as they are, or one
spaced so that part of it could sit out of view (:func:`padded`) is never shown in part: the operation is
blocked. On a command match the security scanner (tirith) still
runs first; its ``block`` verdict stays a block. It is asked through the STRONG-CONFIRM CALLBACK the interactive gateway registered for the
conversation (:func:`register_strong_confirm`, keyed by the approval session key; ``tui_gateway`` does it
per session). It never enters the approval queue, so ``approval.respond``, ``/approve``, ``/approve all``
and messaging surfaces cannot resolve it. Only ``confirmed`` with ``verified: true`` is consent, for this
one operation: nothing is stored, the next identical command asks again. ``declined`` is a deny. Every
other ending (``unavailable`` for any reason, ``timeout``, no callback because the conversation is the
terminal CLI, a messaging platform or a scheduled job, a text too long or not faithfully showable, an
error) blocks with a message saying a passkey confirmation in the Hermie app is required, and never falls
back to an ordinary approval.

Each decision writes one ``confirm_forced`` record to the dashboard auth audit log: the rule, the
operator's pattern, the session, the signed-in user the session names, the outcome and the reason. Never
the command text (the confirm request's own ``confirm_request`` / ``confirm_outcome`` records carry the
request id and the acting user).
"""

from __future__ import annotations

import bisect
import contextlib
import contextvars
import fnmatch
import hashlib
import json
import logging
import shlex
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable

logger = logging.getLogger(__name__)

RULES = ("commands", "approvals", "smart_denied", "tools")
TITLES = {"command": "Approve a command", "code": "Approve a script", "tool": "Approve a tool call"}
NOUNS = {"command": "command", "code": "script", "tool": "tool call"}
#: The contract's bounds for a ``confirm`` (``tui_gateway.contracts.server_requests``), used when it cannot
#: be imported.
_SUMMARY_MAX, _DETAIL_MAX = 500, 2000
#: The reasons :func:`human_decision` and :func:`command_floor` block for besides the confirm outcomes.
OWN_REASONS = ("no_callback", "too_long", "hidden_characters", "trailing_whitespace", "padding", "redacted",
               "not_showable", "scanner_block", "error")


# ── rules ─────────────────────────────────────────────────────────────────────────────────────────


def _config() -> Any:
    from hermes_cli.config import load_config_readonly
    return load_config_readonly()


def _gateway_homes() -> list:
    """The homes whose rules apply besides the scoped profile's own: the gateway's own home when a turn in
    the gateway runs scoped to a profile (``paths.gateway_home``), and the home of the host gateway that
    serves this process's own profile when this is a separate process of a served profile
    (``serving.serving_gateway_home``: ``hermes -p <name> chat``, a kanban worker). Each once, never the
    scoped home itself."""
    from hermes_cli.dashboard_auth.passkeys.paths import gateway_home
    from hermes_cli.dashboard_auth.passkeys.serving import serving_gateway_home
    from hermes_constants import get_hermes_home, hermes_home_key
    seen = {hermes_home_key(get_hermes_home())}
    homes = []
    for home in (gateway_home(), serving_gateway_home()):
        if home is not None and hermes_home_key(home) not in seen:
            seen.add(hermes_home_key(home))
            homes.append(home)
    return homes


def require():
    """The operator rules now (``settings.Require``): the scoped profile's own plus those of every gateway
    home that serves it (:func:`_gateway_homes`), which a profile can add to and never remove one of. An
    unreadable config reads as no rules from that file, the way ``approvals.deny`` does (the config loader
    serves the last readable file when an edit breaks it)."""
    from hermes_cli.dashboard_auth.passkeys.settings import Require, merge_require, require_at, \
        require_from_config
    try:
        own = require_from_config(_config())
    except Exception:  # noqa: BLE001 - parity with approvals.deny: logged, not raised into every command
        logger.warning("confirm.passkey.require could not be read; no passkey rules apply", exc_info=True)
        own = Require()
    rules = [own]
    try:
        homes = _gateway_homes()
    except Exception:  # noqa: BLE001 - as above
        logger.warning("the serving gateway's home could not be resolved; only this profile's passkey rules "
                       "apply", exc_info=True)
        homes = []
    for home in homes:
        try:
            rules.append(require_at(home))
        except Exception:  # noqa: BLE001 - as above, for the gateway's file
            logger.warning("the gateway's confirm.passkey.require could not be read; its rules do not apply",
                           exc_info=True)
    return own if len(rules) == 1 else merge_require(*rules[1:], own)


@dataclass(frozen=True)
class Match:
    """Why a confirmation is forced: the rule, the operator's pattern (a glob, or the detector's key for
    ``approvals``) and the description the summary shows."""

    rule: str
    pattern: str = ""
    description: str = ""


_SEGMENT_OPS = frozenset({";", "&&", "||", "|", "&", "|&", ";;", "(", ")", "\n"})
_XARGS_VALUE_OPTIONS = frozenset({"-I", "-i", "-n", "-P", "-L", "-l", "-d", "-E", "-e", "-s", "-a",
                                  "--max-args", "--max-procs", "--max-lines", "--delimiter", "--arg-file",
                                  "--replace", "--eof", "--max-chars"})
_MAX_PROJECTION_DEPTH = 3
_MAX_VARIANTS = 256


def _segments(text: str) -> list[list[str]]:
    """Shell words per simple command (posix quoting removed), or [] when *text* does not tokenise."""
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SEGMENT_OPS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def _inner_commands(text: str) -> list[str]:
    """Command text another command runs, in the forms ``approvals.deny``'s projection does not see:
    ``eval <words>``, a here-string (``... <<< <word>``) and ``xargs [options] <command>``."""
    inner: list[str] = []
    for words in _segments(text):
        while words and "=" in words[0] and not words[0].startswith("="):
            words = words[1:]  # FOO=1 eval ...
        if not words:
            continue
        head = words[0].rsplit("/", 1)[-1]
        if head == "eval" and len(words) > 1:
            inner.append(" ".join(words[1:]))
        if head == "xargs":
            rest, index = words[1:], 0
            while index < len(rest) and rest[index].startswith("-"):
                index += 2 if rest[index] in _XARGS_VALUE_OPTIONS else 1
            if index < len(rest):
                inner.append(" ".join(rest[index:]))
        for index, word in enumerate(words[:-1]):
            if word == "<<<":
                inner.append(words[index + 1])
    return inner


def command_variants(command: str):
    """``approvals.deny``'s variants of *command* (``tools.approval_detection._deny_command_variants``:
    normalised, de-obfuscated, per segment, ``sh -c`` unwrapped), plus the commands it hands to ``eval``,
    a here-string or ``xargs``, recursively (bounded). A fork-side wrapper: ``approvals.deny`` keeps
    upstream's matching. It does not see reordered options (``git -C repo push``) or a script run by name."""
    from tools.approval_detection import _deny_command_variants
    seen: set[str] = set()
    pending = [(command, 0)]
    while pending and len(seen) < _MAX_VARIANTS:
        text, depth = pending.pop()
        for variant in _deny_command_variants(text):
            if variant in seen:
                continue
            seen.add(variant)
            yield variant
            if depth < _MAX_PROJECTION_DEPTH:
                pending.extend((inner, depth + 1) for inner in _inner_commands(variant))


def match_command_globs(command: str, globs) -> str | None:
    """The first glob of *globs* that *command* matches: ``approvals.deny``'s matching
    (``tools.approval_floors._match_user_deny_rule``: case-insensitive ``fnmatchcase`` over the normalised
    and de-obfuscated variants) over :func:`command_variants`, which also sees the commands ``eval``, a
    here-string and ``xargs`` run. Globs do not see reordered options or a script run by name."""
    patterns = [g.strip() for g in globs if isinstance(g, str) and g.strip()]
    if not patterns:
        return None
    for variant in command_variants(command):
        candidate = variant.lower().strip()
        for pattern in patterns:
            if fnmatch.fnmatchcase(candidate, pattern.lower()):
                return pattern
    return None


def match_command(command: str, rules=None) -> Match | None:
    """The floor's decision for *command*: a ``commands`` glob, else (with ``approvals``) a command the
    dangerous-command detector flags. None: no rule applies here."""
    rules = rules if rules is not None else require()
    if not rules.commands and not rules.approvals:
        return None
    from tools.approval_detection import detect_dangerous_command
    dangerous, pattern_key, description = detect_dangerous_command(command)
    description = description if dangerous else ""
    glob = match_command_globs(command, rules.commands)
    if glob is not None:
        return Match("commands", glob, description)
    if rules.approvals and dangerous:
        return Match("approvals", pattern_key, description)
    return None


def match_tool(tool_name: str, rules=None) -> Match | None:
    rules = rules if rules is not None else require()
    name = str(tool_name or "").strip().lower()
    for pattern in rules.tools:
        if name and fnmatch.fnmatchcase(name, pattern.lower()):
            return Match("tools", pattern)
    return None


# ── the strong-confirm callback, per conversation ────────────────────────────────────────────────────

_callbacks: dict[str, Callable[[dict], Any]] = {}
_callbacks_lock = threading.Lock()


def register_strong_confirm(session_key: str, callback: Callable[[dict], Any]) -> None:
    """Install the callback that asks the conversation's person for a passkey confirmation. It takes
    ``{title, summary, detail}`` and returns an outcome (``outcome``, ``verified``, ``reason``, as an object
    or a dict); it raises ``ValueError`` for text it cannot show. It runs on the thread of the guarded
    operation, inside the turn's context. Without one a forced confirmation blocks."""
    if session_key:
        with _callbacks_lock:
            _callbacks[session_key] = callback


def unregister_strong_confirm(session_key: str) -> None:
    with _callbacks_lock:
        _callbacks.pop(session_key, None)


def strong_confirm_callback(session_key: str) -> Callable[[dict], Any] | None:
    with _callbacks_lock:
        return _callbacks.get(session_key) if session_key else None


def reset_for_tests() -> None:
    with _callbacks_lock:
        _callbacks.clear()


# ── the forced confirmation ───────────────────────────────────────────────────────────────────────────


class NotShowable(ValueError):
    """The text cannot be shown in full and as it is: ``reason`` is ``too_long``, ``hidden_characters``,
    ``trailing_whitespace``, ``padding`` or ``redacted`` (:func:`forced_text`)."""

    def __init__(self, reason: str, limit: int = 0) -> None:
        super().__init__(reason)
        self.reason, self.limit = reason, limit


def _bounds() -> tuple[int, int]:
    try:
        from tui_gateway.contracts.server_requests import CONFIRM_DETAIL_MAX, CONFIRM_SUMMARY_MAX
        return int(CONFIRM_SUMMARY_MAX), int(CONFIRM_DETAIL_MAX)
    except Exception:  # noqa: BLE001 - a process without the gateway's contracts keeps the contract's numbers
        return _SUMMARY_MAX, _DETAIL_MAX


# Characters a ``confirm`` text drops or rewrites (``tui_gateway.request_text.clean_text``) or that read as something
# else than what the shell gets: what the person sees would not be what runs.
_INVISIBLE_LETTERS = frozenset({"ᅟ", "ᅠ", "ㅤ", "ﾠ", "⠀", "\U0001d159", "\U00016fe4"})
_MAX_COMBINING_MARKS = 4
# The layout bounds of a verbatim detail (``tui_gateway.request_text.MAX_SPACE_RUN`` and the rest, which say
# why): spacing beyond them could park part of the detail outside what the person sees.
_MAX_SPACE_RUN, _MAX_INDENT, _MAX_BLANK_LINES, _MAX_LINE_CHARS = 16, 32, 3, 2000
# ``Default_Ignorable_Code_Point`` (Unicode ``DerivedCoreProperties.txt``, 14.0 through 16.0): code points
# a renderer shows as nothing. The same table as ``tui_gateway.request_text.DEFAULT_IGNORABLE``, which says more.
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_IGNORABLE_STARTS = [low for low, _ in _DEFAULT_IGNORABLE]


def _default_ignorable(ch: str) -> bool:
    code = ord(ch)
    at = bisect.bisect_right(_IGNORABLE_STARTS, code) - 1
    return at >= 0 and code <= _DEFAULT_IGNORABLE[at][1]


def hidden_characters(text: str) -> bool:
    """True when *text* holds a character a confirmation could not show faithfully: a control character
    other than newline and tab, a format character (bidi overrides, zero-width characters), a surrogate,
    a private-use character, an invisible letter, whitespace other than space, newline and tab, more
    than four combining marks on one character, an unassigned code point (``Cn``) or a default-ignorable
    one (variation selectors, the combining grapheme joiner and the rest of ``_DEFAULT_IGNORABLE``)."""
    marks = 0
    for ch in text:
        category = unicodedata.category(ch)
        if category == "Cn" or _default_ignorable(ch) or ch in _INVISIBLE_LETTERS:
            return True   # the invisible letters first: U+16FE4 is a combining mark, which the next branch would count
        if category in ("Mn", "Me"):
            marks += 1
            if marks > _MAX_COMBINING_MARKS:
                return True
            continue
        marks = 0
        if ch in ("\n", "\t", " "):
            continue
        if category in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp", "Zs") or ch in _INVISIBLE_LETTERS or ch.isspace():
            return True
    return False


def padded(text: str, *, json_strings: bool = False) -> bool:
    """True when the spacing of *text* could push part of it out of view in a confirmation: more than 16
    spaces in a row after a line's first non-space character, a line indented more than 32 spaces, more
    than 3 blank lines in a row, or a line over 2,000 characters. Clients show the detail monospaced with
    every space kept and scroll long lines sideways, so ``git status`` + 300 spaces + ``; curl … | sh``
    would show as ``git status``. The bounds limit padding; they do not keep everything in view (gaps
    just under them, repeated, still overflow), which is the clients' overflow marker's job.

    *json_strings* (a tool call's detail, ``tui_gateway.request_text.layout_problem`` says more): a run right
    after the visible escape ``\\n`` inside a JSON string is a line's indentation, up to 32."""
    blank = 0
    for line in text.split("\n"):
        if not line.strip(" "):
            blank += 1
            if blank > _MAX_BLANK_LINES:
                return True
            continue
        blank = 0
        body = line.lstrip(" ")
        if len(line) > _MAX_LINE_CHARS or len(line) - len(body) > _MAX_INDENT:
            return True
        start = body.find(" " * (_MAX_SPACE_RUN + 1))
        while start >= 0:
            end = start
            while end < len(body) and body[end] == " ":
                end += 1
            if not (json_strings and end - start <= _MAX_INDENT and body[max(0, start - 2):start] == "\\n"):
                return True
            start = body.find(" " * (_MAX_SPACE_RUN + 1), end)
    return False


def _redact(text: str) -> str:
    from agent.redact import redact_sensitive_text
    return redact_sensitive_text(text)


def forced_text(*, kind: str, description: str, detail: str) -> dict:
    """``{title, summary, detail}`` of a forced confirmation: the title for *kind*, the redacted
    *description* as the summary (the gateway's own words, cut to the contract's bound with an ellipsis
    when longer), and *detail* exactly as it will run. Raises :class:`NotShowable` instead of cutting the
    detail or showing anything other than what runs: ``too_long`` (measured on the raw text),
    ``hidden_characters`` (tabs too: their width depends on the renderer), ``trailing_whitespace`` (no
    rendering shows it), ``padding`` (:func:`padded`: spacing that could push part of it out of view; for
    a tool call ``not_showable`` instead, since the agent cannot respace a file it writes without changing
    it), or ``redacted`` when the secret redactor would change it. The redactor swallows
    whole regions (a fake key block, a shortened token), so a redacted detail could hide a second command
    behind what the person signs. The detail travels verbatim (``confirm.build_params(verbatim_detail=True)``:
    no whitespace collapsing, indentation kept), and clients render it monospaced with whitespace kept."""
    summary_max, detail_max = _bounds()
    if len(detail) > detail_max:
        raise NotShowable("too_long", detail_max)
    if hidden_characters(detail) or "\t" in detail:
        raise NotShowable("hidden_characters")
    if any(line != line.rstrip() for line in detail.split("\n")) or detail != detail.rstrip():
        raise NotShowable("trailing_whitespace")
    if padded(detail, json_strings=kind == "tool"):
        raise NotShowable("not_showable" if kind == "tool" else "padding")
    if _redact(detail) != detail:
        raise NotShowable("redacted")
    shown = detail
    summary = " ".join(_redact(description or "").split()) or "This gateway's operator requires a passkey for it."
    if len(summary) > summary_max:
        summary = summary[:summary_max - 1].rstrip() + "…"
    # ``detail_layout``: the gateway measures a tool call's detail as JSON (``confirm.build_params(detail_layout=)``).
    text = {"title": TITLES[kind], "summary": summary, "detail": shown}
    return {**text, "detail_layout": "json"} if kind == "tool" else text


@dataclass(frozen=True)
class Forced:
    """How a forced confirmation ended: ``confirmed`` (verified, consent for this one operation),
    ``declined`` or ``blocked`` (with the reason). ``before_asking``: blocked by :func:`forced_text`, so
    nothing reached the person."""

    outcome: str
    reason: str = ""
    limit: int = 0
    before_asking: bool = False


def _outcome_fields(outcome: Any) -> tuple[str, bool, str]:
    if isinstance(outcome, dict):
        return str(outcome.get("outcome") or ""), outcome.get("verified") is True, str(outcome.get("reason") or "")
    return (str(getattr(outcome, "outcome", "") or ""), getattr(outcome, "verified", False) is True,
            str(getattr(outcome, "reason", "") or ""))


def _session_key() -> str:
    from tools.approval_context import get_current_session_key
    return get_current_session_key(default="")


def _ask(session_key: str, *, kind: str, description: str, detail: str) -> Forced:
    """Ask once through the conversation's strong-confirm callback. Never raises."""
    callback = strong_confirm_callback(session_key)
    if callback is None:
        return Forced("blocked", "no_callback")
    try:
        text = forced_text(kind=kind, description=description, detail=detail)
    except NotShowable as exc:
        return Forced("blocked", exc.reason, exc.limit, before_asking=True)
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: the confirmation text could not be built", exc_info=True)
        return Forced("blocked", "error")
    try:
        from tools.approval_human_wait import human_wait_window
        # Time parked on the person is excluded from a tool batch's deadline, like an approval prompt.
        with human_wait_window(session_key):
            result = callback(text)
    except ValueError:
        # The gateway refused the text as not showable verbatim (the checks above are meant to catch it first).
        return Forced("blocked", "not_showable")
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: the forced confirmation failed", exc_info=True)
        return Forced("blocked", "error")
    outcome, verified, reason = _outcome_fields(result)
    if outcome == "confirmed" and verified:
        return Forced("confirmed")
    if outcome == "declined":
        return Forced("declined")
    if outcome == "timeout":
        return Forced("blocked", "timeout")
    # ``confirmed`` without ``verified`` cannot happen at level passkey; it is not consent either way.
    return Forced("blocked", reason or (outcome if outcome != "confirmed" else "unverified") or "unavailable")


def _audit_sink(event: str, **fields: Any) -> None:
    """One record in the dashboard auth audit log (never raises). Replaced in tests."""
    try:
        from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
        audit_log(AuditEvent(event), **fields)
    except Exception:  # noqa: BLE001 - an audit failure must not change the decision
        logger.debug("confirm_forced audit record not written", exc_info=True)


def _audit(match: Match, kind: str, session_key: str, forced: Forced, *, tool: str = "") -> None:
    try:
        from gateway.session_context import get_session_env
        user_id = get_session_env("HERMES_SESSION_USER_ID", "") or ""
        ui_session = get_session_env("HERMES_UI_SESSION_ID", "") or ""
    except Exception:  # noqa: BLE001
        user_id = ui_session = ""
    _audit_sink("confirm_forced", rule=match.rule, pattern=match.pattern, kind=kind, tool=tool,
                session_key=session_key, session_id=ui_session, user_id=user_id, outcome=forced.outcome,
                reason=forced.reason)


def _force(match: Match, *, kind: str, description: str, detail: str, tool: str = "") -> Forced:
    session_key = _session_key()
    try:
        forced = _ask(session_key, kind=kind, description=description, detail=detail)
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: forced confirmation failed", exc_info=True)
        forced = Forced("blocked", "error")
    _audit(match, kind, session_key, forced, tool=tool)
    return forced


# ── messages ──────────────────────────────────────────────────────────────────────────────────────────

_WHY = {
    "no_callback": "this conversation cannot ask for one: only a conversation in the Hermie app can, not the "
                   "terminal CLI, a messaging platform or a scheduled job",
    "timeout": "nobody confirmed within 120 seconds",
    "too_long": "the {noun} is too long to show in full in a confirmation (at most {limit} characters)",
    "hidden_characters": "the {noun} contains invisible, control or tab characters a confirmation cannot show "
                         "as they are",
    "trailing_whitespace": "the {noun} has whitespace at the end of a line, which a confirmation cannot show",
    "padding": "the {noun} is spaced so that part of it could sit out of view in the confirmation (more than "
               "16 spaces in a row inside a line, a line indented more than 32 spaces, more than 3 blank lines "
               "in a row, or a line over 2000 characters); a confirmation shows a {noun} only when it is "
               "written without the padding",
    "not_showable": "the {noun} cannot be shown in full and exactly as it runs",
    "redacted": "the {noun} contains what looks like a secret (a key, token or password), and a confirmation "
                "shows exactly what runs, so it cannot be shown; reference secrets through environment "
                "variables or the vault, never inline in the {noun}",
    # Never "ask you again": a blocked forced operation is not to be retried by the agent.
    "no_capable_client": "none of the person's apps that can use their passkey for this gateway is attached to "
                         "this conversation",
    "error": "the confirmation could not be requested",
    # Never "plain remains available" (the tool's sentence for a voluntary request): a rule has no fallback.
    "disabled": "passkey confirmations are switched off on this gateway (confirm.passkey.enabled), so none can "
                "be asked; the rule still applies",
}


def _why(reason: str, noun: str, limit: int) -> str:
    if reason in _WHY:
        return _WHY[reason].format(noun=noun, limit=limit)
    missing = ""
    try:
        from tools.confirm_tool import _PASSKEY_MISSING
        missing = _PASSKEY_MISSING.get(reason, "")
    except Exception:  # noqa: BLE001
        pass
    head = f"none was obtained (reason: {reason})"
    return f"{head}. {missing.rstrip('.')}" if missing else head


def block_message(forced: Forced, noun: str) -> str:
    """The text the agent gets for a forced confirmation that did not end in consent. Every ending says
    "do NOT retry it" except ``padding``: there nothing was shown to the person, and the same operation
    written without the extra whitespace is a new forced confirmation, shown in full and signed with a
    passkey like any other, so resubmitting it compactly costs the rule nothing. The padded form itself
    is never to be sent again."""
    if forced.outcome == "declined":
        return (f"BLOCKED: the person declined this {noun} in the passkey confirmation. The user has NOT "
                f"consented. Do NOT retry it, do NOT rephrase it, and do NOT reach the same outcome another way.")
    if forced.outcome == "blocked" and forced.reason == "padding" and forced.before_asking:
        return (f"BLOCKED: this gateway's operator requires a passkey confirmation in the Hermie app for this "
                f"{noun}, and {_why(forced.reason, noun, forced.limit)}. It did not run and nothing was shown to "
                f"the person; this is not consent. Submit the same {noun} once more without the extra whitespace: "
                f"at most 16 spaces in a row inside a line, at most 32 spaces of indentation and at most 3 blank "
                f"lines in a row. Do NOT send "
                f"the padded form again, do NOT change what the {noun} does, and do NOT reach the same effect "
                f"another way. The person then confirms the {noun} as written, with their passkey.")
    return (f"BLOCKED: this gateway's operator requires a passkey confirmation in the Hermie app for this "
            f"{noun}, and {_why(forced.reason, noun, forced.limit)}. It did not run. This is not consent: do "
            f"NOT retry it, do NOT rephrase it, and do NOT reach the same effect another way; an ordinary "
            f"approval cannot replace it. Tell the person that a passkey confirmation in the Hermie app is "
            f"required for this {noun}.")


def user_summary(forced: Forced, noun: str) -> str:
    """One line for the person, shown before the agent's text."""
    if forced.outcome == "declined":
        return f"You declined this {noun} — it did not run."
    if forced.reason == "timeout":
        return f"No passkey confirmation within 2 minutes — the {noun} did not run."
    return f"This {noun} needs a passkey confirmation in the Hermie app — it did not run."


def _approval_result(forced: Forced, *, kind: str, pattern_key: str, description: str) -> dict:
    """The gate result shape (``tools.approval``) for a forced confirmation."""
    if forced.outcome == "confirmed":
        return {"approved": True, "message": None, "user_approved": True, "passkey_confirmed": True,
                "description": description}
    noun = NOUNS[kind]
    outcome = "denied" if forced.outcome == "declined" else "timeout" if forced.reason == "timeout" else "blocked"
    return {"approved": False, "message": block_message(forced, noun), "pattern_key": pattern_key,
            "description": description, "outcome": outcome, "user_consent": False,
            "user_summary": user_summary(forced, noun), "passkey_required": True,
            **({"passkey_reason": forced.reason} if forced.reason else {})}


# ── the desktop terminal batch: decided once per prepared call ───────────────────────────────────────
# The desktop's terminal batch runs every command guard once to prepare the approvals and again when the
# command runs (``agent/terminal_approval_batch.py``), on the same slot. The WHOLE outcome of the first
# pass (confirmed, declined, blocked) is kept on that slot, for exactly that command text, and the run pass
# takes it instead of asking again: a decline is not asked twice, and a confirmation lives exactly as long
# as its batch (a stopped batch takes it with it; the same call in a later batch asks again).

_SLOT_ATTR = "passkey_forced"


def _batch_slot() -> Any:
    try:
        from agent.terminal_approval_batch import _slot
        return _slot.get()
    except Exception:  # noqa: BLE001
        return None


def _digest(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8", "surrogatepass")).hexdigest()


def _keep_prepared(command: str, forced: Forced) -> None:
    slot = _batch_slot()
    if slot is not None and getattr(slot, "preparing", False):
        setattr(slot, _SLOT_ATTR, (_digest(command), forced))


def _take_prepared(command: str) -> Forced | None:
    slot = _batch_slot()
    if slot is None or getattr(slot, "preparing", False):
        return None
    kept = getattr(slot, _SLOT_ATTR, None)
    setattr(slot, _SLOT_ATTR, None)  # single use, whatever it held
    if not kept or kept[0] != _digest(command):
        return None
    return kept[1]


# ── where a command runs ─────────────────────────────────────────────────────────────────────────────

_command_cwd: contextvars.ContextVar[str | None] = contextvars.ContextVar("passkey_policy_command_cwd",
                                                                           default=None)
_BATCH_CWD = "the directory the session is in when the command's turn in the batch comes"


@contextlib.contextmanager
def command_cwd(cwd: str | None):
    """Bind the directory the guarded command runs in (the terminal tool, the Codex exec request), so a
    forced confirmation's summary can say where."""
    token = _command_cwd.set(str(cwd) if cwd else None)
    try:
        yield
    finally:
        _command_cwd.reset(token)


def _where() -> str:
    """Where the command runs, as far as it is known now: the bound directory, or in the desktop batch's
    prepare pass the call's own ``workdir`` (the session's directory can still change before it runs)."""
    if cwd := _command_cwd.get():
        return cwd
    slot = _batch_slot()
    if slot is not None and getattr(slot, "preparing", False):
        args = getattr(slot, "args", None)
        workdir = args.get("workdir") if isinstance(args, dict) else None
        return str(workdir) if workdir else _BATCH_CWD
    return ""


# ── the security scanner on a floor match ────────────────────────────────────────────────────────────


def _scan(command: str) -> tuple[str, str]:
    """``(action, description)`` of the guardian scan (tirith) the command gate runs, with the gate's own
    fail-open / fail-closed handling (``tools.approval._tirith_scan``)."""
    from tools import approval
    result = approval._tirith_scan(command)
    action = str(result.get("action") or "allow")
    if action in ("block", "warn"):
        return action, approval._format_tirith_description(result)
    return "allow", ""


# ── the three call sites ──────────────────────────────────────────────────────────────────────────────


def command_floor(command: str) -> dict | None:
    """The floor of every command guard (``tools.approval._user_deny_block``): None when no rule applies,
    else the gate result of a forced confirmation (approved only when the person confirmed it with a
    passkey). Never raises once a rule matched: any failure blocks."""
    try:
        match = match_command(command)
    except Exception:  # noqa: BLE001 - parity with approvals.deny: an unreadable rule set is no rule
        logger.warning("passkey policy: command rules could not be evaluated", exc_info=True)
        return None
    if match is None:
        return None
    description = match.description or "Run a command this gateway's operator requires a passkey for."
    try:
        logger.warning("Passkey rule %s:%r requires a confirmation for command: %s", match.rule, match.pattern,
                       command[:200])
        prepared = _take_prepared(command)
        if prepared is not None:
            return _approval_result(prepared, kind="command", pattern_key=match.pattern, description=description)
        # The summary the person sees: where, what, and the scanner's findings; the gate result keeps the
        # plain description.
        where = _where()
        summary = f"In {where}: {description}" if where else description
        action, findings = _scan(command)
        if action == "block":
            # A scanner block is not something a person's confirmation can lift.
            forced = Forced("blocked", "scanner_block")
            _audit(match, "command", _session_key(), forced)
            return _scanner_block(findings, pattern_key=match.pattern, description=description)
        if findings:
            summary = f"{summary}; {findings}"
        forced = _force(match, kind="command", description=summary, detail=command)
        _keep_prepared(command, forced)
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: command floor failed", exc_info=True)
        forced = Forced("blocked", "error")
    return _approval_result(forced, kind="command", pattern_key=match.pattern, description=description)


def _scanner_block(findings: str, *, pattern_key: str, description: str) -> dict:
    message = (f"BLOCKED: the security scan blocked this command ({findings}). A passkey confirmation cannot "
               "lift a scanner block. Do NOT retry it, do NOT rephrase it, and do NOT reach the same effect "
               "another way.")
    return {"approved": False, "message": message, "pattern_key": pattern_key, "description": description,
            "outcome": "blocked", "user_consent": False,
            "user_summary": "The security scan blocked this command — it did not run.", "passkey_required": True,
            "passkey_reason": "scanner_block"}


def human_decision(*, noun: str, command: str, description: str, pattern_key: str,
                   smart_denied: bool) -> dict | None:
    """Where ``tools.approval._human_decision`` would ask a person: None to ask as before, else the result
    of a forced confirmation in its place (``smart_denied`` for a guardian DENY the owner could override,
    ``approvals`` for any approval of the command and ``execute_code`` gates). *noun* is the gate's."""
    kind = {"command": "command", "code": "code"}.get(noun)
    try:
        rules = require()
        if smart_denied and rules.smart_denied:
            match = Match("smart_denied", pattern_key, description)
        elif rules.approvals and kind is not None:
            match = Match("approvals", pattern_key, description)
        else:
            return None
    except Exception:  # noqa: BLE001 - parity with approvals.deny
        logger.warning("passkey policy: approval rules could not be evaluated", exc_info=True)
        return None
    kind = kind or "tool"
    try:
        forced = _force(match, kind=kind, description=description, detail=command)
        if forced.outcome == "confirmed" and smart_denied:
            from tools import approval
            approval._reset_denials(_session_key())  # a person's override, like an ordinary one
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: forced approval failed", exc_info=True)
        forced = Forced("blocked", "error")
    return _approval_result(forced, kind=kind, pattern_key=pattern_key, description=description)


def _tool_detail(tool_name: str, args: Any) -> str:
    body = args if isinstance(args, dict) else {}
    # Raises when the arguments cannot be serialised: the caller blocks (never a placeholder to sign).
    text = json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    if hidden_characters(text):
        # Escaped (\\uXXXX) rather than refused: the arguments stay readable and nothing is hidden.
        text = json.dumps(body, ensure_ascii=True, indent=2, sort_keys=True, default=str)
    return f"{tool_name}\n{text}"


def tool_call_block(tool_name: str, args: Any = None) -> str | None:
    """At tool dispatch, after the plugin hooks: None to proceed, else the block message. A ``tools``
    match proceeds only when the person confirmed this call with a passkey."""
    try:
        match = match_tool(tool_name)
    except Exception:  # noqa: BLE001 - parity with approvals.deny
        logger.warning("passkey policy: tool rules could not be evaluated", exc_info=True)
        return None
    if match is None:
        return None
    try:
        forced = _force(match, kind="tool", description=f"Use the tool {tool_name}.",
                        detail=_tool_detail(tool_name, args), tool=str(tool_name))
    except Exception:  # noqa: BLE001 - fail closed
        logger.warning("passkey policy: forced tool confirmation failed", exc_info=True)
        forced = Forced("blocked", "error")
    if forced.outcome == "confirmed":
        return None
    return block_message(forced, NOUNS["tool"])


__all__ = ["Forced", "Match", "NotShowable", "RULES", "block_message", "command_floor", "forced_text",
           "hidden_characters", "human_decision", "match_command", "match_command_globs", "match_tool", "padded",
           "register_strong_confirm", "require", "strong_confirm_callback", "tool_call_block",
           "unregister_strong_confirm", "user_summary"]
