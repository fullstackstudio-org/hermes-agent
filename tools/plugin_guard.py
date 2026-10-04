#!/usr/bin/env python3
"""Plugin Guard — ``skills_guard`` engine applied to ``hermes plugins install``/``update``.

Plugins run in-process but are *expected* to read their own env keys, call provider APIs
and spawn subprocesses, so: full pattern set on docs/config files (where prompt-injection
lives); the "reads own secret"/"HTTP call with key" family exempt on *code* files;
plugin-sized structural limits; VCS/venv noise skipped. ``safe`` installs, ``caution``
needs confirmation, ``dangerous`` is blocked and ``--force`` does NOT override.
"""

from __future__ import annotations

import ast
import importlib.machinery as _machinery
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

from tools.plugin_guard_code import (
    PYTHON_SOURCE_EXTENSIONS, ROUTE_PATTERN_IDS, ModuleRefs, module_refs, python_code_findings)
from tools.plugin_guard_context import (
    STEP_DOWN, is_agent_facing, is_base64_media, is_ci_workflow, is_data_decode, is_doc_prose,
    JsSinkInventory, is_inert_fixture_line, is_loopback_only, is_pip_install_in_prose_literal,
    is_regex_alternation_token, is_self_uninstall_doc, is_test_tree, prose_cap)
from tools.skills_guard import (
    Finding, ScanResult, SCANNABLE_EXTENSIONS, SUSPICIOUS_BINARY_EXTENSIONS, SourceText, _determine_verdict,
    decode_python_source, format_scan_report, read_source_text, scan_text)

PLUGIN_SCANNER_VERSION = "plugin-guard-fork-15"

# Caches and vendored environments a checkout makes for itself. Skipped only when nothing in
# them is tracked by git: a TRACKED ``venv/evil.py`` or ``__pycache__/x.pyc`` ships with the
# plugin and is importable (``from .venv import evil``), so it is scanned like any other file.
# A tree that is not a git checkout cannot say what it ships, so there they are scanned too.
# ``.git`` itself is never scanned. (HERM-196.)
EXCLUDED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox"}

# Compiled Python bytecode. ``helper.pyc`` beside ``__init__.py`` is imported by
# ``from . import helper`` with no ``helper.py`` at all, and an unchecked-hash
# ``__pycache__/x.cpython-3XX.pyc`` is imported in place of a harmless ``x.py``: code that runs
# and that no text scan can read. Any bytecode in a plugin tree is ``dangerous``.
BYTECODE_EXTENSIONS = {".pyc", ".pyo"}
# Native extension modules: a file Python imports as compiled code (``helper.cpython-311-darwin.so``,
# ``helper.abi3.so``, ``helper.so``, ``helper.pyd``). In a plugin that holds Python source it is
# importable and unreadable, so it is ``dangerous`` like bytecode. The suffixes of every platform
# count, not only this interpreter's, so a scan on macOS judges a Linux or Windows tree the same.
NATIVE_EXTENSION_SUFFIXES = tuple(sorted(set(_machinery.EXTENSION_SUFFIXES) | {".so", ".pyd"}, key=len, reverse=True))
# Archives Python can import from (zipimport, a wheel or egg on sys.path, a zipapp): unreadable to
# a text scan, so at least a binary finding. A zip is importable whatever it is called (``logo.png``
# on sys.path imports as well as ``deps.zip``), so every file is also checked for a zip signature
# (``_archive_findings``).
ARCHIVE_EXTENSIONS = {".zip", ".whl", ".egg", ".pyz"}
EXTRA_BINARY_EXTENSIONS = {".pyd"} | ARCHIVE_EXTENSIONS

# Test trees ARE scanned (``plugins_loader`` sets ``submodule_search_locations`` to the
# plugin root, so ``from .tests import evil`` runs whatever lives there), but findings under
# them step down one severity (``plugin_guard_context.is_test_tree``): fixtures deliberately
# hold hostile strings to prove the plugin rejects them, and an un-overridable ``dangerous``
# made such plugins uninstallable and taught authors to obfuscate their own tests (#89610).

# Code files, where "reads an env secret" / "HTTP call with a key" is normal (requires_env).
CODE_FILE_EXTENSIONS = {".py", ".pyw", ".js", ".ts", ".sh", ".bash", ".rb", ".pl", ".php",
                        ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts", ".vue", ".svelte"}

# Line-comment marker per code extension. Whole-line comments explain intent; hardening
# notes like "# a symlink could point at /etc/passwd" are prose *about* a defense.
COMMENT_PREFIXES_BY_EXTENSION = {
    ".py": "#", ".pyw": "#", ".sh": "#", ".bash": "#", ".rb": "#", ".pl": "#", ".r": "#", ".jl": "#",
    ".js": "//", ".ts": "//", ".php": "//", ".mjs": "//", ".cjs": "//", ".jsx": "//", ".tsx": "//",
    ".mts": "//", ".cts": "//", ".vue": "//", ".svelte": "//"}

# A file whose name says nothing (``bin/tool``, ``hooks/pre-commit``) is read as the language its
# shebang names, so a script is judged as code like its ``.py``/``.sh`` twin (HERM-195).
SHEBANG_SUFFIXES = {"python": ".py", "sh": ".sh", "bash": ".sh", "zsh": ".sh", "dash": ".sh", "ksh": ".sh",
                    "node": ".js", "deno": ".ts", "bun": ".js", "ruby": ".rb", "perl": ".pl", "php": ".php"}
_SHEBANG = re.compile(r"#!\s*(?:/usr/bin/env\s+(?:-\S+\s+)*)?(?:\S*/)?([A-Za-z]+)")

# One severity step down from the pattern's default.
_COMMENT_SEVERITY_CAP = {"critical": "high", "high": "medium"}

# History, not an agent-facing instruction surface: a hardening entry mentioning the threat
# it fixed ("A symlink could point at /etc/passwd, so ...") is documentation, not the attack.
CHANGELOG_FILENAMES = {"changelog.md"}

# Pattern ids exempt on code files (every legitimate provider plugin trips them); still
# applied in full to docs/config files.
CODE_EXEMPT_PATTERN_IDS = {
    "python_environ_get_secret", "python_getenv_secret", "python_os_environ", "node_process_env",
    "ruby_env_secret", "env_exfil_httpx", "env_exfil_requests", "env_exfil_fetch",
    "env_exfil_curl", "env_exfil_wget",
    # Agent-facing instruction patterns are meaningless inside code (prompt docstrings trip them).
    "context_exfil", "send_to_url", "fake_policy",
    # Plugins legitimately write config.yaml in post_setup and base64 credentials (Basic auth).
    "agent_config_mod", "agent_config_contract", "encoded_exfil"}

# Severity remaps: a bundled binary is warn-tier (repos occasionally vendor one); a mere
# ``~/.hermes/.env`` mention is how READMEs say where keys go (READING it still trips
# ``read_secrets_file``, critical); ``curl | sh`` in READMEs is caution, not a hard block.
SEVERITY_REMAP = {
    "binary_file": "high", "hermes_env_access": "medium", "curl_pipe_shell": "high"}

# In JS/TS, these text matches cannot distinguish a UI label or DNS lookup
# template from a write or exfiltration operation. Keep them visible and require
# confirmation; do not silently allow them. Shell commands and instructions keep
# their critical severity, as do separate credential-read/exfiltration findings.
JS_CAPABILITY_REMAP = {"dns_exfil": "high", "ssh_backdoor": "high"}

# Plugin scans gate a HOST install: what matters is what executes on the host. Two critical
# families describe the author's own dev workflow when they appear in documentation files, so
# they land at high (caution) there instead of hard-blocking an otherwise auditable plugin; the
# same content in runtime code keeps its critical severity. The generic one-step prose cap for
# command/path-shaped findings lives in ``plugin_guard_context`` (``DOC_PROSE_EXTENSIONS``).
DOC_PROSE_DEMOTIONS = {
    # Prose modification bullets ("- Modify: `CLAUDE.md`") in plan/design docs describe the
    # repo's own files; only executable intent (shell writes, code) stays critical.
    "agent_config_mod": "high",
    # Example/demo credentials quoted in docs (placeholder hex, test tokens). Real token-shaped
    # literals (sk-, ghp_, AKIA, glpat-, private keys) keep their own critical patterns.
    "hardcoded_secret": "high",
}

# A root-level ``if __name__ == "__main__":`` block is the module's own self-test harness:
# ``plugins_loader`` imports plugins and never runs them as scripts, so a sample credential
# quoted there is a fixture, not a shipped secret — the test-tree reasoning applied where a
# root-level runtime file has no ``tests/`` to hold it (#112139). Narrower than the
# test-tree cap because the block is still directly executable code: only the generic
# sample-token pattern is demoted; destructive/persistence/exfil findings and the
# provider-signature patterns (``sk-``, ``AKIA``, ``ghp_`` ...) keep full severity there.
MAIN_GUARD_DEMOTIONS = {"hardcoded_secret": "high"}

# Structural limits — plugins are real codebases, far larger than skills.
MAX_PLUGIN_FILE_COUNT = 400
MAX_PLUGIN_TOTAL_SIZE_KB = 10 * 1024   # 10MB of scannable tree
MAX_PLUGIN_SINGLE_FILE_KB = 1024       # 1MB single file


def _tracked_paths(plugin_dir: Path) -> Optional[set]:
    """The paths under *plugin_dir* that git tracks, relative to it, or ``None`` when *plugin_dir*
    is not a checkout of the plugin: no git, not inside a work tree, a repository git refuses, or a
    work tree that is not *plugin_dir* itself and tracks nothing under it.
    Run with no global/system config, no hooks and no fsmonitor, and without any inherited
    repository redirection, so the tree cannot make git do anything but list files."""
    import subprocess

    git = shutil.which("git")
    if not git or not plugin_dir.is_dir():
        return None
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    base = [git, "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "core.quotePath=false"]
    try:
        top = subprocess.run(base + ["rev-parse", "--show-toplevel"], cwd=str(plugin_dir), env=env,
                             capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        if top.returncode != 0 or not top.stdout.strip():
            return None
        listed = subprocess.run(base + ["ls-files", "-z", "--cached"], cwd=str(plugin_dir), env=env,
                                capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        return None
    tracked = {os.fsdecode(p) for p in listed.stdout.split(b"\0") if p}
    try:
        is_top = Path(os.fsdecode(top.stdout.strip())).resolve() == plugin_dir.resolve()
    except OSError:
        is_top = False
    # A plugin dir inside some other repository that tracks nothing of it (a home-directory
    # dotfiles repo, a parent project) is not a checkout of the plugin: "untracked" would then
    # hide everything in its venv/ or __pycache__/. Scan it fully instead.
    return tracked if (is_top or tracked) else None


def _walk(plugin_dir: Path, tracked: Optional[set] = None, *, know_tracked: bool = False) -> Iterator[Tuple[Path, str]]:
    """Yield (path, "a/b/c" relative path) for every entry under plugin_dir the scan reads.

    ``.git`` is not read (in a tree that is not a checkout, only the top-level one is skipped). An
    entry inside another of ``EXCLUDED_DIRS`` is read when git tracks it
    (or it holds a tracked path), or when the tree is not a git checkout (*tracked* is None);
    *know_tracked* False asks git here."""
    if not know_tracked:
        tracked = _tracked_paths(plugin_dir)
    tracked_dirs = set()
    if tracked is not None:
        for path in tracked:
            parts = path.split("/")
            tracked_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    for f in plugin_dir.rglob("*"):
        try:
            rel_parts = f.relative_to(plugin_dir).parts
        except ValueError:
            continue
        # A checkout cannot ship anything inside a .git directory (git refuses such paths), so there
        # every .git is skipped; a tree that is not a checkout skips only its own top-level .git.
        if (".git" in rel_parts) if tracked is not None else (rel_parts[:1] == (".git",)):
            continue
        rel = "/".join(rel_parts)
        if any(part in EXCLUDED_DIRS for part in rel_parts) and tracked is not None \
                and rel not in tracked and rel not in tracked_dirs:
            continue
        yield f, rel


def _code_suffix(file_path: Path) -> str:
    """The extension *file_path* is judged by: its own when it has a known one, otherwise the one its
    shebang names, otherwise its own (possibly empty)."""
    suffix = file_path.suffix.lower()
    if suffix in SCANNABLE_EXTENSIONS or suffix in CODE_FILE_EXTENSIONS:
        return suffix
    try:
        with open(file_path, "rb") as handle:
            first = handle.readline(256).decode("utf-8", "replace")
    except OSError:
        return suffix
    match = _SHEBANG.match(first)
    if match:
        interpreter = re.sub(r"[\d.]+$", "", match.group(1).lower())
        return SHEBANG_SUFFIXES.get(interpreter, suffix)
    return suffix


def _finding(pattern_id: str, severity: str, category: str, file: str, match: str, description: str) -> Finding:
    return Finding(pattern_id, severity, category, file, 0, match, description)


def _is_main_guard(node: ast.If) -> bool:
    """Return whether an ``if`` node is the conventional module self-test guard."""
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    if len(test.comparators) != 1:
        return False
    left, right = test.left, test.comparators[0]
    return (
        isinstance(left, ast.Name) and left.id == "__name__"
        and isinstance(right, ast.Constant) and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name) and right.id == "__name__"
        and isinstance(left, ast.Constant) and left.value == "__main__"
    )


def _main_guard_body_lines(text: str) -> set[int]:
    """Return lines executed only by ``if __name__ == '__main__'`` blocks.

    Invalid Python deliberately returns no lines so its findings retain the
    conservative severity.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):  # ValueError: NUL bytes
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not _is_main_guard(node):
            continue
        for statement in node.body:
            lines.update(range(statement.lineno, getattr(statement, "end_lineno", statement.lineno) + 1))
    return lines


def _filter_findings(findings: List[Finding], rel_path: str, file_path: Path,
                     js: Optional[JsSinkInventory] = None, *, parsed_python: bool = False,
                     text: Optional[str] = None, from_ast: bool = False, unreached: bool = False) -> List[Finding]:
    """Apply plugin-specific exemptions and severity remaps to raw findings. *js* is the scan's
    JavaScript inventory (``plugin_guard_context`` (5b)); without it no JS token rule applies.
    *parsed_python*: the findings come from parsing the file as Python, so it is code whatever its
    name (a ``notes.txt`` a loader runs is not documentation). *text*: the file as the scan decoded
    it (read here as UTF-8 when not given). *from_ast*: the findings come from the parsed code
    itself, so no comment heuristic applies to them. *unreached*: the file is test or script code
    that nothing the plugin runs imports (``_unreached_dev_files``)."""
    if not findings:
        return []
    suffix = ".py" if parsed_python else _code_suffix(file_path)
    is_code = suffix in CODE_FILE_EXTENSIONS
    if text is None:
        text = "\n".join(_file_lines(file_path))
    main_guard_lines: Optional[set] = None
    comment_lines: Optional[set] = None
    is_js = suffix in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
    # A CI workflow definition runs on the forge's runner, not the host: same cap as a README.
    doc_prose = not parsed_python and (is_doc_prose(rel_path) or is_ci_workflow(rel_path))
    lines = text.split("\n")
    out: List[Finding] = []
    for f in findings:
        if is_code and f.pattern_id in CODE_EXEMPT_PATTERN_IDS:
            continue
        f.severity = (
            (JS_CAPABILITY_REMAP.get(f.pattern_id) if is_js else None)
            or SEVERITY_REMAP.get(f.pattern_id) or f.severity
        )
        if doc_prose and f.pattern_id in DOC_PROSE_DEMOTIONS:
            f.severity = DOC_PROSE_DEMOTIONS[f.pattern_id]
        line = lines[f.line - 1] if 0 < f.line <= len(lines) else f.match
        js_data = js is not None and js.js_data(f, rel_path, f.line, line)
        f.severity = _context_severity(f, rel_path, line, doc_prose, is_code, js_data, unreached)
        if not from_ast and _is_defensive_documentation(f, rel_path, suffix):
            # In Python, "a line that starts with #" is a comment only when the tokenizer says so:
            # ``a = """`` / ``# """; exec(src)`` starts with # inside a string and runs.
            if parsed_python and comment_lines is None:
                comment_lines = _python_comment_lines(text)
            if not parsed_python or f.line in comment_lines:
                f.severity = _comment_severity(f)
        # Last and critical-only: a one-step cap that can never re-raise a finding an
        # earlier remap already lowered.
        if f.pattern_id in MAIN_GUARD_DEMOTIONS and f.severity == "critical" \
                and suffix in PYTHON_SOURCE_EXTENSIONS:
            if main_guard_lines is None:     # parsed only when a finding needs it
                main_guard_lines = _main_guard_body_lines(text)
            if f.line in main_guard_lines:
                f.severity = MAIN_GUARD_DEMOTIONS[f.pattern_id]
        out.append(f)
    return out


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _at_most(severity: str, cap: str) -> str:
    """Lower *severity* to *cap*; never raise it."""
    return cap if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK[cap] else severity


def _comment_severity(f: Finding) -> str:
    """A whole-line comment / changelog entry cannot execute: one step down for every finding,
    a second for command/path shapes (a comment is prose); agent-facing shapes keep one step."""
    sev = _COMMENT_SEVERITY_CAP.get(f.severity, f.severity)
    return sev if is_agent_facing(f) else STEP_DOWN.get(sev, sev)


def _file_lines(file_path: Path) -> List[str]:
    """Full source lines (``Finding.match`` is truncated to 120 chars); unreadable → []."""
    try:
        return file_path.read_text(encoding="utf-8").split("\n")
    except (OSError, UnicodeDecodeError):
        return []


def _context_severity(f: Finding, rel_path: str, line: str, doc_prose: bool, is_code: bool,
                      js_data: bool = False, unreached: bool = False) -> str:
    """Severity after the inert-context demotions (``plugin_guard_context``). Each rule only
    ever lowers, and every finding stays in the report; the order runs from the broadest
    context (where the text lives) to the narrowest (what the token sits inside)."""
    sev = f.severity
    if f.pattern_id in ROUTE_IDS:
        # A route by which code runs unread steps down only in test code nothing the plugin runs
        # can import: a file NAMED like a test is no reason (``from .tests import x``).
        return STEP_DOWN.get(sev, sev) if unreached else sev
    if doc_prose:
        sev = prose_cap(f) or sev
        if is_self_uninstall_doc(f, line):
            sev = _at_most(sev, "medium")
    if unreached:          # test code nothing the plugin runs can import (``_unreached_dev_files``)
        # A key-shaped literal or quoted-only hostile string in a fixture is the corpus the
        # plugin's own tests reject (#89610): a note. Executable test code steps down once.
        inert = f.category == "credential_exposure" or is_inert_fixture_line(f, line, is_code)
        sev = _at_most(sev, "medium") if inert else STEP_DOWN.get(sev, sev)
    if f.pattern_id == "encoded_exfil" and is_base64_media(line):
        sev = "low"
    if is_code and is_regex_alternation_token(f, line):
        sev = STEP_DOWN.get(sev, sev)
    if f.pattern_id == "base64_decode_pipe" and is_data_decode(line):
        sev = STEP_DOWN.get(sev, sev)
    if is_loopback_only(f, line):
        sev = "low"    # 127.0.0.0/8 is a local service, not egress
    if is_code and is_pip_install_in_prose_literal(f, line):
        sev = "low"    # "no pip install is needed" in a user-facing message
    if js_data:
        sev = _at_most(sev, "low")    # `case"sudo":`, `/re/.exec("")`: data (context (5b))
    return sev


def _python_prose_lines(text: str) -> Optional[set]:
    """Lines of Python *text* that hold only a docstring or the inside of a multi-line string
    literal (prose), by the AST: a line where any other code starts or ends is not prose, so
    ``# \"\"\"; exec(src)`` closing a string is scanned. None when the text does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    statements = {node.value for node in ast.walk(tree) if isinstance(node, ast.Expr)}
    strings = [node for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
               and (node in statements or getattr(node, "end_lineno", node.lineno) > node.lineno)]
    if not strings:
        return set()
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    exempt = set()
    for node in strings:
        exempt.add(node)
        up = parents.get(node)
        while up is not None:
            exempt.add(up)
            up = parents.get(up)
    for node in ast.walk(tree):      # the name a string is assigned to is not code that runs
        if isinstance(getattr(node, "ctx", None), ast.Store):
            exempt.update(ast.walk(node))
    code = set()
    for node in ast.walk(tree):
        if node not in exempt and hasattr(node, "lineno") and not isinstance(node, ast.JoinedStr):
            code.add(node.lineno)
            code.add(getattr(node, "end_lineno", node.lineno))
    prose = set()
    for node in strings:
        prose.update(range(node.lineno, node.end_lineno + 1))
    return prose - code


def _python_comment_lines(text: str) -> set:
    """Lines whose first token is a comment, by the tokenizer (so ``#`` inside a string is not)."""
    import io
    import tokenize

    lines: set = set()
    seen: set = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            row = token.start[0]
            if token.type in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING):
                continue
            if row not in seen:
                seen.add(row)
                if token.type == tokenize.COMMENT:
                    lines.add(row)
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return lines


# Manifests whose strings can name a file the plugin runs (``hooks``, a dashboard ``api`` entry).
_MANIFEST_NAMES = {"plugin.yaml", "plugin.yml", "manifest.json", "plugin.json"}
ROUTE_IDS = ROUTE_PATTERN_IDS | {"source_encoding", "undecodable_source"}


def _module_parts(rel: str) -> Tuple[str, ...]:
    parts = rel.split("/")
    parts[-1] = parts[-1].rsplit(".", 1)[0]
    return tuple(parts[:-1]) if parts[-1] == "__init__" else tuple(parts)


def _name_parts(value: str) -> set:
    return set(re.split(r"[./\\:]+", value))


def _manifest_strings(text: str) -> set:
    """Every scalar in a YAML or JSON manifest, quotes and punctuation stripped (``{"api":
    "test_api.py"}`` yields ``test_api.py``). A token reading, not a parser: it can only find more."""
    return {token for token in re.split(r"[\s:,\[\]{}\"'#=|>]+", text) if token}


def _unreached_dev_files(refs: dict, manifest_strings: set, other_files: Iterable[str] = ()) -> Tuple[set, bool]:
    """The test files (``is_test_tree``) that nothing the plugin runs can import, and whether the
    analysis ran at all (False: too many files; then nothing is unreached).

    *refs* maps every Python file to its ``ModuleRefs`` (None: it does not parse); *other_files* are
    the plugin's other files (a fixture a loader is pointed at is reached too). Starting from
    the files that are not test code, a file is reached by a relative import of it or a package
    above it, an absolute import containing its module path, a path a loader or a process is given,
    or a string constant (or a manifest scalar) holding its name; reached files reach on. If any
    reached file does not parse, or imports, loads or runs something that is not one complete
    constant, every test file counts as reached: nothing steps down."""
    if len(refs) > MAX_PLUGIN_FILE_COUNT:
        return set(), False
    dev = {rel for rel in list(refs) + list(other_files) if is_test_tree(rel)}
    if not dev:
        return set(), True
    modules = {rel: _module_parts(rel) for rel in set(refs) | dev}
    by_module = {mod: rel for rel, mod in modules.items()}
    dev_by_module = {modules[rel]: rel for rel in dev if modules[rel]}
    dev_by_stem: dict = {}
    for rel in dev:
        if modules[rel]:
            dev_by_stem.setdefault(modules[rel][-1], set()).add(rel)
    reached: set = set()
    queue = [rel for rel in refs if rel not in dev]

    def reach(rel: Optional[str]) -> None:
        if rel is not None and rel in dev and rel not in reached:
            reached.add(rel)
            queue.append(rel)

    def reach_by_strings(strings: set) -> None:
        for value in strings:
            for part in _name_parts(value):
                for rel in dev_by_stem.get(part, ()):
                    reach(rel)

    reach_by_strings(manifest_strings)
    while queue:
        rel = queue.pop()
        if rel not in refs:
            continue          # a non-Python file: reached, and it imports nothing
        found: Optional[ModuleRefs] = refs[rel]
        if found is None or found.dynamic:
            return set(), True
        package = modules[rel] if rel.endswith(("/__init__.py", "/__init__.pyw")) or rel in (
            "__init__.py", "__init__.pyw") else modules[rel][:-1]
        targets = []
        for level, module, names in found.relative:
            if level - 1 > len(package):
                continue
            base = package[:len(package) - (level - 1)] + tuple(module)
            targets.append(base)
            targets.extend(base + (name,) for name in names)
        for target in targets:
            for k in range(1, len(target) + 1):
                reach(by_module.get(target[:k]))
        for parts in found.absolute:
            for i in range(len(parts)):
                for j in range(i + 1, len(parts) + 1):
                    reach(dev_by_module.get(tuple(parts[i:j])))
        for path in found.paths:
            reach(path)
            reach(by_module.get(_module_parts(path)) if path.endswith((".py", ".pyw")) else None)
        reach_by_strings(found.strings)
    return dev - reached, True


def _package_names(sources: dict) -> dict:
    """The names each package's ``__init__.py`` defines at MODULE level, by package directory: what
    ``from . import name`` can find without a module file. Not a name bound inside a function or
    class, under ``if False:``/``if TYPE_CHECKING:``, in an ``except`` handler (``_speedups =
    None``), by ``from . import name`` itself, or by a ``name = None`` placeholder."""
    out: dict = {}
    for rel, source in sources.items():
        if source is None or rel.rsplit("/", 1)[-1] not in ("__init__.py", "__init__.pyw"):
            continue
        try:
            tree = ast.parse(source.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        names: set = set()
        _module_level_names(tree.body, names)
        out[rel.rsplit("/", 1)[0] if "/" in rel else ""] = names
    return out


def _never_runs(test: ast.AST) -> bool:
    """An ``if`` test that is false when the module runs: a false constant, or TYPE_CHECKING."""
    if isinstance(test, ast.Constant):
        return not test.value
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _module_level_names(body: list, names: set) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if node.value is None or (isinstance(node.value, ast.Constant) and node.value.value is None):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                names.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
        elif isinstance(node, ast.Import):
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if not (node.level == 1 and not node.module):
                names.update(a.asname or a.name for a in node.names)
        elif isinstance(node, ast.If):
            if not _never_runs(node.test):
                _module_level_names(node.body, names)
            if not (isinstance(node.test, ast.Constant) and node.test.value):
                _module_level_names(node.orelse, names)
        elif isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
            _module_level_names(node.body + node.orelse + node.finalbody, names)
        elif isinstance(node, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
            _module_level_names(node.body, names)


def _is_defensive_documentation(finding: Finding, rel_path: str, suffix: str = "") -> bool:
    """A whole-line code comment or a changelog entry *describes* threats (the attack a
    defense rejects, the hardening a release shipped) instead of executing them, so its
    findings cap one severity step lower — visible and reviewable, never un-overridable
    ``dangerous`` from prose alone. Runtime code and agent-facing docs keep full severity.
    """
    if Path(rel_path).name.lower() in CHANGELOG_FILENAMES:
        return True
    prefix = COMMENT_PREFIXES_BY_EXTENSION.get(suffix or Path(rel_path).suffix.lower())
    if prefix is None or not finding.match:
        return False
    stripped = finding.match.lstrip()
    if not stripped.startswith(prefix):
        return False
    if prefix == "#" and stripped.startswith(("#!", "#:")):
        return False
    return True


_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_ZIP_END_OF_DIRECTORY = b"PK\x05\x06"
_ZIP_TAIL = 22 + 0xFFFF          # the end record plus the longest archive comment
_ARCHIVE_IMPORTABLE = (".py", ".pyc", ".pyo")
MAX_ARCHIVE_MEMBERS = 2000


def _looks_like_zip(file_path: Path) -> bool:
    try:
        with open(file_path, "rb") as handle:
            head = handle.read(4)
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - _ZIP_TAIL))
            tail = handle.read()
    except OSError:
        return False
    return head == _ZIP_LOCAL_HEADER or _ZIP_END_OF_DIRECTORY in tail


def _archive_findings(file_path: Path, rel: str) -> List[Tuple[Finding, Optional[str], Optional[str]]]:
    """Findings for a file that is a zip archive, whatever its name, as ``(finding, member text,
    member suffix)``: a zip that holds Python modules is importable once it is on sys.path, so it is
    reported high, and each Python member is returned with its text to be scanned like a file."""
    import zipfile

    if not _looks_like_zip(file_path):
        return []
    try:
        with zipfile.ZipFile(file_path) as archive:
            members = archive.infolist()
            importable = [m for m in members if m.filename.lower().endswith(_ARCHIVE_IMPORTABLE)]
            if not importable:
                return []
            out: List[Tuple[Finding, Optional[str], Optional[str]]] = [(Finding(
                "importable_archive", "high", "execution", rel, 0,
                f"zip with {len(importable)} Python module(s)",
                "a zip archive (whatever its name) holding Python modules: importable once it is on "
                "sys.path, and its contents are scanned only as far as listed here"), None, None)]
            budget = MAX_PLUGIN_TOTAL_SIZE_KB * 1024
            for member in importable[:MAX_ARCHIVE_MEMBERS]:
                where = f"{rel}!/{member.filename}"
                if member.filename.lower().endswith((".pyc", ".pyo")):
                    out.append((_finding("compiled_bytecode", "critical", "execution", where, "bytecode in a zip",
                                         "compiled Python bytecode inside an archive: importable, cannot be "
                                         "scanned"), None, None))
                    continue
                if member.file_size > MAX_PLUGIN_SINGLE_FILE_KB * 1024 or member.file_size > budget:
                    out.append((_finding("too_large_to_analyse", "high", "structural", where,
                                         f"{member.file_size // 1024}KB", "archive member too large to analyse"),
                                None, None))
                    continue
                budget -= member.file_size
                source = decode_python_source(archive.read(member))
                if source is None:
                    out.append((_finding("undecodable_source", "high", "obfuscation", where, "undecodable",
                                         "Python module in an archive that cannot be decoded"), None, None))
                    continue
                out.append((Finding("archive_member", "low", "structural", where, 0, member.filename,
                                    "Python module inside an archive (scanned)"), source.text, where))
            if len(importable) > MAX_ARCHIVE_MEMBERS:
                out.append((_finding("too_large_to_analyse", "high", "structural", rel, f"{len(importable)} modules",
                                     "archive holds more Python modules than the scan reads"), None, None))
            return out
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, EOFError):
        if _ZIP_LOCAL_HEADER != _read_head(file_path):
            return []        # a stray end-record signature in a binary: neither zipfile nor zipimport opens it
        return [(_finding("unreadable_archive", "high", "structural", rel, "zip that cannot be read",
                          "file starts like a zip archive but cannot be read: its contents are not scanned"),
                 None, None)]


def _read_head(file_path: Path) -> bytes:
    try:
        with open(file_path, "rb") as handle:
            return handle.read(4)
    except OSError:
        return b""


_MACHO_MAGICS = {bytes.fromhex(h) for h in ("feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca")}


def _machine_code_format(file_path: Path) -> Optional[str]:
    """"ELF", "Mach-O" or "PE" when the file IS native code, by its bytes rather than its name."""
    try:
        with open(file_path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return None
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head[:4] in _MACHO_MAGICS:
        # 0xCAFEBABE is also a Java class file; a fat Mach-O names a small architecture count there.
        if head[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(head[4:8], "big") > 30:
            return None
        return "Mach-O"
    if head.startswith(b"MZ") and len(head) >= 0x40:
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if offset + 4 <= len(head) and head[offset:offset + 4] == b"PE\x00\x00":
            return "PE"
    return None


def _dangerous_findings_summary(findings: List[Finding]) -> str:
    """Describe the critical findings that made a plugin install dangerous."""
    critical = [finding for finding in findings if finding.severity == "critical"]
    pattern_ids = sorted({finding.pattern_id for finding in critical})
    names = f" ({', '.join(pattern_ids)})" if pattern_ids else ""
    return f"{len(critical)} critical of {len(findings)} findings{names}"


def _check_plugin_structure(plugin_dir: Path, tracked: Optional[set] = None) -> List[Finding]:
    """Structural checks sized for plugin repositories. *tracked*: see :func:`_walk`."""
    findings: List[Finding] = []
    file_count = 0
    total_size = 0
    resolved_root = plugin_dir.resolve()
    entries = list(_walk(plugin_dir, tracked, know_tracked=True))
    has_python = any(f.suffix.lower() in PYTHON_SOURCE_EXTENSIONS and f.is_file() and not f.is_symlink()
                     for f, _rel in entries)
    for f, rel in entries:
        if f.is_symlink():
            file_count += 1
            try:
                resolved = f.resolve()
            except OSError:
                findings.append(_finding("broken_symlink", "medium", "traversal", rel,
                                         "broken symlink", "broken or circular symlink"))
                continue
            if not resolved.is_relative_to(resolved_root):
                findings.append(_finding("symlink_escape", "critical", "traversal", rel,
                                         f"symlink -> {resolved}", "symlink points outside the plugin directory"))
            continue
        if not f.is_file():
            continue
        file_count += 1
        try:
            size = f.stat().st_size
        except OSError:
            continue
        total_size += size
        if size > MAX_PLUGIN_SINGLE_FILE_KB * 1024:
            findings.append(_finding("oversized_file", "medium", "structural", rel, f"{size // 1024}KB",
                                     f"file is {size // 1024}KB (limit: {MAX_PLUGIN_SINGLE_FILE_KB}KB)"))
        ext = f.suffix.lower()
        native = next((sfx for sfx in NATIVE_EXTENSION_SUFFIXES if f.name.lower().endswith(sfx)), None)
        machine = _machine_code_format(f)
        if machine and not (native and has_python):
            findings.append(_finding("native_binary", "critical", "execution", rel, f"{machine} binary",
                                     f"native machine code ({machine}) whatever the file is called: loadable "
                                     "with ctypes, or as an extension module once copied or renamed"))
            continue
        if ext in BYTECODE_EXTENSIONS:
            findings.append(_finding("compiled_bytecode", "critical", "execution", rel, f"bytecode: {ext}",
                                     "compiled Python bytecode: imported in place of (or without) source "
                                     "and cannot be scanned"))
        elif native and has_python:
            findings.append(_finding("native_extension", "critical", "execution", rel, f"extension: {native}",
                                     "native Python extension module beside Python code: importable, "
                                     "cannot be scanned"))
        elif ext == ".pth":
            findings.append(_finding("pth_file", "high", "execution", rel, "path configuration file",
                                     "a .pth file: its `import` lines run when its directory becomes a site "
                                     "directory (site.addsitedir)"))
        elif ext in SUSPICIOUS_BINARY_EXTENSIONS or ext in EXTRA_BINARY_EXTENSIONS:
            findings.append(_finding("binary_file", SEVERITY_REMAP["binary_file"], "structural", rel,
                                     f"binary: {ext}", f"binary/executable file ({ext}) bundled in plugin (cannot be scanned)"))
    if file_count > MAX_PLUGIN_FILE_COUNT:
        findings.append(_finding("too_many_files", "medium", "structural", "(directory)", f"{file_count} files",
                                 f"plugin has {file_count} files (limit: {MAX_PLUGIN_FILE_COUNT})"))
    if total_size > MAX_PLUGIN_TOTAL_SIZE_KB * 1024:
        findings.append(_finding("oversized_bundle", "medium", "structural", "(directory)", f"{total_size // 1024}KB",
                                 f"plugin is {total_size // 1024}KB total (limit: {MAX_PLUGIN_TOTAL_SIZE_KB}KB)"))
    return findings


# A PEP 263 coding cookie (line 1 or 2). Python honours it on any file a loader compiles.
_CODING_COOKIE = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_UTF8_NAMES = {"utf-8", "utf-8-sig", "utf8", "utf_8"}


def _looks_like_text(file_path: Path) -> bool:
    """A cheap look at the head of a file the scan will not read in full."""
    if file_path.suffix.lower() in SCANNABLE_EXTENSIONS or file_path.suffix.lower() in CODE_FILE_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as handle:
            head = handle.read(8192)
    except OSError:
        return False
    return head.startswith(b"#!") or b"\x00" not in head


def _read_within_limits(entries: List[Tuple[Path, str]]) -> Tuple[dict, List[Finding]]:
    """Every file decoded for the scan, within the scan's limits: a text file over
    ``MAX_PLUGIN_SINGLE_FILE_KB``, or past ``MAX_PLUGIN_TOTAL_SIZE_KB`` of text in all, is not read
    (the regex and AST passes cost time and memory in proportion) and is a high finding instead,
    so a plugin cannot hide code by being large. Binaries are not read either way."""
    sources: dict = {}
    findings: List[Finding] = []
    budget = MAX_PLUGIN_TOTAL_SIZE_KB * 1024
    for f, rel in entries:
        try:
            size = f.stat().st_size
        except OSError:
            sources[rel] = None
            continue
        if size > MAX_PLUGIN_SINGLE_FILE_KB * 1024 or size > budget:
            sources[rel] = None
            if _looks_like_text(f):
                reason = (f"text file is {size // 1024}KB (limit: {MAX_PLUGIN_SINGLE_FILE_KB}KB)"
                          if size > MAX_PLUGIN_SINGLE_FILE_KB * 1024 else
                          f"the plugin holds more than {MAX_PLUGIN_TOTAL_SIZE_KB}KB of text")
                findings.append(_finding("too_large_to_analyse", "high", "structural", rel, f"{size // 1024}KB",
                                         f"{reason}: not analysed, review it by hand"))
            continue
        sources[rel] = _read_plugin_file(f)
        if sources[rel] is not None:
            budget -= size
    return sources, findings


def _read_plugin_file(file_path: Path) -> Optional[SourceText]:
    """*file_path* decoded as the scan reads it (``skills_guard.read_source_text``): Python source,
    a script whose shebang names Python included, as the interpreter decodes it."""
    return read_source_text(file_path, any_text=True,
                            python=_code_suffix(file_path) in PYTHON_SOURCE_EXTENSIONS)


def _encoding_findings(source: SourceText, rel: str, suffix: str) -> List[Finding]:
    """Code whose bytes a UTF-8 reader and the interpreter (or shell) would read differently."""
    out: List[Finding] = []
    if suffix in PYTHON_SOURCE_EXTENSIONS and source.encoding.lower() not in _UTF8_NAMES:
        out.append(Finding("source_encoding", "high", "obfuscation", rel, 1, f"encoding: {source.encoding}",
                           f"Python source declares the {source.encoding} encoding: what runs is not what a "
                           "UTF-8 reader shows (it is scanned as the interpreter decodes it)"))
    if suffix in CODE_FILE_EXTENSIONS and not source.strict:
        out.append(Finding("undecodable_source", "high", "obfuscation", rel, 0, "invalid bytes or NUL",
                           "code file holds bytes that are not valid in its encoding, or NUL bytes "
                           "(scanned with them replaced or removed)"))
    return out


# Text a Python loader could run but that is something else first; a ``.json`` never calls anything.
_NEVER_PYTHON = {".html", ".htm", ".xhtml", ".svg", ".css", ".json", ".xml"}


def _parses_as_code(text: str) -> bool:
    """Whether *text* is Python that does something: it parses and holds an import or a call (a
    one-word ``.txt`` parses too, and is not code)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) for node in ast.walk(tree))


def _python_view(file_path: Path, source: SourceText, suffix: str) -> Tuple[SourceText, bool]:
    """The text the Python checks read and whether it is Python code. Python source as decoded; a
    file of another name is code when it parses as Python that imports or calls something, because
    a loader can be pointed at a file of any name. When such a file's coding cookie declares another
    encoding it is read as a loader would read it."""
    if suffix in PYTHON_SOURCE_EXTENSIONS:
        return source, True
    if suffix in CODE_FILE_EXTENSIONS or suffix in _NEVER_PYTHON:
        return source, False      # another language's code, or markup: judged as what it is
    head = source.text.split("\n", 2)[:2]
    cookie = next((m.group(1) for m in map(_CODING_COOKIE.match, head) if m), None)
    if cookie and cookie.lower() not in _UTF8_NAMES:
        try:
            as_python = decode_python_source(file_path.read_bytes())
        except OSError:
            as_python = None
        if as_python is not None and _parses_as_code(as_python.text):
            return as_python, True
    return source, _parses_as_code(source.text)


def scan_plugin(plugin_dir: Path, source: str = "") -> ScanResult:
    """Scan a plugin directory (typically the temp clone); every external plugin is ``community`` trust."""
    all_findings: List[Finding] = []
    if plugin_dir.is_dir():
        tracked = _tracked_paths(plugin_dir)
        all_findings.extend(_check_plugin_structure(plugin_dir, tracked))
        js = JsSinkInventory(plugin_dir, frozenset(EXCLUDED_DIRS),
                             walk=lambda: _walk(plugin_dir, tracked, know_tracked=True))
        entries = [(f, rel) for f, rel in sorted(_walk(plugin_dir, tracked, know_tracked=True))
                   if f.is_file() and not f.is_symlink()]
        sources, too_large = _read_within_limits(entries)
        all_findings.extend(too_large)
        python_refs = {rel: (module_refs(sources[rel].text, rel) if sources[rel] is not None else None)
                       for f, rel in entries if _code_suffix(f) in PYTHON_SOURCE_EXTENSIONS}
        tree_files = {rel for _f, rel in entries}
        package_names = _package_names(sources)
        manifest_strings = {token for f, rel in entries if f.name.lower() in _MANIFEST_NAMES
                            and sources[rel] is not None for token in _manifest_strings(sources[rel].text)}
        unreached, analysed = _unreached_dev_files(python_refs, manifest_strings,
                                                   [rel for _f, rel in entries if rel not in python_refs])
        if not analysed:
            all_findings.append(_finding("too_large_to_analyse", "high", "structural", "(directory)",
                                         f"{len(python_refs)} Python files",
                                         f"more than {MAX_PLUGIN_FILE_COUNT} Python files: which test code the "
                                         "plugin can import was not worked out, so none of it steps down"))
        for f, rel in entries:
            for finding, member_text, where in _archive_findings(f, rel):
                all_findings.append(finding)
                if member_text is not None:
                    all_findings.extend(_filter_findings(
                        scan_text(member_text, where, ".py", _python_prose_lines(member_text)), where, f, js,
                        parsed_python=True, text=member_text))
                    all_findings.extend(_filter_findings(python_code_findings(member_text, where), where, f, js,
                                                         parsed_python=True, text=member_text, from_ast=True))
            # Every text file, whatever its name: a loader can be pointed at any of them (HERM-195).
            source = sources[rel]
            if source is None:
                continue
            suffix = _code_suffix(f)
            view, is_python = _python_view(f, source, suffix)
            # A file that parses as Python code is judged as code whatever its name.
            judged = dict(parsed_python=is_python, text=view.text, unreached=rel in unreached)
            prose = _python_prose_lines(view.text) if is_python else None
            all_findings.extend(_filter_findings(scan_text(view.text, rel, ".py" if is_python else suffix, prose),
                                                 rel, f, js, **judged))
            all_findings.extend(_filter_findings(
                _encoding_findings(view, rel, ".py" if is_python else suffix), rel, f, js, from_ast=True, **judged))
            if is_python:
                all_findings.extend(_filter_findings(
                    python_code_findings(view.text, rel, line_fallback=suffix in PYTHON_SOURCE_EXTENSIONS,
                                         tree_files=tree_files, package_names=package_names),
                    rel, f, js, from_ast=True, **judged))
    verdict = _determine_verdict(all_findings)
    if all_findings:
        categories = sorted({f.category for f in all_findings})
        summary = f"{plugin_dir.name}: {verdict} — {len(all_findings)} finding(s) in {', '.join(categories)}"
    else:
        summary = f"{plugin_dir.name}: clean scan, no threats detected"
    result = ScanResult(
        skill_name=plugin_dir.name, source=source or plugin_dir.name, trust_level="community",
        verdict=verdict, findings=all_findings, scanned_at=datetime.now(timezone.utc).isoformat(),
        summary=summary)
    result.scan_provenance = {
        "scanner_version": PLUGIN_SCANNER_VERSION, "verdict": verdict, "source": result.source}
    return result


def should_allow_plugin_install(
    result: ScanResult, force: bool = False) -> Tuple[Optional[bool], str]:
    """Map a verdict to ``(allowed, reason)``: True installs, None asks to confirm, False blocks."""
    n = len(result.findings)
    if result.verdict == "safe":
        return True, "Allowed (clean scan)"
    if result.verdict == "caution":
        if force:
            return True, f"Force-installed despite caution verdict ({n} findings)"
        return None, f"Requires confirmation (caution verdict, {n} findings)"
    return False, (
        f"Blocked (dangerous verdict, {_dangerous_findings_summary(result.findings)}). "
        f"--force does not override a dangerous verdict.")


__all__ = [
    "scan_plugin", "should_allow_plugin_install", "format_scan_report", "PLUGIN_SCANNER_VERSION"]
