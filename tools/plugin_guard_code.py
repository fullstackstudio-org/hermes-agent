"""Python a plugin can run that no text scan reads (``tools.plugin_guard``; HERM-196b, HERM-197).

Read from the AST, not line by line, so a docstring that names a route is prose, a loader is
judged by the path it is given rather than by every dotted string on its line, a call that spans
several lines is one call, and only a CHANGE to ``sys.path`` counts. Source the scanner's own
Python cannot parse (newer syntax than the scanner, or a broken file) is read line by line instead,
with docstrings skipped there too.

Every finding is ``high`` (confirm before installing) except a loader whose path the scan cannot
work out: that file is scanned like any other wherever it is, so it is reported at ``medium``.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Dict, Iterator, List, Optional, Set, Tuple

from tools.skills_guard import Finding, _compute_docstring_lines

PYTHON_SOURCE_EXTENSIONS = {".py", ".pyw"}

_ARCHIVE_MENTION = re.compile(r"\.(?:zip|whl|egg|pyz)\b", re.IGNORECASE)

# Calls that load a module from a file, and which argument (position, keyword) names that file.
_FILE_LOADERS: Dict[str, Tuple[int, str]] = {
    "SourceFileLoader": (1, "path"),
    "spec_from_file_location": (1, "location"),
    "load_source": (1, "pathname"),
    "run_path": (0, "path_name"),
}
# Names that load bytecode or a native module directly, whatever they are given.
_RAW_LOADERS = {"SourcelessFileLoader", "ExtensionFileLoader", "load_compiled", "load_dynamic"}
# Calls that build a path whose last literal piece is the file name.
_PATH_BUILDERS = {"join", "Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath",
                  "joinpath", "str", "fspath", "abspath", "realpath", "normpath", "expanduser", "resolve",
                  "absolute", "expandvars", "fsdecode"}

_DESCRIPTIONS = {
    "archive_on_sys_path": "puts an archive on sys.path (imports code no scan reads)",
    "zipimport_use": "uses zipimport (imports code from an archive no scan reads)",
    "bytecode_or_native_loader": "loads bytecode or a native module directly",
    "non_source_loader": "loads a file that is not .py source as a module",
    "dynamic_source_loader": "loads a module from a path the scan cannot work out (the file is scanned wherever it is)",
}
_SEVERITY = {"dynamic_source_loader": "medium"}


def python_code_findings(text: str, rel: str, *, line_fallback: bool = True) -> List[Finding]:
    """Findings for Python *text* (the file at *rel*). With *line_fallback*, text that does not parse
    is read line by line instead; without it, such text yields nothing."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _line_findings(text, rel) if line_fallback else []
    return _CodeReader(text, rel).read(tree)


class _CodeReader:
    def __init__(self, text: str, rel: str) -> None:
        self.lines = text.split("\n")
        self.rel = rel
        self.found: Dict[Tuple[str, int], Finding] = {}
        self.sys_names: Set[str] = {"sys"}
        self.site_names: Set[str] = {"site"}
        self.from_sys: Dict[str, str] = {}       # local name -> sys attribute it is
        self.site_funcs: Set[str] = set()

    # ── output ──────────────────────────────────────────────────────────────────────────────

    def add(self, pattern_id: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", 0)
        if (pattern_id, line) in self.found:
            return
        text = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.found[(pattern_id, line)] = Finding(
            pattern_id, _SEVERITY.get(pattern_id, "high"), "execution", self.rel, line,
            text if len(text) <= 120 else text[:117] + "...", _DESCRIPTIONS[pattern_id])

    def read(self, tree: ast.AST) -> List[Finding]:
        nodes = list(ast.walk(tree))      # iterative: a deeply nested file cannot recurse the scan
        for node in nodes:
            self.note_import(node)
        for node in nodes:
            self.check(node)
        return sorted(self.found.values(), key=lambda f: (f.line, f.pattern_id))

    # ── names ───────────────────────────────────────────────────────────────────────────────

    def note_import(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                if alias.name == "sys":
                    self.sys_names.add(local)
                elif alias.name == "site":
                    self.site_names.add(local)
                elif alias.name == "zipimport":
                    self.add("zipimport_use", node)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                if module == "sys":
                    self.from_sys[local] = alias.name
                elif module == "site" and alias.name == "addsitedir":
                    self.site_funcs.add(local)
                if module == "zipimport":
                    self.add("zipimport_use", node)
                if alias.name in _RAW_LOADERS:
                    self.add("bytecode_or_native_loader", node)

    def sys_attr(self, node: ast.AST) -> Optional[str]:
        """``"path"`` for ``sys.path`` (under any alias, or imported from sys); else None."""
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in self.sys_names:
            return node.attr
        if isinstance(node, ast.Name):
            return self.from_sys.get(node.id)
        return None

    # ── checks ──────────────────────────────────────────────────────────────────────────────

    def check(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            self.check_call(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.check_store(target, node)
        elif isinstance(node, ast.Name) and node.id in _RAW_LOADERS | {"zipimporter"}:
            self.add("zipimport_use" if node.id == "zipimporter" else "bytecode_or_native_loader", node)
        elif isinstance(node, ast.Attribute) and node.attr in _RAW_LOADERS | {"zipimporter"}:
            self.add("zipimport_use" if node.attr == "zipimporter" else "bytecode_or_native_loader", node)

    def check_store(self, target: ast.AST, statement: ast.AST) -> None:
        """An assignment to ``sys.path`` (or a slice of it) that holds an archive."""
        base = target.value if isinstance(target, ast.Subscript) else target
        if self.sys_attr(base) == "path" and statement.value is not None and _mentions_archive(statement.value):
            self.add("archive_on_sys_path", statement)

    def check_call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if isinstance(func, ast.Attribute) and func.attr in {"insert", "append", "extend", "__iadd__"} \
                and self.sys_attr(func.value) == "path" and _mentions_archive(node):
            self.add("archive_on_sys_path", node)
        is_addsitedir = (isinstance(func, ast.Attribute) and func.attr == "addsitedir"
                         and isinstance(func.value, ast.Name) and func.value.id in self.site_names) \
            or (isinstance(func, ast.Name) and func.id in self.site_funcs)
        if is_addsitedir and _mentions_archive(node):
            self.add("archive_on_sys_path", node)
        if name in _FILE_LOADERS:
            position, keyword = _FILE_LOADERS[name]
            path = _argument(node, position, keyword)
            if path is not None:
                tail = _literal_tail(path)
                if tail is None:
                    self.add("dynamic_source_loader", node)
                elif _suffix(tail) not in PYTHON_SOURCE_EXTENSIONS:
                    self.add("non_source_loader", node)


def _argument(call: ast.Call, position: int, keyword: str) -> Optional[ast.AST]:
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    if len(call.args) > position and not any(isinstance(a, ast.Starred) for a in call.args[:position + 1]):
        return call.args[position]
    return None


def _literal_tail(node: ast.AST) -> Optional[str]:
    """The last literal piece of a path expression (what decides its file name), or None when the
    expression does not end in one the scan can see."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", "replace")
        return None
    if isinstance(node, ast.JoinedStr):
        return _literal_tail(node.values[-1]) if node.values else None
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Add, ast.Div)):
            return _literal_tail(node.right)
        if isinstance(node.op, ast.Mod):        # '%s/helpers.py' % HERE
            return _literal_tail(node.left)
        return None
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name == "with_suffix" and node.args:
            tail = _literal_tail(node.args[0])
            return None if tail is None else "x" + tail
        if name == "format" and isinstance(func, ast.Attribute):
            return _literal_tail(func.value)
        if name in _PATH_BUILDERS:
            if node.args:
                return _literal_tail(node.args[-1])
            if isinstance(func, ast.Attribute):    # (HERE / 'mod.py').resolve()
                return _literal_tail(func.value)
        return None
    return None


def _suffix(tail: str) -> str:
    name = tail.replace("\\", "/").rsplit("/", 1)[-1]
    return os.path.splitext("x" + name)[1].lower()


def _strings(node: ast.AST) -> Iterator[str]:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            yield sub.value


def _mentions_archive(node: ast.AST) -> bool:
    return any(_ARCHIVE_MENTION.search(s) for s in _strings(node))


# ── fallback: Python the scanner cannot parse ───────────────────────────────────────────────

_IMPORT_PATH_CALL = re.compile(
    r"\bsys\.path\s*\.\s*(?:insert|append|extend)\s*\(|\bsys\.path\s*(?:\+=|\[[^\]\n]*\]\s*=(?!=)|=(?!=))"
    r"|\bsite\.addsitedir\s*\(")
_ZIPIMPORT = re.compile(r"\bzipimport\b|\bzipimporter\s*\(")
_RAW_LOADER_NAMES = re.compile(r"\b(?:SourcelessFileLoader|ExtensionFileLoader|load_compiled|load_dynamic)\b")
_FILE_LOADER_CALL = re.compile(r"\b(?:SourceFileLoader|spec_from_file_location|load_source|run_path)\s*\(")
_QUOTED = re.compile(r"""["']([^"'\n]*)["']""")


def _line_findings(text: str, rel: str) -> List[Finding]:
    """The line-by-line reading for source that does not parse: whole-line comments and docstrings
    skipped, and a loader judged by the LAST quoted string on its line (the path comes after the
    module name)."""
    lines = text.split("\n")
    docstrings = _compute_docstring_lines(lines)
    out: List[Finding] = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or number in docstrings:
            continue
        hits = []
        if _IMPORT_PATH_CALL.search(line) and _ARCHIVE_MENTION.search(line):
            hits.append("archive_on_sys_path")
        if _ZIPIMPORT.search(line):
            hits.append("zipimport_use")
        if _RAW_LOADER_NAMES.search(line):
            hits.append("bytecode_or_native_loader")
        if _FILE_LOADER_CALL.search(line):
            quoted = _QUOTED.findall(line)
            if quoted and _suffix(quoted[-1]) not in PYTHON_SOURCE_EXTENSIONS:
                hits.append("non_source_loader")
        for pattern_id in hits:
            out.append(Finding(pattern_id, _SEVERITY.get(pattern_id, "high"), "execution", rel, number,
                               stripped if len(stripped) <= 120 else stripped[:117] + "...",
                               _DESCRIPTIONS[pattern_id]))
    return out
