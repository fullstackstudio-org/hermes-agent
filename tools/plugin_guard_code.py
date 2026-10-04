"""Python a plugin can run that no text scan reads (``tools.plugin_guard``; HERM-196b, HERM-197).

Two kinds of route:

* code imported from somewhere the scan does not read: an archive or any other file put on
  ``sys.path``, a directory outside the plugin, bytecode, a file that is not ``.py``, a custom
  loader or finder, a change to the import machinery;
* code the plugin builds at run time and executes: ``exec``/``eval``/``compile`` of anything but a
  literal, and the other ways to run a string or a code object (``marshal``/``pickle`` and kin,
  ``timeit``, the ``code`` module, ``pdb``/``profile`` runners, ``ctypes.pythonapi``, code objects
  built or swapped by hand, ``python -c`` with a computed argument).

The runtime-code checks are a TRIPWIRE, not a boundary. The second list is a denylist and has the
limits every denylist has: Python can reach an
interpreter in more ways than any list names, and a determined author can hide a name from static
analysis altogether. The checks follow the spellings a scan can see (aliases, ``import ... as``,
``getattr`` and subscripts with a constant or concatenated name, ``vars(builtins)``,
``importlib.import_module('builtins')``); what they cannot follow is not reported. They exist to
make a plain bypass visible, not to prove a plugin harmless.

Read from the AST, not line by line, so a docstring that names a route is prose, a loader is
judged by the path it is given rather than by every dotted string on its line, a call that spans
several lines is one call, and only a CHANGE to ``sys.path`` counts. A loader path or a ``sys.path``
entry is accepted only when it is anchored to the plugin itself (built from ``__file__``, without
leaving the plugin's directory); an absolute path, a path relative to the working directory, or one
computed from anything else is high. Source the scanner's own Python cannot parse (newer syntax
than the scanner, or a broken file) is read line by line instead, with docstrings skipped there too.

Every finding is ``high`` (confirm before installing) except a loader anchored to the plugin whose
file name the scan cannot work out: the file is somewhere in the plugin, which is scanned, so it
is reported at ``medium``.
"""

from __future__ import annotations

import ast
import builtins as _builtins_module
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from tools.skills_guard import Finding, _compute_docstring_lines

PYTHON_SOURCE_EXTENSIONS = {".py", ".pyw"}

_ARCHIVE_MENTION = re.compile(r"\.(?:zip|whl|egg|pyz)\b", re.IGNORECASE)

# Calls that load a module from a file, and which argument (position, keyword) names that file.
_FILE_LOADERS: Dict[str, Tuple[int, str]] = {
    "SourceFileLoader": (1, "path"),
    "spec_from_file_location": (1, "location"),
    "load_source": (1, "pathname"),
    "load_module": (2, "pathname"),          # imp.load_module(name, file, pathname, description)
    "run_path": (0, "path_name"),
}
# Names that load bytecode or a native module directly, whatever they are given.
_RAW_LOADERS = {"SourcelessFileLoader", "ExtensionFileLoader", "load_compiled", "load_dynamic"}
_ZIP_NAMES = {"zipimport", "zipimporter"}
# Builtins that run code given to them.
_CODE_RUNNERS = {"exec", "eval", "compile"}
_BUILTIN_NAMES = frozenset(dir(_builtins_module))
# The import machinery: a finder or hook put here decides where every later import comes from.
_IMPORT_HOOKS = {"sys.meta_path", "sys.path_hooks", "sys.path_importer_cache"}
_MUTATORS = {"insert", "append", "extend", "__setitem__", "__iadd__", "update", "setdefault"}
# Calls that build a path whose last literal piece is the file name.
_PATH_BUILDERS = {"join", "Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath",
                  "joinpath", "str", "fspath", "abspath", "realpath", "normpath", "expanduser", "resolve",
                  "absolute", "expandvars", "fsdecode", "glob", "rglob"}
# Loading any of these runs code that is in the data (a pickle's __reduce__, a marshalled code object).
_DESERIALIZERS = {
    "marshal.loads": "marshal_code", "marshal.load": "marshal_code",
    **{f"{module}.{name}": "unpickle_code"
       for module in ("pickle", "_pickle", "cPickle", "dill", "cloudpickle")
       for name in ("load", "loads", "Unpickler")},
    "shelve.open": "unpickle_code", "shelve.Shelf": "unpickle_code", "shelve.DbfilenameShelf": "unpickle_code",
    "jsonpickle.decode": "unpickle_code", "joblib.load": "unpickle_code", "pandas.read_pickle": "unpickle_code",
}
# Run a string of Python: flagged unless that string is a literal (or, for timeit, a lambda).
_STRING_RUNNERS = {"timeit.timeit", "timeit.repeat", "timeit.Timer", "pdb.run", "pdb.runeval", "pdb.runctx",
                   "cProfile.run", "cProfile.runctx", "profile.run", "profile.runctx"}
_STRING_RUNNER_METHODS = {"runctx", "runeval", "runsource", "runcode"}
# Interpreters and code objects: any use at all.
_CODE_MACHINERY = {
    "code.InteractiveInterpreter": "code_runner", "code.InteractiveConsole": "code_runner",
    "code.interact": "code_runner", "code.compile_command": "code_runner", "codeop.compile_command": "code_runner",
    "codeop.Compile": "code_runner", "codeop.CommandCompiler": "code_runner", "ctypes.pythonapi": "code_runner",
    "types.CodeType": "code_object", "types.FunctionType": "code_object", "types.LambdaType": "code_object",
    "zipimport": "zipimport_use", "zipimport.zipimporter": "zipimport_use",
}
# Names distinctive enough to flag on any object, and constant strings naming them.
_DISTINCT_NAMES = {**{name: "bytecode_or_native_loader" for name in _RAW_LOADERS},
                   **{name: "zipimport_use" for name in _ZIP_NAMES},
                   "pythonapi": "code_runner", "source_to_code": "compile_dynamic_code", "CodeType": "code_object",
                   "__builtins__": "exec_dynamic_code"}
_C_API_RUNNERS = ("PyRun_", "Py_CompileString", "PyEval_EvalCode", "PyImport_ExecCode", "Py_Main")
# A class that is (or acts as) an import loader or finder: it decides what code an import runs.
_LOADER_BASE_SUFFIXES = ("Loader", "Finder", "Importer")
_LOADER_METHODS = {"exec_module", "get_code", "source_to_code", "find_spec", "find_module", "create_module"}
# Loading native code from a file: whatever the file is called, it runs machine code in the process.
_NATIVE_LOADERS = {"ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL", "ctypes.OleDLL", "ctypes.cdll", "ctypes.pydll",
                   "ctypes.windll", "ctypes.oledll", "ctypes.LibraryLoader", "ctypes.util.find_library",
                   "_ctypes.dlopen", "_ctypes.LoadLibrary", "cffi.FFI", "ctypes.cdll.LoadLibrary"}
_NATIVE_LOADER_ATTRS = {"dlopen", "LoadLibrary"}
# Frame attributes that hand out a module's namespace, builtins included.
_FRAME_NAMESPACES = {"f_builtins", "f_globals", "f_locals"}
# What Python (or the dynamic linker) loads by suffix: a file with one of these written at run time is code.
_IMPORTABLE_SUFFIXES = {".py", ".pyw", ".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll", ".pth"}
# (An archive written elsewhere imports nothing until it is put on sys.path, which is checked there.)
# Calls that write a file, and which argument names the destination.
_WRITERS: Dict[str, Tuple[int, str]] = {"copy": (1, "dst"), "copy2": (1, "dst"), "copyfile": (1, "dst"),
                                        "copytree": (1, "dst"), "move": (1, "dst"), "rename": (1, "dst"),
                                        "replace": (1, "dst"), "symlink": (1, "dst"), "link": (1, "dst"),
                                        "extractall": (0, "path"), "extract": (1, "path"),
                                        "unpack_archive": (1, "extract_dir")}
_PYTHON_EXE = re.compile(r"(?:^|[\\/])python[\d.]*(?:\.exe)?$")
# A constant longer than this is not followed (``v = v + v`` doubles each line).
_FOLD_LIMIT = 4096
# Openers that take (file, mode): a write mode makes them writers.
_FILE_OPENERS = {"builtins.open", "io.open", "_io.open", "codecs.open", "io.FileIO", "_io.FileIO", "tarfile.open",
                 "gzip.open", "bz2.open", "lzma.open", "zipfile.ZipFile", "tarfile.TarFile"}
_OS_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL"}
# tempfile creators: (positional index of suffix, of dir) when they take them positionally.
_TEMPFILE_MAKERS = {"mkstemp": (0, 2), "mkdtemp": (0, 2), "NamedTemporaryFile": (4, 6),
                    "TemporaryFile": (4, 6), "SpooledTemporaryFile": (5, 7), "TemporaryDirectory": (0, 2)}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh", "csh", "tcsh"}
# Shell options that take an argument (``bash -o pipefail -c cmd``), short and long.
_SHELL_OPTIONS_WITH_ARGUMENT = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
# Interpreters other than Python and the flag that makes them run code given on the command line.
_CODE_FLAGS = {"perl": {"-e", "-E"}, "ruby": {"-e"}, "node": {"-e", "--eval", "-p", "--print"},
               "nodejs": {"-e", "--eval", "-p", "--print"}, "bun": {"-e", "--eval"}, "deno": {"eval"},
               "php": {"-r"}, "lua": {"-e"}, "Rscript": {"-e"}, "osascript": {"-e"}, "tclsh": set(),
               "awk": set(), "gawk": set()}
# Path methods that write to the path they are called on; rename/replace write to their argument.
_PATH_WRITE_METHODS = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to"}
_PATH_MOVE_METHODS = {"rename", "replace"}
# Process calls that hand a whole string to a shell.
_SHELL_STRING_CALLS = {"subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
                       "os.system", "os.popen"}
        # a constant longer than this is not followed (``v = v + v`` doubles each line)
# Ways a path expression climbs one directory.
_UP_CALLS = {"dirname"}
_SAME_DIR_CALLS = {"Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath", "str",
                   "fspath", "abspath", "realpath", "normpath", "resolve", "absolute", "expanduser", "fsdecode",
                   "joinpath", "glob", "rglob", "iterdir", "with_suffix", "with_name", "files"}

_DESCRIPTIONS = {
    "archive_on_sys_path": "puts a file (an archive, whatever its name) on sys.path: imports code no scan reads",
    "foreign_sys_path": "puts a directory outside the plugin (absolute, working-directory relative or computed) "
                        "on sys.path: imports code no scan reads",
    "zipimport_use": "uses zipimport (imports code from an archive no scan reads)",
    "bytecode_or_native_loader": "loads bytecode or a native module directly",
    "non_source_loader": "loads a file that is not .py source as a module",
    "foreign_source_loader": "loads a module from a path outside the plugin (absolute, working-directory "
                             "relative or computed): no scan reads it",
    "dynamic_source_loader": "loads a module from a file in the plugin the scan cannot name (the plugin is scanned)",
    "exec_dynamic_code": "runs code built at run time with exec()/eval(), or reaches them indirectly "
                         "(no scan reads what runs)",
    "compile_dynamic_code": "compiles code built at run time (no scan reads what runs)",
    "marshal_code": "loads marshalled code objects (bytecode no scan reads)",
    "unpickle_code": "unpickles data (pickle and kin run code named in the data)",
    "code_runner": "runs a string of Python through an interpreter API (timeit, code, pdb/profile, ctypes "
                   "pythonapi)",
    "code_object": "builds or swaps a code object by hand (bytecode no scan reads)",
    "custom_loader": "defines an import loader or finder: it decides what code an import runs",
    "interpreter_code": "runs an interpreter on code built at run time (python -c, perl -e, node -e, "
                        "code on stdin)",
    "import_hook_change": "changes the import machinery (sys.meta_path / sys.path_hooks): later imports can "
                          "come from anywhere",
    "sys_modules_lookup": "reaches a module through sys.modules by a computed name",
    "native_load": "loads native code with ctypes or cffi (machine code no scan reads)",
    "missing_module": "imports or loads a module the plugin does not ship (written or unpacked at run time?)",
    "code_written": "writes or unpacks a file Python can import, or into the plugin's own directory, at run time",
    "shell_code": "runs a shell on a command built at run time (sh -c <computed>): no scan reads what runs",
    "foreign_python_path": "sets PYTHONPATH/PYTHONHOME/PYTHONSTARTUP for a child process to something computed: "
                           "the child imports code from wherever that points (sys.path, out of process)",
}
_SEVERITY = {"dynamic_source_loader": "medium", "foreign_python_path": "medium"}
# Environment variables that decide what a child Python imports or runs first.
_PYTHON_ENV_KEYS = {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE"}
# Every finding this module makes: a route by which code runs that no text scan reads. Under a test
# tree these step down only when nothing the plugin runs imports the file (``plugin_guard``).
ROUTE_PATTERN_IDS = frozenset(_DESCRIPTIONS)

_MAX_DEPTH = 12


def python_code_findings(text: str, rel: str, *, line_fallback: bool = True,
                         tree_files: Optional[Set[str]] = None,
                         package_names: Optional[Dict[str, Set[str]]] = None) -> List[Finding]:
    """Findings for Python *text* (the file at *rel* in the plugin). With *line_fallback*, text that
    does not parse is read line by line instead; without it, such text yields nothing. *tree_files*
    (every path the plugin ships) and *package_names* (the names each package's ``__init__.py``
    binds, by package directory) let an import of something the plugin does not ship be reported."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _line_findings(text, rel) if line_fallback else []
    return _CodeReader(text, rel, tree, tree_files, package_names).read()


class _CodeReader:
    def __init__(self, text: str, rel: str, tree: ast.AST, tree_files: Optional[Set[str]] = None,
                 package_names: Optional[Dict[str, Set[str]]] = None) -> None:
        self.lines = text.split("\n")
        self.rel = rel
        self.tree = tree
        self.tree_files = tree_files
        self.tree_dirs = {"/".join(f.split("/")[:i]) for f in (tree_files or ()) for i in range(1, f.count("/") + 1)}
        self.package_names = package_names or {}
        self.memo: Dict[Tuple[str, int], object] = {}
        self.scopes: Dict[int, ast.AST] = {}
        self.mentions_interpreter = False
        # How many directories the file sits below the plugin root (an archive member: none of its own).
        self.depth = -1 if "!/" in rel else rel.count("/")
        self.found: Dict[Tuple[str, int], Finding] = {}
        self.nodes = list(ast.walk(tree))      # iterative: a deeply nested file cannot recurse the scan
        self.parents: Dict[ast.AST, ast.AST] = {}
        self.bindings: Dict[Tuple[ast.AST, str], _Binding] = {}   # (scope, name) -> how it is bound there
        self.prose: Set[ast.AST] = set()          # string statements: docstrings and bare prose

    # ── output ──────────────────────────────────────────────────────────────────────────────

    def add(self, pattern_id: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", 0)
        if (pattern_id, line) in self.found:
            return
        text = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.found[(pattern_id, line)] = Finding(
            pattern_id, _SEVERITY.get(pattern_id, "high"), "execution", self.rel, line,
            text if len(text) <= 120 else text[:117] + "...", _DESCRIPTIONS[pattern_id])

    def prepare(self) -> None:
        for node in self.nodes:
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
        for node in self.nodes:
            self.note_binding(node)
        self.mentions_interpreter = any(
            (isinstance(n, ast.Attribute) and n.attr == "executable") or
            (isinstance(n, ast.Constant) and isinstance(n.value, str) and _PYTHON_EXE.search(n.value))
            for n in self.nodes)

    def read(self) -> List[Finding]:
        self.prepare()
        for node in self.nodes:
            self.check(node)
        return sorted(self.found.values(), key=lambda f: (f.line, f.pattern_id))

    def remembered(self, kind: str, node: ast.AST, compute):
        key = (kind, id(node))
        if key not in self.memo:
            self.memo[key] = None          # a cycle reads "unknown"
            self.memo[key] = compute()
        return self.memo[key]

    # ── names ───────────────────────────────────────────────────────────────────────────────

    def scope(self, node: ast.AST) -> ast.AST:
        """The function, lambda, class or module whose namespace *node* is evaluated in."""
        found = self.scopes.get(id(node))
        if found is None:
            up = self.parents.get(node)
            while up is not None and not isinstance(up, _SCOPES):
                up = self.parents.get(up)
            found = up if up is not None else self.tree
            self.scopes[id(node)] = found
        return found

    def binding(self, node: ast.AST, name: str) -> "_Binding":
        """The record for *name* in the scope *node* binds it in."""
        key = (self.scope(node), name)
        if key not in self.bindings:
            self.bindings[key] = _Binding()
        return self.bindings[key]

    def lookup(self, node: ast.Name) -> Optional["_Binding"]:
        """How the name *node* reads is bound: its own scope, then enclosing functions (a class body
        is not visible from its methods), then the module; None for a builtin or unknown name."""
        scope, first = self.scope(node), True
        while True:
            if first or not isinstance(scope, ast.ClassDef):
                found = self.bindings.get((scope, node.id))
                if found is not None:
                    return found
            if scope is self.tree:
                return None
            scope, first = self.scope(scope), False

    def note_binding(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.binding(node, alias.asname).imported.append(alias.name)
                else:
                    top = alias.name.split(".")[0]
                    self.binding(node, top).imported.append(top)
                if alias.name.split(".")[0] in _ZIP_NAMES:
                    self.add("zipimport_use", node)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                if node.level == 0 and node.module:
                    self.binding(node, local).imported.append(f"{node.module}.{alias.name}")
                else:
                    self.binding(node, local).other = True
                if (node.module or "").split(".")[0] in _ZIP_NAMES or alias.name in _ZIP_NAMES:
                    self.add("zipimport_use", node)
                if alias.name in _RAW_LOADERS:
                    self.add("bytecode_or_native_loader", node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and node.value is not None:
                    # x += ... rebinds to something new: ambiguous on purpose.
                    self.binding(node, target.id).values.append(
                        node.value if not isinstance(node, ast.AugAssign) else node)
                else:
                    for name in _stored_names(target):
                        self.binding(node, name).other = True
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            if isinstance(node.target, ast.Name):
                self.binding(node, node.target.id).iters.append(node.iter)
            else:
                for name in _stored_names(node.target):
                    self.binding(node, name).other = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.binding(node, node.name).other = True
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                self.prose.add(body[0].value)
        elif isinstance(node, ast.arg):
            self.binding(node, node.arg).other = True
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self.binding(node, node.name).other = True
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            for name in _stored_names(node.optional_vars):
                self.binding(node, name).other = True
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            self.prose.add(node.value)

    def single_value(self, node: ast.Name) -> Optional[ast.AST]:
        """The one value a name is assigned, a ``None`` placeholder before it not counting."""
        found = self.lookup(node)
        if found is None or found.other or found.imported or found.iters:
            return None
        values = [v for v in found.values if not _is_none(v)]
        return values[0] if len(values) == 1 else None

    def call_name(self, func: ast.AST) -> Optional[str]:
        """The last part of what a call calls, through imports and aliases (``P`` for ``Path``)."""
        qualified = self.qual(func)
        if qualified:
            return qualified.rsplit(".", 1)[-1]
        return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None

    def is_own_file(self, node: ast.AST) -> bool:
        """``__file__``, or ``sys.modules[__name__].__file__``: this file's own path."""
        if isinstance(node, ast.Name):
            return node.id == "__file__"
        return isinstance(node, ast.Attribute) and node.attr == "__file__" and isinstance(node.value, ast.Subscript) \
            and self.qual(node.value.value) == "sys.modules" and self.own_module_name(node.value.slice)

    def qual(self, node: ast.AST, depth: int = 0) -> Optional[str]:
        """The dotted name *node* stands for ("builtins.exec", "marshal.loads", "sys.path"), through
        imports, single assignments, ``getattr``/subscripts with a constant name, ``vars(x)``,
        ``__builtins__``, ``sys.modules[...]``, ``<builtin>.__self__`` and
        ``import_module``/``__import__`` of a constant; None when unknown."""
        if depth > _MAX_DEPTH:
            return None
        return self.remembered("qual", node, lambda: self._qual(node, depth))

    def _qual(self, node: ast.AST, depth: int) -> Optional[str]:
        if isinstance(node, ast.Name):
            if node.id == "__builtins__":
                return "builtins"
            found = self.lookup(node)
            if found is None:
                return f"builtins.{node.id}" if node.id in _BUILTIN_NAMES else None
            if len(found.imported) == 1 and not (found.values or found.iters or found.other):
                return found.imported[0]
            value = self.single_value(node)
            return self.qual(value, depth + 1) if value is not None else None
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value, depth + 1)
            if node.attr == "__self__" and base and base.startswith("builtins."):
                return "builtins"            # len.__self__ is the builtins module
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            func = self.qual(node.func, depth + 1)
            if func == "sys.modules.get" and node.args:
                return self.fold(node.args[0])
            if func in {"builtins.__import__", "importlib.import_module"} and node.args:
                name = self.fold(node.args[0])
                return name if name and not name.startswith(".") else None
            if func == "builtins.getattr" and len(node.args) >= 2:
                base, name = self.qual(node.args[0], depth + 1), self.fold(node.args[1])
                return f"{base}.{name}" if base and name else None
            if func == "builtins.vars" and node.args:
                base = self.qual(node.args[0], depth + 1)
                return f"{base}.__dict__" if base else None
            return None
        if isinstance(node, ast.Subscript):
            key = self.fold(node.slice)
            if key == "__builtins__":
                return "builtins"
            base = self.qual(node.value, depth + 1)
            if base == "sys.modules":
                return key                   # sys.modules['builtins'] is the module itself
            if key is None or base is None:
                return None
            return f"{base[:-len('.__dict__')] if base.endswith('.__dict__') else base}.{key}"
        return None

    def fold(self, node: ast.AST, depth: int = 0) -> Optional[str]:
        """The constant string *node* evaluates to (literals, ``+``, f-strings of constants,
        ``''.join([...])``, ``os.sep``, a name assigned once), or None; never longer than
        ``_FOLD_LIMIT``."""
        if depth > _MAX_DEPTH:
            return None
        value = self.remembered("fold", node, lambda: self._fold(node, depth))
        return value if value is None or len(value) <= _FOLD_LIMIT else None

    def _fold(self, node: ast.AST, depth: int) -> Optional[str]:
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.JoinedStr):
            parts = [self.fold(v.value if isinstance(v, ast.FormattedValue) else v, depth + 1) for v in node.values]
            return None if None in parts else "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.fold(node.left, depth + 1), self.fold(node.right, depth + 1)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
                and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) \
                and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
            parts = [self.fold(e, depth + 1) for e in node.args[0].elts]
            return None if None in parts else node.func.value.value.join(parts)
        if isinstance(node, ast.Name):
            value = self.single_value(node)
            return self.fold(value, depth + 1) if value is not None else None
        if isinstance(node, ast.Attribute) and node.attr == "sep" and self.qual(node) in {"os.sep", "os.path.sep"}:
            return "/"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):       # 'payload.%s' % 'py'
            left = self.fold(node.left, depth + 1)
            right = [self.fold(e, depth + 1) for e in node.right.elts] if isinstance(node.right, ast.Tuple) \
                else [self.fold(node.right, depth + 1)]
            if left is None or None in right or len(left) > _FOLD_LIMIT:
                return None
            try:
                return left % tuple(right)
            except (TypeError, ValueError):
                return None
        return None

    # ── paths ───────────────────────────────────────────────────────────────────────────────

    def tail(self, node: ast.AST, depth: int = 0) -> Optional[str]:
        """The last literal piece of a path expression (what decides its file name), through names
        assigned once and loops over a glob; None when it does not end in one."""
        if depth > _MAX_DEPTH:
            return None
        folded = self.fold(node)
        if folded is not None:
            return folded
        if isinstance(node, ast.Name):
            value = self.single_value(node)
            if value is not None:
                return self.tail(value, depth + 1)
            found = self.lookup(node)
            if found is not None and len(found.iters) == 1 and not (found.values or found.other or found.imported):
                return self.tail(found.iters[0], depth + 1)
            return None
        return _literal_tail(node, lambda sub: self.tail(sub, depth + 1))

    def ups(self, node: ast.AST, depth: int = 0) -> Optional[int]:
        """How many directories above the file's own directory a path expression is rooted, when it
        is built from ``__file__`` (``dirname(__file__)`` is 0, each further ``dirname``/``.parent``
        or ``..`` one more); None when it is not built from this file's location, or a literal piece
        is absolute (``os.path.join(HERE, '/tmp/x')`` discards HERE)."""
        if depth > _MAX_DEPTH:
            return None
        if self.is_own_file(node):
            return -1
        if isinstance(node, ast.Name):
            if node.id == "__path__":
                return 0
            found = self.lookup(node)
            if found is None or found.other or found.imported:
                return None
            values = [v for v in found.values if not _is_none(v)] + found.iters
            if not values:
                return None
            found = [self.ups(v, depth + 1) for v in values]
            return None if None in found else max(found)
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                base = self.ups(node.value, depth + 1)
                return None if base is None else base + 1
            if node.attr == "origin" and isinstance(node.value, ast.Name) and node.value.id == "__spec__":
                return -1
            return None
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
                base = self.ups(node.value.value, depth + 1)
                index = node.slice.value if isinstance(node.slice, ast.Constant) else None
                return None if base is None or not isinstance(index, int) else base + index + 1
            if isinstance(node.value, ast.Name) and node.value.id == "__path__":
                return 0
            return None
        if isinstance(node, ast.JoinedStr):
            if not node.values or not isinstance(node.values[0], ast.FormattedValue):
                return None
            base = self.ups(node.values[0].value, depth + 1)
            return self.climb(base, [v for v in node.values[1:] if isinstance(v, ast.Constant)])
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            base = self.ups(node.left, depth + 1)
            return self.climb(base, [node.right])
        if isinstance(node, ast.Call):
            func = node.func
            name = self.call_name(func)
            if name in _UP_CALLS and node.args:
                base = self.ups(node.args[0], depth + 1)
                return None if base is None else base + 1
            if name == "join" and node.args:
                return self.climb(self.ups(node.args[0], depth + 1), node.args[1:])
            if name == "files":           # importlib.resources.files(__package__)
                return 0 if any(isinstance(n, ast.Name) and n.id in {"__package__", "__name__"}
                                for n in ast.walk(node)) else None
            if name in _SAME_DIR_CALLS:
                if isinstance(func, ast.Attribute) and name not in {"Path", "PurePath", "str", "fspath", "abspath",
                                                                     "realpath", "normpath", "files"}:
                    return self.climb(self.ups(func.value, depth + 1), node.args)
                if node.args:
                    return self.climb(self.ups(node.args[0], depth + 1), node.args[1:])
            return None
        return None

    def climb(self, base: Optional[int], pieces: List[ast.AST]) -> Optional[int]:
        """*base* moved by the literal path pieces after it: ``..`` climbs, an absolute piece escapes."""
        if base is None:
            return None
        for piece in pieces:
            text = self.fold(piece)
            if text is None:
                continue          # a computed piece below the anchor: the file name is unknown, not the root
            if text.startswith(("/", "\\", "~")) or re.match(r"^[A-Za-z]:[\\/]", text):
                return None
            base += sum(1 for part in re.split(r"[\\/]+", text) if part == "..")
        return base

    def locate(self, node: ast.AST, depth: int = 0) -> Optional[List[str]]:
        """The plugin-relative path a path expression names, when it is built from ``__file__`` and
        every piece after the anchor is a constant; None otherwise (or when it leaves the plugin)."""
        if depth > _MAX_DEPTH or "!/" in self.rel:
            return None
        parts = self.remembered("locate", node, lambda: self._locate(node, depth))
        if parts is None:
            return None
        out: List[str] = []
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                if not out:
                    return None
                out.pop()
            else:
                out.append(part)
        return out

    def _locate(self, node: ast.AST, depth: int) -> Optional[List[str]]:
        here = self.rel.split("/")
        def pieces(base, rest):
            if base is None:
                return None
            out = list(base)
            for piece in rest:
                text = self.fold(piece)
                if text is None or text.startswith(("/", "\\", "~")) or re.match(r"^[A-Za-z]:[\\/]", text):
                    return None
                out.extend(re.split(r"[\\/]+", text))
            return out
        if self.is_own_file(node):
            return here
        if isinstance(node, ast.Name):
            if node.id == "__path__":
                return here[:-1]
            value = self.single_value(node)
            return self.locate(value, depth + 1) if value is not None else None
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                base = self.locate(node.value, depth + 1)
                return base[:-1] if base else None
            if node.attr == "origin" and isinstance(node.value, ast.Name) and node.value.id == "__spec__":
                return here
            return None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
            base = self.locate(node.value.value, depth + 1)
            index = node.slice.value if isinstance(node.slice, ast.Constant) else None
            return base[:-(index + 1)] if base and isinstance(index, int) and index + 1 <= len(base) else None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "__path__":
            return here[:-1]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return pieces(self.locate(node.left, depth + 1), [node.right])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            base, text = self.locate(node.left, depth + 1), self.fold(node.right)
            if base is None or text is None:
                return None
            if text.startswith(("/", "\\")):
                return base + re.split(r"[\\/]+", text.lstrip("/\\"))
            return base[:-1] + [base[-1] + text] if base else None
        if isinstance(node, ast.Call):
            func = node.func
            name = self.call_name(func)
            if name in _UP_CALLS and node.args:
                base = self.locate(node.args[0], depth + 1)
                return base[:-1] if base else None
            if name == "with_name" and isinstance(func, ast.Attribute) and node.args:
                base, text = self.locate(func.value, depth + 1), self.fold(node.args[0])
                return base[:-1] + [text] if base and text else None
            if name in ("join", "Path", "PurePath", "PosixPath", "WindowsPath", "joinpath") and (
                    node.args or isinstance(func, ast.Attribute)):
                if isinstance(func, ast.Attribute) and name == "joinpath":
                    return pieces(self.locate(func.value, depth + 1), node.args)
                return pieces(self.locate(node.args[0], depth + 1), node.args[1:]) if node.args else None
            if name in {"str", "fspath", "abspath", "realpath", "normpath", "resolve", "absolute"}:
                if node.args:
                    return self.locate(node.args[0], depth + 1)
                if isinstance(func, ast.Attribute):
                    return self.locate(func.value, depth + 1)
            return None
        return None

    def ships(self, parts: List[str]) -> bool:
        """Whether the plugin ships the file or directory at *parts* (unknown tree: assume it does)."""
        if self.tree_files is None:
            return True
        path = "/".join(parts)
        return path in self.tree_files or path in self.tree_dirs or path == ""

    def ships_module(self, parts: List[str]) -> bool:
        """Whether the plugin ships the module *parts* (a .py, a package, a namespace directory or a
        native extension module named like it)."""
        if self.tree_files is None:
            return True
        path = "/".join(parts)
        if path in self.tree_dirs or f"{path}.py" in self.tree_files or f"{path}.pyw" in self.tree_files:
            return True
        prefix = path + "."
        return any(f.startswith(prefix) and "/" not in f[len(prefix):] for f in self.tree_files)

    def package(self) -> List[str]:
        parts = self.rel.split("/")
        return parts[:-1]

    def inside_plugin(self, node: ast.AST) -> bool:
        up = self.ups(node)
        return up is not None and up <= self.depth

    # ── checks ──────────────────────────────────────────────────────────────────────────────

    def check(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            self.check_call(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.check_store(target, node)
        elif isinstance(node, ast.ClassDef):
            self.check_class(node)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None and self.fold(key) in _PYTHON_ENV_KEYS:
                    self.check_python_env(value, node)
        elif isinstance(node, ast.ImportFrom) and node.level:
            self.check_relative_module(node.level, node.module or "",
                                       tuple(a.name for a in node.names if a.name != "*"), node)
        elif isinstance(node, (ast.List, ast.Tuple)):
            self.check_interpreter_argv(node)
            self.check_shell(list(node.elts), node)
            self.check_code_flags(list(node.elts), node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node not in self.prose:
            self.check_string(node.value.strip(), node)
        elif isinstance(node, (ast.BinOp, ast.JoinedStr)) and not isinstance(self.parents.get(node), ast.BinOp):
            folded = self.fold(node)
            if folded is not None:
                self.check_string(folded.strip(), node)
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            self.check_reference(node)
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) \
                and self.qual(node.value) == "sys.modules" and not self.own_module_name(node.slice):
            self.add("sys_modules_lookup", node)
        if isinstance(node, ast.Attribute):
            if node.attr in _FRAME_NAMESPACES:
                self.add("exec_dynamic_code", node)       # a frame's builtins/globals: exec by another name
            elif node.attr == "__self__" and any(
                    isinstance(n, ast.Name) and (self.qual(n) or "").startswith("builtins.") for n in ast.walk(node.value)):
                self.add("exec_dynamic_code", node)       # len.__self__, type(len).__self__: the builtins module
            elif node.attr in _NATIVE_LOADER_ATTRS:
                self.add("native_load", node)
            if node.attr in _DISTINCT_NAMES and node.attr != "__builtins__":
                self.add(_DISTINCT_NAMES[node.attr], node)
            elif node.attr.startswith(_C_API_RUNNERS):
                self.add("code_runner", node)
            elif node.attr == "__code__" and isinstance(node.ctx, ast.Store):
                self.add("code_object", node)
            elif node.attr == "replace" and isinstance(node.value, ast.Attribute) and node.value.attr == "__code__":
                self.add("code_object", node)
        elif isinstance(node, ast.Name) and node.id in _DISTINCT_NAMES and node.id != "__builtins__" \
                and not (self.lookup(node) is not None and self.lookup(node).other):
            self.add(_DISTINCT_NAMES[node.id], node)

    def own_module_name(self, key: ast.AST) -> bool:
        """``sys.modules[__name__]``: the module itself. Any other key the scan can fold is resolved by
        ``qual``; a key it cannot is a module reached by a computed name."""
        if self.fold(key) is not None:
            return True
        return isinstance(key, ast.Name) and key.id in {"__name__", "__package__"} or (
            isinstance(key, ast.Attribute) and key.attr == "name" and isinstance(key.value, ast.Name)
            and key.value.id == "__spec__")

    def check_string(self, value: str, node: ast.AST) -> None:
        """A constant (or concatenated) string that names a route: ``getattr(m, 'zip' + 'importer')``."""
        if value in _DISTINCT_NAMES:
            self.add(_DISTINCT_NAMES[value], node)
        elif value.startswith(_C_API_RUNNERS):
            self.add("code_runner", node)

    def check_reference(self, node: ast.AST) -> None:
        """Every reference to a code runner by any spelling the scan can follow. A direct call with a
        literal source is left to the pattern scan; anything else (an alias, ``map(exec, ...)``,
        ``partial(exec)``) is a finding."""
        if isinstance(getattr(node, "ctx", None), ast.Store) or isinstance(getattr(node, "ctx", None), ast.Del):
            return
        name = self.qual(node)
        if name is None:
            return
        parent = self.parents.get(node)
        called = isinstance(parent, ast.Call) and parent.func is node
        if name in {"builtins.exec", "builtins.eval", "builtins.compile"}:
            runner = name.split(".")[1]
            if not called:
                self.add("compile_dynamic_code" if runner == "compile" else "exec_dynamic_code", node)
            elif runner == "compile":
                # In any mode: an 'eval'-mode code object runs under exec() as well as eval().
                source = _argument(parent, 0, "source")
                if not (source is not None and _is_literal(source)):
                    self.add("compile_dynamic_code", parent)
            else:
                source = _argument(parent, 0, "source")
                if source is None or not _is_literal(source):
                    self.add("exec_dynamic_code", parent)     # exec(*parts) is dynamic too
        elif name == "builtins":
            # The builtins module itself, other than for one of its names spelled out.
            if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr != "__dict__":
                return
            if isinstance(parent, (ast.Subscript, ast.Call)) and self.qual(parent) is not None \
                    and self.qual(parent).split(".")[-1] not in {"__dict__"}:
                return            # builtins['open'] / getattr(builtins, 'open'): judged by that name
            self.add("exec_dynamic_code", node)
        elif name == "builtins.__dict__":
            self.add("exec_dynamic_code", node)
        elif name in _DESERIALIZERS:
            self.add(_DESERIALIZERS[name], node)
        elif name in _CODE_MACHINERY:
            self.add(_CODE_MACHINERY[name], node)
        elif name in _STRING_RUNNERS:
            if not called:
                self.add("code_runner", node)
                return
            statements = [a for a in (_argument(parent, 0, "stmt"), _argument(parent, 1, "setup")) if a is not None] \
                if name.startswith("timeit.") else [a for a in (_argument(parent, 0, "cmd"),) if a is not None]
            if any(not _is_literal(a) and not isinstance(a, ast.Lambda) for a in statements):
                self.add("code_runner", parent)
        elif name in _IMPORT_HOOKS and isinstance(parent, ast.Attribute) and parent.attr in _MUTATORS:
            self.add("import_hook_change", parent)
        elif name in _NATIVE_LOADERS or name.startswith("cffi.") and name.endswith(".dlopen"):
            self.add("native_load", node)
        elif name == "sys.modules.get" and called and parent.args and not self.own_module_name(parent.args[0]):
            self.add("sys_modules_lookup", parent)

    def check_python_env(self, value: Optional[ast.AST], where: ast.AST) -> None:
        """PYTHONPATH (and kin) set to something that is neither a constant nor a path in the plugin:
        the out-of-process twin of ``foreign_sys_path``, reported as a tripwire (medium)."""
        if value is not None and self.fold(value) is None and not self.inside_plugin(value):
            self.add("foreign_python_path", where)

    def check_store(self, target: ast.AST, statement: ast.AST) -> None:
        """An assignment to ``sys.path`` (or a slice of it), or to the import machinery at all."""
        if isinstance(target, ast.Subscript) and self.fold(target.slice) in _PYTHON_ENV_KEYS \
                and getattr(statement, "value", None) is not None:
            self.check_python_env(statement.value, statement)     # env["PYTHONPATH"] = root
        base = target.value if isinstance(target, ast.Subscript) else target
        name = self.qual(base)
        if name in _IMPORT_HOOKS:
            self.add("import_hook_change", statement)
        elif name == "sys.path" and statement.value is not None:
            self.check_sys_path(self.added_paths(statement.value), statement)

    def added_paths(self, value: ast.AST) -> List[ast.AST]:
        """The path expressions *value* adds to ``sys.path``: the elements of a list or tuple, both
        sides of a ``+`` (``sys.path`` itself excepted), else *value* itself."""
        if isinstance(value, (ast.List, ast.Tuple)):
            return list(value.elts)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return self.added_paths(value.left) + self.added_paths(value.right)
        if self.qual(value) == "sys.path":
            return []
        if isinstance(value, (ast.ListComp, ast.GeneratorExp)) and any(
                self.qual(gen.iter) == "sys.path" for gen in value.generators):
            return []          # sys.path filtered: nothing added
        return [value]

    def check_sys_path(self, paths: List[ast.AST], where: ast.AST) -> None:
        for path in paths:
            tail = self.tail(path)
            if _mentions_archive(path) or (tail is not None and _suffix(tail)):
                self.add("archive_on_sys_path", where)
            elif not self.inside_plugin(path):
                self.add("foreign_sys_path", where)

    def check_class(self, node: ast.ClassDef) -> None:
        bases = []
        for base in node.bases:
            name = self.qual(base) or (base.attr if isinstance(base, ast.Attribute) else
                                       base.id if isinstance(base, ast.Name) else "")
            bases.append(name.split(".")[-1])
        methods = {item.name for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if any(b.endswith(_LOADER_BASE_SUFFIXES) for b in bases) or methods & _LOADER_METHODS \
                or {"get_data", "get_filename"} <= methods:
            self.add("custom_loader", node)

    def is_interpreter(self, node: ast.AST) -> bool:
        return self.qual(node) == "sys.executable" or _PYTHON_EXE.search(self.fold(node) or "") is not None

    def check_interpreter_argv(self, node: ast.AST) -> None:
        """``[sys.executable, '-c', src]`` with a computed *src*, ``[sys.executable, '-']`` (code on
        stdin), and, in a file that names an interpreter at all, ``['-c', src]`` built step by step."""
        elts = node.elts
        for i, elt in enumerate(elts):
            if self.is_interpreter(elt) and i + 1 < len(elts) and self.fold(elts[i + 1]) == "-":
                self.add("interpreter_code", node)
            if self.fold(elt) == "-c" and i + 1 < len(elts) and not _is_literal(elts[i + 1]) and (
                    (i > 0 and self.is_interpreter(elts[i - 1])) or self.mentions_interpreter):
                self.add("interpreter_code", node)

    def check_call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        qualified = self.qual(func) or ""
        if isinstance(func, ast.Attribute) and func.attr in {"insert", "append", "extend", "__iadd__"} \
                and self.qual(func.value) == "sys.path":
            added = _argument(node, 1 if func.attr == "insert" else 0, "object")
            if added is not None:
                self.check_sys_path(self.added_paths(added) if func.attr == "extend" else [added], node)
        if (qualified == "site.addsitedir" or name == "addsitedir") and node.args:
            self.check_sys_path([node.args[0]], node)
        if qualified == "builtins.setattr" and len(node.args) >= 2 and self.qual(node.args[0]) == "sys" \
                and f"sys.{self.fold(node.args[1])}" in _IMPORT_HOOKS:
            self.add("import_hook_change", node)
        if name in _STRING_RUNNER_METHODS and isinstance(func, ast.Attribute) and node.args \
                and not _is_literal(node.args[0]):
            self.add("code_runner", node)
        if name in {"load_compiled", "load_dynamic"}:
            self.add("bytecode_or_native_loader", node)
        if name in _FILE_LOADERS:
            position, keyword = _FILE_LOADERS[name]
            path = _argument(node, position, keyword)
            if path is not None:
                tail = self.tail(path)
                located = self.locate(path)
                if tail is not None and _suffix(tail) not in PYTHON_SOURCE_EXTENSIONS:
                    self.add("non_source_loader", node)
                elif not self.inside_plugin(path):
                    self.add("foreign_source_loader", node)
                elif located is not None and not self.ships(located):
                    self.add("missing_module", node)
                elif tail is None:
                    self.add("dynamic_source_loader", node)
        if qualified in {"importlib.import_module", "builtins.__import__"} and node.args:
            target = self.fold(node.args[0])
            if target and target.startswith("."):
                level = len(target) - len(target.lstrip("."))
                self.check_relative_module(level, target.lstrip("."), (), node)
        self.check_write(node, name, qualified)
        self.check_process(node, qualified)
        for keyword in node.keywords:       # dict(os.environ, PYTHONPATH=root), env.update(PYTHONPATH=root)
            if keyword.arg in _PYTHON_ENV_KEYS:
                self.check_python_env(keyword.value, node)
        if name in {"setdefault", "putenv"} and len(node.args) >= 2 and self.fold(node.args[0]) in _PYTHON_ENV_KEYS:
            self.check_python_env(node.args[1], node)

    def check_relative_module(self, level: int, module: str, names: Tuple[str, ...], node: ast.AST) -> None:
        """A relative import of something the plugin does not ship: code written at run time."""
        if self.tree_files is None or "!/" in self.rel:
            return
        package = self.package()
        if level - 1 > len(package):
            return
        base = package[:len(package) - (level - 1)] + ([p for p in module.split(".") if p] if module else [])
        if module and not self.ships_module(base):
            self.add_missing(node)
            return
        if module:
            return            # from .x import name: name is an attribute of x as often as a submodule
        defined = self.package_names.get("/".join(base))
        for item in names:
            if not self.ships_module(base + [item]) and (defined is None or item not in defined):
                self.add_missing(node)

    def add_missing(self, node: ast.AST) -> None:
        """``missing_module``, high even inside ``try: ... except ImportError`` (an optional import
        looks the same as a module written at run time, and the scan cannot tell them apart)."""
        self.add("missing_module", node)

    def method_call(self, node: ast.Call) -> Tuple[Optional[str], Optional[ast.AST], List[ast.AST]]:
        """``(method, object, arguments)`` for a call of a method on an object, by any spelling the
        scan can follow: ``p.write_text(x)``, ``getattr(p, 'write_text')(x)``, ``w = getattr(...);
        w(x)``, and the unbound ``pathlib.Path.write_text(p, x)``."""
        func = node.func
        if isinstance(func, ast.Name):
            func = self.single_value(func) or func
        if isinstance(func, ast.Call) and self.qual(func.func) == "builtins.getattr" and len(func.args) >= 2:
            return self.fold(func.args[1]), func.args[0], list(node.args)
        qualified = self.qual(func) or ""
        if qualified.startswith(("pathlib.Path.", "pathlib.PosixPath.", "pathlib.WindowsPath.")) and node.args:
            return qualified.rsplit(".", 1)[-1], node.args[0], list(node.args[1:])
        if isinstance(func, ast.Attribute) and not qualified:
            return func.attr, func.value, list(node.args)
        return None, None, []

    def check_write(self, node: ast.Call, name: Optional[str], qualified: str) -> None:
        """A write whose destination Python can import, or that lands in the plugin's own directory:
        ``open``/``io.open``/``codecs.open`` and the compressed-file openers in a write mode,
        ``Path.open`` in a write mode, ``os.open`` with write flags, ``write_text``/``write_bytes``,
        ``rename``/``replace`` onto a path, copies, moves, links, archive extraction, ``tempfile``
        files made in the plugin or with an importable suffix, and a process given a path in the
        plugin (``pip install --target``, ``cp``)."""
        targets: List[ast.AST] = []
        method, obj, arguments = self.method_call(node)
        keywords = {kw.arg for kw in node.keywords}
        if qualified in _FILE_OPENERS or (name == "open" and isinstance(node.func, ast.Name)):
            if self.writes_mode(_argument(node, 1, "mode")):
                targets = [t for t in (_argument(node, 0, "file") or _argument(node, 0, "name")
                                       or _argument(node, 0, "filename"),) if t is not None]
        elif qualified == "os.open":
            if self.writes_flags(_argument(node, 1, "flags")):
                targets = [t for t in (_argument(node, 0, "path"),) if t is not None]
        elif method == "open" and obj is not None:
            # Path(...).open(mode): the object is the path, the mode is the first argument.
            mode = arguments[0] if arguments else next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
            text = self.fold(mode) if mode is not None else None
            if text is not None and not set(text) <= set("rwxabt+U"):
                return            # ZipFile(...).open(name): the first argument is not a mode
            if self.writes_mode(mode):
                targets = [obj]
        elif method in _PATH_WRITE_METHODS and obj is not None and not qualified.startswith(("zipfile.", "tarfile.")):
            targets = [obj]
        elif method in _PATH_MOVE_METHODS and obj is not None and len(arguments) == 1 and keywords <= {"target"}:
            targets = arguments                 # Path.rename(dst): str.replace takes two arguments
        elif name in _TEMPFILE_MAKERS and qualified.startswith("tempfile."):
            suffix_at, dir_at = _TEMPFILE_MAKERS[name]
            suffix, folder = _argument(node, suffix_at, "suffix"), _argument(node, dir_at, "dir")
            folded = self.fold(suffix) if suffix is not None else None
            if (folded is not None and _suffix("x" + folded) in _IMPORTABLE_SUFFIXES) or (
                    folder is not None and (self.locate(folder) is not None or self.inside_plugin(folder))):
                self.add("code_written", node)
            return
        elif name in _WRITERS and (qualified.startswith(("shutil.", "os.", "tarfile.", "zipfile."))
                                   or name in {"extractall", "extract", "copyfile", "copytree", "unpack_archive"}):
            position, keyword = _WRITERS[name]
            target = _argument(node, position, keyword)
            if target is None and name == "extractall":
                return            # into the working directory: not importable from the plugin by itself
            targets = [target] if target is not None else []
        elif self.is_process_call(qualified):
            argv = self.argv_of(node, qualified) or []
            run = self.runs_from(argv)
            cwd = _argument(node, 99, "cwd")
            targets = [a for i, a in enumerate(argv) if i not in run and not isinstance(a, ast.Starred)]
            targets += [cwd] if cwd is not None else []
            if any(self.inside_plugin(t) for t in targets):
                self.add("code_written", node)
            return
        for target in targets:
            if self.writes_code(target):
                self.add("code_written", node)
                return

    def writes_code(self, target: ast.AST) -> bool:
        """A destination with an importable suffix, or in the plugin's own directory: located there,
        or anchored there with a last part that is not one whole literal (``HERE / ('a.' + x)``)."""
        tail = self.tail(target)
        if tail is not None and _suffix(tail) in _IMPORTABLE_SUFFIXES:
            return True
        if self.locate(target) is not None:
            return True
        return self.inside_plugin(target) and self.fold(self.last_part(target)) is None

    def last_part(self, node: ast.AST, depth: int = 0) -> ast.AST:
        """The expression that names the last component of a path expression."""
        if depth > _MAX_DEPTH:
            return node
        if isinstance(node, ast.Name):
            value = self.single_value(node)
            return self.last_part(value, depth + 1) if value is not None else node
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return node.right
        if isinstance(node, ast.Call):
            name = self.call_name(node.func)
            if name in {"join", "Path", "PurePath", "joinpath"} and node.args:
                return node.args[-1]
            if name in {"str", "fspath", "abspath", "realpath", "normpath"} and node.args:
                return self.last_part(node.args[0], depth + 1)
            if name in {"resolve", "absolute"} and isinstance(node.func, ast.Attribute):
                return self.last_part(node.func.value, depth + 1)
        return node

    def writes_mode(self, mode: Optional[ast.AST]) -> bool:
        """Whether an open() mode writes: absent is read, a mode the scan cannot fold may write."""
        if mode is None:
            return False
        text = self.fold(mode)
        return text is None or bool(set(text) & set("wax+"))

    def writes_flags(self, flags: Optional[ast.AST]) -> bool:
        """Whether ``os.open`` flags may write: any write flag named, or flags the scan cannot read."""
        if flags is None:
            return False
        names = {n.attr if isinstance(n, ast.Attribute) else n.id for n in ast.walk(flags)
                 if isinstance(n, (ast.Attribute, ast.Name))}
        if names & _OS_WRITE_FLAGS:
            return True
        return not (names and names <= {"os", "O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_BINARY", "O_NONBLOCK"})

    # ── shells ──────────────────────────────────────────────────────────────────────────────

    def text(self, item) -> Optional[str]:
        """An argv item's constant text (*item* is an expression, or a str split out of ``env -S``)."""
        return item if isinstance(item, str) else self.fold(item)

    def program(self, node) -> str:
        """The base name of a program an argv item names (``/bin/bash`` -> ``bash``), through a name
        assigned once and ``shutil.which``; "" when unknown."""
        if isinstance(node, str):
            return _basename(node)
        if isinstance(node, ast.Name):
            node = self.single_value(node) or node
        text = self.fold(node)
        if text is None and isinstance(node, ast.Call) and self.qual(node.func) == "shutil.which" and node.args:
            text = self.fold(node.args[0])
        return _basename(text)

    def is_shell(self, node: ast.AST) -> bool:
        return self.program(node) in _SHELLS

    def is_process_call(self, qualified: str) -> bool:
        return qualified.startswith(_PROCESS_PREFIXES) or qualified == "pty.spawn"

    def argv_of(self, node: ast.Call, qualified: str) -> Optional[List[ast.AST]]:
        """The argv a process call runs, as expressions: a list or tuple literal, a name assigned one
        (``argv += [...]`` included), or the call's own arguments (``os.execl``/``os.spawnl``)."""
        short = qualified.rsplit(".", 1)[-1]
        if qualified.startswith("os.") and short.startswith(("execl", "spawnl")):
            skip = 2 if short.startswith("spawn") else 1
            return [a for a in node.args[skip:] if not (short.endswith("e") and a is node.args[-1])]
        if qualified.startswith("os.") and short.startswith(("execv", "spawnv", "posix_spawn")):
            index = 2 if short.startswith("spawn") else 1
            return self.expand(node.args[index]) if len(node.args) > index else None
        if qualified == "asyncio.create_subprocess_exec":
            return list(node.args)
        argv = node.args[0] if node.args else _argument(node, 0, "args")
        return self.expand(argv) if argv is not None else None

    def expand(self, node: ast.AST) -> Optional[List[ast.AST]]:
        if isinstance(node, (ast.List, ast.Tuple)):
            return list(node.elts)
        if isinstance(node, ast.Name):
            found = self.lookup(node)
            if found is None or found.other or found.imported or found.iters or not found.values:
                return None
            items: List[ast.AST] = []
            for value in found.values:
                value = value.value if isinstance(value, ast.AugAssign) else value
                if not isinstance(value, (ast.List, ast.Tuple)):
                    return None
                items.extend(value.elts)
            return items
        return [node]

    def runs_from(self, argv: List[ast.AST]) -> Set[int]:
        """Indexes of the argv items that name what runs (the program, and the script or module an
        interpreter or shell is given): those are read, not written."""
        run = {0}
        if argv and (self.is_interpreter(argv[0]) or self.is_shell(argv[0])):
            for i, item in enumerate(argv[1:], start=1):
                flag = self.fold(item)
                if flag is None or not flag.startswith("-"):
                    run.add(i)
                    break
        return run

    def shell_target(self, argv: List[ast.AST]) -> Tuple[str, Optional[ast.AST]]:
        """What a shell in *argv* runs: ``("command", node)`` for ``-c``, ``("script", node)`` for a
        script path, ``("stdin", None)`` when it reads its commands from stdin; ``("", None)`` when
        *argv* does not run a shell. Handles ``env [opts] [VAR=x] [-S 'sh -c']``, ``busybox sh``,
        options with an argument (``-o pipefail``), long options and ``--``."""
        items = list(argv)
        i = 0
        while i < len(items) and self.program(items[i]) in {"env", "busybox"}:
            if self.program(items[i]) == "busybox":
                i += 1
                continue
            i += 1
            while i < len(items):
                text = self.text(items[i]) or ""
                if text in {"-S", "--split-string"} and i + 1 < len(items) and self.text(items[i + 1]):
                    items = items[:i] + self.text(items[i + 1]).split() + items[i + 2:]
                    break
                if text.startswith("-") or "=" in text:
                    i += 1 + (text in {"-u", "--unset", "-C", "--chdir"})
                    continue
                break
        if i >= len(items) or not self.is_shell(items[i]):
            return "", None
        j = i + 1
        while j < len(items):
            flag = self.text(items[j])
            if flag == "--":
                return ("script", items[j + 1]) if j + 1 < len(items) else ("stdin", None)
            if flag is None or not flag.startswith(("-", "+")):
                return "script", items[j]
            if flag in _SHELL_OPTIONS_WITH_ARGUMENT:
                j += 2
                continue
            if flag.startswith("--"):
                j += 1
                continue
            if "c" in flag[1:]:
                return ("command", items[j + 1]) if j + 1 < len(items) else ("", None)
            if "s" in flag[1:]:
                return "stdin", None
            j += 1
        return "stdin", None

    def check_shell(self, argv: List[ast.AST], where: ast.AST, call: Optional[ast.Call] = None) -> None:
        kind, target = self.shell_target(argv)
        if kind == "command" and self.text(target) is None:
            self.add("shell_code", where)
        elif kind == "script" and self.text(target) is None and self.locate(target) is None:
            self.add("shell_code", where)
        elif kind == "stdin" and call is not None and _argument(call, 99, "input") is not None \
                and self.fold(_argument(call, 99, "input")) is None:
            self.add("shell_code", where)

    def check_code_flags(self, argv: List[ast.AST], where: ast.AST) -> None:
        """``perl -e``, ``node -e``, ``ruby -e`` ... with a computed script."""
        for i, item in enumerate(argv):
            flags = _CODE_FLAGS.get(self.program(item))
            if flags is None:
                continue
            for j in range(i + 1, len(argv) - 1):
                if self.fold(argv[j]) in flags and self.fold(argv[j + 1]) is None:
                    self.add("interpreter_code", where)
                    return
            if not flags and i + 1 < len(argv) and self.fold(argv[i + 1]) is None:
                self.add("interpreter_code", where)    # awk/tclsh: the first argument is the program
            return

    def check_process(self, node: ast.Call, qualified: str) -> None:
        """A shell or another interpreter run on something the scan cannot read."""
        if qualified in _SHELL_STRING_CALLS:
            command = _argument(node, 0, "cmd") or _argument(node, 0, "command")
            if command is not None and self.fold(command) is None:
                self.add("shell_code", node)
            return
        if not self.is_process_call(qualified):
            return
        shell = _argument(node, 99, "shell")
        if shell is not None and not (isinstance(shell, ast.Constant) and not shell.value):
            command = node.args[0] if node.args else _argument(node, 0, "args")
            if isinstance(command, (ast.List, ast.Tuple)):
                command = command.elts[0] if command.elts else None
            if command is not None and self.fold(command) is None:
                self.add("shell_code", node)
            return
        argv = self.argv_of(node, qualified)
        if argv:
            self.check_shell(argv, node, node)
            self.check_code_flags(argv, node)
            if self.is_interpreter(argv[0]) and len(argv) == 1 and _argument(node, 99, "input") is not None:
                self.add("interpreter_code", node)    # python reading its program from input=

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.Module)


@dataclass
class _Binding:
    """How a name is bound in one scope: assigned *values*, loop *iters*, *imported* names, or
    *other* (an argument, a def, a tuple target ...: nothing the scan can follow)."""
    values: List[ast.AST] = field(default_factory=list)
    iters: List[ast.AST] = field(default_factory=list)
    imported: List[str] = field(default_factory=list)
    other: bool = False


@dataclass
class ModuleRefs:
    """What a Python file can make the interpreter load from the plugin: relative imports as
    ``(level, module parts, imported names)``, absolute imports as dotted parts, plugin-relative
    *paths* it loads or runs, every string constant (a module or file name can be built from one),
    and *dynamic* when it imports, loads or runs something the scan cannot name as one complete
    constant."""
    relative: List[Tuple[int, Tuple[str, ...], Tuple[str, ...]]] = field(default_factory=list)
    absolute: List[Tuple[str, ...]] = field(default_factory=list)
    paths: Set[str] = field(default_factory=set)
    strings: Set[str] = field(default_factory=set)
    dynamic: bool = False


_MODULE_IMPORTERS = {"importlib.import_module", "builtins.__import__", "importlib.util.find_spec",
                     "runpy.run_module"}
_MODULE_IMPORTER_NAMES = {"import_module", "__import__", "find_spec", "run_module", "iter_modules", "walk_packages"}
_PROCESS_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn", "os.system", "os.popen",
                     "asyncio.create_subprocess", "pty.spawn")


def module_refs(text: str, rel: str = "__init__.py") -> Optional[ModuleRefs]:
    """The ``ModuleRefs`` of Python *text* (the file at *rel*), or None when it does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    reader = _CodeReader(text, rel, tree)
    reader.prepare()
    refs = ModuleRefs()
    for node in reader.nodes:
        if isinstance(node, ast.Import):
            refs.absolute.extend(tuple(alias.name.split(".")) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = tuple(node.module.split(".")) if node.module else ()
            names = tuple(alias.name for alias in node.names if alias.name != "*")
            if node.level:
                refs.relative.append((node.level, module, names))
            else:
                refs.absolute.extend([module] + [module + (name,) for name in names])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            refs.strings.add(node.value)
        elif isinstance(node, ast.Call):
            _call_refs(reader, node, refs)
    return refs


def _call_refs(reader: "_CodeReader", node: ast.Call, refs: ModuleRefs) -> None:
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    qualified = reader.qual(func) or ""

    def constant(arg: Optional[ast.AST]) -> bool:
        """Whether *arg* is one complete constant (a string, or a path in the plugin), noting it."""
        if arg is None:
            return False
        located = reader.locate(arg)
        if located is not None:
            refs.paths.add("/".join(located))
            return True
        folded = reader.fold(arg)
        if folded is not None:
            refs.strings.add(folded)
            return True
        return False

    if qualified in _MODULE_IMPORTERS or name in _MODULE_IMPORTER_NAMES:
        target = _argument(node, 0, "name")
        folded = reader.fold(target) if target is not None else None
        if name in {"iter_modules", "walk_packages"} or folded is None:
            refs.dynamic = True
            return
        refs.strings.add(folded)
        if folded.startswith("."):
            level = len(folded) - len(folded.lstrip("."))
            refs.relative.append((level, tuple(p for p in folded.lstrip(".").split(".") if p), ()))
        else:
            refs.absolute.append(tuple(folded.split(".")))
    elif name in _FILE_LOADERS:
        position, keyword = _FILE_LOADERS[name]
        path = _argument(node, position, keyword)
        if path is not None and not constant(path):
            refs.dynamic = True
    elif qualified in {"builtins.exec", "builtins.eval", "builtins.compile"}:
        source = _argument(node, 0, "source")
        if source is None or not _is_literal(source):
            refs.dynamic = True
    elif qualified in _SHELL_STRING_CALLS or (qualified.startswith(_PROCESS_PREFIXES) and any(
            kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
            for kw in node.keywords)):
        command = node.args[0] if node.args else (_argument(node, 0, "args") or _argument(node, 0, "cmd"))
        if not constant(command):
            refs.dynamic = True           # a shell string the scan cannot read
    elif qualified.startswith(_PROCESS_PREFIXES):
        argv = node.args[0] if node.args else _argument(node, 0, "args")
        if isinstance(argv, ast.Name):
            argv = reader.single_value(argv) or argv
        items = list(argv.elts) if isinstance(argv, (ast.List, ast.Tuple)) else \
            [argv] + list(node.args[1:]) if argv is not None else []
        if not items or isinstance(items[0], ast.Starred):
            refs.dynamic = True
            return
        if not reader.is_interpreter(items[0]):
            if not constant(items[0]):
                refs.dynamic = True       # the program itself is computed
            kind, target = reader.shell_target(items)
            if kind == "stdin" or (kind in {"command", "script"} and not isinstance(target, str)
                                    and not constant(target)):
                refs.dynamic = True       # a shell runs commands the scan cannot read
            if _CODE_FLAGS.get(reader.program(items[0])) is not None and any(
                    reader.fold(i) is None for i in items[1:]):
                refs.dynamic = True       # perl -e / node -e on something computed
            return
        # A Python interpreter: what it runs is the first argument that is not an option.
        rest = iter(items[1:])
        for item in rest:
            if isinstance(item, ast.Starred):
                refs.dynamic = True
                return
            flag = reader.fold(item)
            if flag in {"-c", "-"}:
                refs.dynamic = True
                return
            if flag == "-m":
                if not constant(next(rest, None)):
                    refs.dynamic = True
                return
            if flag in {"-W", "-X", "-Q"}:
                next(rest, None)
                continue
            if flag is not None and flag.startswith("-"):
                continue
            if not constant(item):
                refs.dynamic = True
            return
        refs.dynamic = True               # an interpreter with no script reads stdin


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _basename(text: Optional[str]) -> str:
    return re.split(r"[\\/]", text)[-1] if text else ""


def _catches_only_import_errors(handler: ast.ExceptHandler) -> bool:
    kinds = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return handler.type is not None and all(
        isinstance(k, ast.Name) and k.id in {"ImportError", "ModuleNotFoundError"} for k in kinds)


def _stored_names(target: ast.AST) -> List[str]:
    """The names an assignment target binds (``a, b = ...``), not those it only reads (``x[i] = ...``)."""
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)]


def _argument(call: ast.Call, position: int, keyword: str) -> Optional[ast.AST]:
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    if len(call.args) > position and not any(isinstance(a, ast.Starred) for a in call.args[:position + 1]):
        return call.args[position]
    return None


def _is_literal(node: ast.AST) -> bool:
    """A string or bytes literal: text the pattern scan reads where it stands."""
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _literal_tail(node: ast.AST, inner=None) -> Optional[str]:
    """The last literal piece of a path expression (what decides its file name), or None when the
    expression does not end in one the scan can see. *inner* resolves sub-expressions (names)."""
    inner = inner or (lambda sub: _literal_tail(sub))
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", "replace")
        return None
    if isinstance(node, ast.JoinedStr):
        return inner(node.values[-1]) if node.values else None
    if isinstance(node, ast.FormattedValue):
        return inner(node.value)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Add, ast.Div)):
            return inner(node.right)
        if isinstance(node.op, ast.Mod):        # '%s/helpers.py' % HERE
            return inner(node.left)
        return None
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name == "with_suffix" and node.args:
            tail = inner(node.args[0])
            return None if tail is None else "x" + tail
        if name == "format" and isinstance(func, ast.Attribute):
            return inner(func.value)
        if name in _PATH_BUILDERS:
            if node.args:
                return inner(node.args[-1])
            if isinstance(func, ast.Attribute):    # (HERE / 'mod.py').resolve()
                return inner(func.value)
        return None
    return None


def _suffix(tail: str) -> str:
    name = tail.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if name in ("", ".", ".."):
        return ""
    suffix = os.path.splitext("x" + name)[1].lower()
    return "" if suffix == "." else suffix


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
_RUNTIME_CODE = re.compile(r"\b(?:exec|eval|compile)\s*\((?!\s*[rbuf]*[\"'])|\bmarshal\.loads?\b|\bpickle\.loads?\b"
                           r"|\bsys\.(?:meta_path|path_hooks)\b|__builtins__")
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
        if _RUNTIME_CODE.search(line):
            hits.append("exec_dynamic_code")
        for pattern_id in hits:
            out.append(Finding(pattern_id, _SEVERITY.get(pattern_id, "high"), "execution", rel, number,
                               stripped if len(stripped) <= 120 else stripped[:117] + "...",
                               _DESCRIPTIONS[pattern_id]))
    return out
