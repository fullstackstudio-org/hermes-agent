"""Python a plugin runs from somewhere a text scan does not read (HERM-197).

The import-route checks of HERM-196b read the AST, not the line: a loader is judged by the
path it is given (not by every dotted string on its line), docstrings are prose, and only a
change to ``sys.path`` counts, not a read of it.

Where a case can run, it first proves the route is real: the plugin is imported by the
loader's own ``_load_directory_module`` in a fresh interpreter and the payload writes
``PAYLOAD RAN`` to a marker file. Payloads only ever write that marker.
"""

from __future__ import annotations

import pytest

from tests.tools.test_plugin_guard_unscanned_imports import (
    _commit_all, _load_with_the_loader, _payload, _plugin)
from tools.plugin_guard import scan_plugin, should_allow_plugin_install

LOADER_IDS = {"non_source_loader", "dynamic_source_loader", "archive_on_sys_path", "zipimport_use",
              "bytecode_or_native_loader"}


def _ids(plugin, *, at_least: str = "low") -> set:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return {f.pattern_id for f in scan_plugin(plugin).findings if rank[f.severity] >= rank[at_least]}


# ── a loader is judged by its path argument ─────────────────────────────────────────────────


def test_a_dotted_module_name_is_not_a_path(tmp_path):
    """``spec_from_file_location('myplugin.helpers', ...helpers.py)``: the name is not a file."""
    plugin = _plugin(tmp_path, {
        "__init__.py": ("import importlib.util, os\n"
                        "HERE = os.path.dirname(__file__)\n"
                        "spec = importlib.util.spec_from_file_location('myplugin.helpers', "
                        "os.path.join(HERE, 'helpers.py'))\n"),
        "helpers.py": "VALUE = 1\n"})
    _commit_all(plugin)
    result = scan_plugin(plugin)
    assert not {f.pattern_id for f in result.findings} & LOADER_IDS, result.findings
    assert result.verdict == "safe"


def test_a_loader_aimed_at_a_file_without_an_extension_runs_and_is_flagged(tmp_path):
    marker = tmp_path / "ran.txt"
    plugin = _plugin(tmp_path, {
        "__init__.py": ("import os\n"
                        "from importlib.machinery import SourceFileLoader\n"
                        "HERE = os.path.dirname(__file__)\n"
                        "SourceFileLoader('herm197_hidden', os.path.join(HERE, 'payload')).load_module()\n"),
        "payload": _payload(marker)})
    _commit_all(plugin)
    _load_with_the_loader(plugin)
    assert marker.read_text() == "PAYLOAD RAN"          # the route is real
    result = scan_plugin(plugin)
    assert any(f.pattern_id == "non_source_loader" and f.severity == "high" and f.line == 4
               for f in result.findings)
    assert should_allow_plugin_install(result)[0] is not True


@pytest.mark.parametrize("call", [
    "SourceFileLoader('h', 'payload')",
    "SourceFileLoader(fullname='h', path='payload')",
    "importlib.util.spec_from_file_location('h', HERE / 'payload.txt')",
    "importlib.util.spec_from_file_location('h', f'{HERE}/payload.cfg')",
    "importlib.util.spec_from_file_location(\n    'h',\n    'helper.data',\n)",
    "runpy.run_path(os.path.join(HERE, 'tool.dat'))",
    "imp.load_source('h', HERE + '/payload')",
])
def test_a_loader_path_that_is_not_python_source_is_flagged(tmp_path, call):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import imp, importlib.util, os, runpy\nfrom importlib.machinery import SourceFileLoader\n"
        f"HERE = os.path.dirname(__file__)\n{call}\n")})
    _commit_all(plugin)
    assert "non_source_loader" in _ids(plugin, at_least="high"), call


@pytest.mark.parametrize("call", [
    "importlib.util.spec_from_file_location('pkg.mod', HERE / 'mod.py')",
    "importlib.util.spec_from_file_location('pkg.mod', (HERE / 'mod.py').resolve())",
    "importlib.util.spec_from_file_location('pkg.mod', Path(HERE, 'sub', 'mod.py'))",
    "importlib.util.spec_from_file_location('pkg.mod', f'{HERE}/mod.py')",
    "importlib.util.spec_from_file_location('pkg', HERE / '__init__.py', submodule_search_locations=[HERE])",
    "SourceFileLoader('pkg.tool', str(HERE / 'tool.pyw'))",
    "runpy.run_path(os.path.join(HERE, 'tool.py'), run_name='x.y')",
])
def test_a_loader_aimed_at_python_source_is_not_flagged(tmp_path, call):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import importlib.util, os, runpy\nfrom importlib.machinery import SourceFileLoader\n"
        f"from pathlib import Path\nHERE = Path(__file__).parent\n{call}\n")})
    _commit_all(plugin)
    assert not _ids(plugin) & LOADER_IDS, call


def test_a_loader_path_in_the_plugin_the_scan_cannot_name_is_reported_but_does_not_block(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import importlib.util, os\n"
        "HERE = os.path.dirname(__file__)\n"
        "def load(name):\n"
        "    return importlib.util.spec_from_file_location(name, os.path.join(HERE, name))\n")})
    _commit_all(plugin)
    result = scan_plugin(plugin)
    found = [f for f in result.findings if f.pattern_id == "dynamic_source_loader"]
    assert found and found[0].severity == "medium" and found[0].line == 4
    assert result.verdict == "safe"


@pytest.mark.parametrize("path", ["path", "'/tmp/m.py'", "'m.py'", "os.path.join(HERE, '..', 'm.py')",
                                  "os.path.join(HERE, '/tmp/m.py')", "os.path.join(tempfile.mkdtemp(), 'm.py')",
                                  "os.path.join(os.path.dirname(HERE), 'm.py')"])
def test_a_loader_path_outside_the_plugin_is_flagged(tmp_path, path):
    """Only a path built from ``__file__`` that stays in the plugin is the plugin's own code."""
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import importlib.util, os, tempfile\n"
        "HERE = os.path.dirname(__file__)\n"
        f"def load(name, path):\n    return importlib.util.spec_from_file_location(name, {path})\n")})
    _commit_all(plugin)
    assert "foreign_source_loader" in _ids(plugin, at_least="high"), path


def test_load_compiled_is_a_bytecode_loader_whatever_its_path(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "import imp\nimp.load_compiled('h', 'helper.py')\n"})
    _commit_all(plugin)
    assert "bytecode_or_native_loader" in _ids(plugin, at_least="high")


# ── docstrings are prose; only a change to sys.path counts ──────────────────────────────────


def test_a_docstring_that_names_an_import_route_is_not_flagged(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": (
        '"""Never sys.path.insert(0, "deps.zip"), import zipimport, or use\n'
        "SourcelessFileLoader / SourceFileLoader('h', 'payload') here.\n"
        '"""\n'
        "def f():\n"
        '    """sys.path.append("vendor.whl") is what we do not do."""\n'
        "    return 1\n")})
    _commit_all(plugin)
    result = scan_plugin(plugin)
    assert not {f.pattern_id for f in result.findings} & LOADER_IDS, result.findings
    assert result.verdict == "safe"


@pytest.mark.parametrize("line", [
    "print(sys.path[0], 'deps.zip')",
    "first = sys.path[0]; ARCHIVE = 'deps.zip'",
    "if sys.path[-1].endswith('.egg'): pass",
])
def test_reading_sys_path_is_not_a_change_to_it(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": f"import sys\n{line}\n"})
    _commit_all(plugin)
    assert "archive_on_sys_path" not in _ids(plugin), line


@pytest.mark.parametrize("line", [
    "sys.path[0:0] = ['deps.zip']",
    "sys.path += [os.path.join(HERE, 'deps.whl')]",
    "sys.path = ['app.pyz'] + sys.path",
    "sys.path.insert(\n    0,\n    os.path.join(HERE, 'deps.zip'),\n)",
    "import sys as s\ns.path.append('vendor/lib.egg')",
    "from site import addsitedir\naddsitedir(os.path.join(HERE, 'deps.egg'))",
])
def test_putting_an_archive_on_sys_path_is_flagged_in_any_spelling(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": f"import os, sys\nHERE = os.path.dirname(__file__)\n{line}\n"})
    _commit_all(plugin)
    assert "archive_on_sys_path" in _ids(plugin, at_least="high"), line


def test_python_that_does_not_parse_is_still_read_line_by_line(tmp_path):
    """A file the scanner's own Python cannot parse falls back to the line scan, docstrings and
    reads of sys.path skipped there too."""
    plugin = _plugin(tmp_path, {"__init__.py": (
        '"""sys.path.insert(0, "docs.zip") in prose."""\n'
        "print(sys.path[0], 'read.zip')\n"
        "sys.path.insert(0, 'deps.zip')\n"
        "def broken(:\n")})
    _commit_all(plugin)
    found = [f for f in scan_plugin(plugin).findings if f.pattern_id == "archive_on_sys_path"]
    assert [f.line for f in found] == [3]


# ── code a plugin builds at run time and executes (HERM-197 (1)) ────────────────────────────

RUNTIME_CODE_IDS = {"exec_dynamic_code", "compile_dynamic_code", "marshal_code", "import_hook_change"}


def _runtime_code_cases(marker) -> dict:
    import base64
    import marshal

    payload = _payload(marker)
    encoded = base64.b64encode(payload.encode()).decode()
    code = marshal.dumps(compile(payload, "payload", "exec"))
    return {
        "exec(open(p).read())": (
            "import os\nexec(open(os.path.join(os.path.dirname(__file__), 'data.txt')).read())\n",
            {"data.txt": payload}, "exec_dynamic_code"),
        "exec(base64.b64decode(...))": (
            f"import base64\nexec(base64.b64decode({encoded!r}))\n", {}, "exec_dynamic_code"),
        "marshal.loads": (
            f"import marshal\nexec(marshal.loads({code!r}))\n", {}, "marshal_code"),
        "marshal.loads into a function": (
            f"import types\nfrom marshal import loads as l\ntypes.FunctionType(l({code!r}), {{}})()\n", {},
            "marshal_code"),
        "compile(src, PATH, 'exec')": (
            "import os\nPATH = os.path.join(os.path.dirname(__file__), 'data.txt')\n"
            "code = compile(open(PATH).read(), PATH, 'exec')\nexec(code)\n",
            {"data.txt": payload}, "compile_dynamic_code"),
        "exec(pkgutil.get_data(...))": (
            "import pkgutil\nexec(pkgutil.get_data(__name__, 'data.txt'))\n", {"data.txt": payload},
            "exec_dynamic_code"),
        "eval(compile(...))": (
            f"import base64\neval(compile(base64.b64decode({encoded!r}), 'x', mode='exec'))\n", {},
            "exec_dynamic_code"),
        "builtins.exec": (
            f"import base64, builtins as b\nb.exec(base64.b64decode({encoded!r}))\n", {}, "exec_dynamic_code"),
        "getattr(builtins, 'exec')": (
            f"import base64, builtins\ngetattr(builtins, 'exec')(base64.b64decode({encoded!r}))\n", {},
            "exec_dynamic_code"),
    }


@pytest.mark.parametrize("case", list(_runtime_code_cases(None)))
def test_code_built_at_run_time_runs_and_is_flagged(tmp_path, case):
    marker = tmp_path / "ran.txt"
    init, extra, pattern = _runtime_code_cases(marker)[case]
    plugin = _plugin(tmp_path, {"__init__.py": init, **extra})
    _commit_all(plugin)
    _load_with_the_loader(plugin)
    assert marker.read_text() == "PAYLOAD RAN"          # the route is real
    result = scan_plugin(plugin)
    assert any(f.pattern_id == pattern and f.severity == "high" for f in result.findings), result.findings
    assert result.verdict != "safe"
    assert should_allow_plugin_install(result)[0] is not True


@pytest.mark.parametrize("line", [
    "sys.meta_path.insert(0, Finder())",
    "sys.meta_path.append(Finder())",
    "sys.meta_path[:0] = [Finder()]",
    "sys.meta_path = [Finder()] + sys.meta_path",
    "sys.meta_path += [Finder()]",
    "sys.path_hooks.append(Finder)",
    "sys.path_hooks.insert(0, Finder)",
    "sys.path_importer_cache['/x'] = Finder()",
    "setattr(sys, 'meta_path', [Finder()])",
    "import sys as s\ns.meta_path.insert(0, Finder())",
    "from sys import meta_path as m\nm.insert(0, Finder())",
])
def test_a_change_to_the_import_machinery_is_flagged(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import sys\nclass Finder:\n    def find_spec(self, *a, **k):\n        return None\n" + line + "\n")})
    _commit_all(plugin)
    assert "import_hook_change" in _ids(plugin, at_least="high"), line


@pytest.mark.parametrize("line", [
    "eval('1 + 1')",
    "exec(b'VALUE = 2')",
    "PATTERN = re.compile(r'\\d+')",
    "code = compile('1 + 1', '<x>', 'eval')",
    "model.eval()",
    "query.exec(statement)",
    "finders = [f for f in sys.meta_path]",
    "hooks = len(sys.path_hooks)",
    "data = marshal.dumps({'a': 1})",
    "proc = asyncio.create_subprocess_exec('ls')",
    "'''exec(open(p).read()) and sys.meta_path.insert(0, x) in a docstring'''",
])
def test_ordinary_code_is_not_runtime_code(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import asyncio, marshal, re, sys\nsource = '1'\nmodel = query = statement = None\n"
        f"def f():\n    {line}\n")})
    _commit_all(plugin)
    assert not _ids(plugin) & RUNTIME_CODE_IDS, line


def test_runtime_code_in_a_test_tree_steps_down(tmp_path):
    """A test that evals a fixture is reported at medium, like every other finding under tests/."""
    plugin = _plugin(tmp_path, {"__init__.py": "", "tests/test_x.py": "def test_x(expr):\n    assert eval(expr, {})\n"})
    _commit_all(plugin)
    result = scan_plugin(plugin)
    assert [f.severity for f in result.findings if f.pattern_id == "exec_dynamic_code"] == ["medium"]
    assert result.verdict == "safe"


def test_exec_of_unpacked_arguments_is_flagged(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "parts = ['VALUE = 1']\nexec(*parts)\n"})
    _commit_all(plugin)
    assert "exec_dynamic_code" in _ids(plugin, at_least="high")
