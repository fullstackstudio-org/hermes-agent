"""Regression tests for the fork-14 verification probes (``/private/tmp/claude-501/scanprobe``,
probes1-4): writers, shells and other interpreters, processes that write into the plugin, missing
modules, and what a package's ``__init__.py`` defines. Every tree is only scanned, never run; the
payload is the marker ``MARKER = 1``."""

from __future__ import annotations

import textwrap

import pytest

from tests.tools.test_plugin_guard_unscanned_imports import _commit_all, _plugin
from tools.plugin_guard import scan_plugin

OPT = "try:\n    from .payload import run\nexcept ImportError:\n    run = None\n"
OUT = "/private/tmp/claude-501/scanprobe/marker.txt"     # never written: these trees are not run


def _high(tmp_path, files) -> set:
    plugin = _plugin(tmp_path, {rel: textwrap.dedent(src) for rel, src in files.items()})
    _commit_all(plugin)
    return {(f.pattern_id, f.file) for f in scan_plugin(plugin).findings if f.severity in ("high", "critical")}


# ── probes1: writers ──────────────────────────────────────────────────────────────────────────

W = ("import os, io, codecs, pathlib, shutil, tempfile\nfrom pathlib import Path\nHERE = Path(__file__).parent\n"
     "SRC = 'MARKER = 1\\n'\n")
WRITERS = {
    "open_w": "open(HERE / 'payload.py', 'w').write(SRC)",
    "path_open_w": "(HERE / 'payload.py').open('w').write(SRC)",
    "path_write_text": "(HERE / 'payload.py').write_text(SRC)",
    "path_var_write_text": "p = HERE / 'payload.py'\np.write_text(SRC)",
    "path_touch": "(HERE / 'payload.py').touch()",
    "io_open": "io.open(HERE / 'payload.py', 'w').write(SRC)",
    "opener_alias": "opener = io.open\nopener(HERE / 'payload.py', 'w').write(SRC)",
    "codecs_open": "codecs.open(str(HERE / 'payload.py'), 'w').write(SRC)",
    "fileio": "io.FileIO(HERE / 'payload.py', 'w').write(SRC.encode())",
    "os_open": "fd = os.open(HERE / 'payload.py', os.O_WRONLY | os.O_CREAT)\nos.write(fd, SRC.encode())",
    "os_open_computed_flags": "F = int(os.environ.get('F', '577'))\nfd = os.open(HERE / 'payload.py', F)",
    "os_open_numeric_flags": "fd = os.open(HERE / 'payload.py', 577)",
    "tempfile_dir_here": "fd, n = tempfile.mkstemp(dir=HERE)",
    "tempfile_suffix_py": "fd, n = tempfile.mkstemp('.py')",
    "ntf_positional": "f = tempfile.NamedTemporaryFile('w', -1, None, None, '.py', 'payload', str(HERE), False)",
    "alias_P": "from pathlib import Path as P\nP(HERE, 'payload.py').write_text(SRC)",
    "alias_P2": "from pathlib import Path as P\nP(__file__).parent.joinpath('payload.py').write_text(SRC)",
    "unbound_Path_write_text": "pathlib.Path.write_text(HERE / 'payload.py', SRC)",
    "unbound_Path_open": "pathlib.Path.open(HERE / 'payload.py', 'w').write(SRC)",
    "getattr_write_text": "getattr(HERE / 'payload.py', 'write_text')(SRC)",
    "getattr_open_var": "w = getattr(HERE / 'payload.py', 'write_text')\nw(SRC)",
    "open_rebound": "o = open\no(HERE / 'payload.py', 'w').write(SRC)",
    "builtins_open": "import builtins\nbuiltins.open(HERE / 'payload.py', mode='w').write(SRC)",
    "path_rename": f"t = Path('{OUT}')\nt.rename(HERE / 'payload.py')",
    "path_replace": f"t = Path('{OUT}')\nt.replace(HERE / 'payload.py')",
    "os_replace": f"os.replace('{OUT}', HERE / 'payload.py')",
    "pct_name_dirname_file": "open(os.path.join(os.path.dirname(__file__), 'payload.%s' % 'py'), 'w').write(SRC)",
    "pct_name_modfile": ("import sys\nopen(os.path.join(os.path.dirname(sys.modules[__name__].__file__), "
                         "'payload.%s' % 'py'), 'w').write(SRC)"),
    "computed_name_spec": ("n = os.environ.get('N', 'payload') + '.py'\n"
                           "open(os.path.join(__spec__.submodule_search_locations[0], n), 'w')"),
    "computed_name_known_anchor": ("n = ''.join(map(chr, [112,97,121,108,111,97,100,46,112,121]))\n"
                                   "open(os.path.join(os.path.dirname(__file__), n), 'w').write(SRC)"),
    "multi_assigned_target": "t = None\nt = HERE / ('pay' + 'load.p' + chr(121))\nopen(t, 'w').write(SRC)",
    "unwhole_last_part": "with open(HERE / ('payload.' + chr(112) + 'y'), 'w') as f: f.write(SRC)",
    "gzip_kw_filename": "import gzip\ngzip.open(filename=HERE / 'payload.py', mode='wb')",
    "zip_in_plugin": "import zipfile\nzipfile.ZipFile(HERE / 'x.zip', 'w')",
}


@pytest.mark.parametrize("case", list(WRITERS))
def test_every_writer_probe_is_code_written(tmp_path, case):
    assert ("code_written", "__init__.py") in _high(tmp_path, {"__init__.py": W + WRITERS[case] + "\n"}), case


def test_an_archive_written_outside_the_plugin_is_judged_where_it_goes_on_sys_path(tmp_path):
    found = _high(tmp_path, {"__init__.py": W + "import zipfile, sys\nzipfile.ZipFile('/var/tmp/x.zip', 'w')\n"
                                                "sys.path.insert(0, os.environ['Z'])\n"})
    assert ("code_written", "__init__.py") not in found and ("foreign_sys_path", "__init__.py") in found


# ── probes2 + probes4: shells, other interpreters, processes that write into the plugin ────────

S = "import os, sys, shutil, subprocess, asyncio, pty\nfrom pathlib import Path\nHERE = Path(__file__).parent\n" \
    "CMD = os.environ.get('C', 'true')\n"
SHELLS = {
    "sh_c_list": "subprocess.run(['sh', '-c', CMD])",
    "bin_bash_lc": "subprocess.run(['/bin/bash', '-lc', CMD])",
    "bash_e_c_split": "subprocess.run(['bash', '-e', '-c', CMD])",
    "bash_o_pipefail_c": "subprocess.run(['bash', '-o', 'pipefail', '-c', CMD])",
    "bash_norc_c": "subprocess.run(['bash', '--norc', '-c', CMD])",
    "env_bash": "subprocess.run(['env', 'bash', '-c', CMD])",
    "usr_bin_env_i_bash": "subprocess.run(['/usr/bin/env', '-i', 'A=1', 'bash', '-c', CMD])",
    "env_S": "subprocess.run(['env', '-S', 'bash -c', CMD])",
    "which_bash": "subprocess.run([shutil.which('bash'), '-c', CMD])",
    "which_var": "b = shutil.which('zsh')\nsubprocess.run([b, '-c', CMD])",
    "execl": "os.execl('/bin/sh', 'sh', '-c', CMD)",
    "execlp": "os.execlp('sh', 'sh', '-c', CMD)",
    "execv_list": "os.execv('/bin/sh', ['sh', '-c', CMD])",
    "execve_list": "os.execve('/bin/sh', ['sh', '-c', CMD], {})",
    "spawnl": "os.spawnl(os.P_WAIT, '/bin/sh', 'sh', '-c', CMD)",
    "posix_spawn": "os.posix_spawn('/bin/sh', ['sh', '-c', CMD], {})",
    "execv_tuple_var": "argv = ('sh', '-c', CMD)\nos.execv('/bin/sh', argv)",
    "popen_list_var": "argv = ['sh']\nargv += ['-c', CMD]\nsubprocess.Popen(argv)",
    "shell_from_var": "SH = '/bin/' + 'sh'\nsubprocess.run([SH, '-c', CMD])",
    "busybox_sh": "subprocess.run(['busybox', 'sh', '-c', CMD])",
    "sh_stdin": "subprocess.run(['sh'], input=CMD.encode())",
    "sh_s_stdin": "subprocess.run(['sh', '-s'], input=CMD.encode())",
    "sh_script_file": "subprocess.run(['sh', CMD])",
    "shell_true": "subprocess.run(CMD, shell=True)",
    "check_output_shell": "subprocess.check_output(CMD, shell=True)",
    "getoutput": "subprocess.getoutput(CMD)",
    "asyncio_shell": "asyncio.create_subprocess_shell(CMD)",
    "pty_spawn": "pty.spawn(['sh', '-c', CMD])",
    "sh_c_kw_args": "subprocess.run(args=['sh', '-c', CMD])",
    "sh_c_fstring": "subprocess.run(['sh', '-c', f'echo {CMD}'])",
    "os_system": "os.system(CMD)",
}
INTERPRETERS = {
    "python_c": "subprocess.run([sys.executable, '-c', CMD])",
    "perl_e": "subprocess.run(['perl', '-e', CMD])",
    "node_e": "subprocess.run(['node', '-e', CMD])",
    "ruby_e": "subprocess.run(['ruby', '-e', CMD])",
}
PROCESS_WRITES = {
    "cp_into_plugin": f"subprocess.run(['cp', '{OUT}', str(HERE / 'payload.py')])",
    "pip_target": "subprocess.run([sys.executable, '-m', 'pip', 'install', '--target', str(HERE), 'markerpkg'])",
    "sh_const_cwd": "subprocess.run(['sh', '-c', 'printf MARKER > payload.py'], cwd=HERE)",
}
CONTROLS = {
    "constant_sh_c": "subprocess.run(['sh', '-c', 'echo marker'])",
    "sh_c_const_var": "C2 = 'echo marker'\nsubprocess.run(['sh', '-c', C2])",
    "shell_true_constant": "subprocess.run('echo marker', shell=True)",
    "python_runs_own_script": "subprocess.run([sys.executable, str(HERE / 'tool.py')])",
    "git_version": "subprocess.run(['git', 'rev-parse', 'HEAD'])",
}


@pytest.mark.parametrize("case", list(SHELLS))
def test_a_shell_on_something_computed_is_flagged(tmp_path, case):
    assert ("shell_code", "__init__.py") in _high(tmp_path, {"__init__.py": S + SHELLS[case] + "\n"}), case


@pytest.mark.parametrize("case", list(INTERPRETERS))
def test_an_interpreter_on_a_computed_script_is_flagged(tmp_path, case):
    assert ("interpreter_code", "__init__.py") in _high(tmp_path, {"__init__.py": S + INTERPRETERS[case] + "\n"})


@pytest.mark.parametrize("case", list(PROCESS_WRITES))
def test_a_process_given_a_path_in_the_plugin_is_code_written(tmp_path, case):
    assert ("code_written", "__init__.py") in _high(tmp_path, {"__init__.py": S + PROCESS_WRITES[case] + "\n"})


@pytest.mark.parametrize("case", list(CONTROLS))
def test_constant_commands_and_a_plugin_running_its_own_script_are_not_flagged(tmp_path, case):
    found = _high(tmp_path, {"__init__.py": S + CONTROLS[case] + "\n", "tool.py": "VALUE = 1\n"})
    assert not found & {("shell_code", "__init__.py"), ("interpreter_code", "__init__.py"),
                        ("code_written", "__init__.py")}, case


def test_a_shell_on_a_computed_command_reaches_every_test_file(tmp_path):
    found = _high(tmp_path, {"__init__.py": S + "subprocess.run(CMD, shell=True)\n",
                             "tests/test_x.py": "src = input()\nexec(src)\n"})
    assert ("exec_dynamic_code", "tests/test_x.py") in found


# ── probes3: missing modules always high; what a package defines ─────────────────────────────

TRY_SHAPES = {
    "only_optional": OPT,
    "try_two_stmts": "try:\n    from .payload import run\n    X = 1\nexcept ImportError:\n    pass\n",
    "except_exception": "try:\n    from .payload import run\nexcept (ImportError, Exception):\n    pass\n",
    "bare_except": "try:\n    from .payload import run\nexcept:\n    pass\n",
    "two_handlers": "try:\n    from .payload import run\nexcept ImportError:\n    pass\nexcept OSError:\n    pass\n",
    "mnfe": "try:\n    from .payload import run\nexcept ModuleNotFoundError:\n    pass\n",
    "finally_only": "try:\n    from .payload import run\nfinally:\n    pass\n",
    "importlib_in_try": "import importlib\ntry:\n    importlib.import_module('.payload', __package__)\nexcept ImportError:\n    pass\n",
    "trystar": "try:\n    from .payload import run\nexcept* ImportError:\n    pass\n",
    "in_func": "def f():\n    try:\n        from .payload import run\n    except ImportError:\n        return None\n",
}


@pytest.mark.parametrize("case", list(TRY_SHAPES))
def test_a_missing_module_is_high_in_every_try_shape(tmp_path, case):
    assert ("missing_module", "__init__.py") in _high(tmp_path, {"__init__.py": TRY_SHAPES[case]}), case


@pytest.mark.parametrize("init", [
    "try:\n    from . import _speedups\nexcept ImportError:\n    _speedups = None\n",     # fallback in except
    "_speedups = None\ntry:\n    from . import _speedups\nexcept ImportError:\n    pass\n",  # None placeholder
    "if False:\n    _speedups = 1\n",                                                       # never runs
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    _speedups = 1\n",
    "def setup():\n    global _speedups\n    _speedups = 1\n",                               # inside a function
    "class K:\n    _speedups = 1\n",                                                        # inside a class
])
def test_a_name_counts_as_defined_only_at_module_level(tmp_path, init):
    found = _high(tmp_path, {"__init__.py": init, "m.py": "from . import _speedups\n"})
    assert ("missing_module", "m.py") in found, init


@pytest.mark.parametrize("init", [
    "try:\n    from ._c import fast as _speedups\nexcept ImportError:\n    def _speedups():\n        return 1\n",
    "_speedups = 1\n",
    "def _speedups():\n    return 1\n",
    "import os\nif os.name == 'posix':\n    _speedups = 1\nelse:\n    _speedups = 2\n",
])
def test_a_name_defined_at_module_level_is_not_missing(tmp_path, init):
    found = _high(tmp_path, {"__init__.py": init, "_c.py": "def fast():\n    return 2\n",
                             "m.py": "from . import _speedups\n"})
    assert ("missing_module", "m.py") not in found, init


# ── a child's PYTHONPATH (round-4 addition): a tripwire at medium ─────────────────────────────


@pytest.mark.parametrize("line", [
    "env = dict(os.environ)\nenv['PYTHONPATH'] = sys.argv[1]\nsubprocess.run([sys.executable, '-m', 'x'], env=env)",
    "subprocess.run([sys.executable, '-m', 'x'], env={**os.environ, 'PYTHONPATH': sys.argv[1]})",
    "subprocess.run([sys.executable, '-m', 'x'], env=dict(os.environ, PYTHONHOME=sys.argv[1]))",
    "os.environ['PYTHONSTARTUP'] = sys.argv[1]",
    "os.environ.setdefault('PYTHONPATH', sys.argv[1])",
])
def test_a_computed_pythonpath_for_a_child_is_a_medium_tripwire(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": S + line + "\n"})
    _commit_all(plugin)
    found = [f for f in scan_plugin(plugin).findings if f.pattern_id == "foreign_python_path"]
    assert found and {f.severity for f in found} == {"medium"}, line


@pytest.mark.parametrize("line", [
    "subprocess.run([sys.executable, '-m', 'x'], env={**os.environ, 'PYTHONPATH': str(HERE)})",
    "subprocess.run([sys.executable, '-m', 'x'], env={'PYTHONPATH': '/opt/app'})",
    "env = dict(os.environ)\nenv['PYTHONDONTWRITEBYTECODE'] = sys.argv[1]",
])
def test_a_constant_or_plugin_pythonpath_is_not_flagged(tmp_path, line):
    plugin = _plugin(tmp_path, {"__init__.py": S + line + "\n"})
    _commit_all(plugin)
    assert not any(f.pattern_id == "foreign_python_path" for f in scan_plugin(plugin).findings), line
