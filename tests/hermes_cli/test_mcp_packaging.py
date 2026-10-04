"""The ``mcp`` package reaches every place a gateway with ``dashboard.mcp.enabled`` runs, and a gateway that
lacks it says so in one line instead of failing.

Pinned here: the image (``Dockerfile``) syncs the ``all`` extra and ``[all]`` includes ``[mcp]`` (checked in
``pyproject.toml`` and in ``uv.lock``, which the image installs frozen); the extra carries the three packages
the endpoint imports; the installers and ``hermes update`` install ``[all]`` too; the container variable is
documented and is the one ``container_env_config`` reads; and a dashboard started with the ``mcp`` package
missing still imports, keeps the endpoint off and logs one error line with the install command.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNTIME_PACKAGES = {"mcp", "httpx2", "starlette"}


def _pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def _names(requirements: list[str]) -> set[str]:
    return {re.split(r"[\[<>=!~ ;]", r, maxsplit=1)[0].strip().lower() for r in requirements}


def test_the_mcp_extra_carries_what_the_endpoint_imports_with_exact_pins():
    extras = _pyproject()["project"]["optional-dependencies"]
    assert _names(extras["mcp"]) == RUNTIME_PACKAGES
    assert all("==" in requirement for requirement in extras["mcp"])  # exact pins, as everywhere in this file


def test_the_all_extra_includes_the_mcp_extra():
    assert "hermes-agent[mcp]" in _pyproject()["project"]["optional-dependencies"]["all"]


def test_the_image_installs_the_all_extra_frozen():
    syncs = [line for line in (REPO / "Dockerfile").read_text(encoding="utf-8").splitlines()
             if line.startswith("RUN uv sync")]
    assert syncs, "the Dockerfile no longer syncs the lockfile"
    assert all("--frozen" in line and "--extra all" in line for line in syncs), syncs


def test_the_lockfile_resolves_the_mcp_packages_under_all_and_mcp():
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    [package] = [p for p in lock["package"] if p["name"] == "hermes-agent"]
    optional = package["optional-dependencies"]
    assert RUNTIME_PACKAGES <= {d["name"] for d in optional["all"]}
    assert RUNTIME_PACKAGES == {d["name"] for d in optional["mcp"]}
    versions = {p["name"]: p["version"] for p in lock["package"] if p["name"] in RUNTIME_PACKAGES}
    pins = {re.split(r"==", r)[0]: re.split(r"==", r)[1].split(" ")[0]
            for r in _pyproject()["project"]["optional-dependencies"]["mcp"]}
    assert versions == pins  # what the image installs is what the extra pins


def test_the_installers_and_update_install_the_all_extra():
    for name in ("setup-hermes.sh", "scripts/install.sh"):
        assert "--extra all" in (REPO / name).read_text(encoding="utf-8"), name
    assert 'install_group = "all"' in (REPO / "hermes_cli" / "update_cmd_deps.py").read_text(encoding="utf-8")


def test_the_container_variable_is_documented_and_is_the_one_the_init_step_reads():
    from hermes_cli import container_env_config as cec

    docker = (REPO / "website" / "docs" / "user-guide" / "docker.md").read_text(encoding="utf-8")
    assert cec.MCP_ENABLED == "HERMES_DASHBOARD_MCP_ENABLED"
    assert re.search(rf"^\| `{cec.MCP_ENABLED}` \|", docker, re.M)
    assert "mcp-endpoint.md" in docker


def test_a_dashboard_without_the_mcp_package_keeps_the_endpoint_off_with_one_error_line(tmp_path):
    """A real process: ``import mcp`` is made to fail before anything imports it, as on an install without the
    extra; the dashboard still imports, the switch stays off and the log carries the install command."""
    script = """
import logging, sys
sys.modules["mcp"] = None
records = []
class Keep(logging.Handler):
    def emit(self, record):
        if record.name == "hermes_cli.dashboard_auth.mcp.mount":
            records.append((record.levelname, record.getMessage()))
logging.getLogger().addHandler(Keep())
from hermes_cli import web_server
from hermes_cli.dashboard_auth.mcp import mount
from hermes_cli.dashboard_auth.origins import origins_from_urls
web_server.app.state.auth_required = True
web_server.app.state.public_origins = origins_from_urls(["https://gw.example.invalid"])
runtime = mount.configure(web_server.app, cfg={"dashboard": {"mcp": {"enabled": True}}})
errors = [m for level, m in records if level == "ERROR"]
assert runtime is None and mount.current() is None, runtime
assert len(errors) == 1, records
assert "dashboard.mcp.enabled" in errors[0] and "stays off" in errors[0], errors[0]
assert "pip install 'hermes-agent[mcp]'" in errors[0] and "uv pip install -e '.[mcp]'" in errors[0], errors[0]
off = mount.configure(web_server.app, cfg={"dashboard": {"mcp": {"enabled": False}}})
assert off is None and len([1 for level, _ in records if level == "ERROR"]) == 1  # off by choice: no error
print("ok")
"""
    env = {**os.environ, "HERMES_HOME": str(tmp_path), "PYTHONPATH": str(REPO)}
    done = subprocess.run([sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True,
                          timeout=180)
    assert done.returncode == 0 and done.stdout.strip().endswith("ok"), done.stderr[-2000:] + done.stdout[-500:]
