"""``dashboard.mcp`` is operator-only, like ``confirm.passkey``: the dashboard's config writers (``PUT
/api/config``, ``PUT /api/config/raw``) refuse a write that would change what the gateway reads there and
change nothing, the settings form does not offer it, and echoing the defaulted section back goes through.
A stolen dashboard session must not be able to switch the MCP endpoint on (decision 6 of the plan)."""

from __future__ import annotations

import json

import pytest
import yaml

from hermes_cli.dashboard_auth.mcp import settings as ms


@pytest.mark.parametrize(("before", "after", "changed"), [
    ({}, {"model": "x"}, False),
    ({}, {"dashboard": {"mcp": {"enabled": False}}}, False),  # an explicit default reads the same
    ({}, {"dashboard": {"mcp": {"enabled": True}}}, True),
    ({"dashboard": {"mcp": {"enabled": True}}}, {}, True),  # dropping the section is a change
    ({"dashboard": {"mcp": {"enabled": True}}}, {"dashboard": {"mcp": 5}}, True),
    ({}, {"dashboard": {"mcp": {"max_grants_per_user": 50}}}, True),
    ({}, {"dashboard": {"mcp": {"new_key": 1}}}, True),
    ({}, {"dashboard": {"theme": "mono"}}, False),
])
def test_changes_protected(before, after, changed):
    assert ms.changes_protected(before, after) is changed


def test_the_defaults_are_what_config_defaults_carries():
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["dashboard"]["mcp"] == ms.default_section()
    assert ms.from_config(DEFAULT_CONFIG).enabled is False


@pytest.fixture
def client(_isolate_hermes_home):
    from starlette.testclient import TestClient
    from hermes_cli import web_server

    c = TestClient(web_server.app)
    c.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    return c


@pytest.fixture
def config_file():
    from hermes_cli.config import get_config_path
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("model: some-model\ndashboard:\n  mcp:\n    enabled: false\n", encoding="utf-8")
    return path


def _audit_events() -> list[dict]:
    from hermes_constants import get_hermes_home
    log = get_hermes_home() / "logs" / "dashboard-auth.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_a_config_put_switching_it_on_is_refused_and_the_file_is_byte_identical(client, config_file):
    before = config_file.read_bytes()
    resp = client.put("/api/config", json={"config": {"display": {"skin": "mono"},
                                                      "dashboard": {"mcp": {"enabled": True}}}})
    assert resp.status_code == 403 and resp.json()["detail"].startswith("protected_setting")
    assert config_file.read_bytes() == before
    line = _audit_events()[-1]
    assert (line["event"], line["surface"], line["key"]) == ("protected_setting_refused", "config_put", "dashboard.mcp")


def test_the_settings_page_round_trip_is_not_refused_and_offers_no_field(client, config_file):
    record = client.get("/api/config").json()
    resp = client.put("/api/config", json={"config": {**record, "display": {**record["display"], "skin": "mono"}}})
    assert resp.status_code == 200, resp.text
    saved = yaml.safe_load(config_file.read_text())
    assert saved["display"]["skin"] == "mono" and saved["dashboard"]["mcp"]["enabled"] is False
    fields = client.get("/api/config/schema").json()["fields"]
    assert not [k for k in fields if k.startswith("dashboard.mcp")]


def test_a_raw_put_changing_the_section_is_refused(client, config_file):
    before = config_file.read_bytes()
    for text in ("model: some-model\ndashboard:\n  mcp:\n    enabled: true\n",
                 "model: some-model\ndashboard:\n  mcp: 1\n"):
        resp = client.put("/api/config/raw", json={"yaml_text": text})
        assert resp.status_code == 403, text
        assert config_file.read_bytes() == before
    text = config_file.read_text() + "display:\n  skin: mono\n"
    assert client.put("/api/config/raw", json={"yaml_text": text}).status_code == 200
