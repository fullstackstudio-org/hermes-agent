"""``contract/sources``: the written contract of a reply's sources agrees with the model and the collector.

``examples.json`` is normative: every valid entry parses with ``Source`` (and the rendered ``schema.json``),
every invalid one is refused by both and by the gateway's own URL check; every ``collect`` case is what
``tui_gateway/sources.py`` builds from those tool results; the ``message.complete`` payload and the history row
parse with their wire models. ``schema.json`` and ``SHA256SUMS`` are rendered by
``scripts/gen_gateway_contracts.py`` (``test_generated.py`` diffs them); here the sums are also checked the way
``sha256sum -c`` would.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tui_gateway import sources
from tui_gateway.contracts.common import Source, TranscriptMessage
from tui_gateway.contracts.events import MessageCompletePayload

CONTRACT = Path(__file__).resolve().parents[3] / "contract" / "sources"
EXAMPLES = json.loads((CONTRACT / "examples.json").read_text(encoding="utf-8"))


def test_sums_pin_every_file():
    lines = (CONTRACT / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert {line.split("  ", 1)[1] for line in lines} == {"README.md", "examples.json", "schema.json"}
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((CONTRACT / name).read_bytes()).hexdigest() == digest, name


def test_valid_entries_parse_and_survive_the_gateways_own_checks():
    for value in EXAMPLES["entries"]["valid"]:
        Source.model_validate(value)
        assert set(value) == set(Source.model_fields)
        assert sources.merge([value]) == [value]


@pytest.mark.parametrize("case", EXAMPLES["entries"]["invalid"], ids=lambda c: c["why"])
def test_invalid_entries_are_refused(case):
    with pytest.raises(ValidationError):
        Source.model_validate(case["value"])
    # The gateway never builds one: a URL or a tier it refuses leaves the entry out (a title it cuts and cleans
    # itself, and it writes no other key).
    if case["why"] not in ("title over 160 characters", "missing title", "unknown key"):
        assert sources.merge([case["value"]]) == [], case["why"]


def test_the_schema_agrees_with_the_examples():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(json.loads((CONTRACT / "schema.json").read_text(encoding="utf-8")))
    validator.validate(EXAMPLES["entries"]["valid"])
    for case in EXAMPLES["entries"]["invalid"]:
        assert not validator.is_valid([case["value"]]), case["why"]
    assert not validator.is_valid([])  # absent, never []
    assert not validator.is_valid([EXAMPLES["entries"]["valid"][0]] * 25)


@pytest.mark.parametrize("case", EXAMPLES["collect"], ids=lambda c: c["why"])
def test_the_collect_cases_are_what_the_gateway_builds(case):
    collector = sources.TurnSources("turn")
    for tool in case["tools"]:
        collector.add(tool["name"], json.dumps(tool["result"]))
    assert collector.sources() == case["sources"]


def test_the_frames_parse_with_their_wire_models():
    payload = MessageCompletePayload.model_validate(EXAMPLES["message_complete"])
    assert payload.sources and payload.sources[0].via == "read"
    row = TranscriptMessage.model_validate(EXAMPLES["history_row"])
    assert row.display_metadata["sources"] == EXAMPLES["message_complete"]["sources"]
    with pytest.raises(ValidationError):
        MessageCompletePayload.model_validate({**EXAMPLES["message_complete"], "sources": []})
