"""``contract/outbox``: the written contract of shared files agrees with the models and the route.

``examples.json`` is normative: every valid attachment parses with ``OutboxAttachment`` (and the rendered
``schema.json``), every invalid one is refused by both; the ``message.complete`` payload and the history row parse
with their wire models; the range table and the disposition table are what the route does. ``schema.json`` and
``SHA256SUMS`` are rendered by ``scripts/gen_gateway_contracts.py`` (``test_generated.py`` diffs them); here the
sums are also checked the way ``sha256sum -c`` would.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_cli.web_routers import files as files_router
from tui_gateway import outbox
from tui_gateway.contracts.common import OutboxAttachment, TranscriptMessage
from tui_gateway.contracts.events import MessageCompletePayload

CONTRACT = Path(__file__).resolve().parents[3] / "contract" / "outbox"
EXAMPLES = json.loads((CONTRACT / "examples.json").read_text(encoding="utf-8"))


def test_sums_pin_every_file():
    for line in (CONTRACT / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((CONTRACT / name).read_bytes()).hexdigest() == digest, name


def test_valid_attachments_parse_and_match_what_the_gateway_builds():
    for value in EXAMPLES["attachments"]["valid"]:
        OutboxAttachment.model_validate(value)
        assert set(value) == set(outbox.ATTACHMENT_KEYS) == set(OutboxAttachment.model_fields)
        assert value["url"] == outbox.attachment_url(value["id"], value["name"])
        assert outbox.clean_attachments([value]) == [value]


@pytest.mark.parametrize("case", EXAMPLES["attachments"]["invalid"], ids=lambda c: c["why"])
def test_invalid_attachments_are_refused(case):
    with pytest.raises(ValidationError):
        OutboxAttachment.model_validate(case["value"])


def test_the_schema_agrees_with_the_examples():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(json.loads((CONTRACT / "schema.json").read_text(encoding="utf-8")))
    for value in EXAMPLES["attachments"]["valid"]:
        validator.validate(value)
    for case in EXAMPLES["attachments"]["invalid"]:
        assert not validator.is_valid(case["value"]), case["why"]


def test_the_frames_parse_with_their_wire_models():
    payload = MessageCompletePayload.model_validate(EXAMPLES["message_complete"])
    assert payload.attachments and payload.attachments[0].kind == "audio"
    row = TranscriptMessage.model_validate(EXAMPLES["history_row"])
    assert row.attachments and row.attachments[0].id == EXAMPLES["attachments"]["valid"][0]["id"]


@pytest.mark.parametrize("case", EXAMPLES["ranges"]["cases"], ids=lambda c: c["range"])
def test_the_range_table_is_what_the_route_does(case):
    size = EXAMPLES["ranges"]["size"]
    wanted = files_router._outbox_range(case["range"], size)
    if case["status"] == 416:
        assert wanted == "unsatisfiable"
    elif case["status"] == 200:
        assert wanted is None
    else:
        first, last = wanted
        assert case["content_range"] == f"bytes {first}-{last}/{size}"


@pytest.mark.parametrize("case", EXAMPLES["dispositions"], ids=lambda c: c["mime"] + c.get("sec_fetch_dest", ""))
def test_the_disposition_table_is_what_the_route_does(case):
    served = outbox.served_type(case["mime"])
    inline = case["kind"] in files_router._OUTBOX_INLINE_KINDS and served == case["mime"]
    if case["kind"] == "pdf" and case.get("sec_fetch_dest") in files_router._OUTBOX_DOCUMENT_DESTS:
        inline = False
    assert served == case["content_type"]
    assert ("inline" if inline else "attachment") == case["disposition"]
