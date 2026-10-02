"""The ``confirm`` level ``passkey`` contract vectors (``contract/confirm-passkey/``).

``generate.py --check`` reproduces ``vectors.json`` byte for byte (stored signatures must still verify),
and the file keeps the coverage the contract promises: one negative per refusal reason, the relay
attack both ways, and the derived test keys. The verifier that consumes these vectors is tested
separately against them.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

DIR = Path(__file__).resolve().parents[2] / "contract" / "confirm-passkey"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("confirm_passkey_generate", DIR / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def vectors():
    return json.loads((DIR / "vectors.json").read_text(encoding="utf-8"))


def test_generate_check_passes(gen):
    assert gen.main(["--check"]) == 0


def test_every_refusal_reason_has_a_vector(vectors):
    reasons = {v["expect"].get("reason") for v in vectors["assertion_vectors"] if not v["expect"]["ok"]}
    order = vectors["assertion_refusal_order"]
    assert set(order) - {"too_many_attempts"} <= reasons
    assert vectors["sequence_vectors"][0]["settled_outcome"]["refusal_reason"] == "too_many_attempts"
    assert any(v["expect"]["ok"] for v in vectors["assertion_vectors"])


def test_relay_is_refused_both_ways(vectors):
    by_name = {v["name"]: v for v in vectors["assertion_vectors"]}
    assert by_name["relay: valid signature for another gateway's origin"]["expect"]["reason"] == "origin_not_accepted"
    assert (by_name["relay: listed origin claimed, challenge made for another gateway"]["expect"]["reason"]
            == "challenge_mismatch")


def test_challenge_vectors_cover_every_purpose_and_origin_kind(vectors):
    challenges = vectors["challenge_vectors"]
    assert {c["purpose"] for c in challenges} == {"confirm", "register", "invite", "revoke"}
    origins = {c["origin"] for c in challenges}
    assert any(o.startswith("http://[") for o in origins) and any("xn--" in o for o in origins)
    assert any(o.count(":") == 2 and not o.startswith("http://[") for o in origins)  # explicit port


def test_challenge_recomputes_from_the_preimage(gen, vectors):
    for c in vectors["challenge_vectors"]:
        assert gen.b64u(gen.sha256(bytes.fromhex(c["preimage_hex"]))) == c["challenge"]


def test_test_keys_are_the_derived_ones(gen, vectors):
    for name, key in vectors["keys"].items():
        derived = gen.Key(name)
        assert key["x"] == gen.b64u(derived.x) and key["y"] == gen.b64u(derived.y)
