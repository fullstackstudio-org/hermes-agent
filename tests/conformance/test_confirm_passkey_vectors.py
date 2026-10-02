"""The ``confirm`` level ``passkey`` contract vectors (``contract/confirm-passkey/``).

``generate.py --check`` rebuilds ``vectors.json`` byte for byte, runs every vector through the reference
evaluator written from the README's step order, and verifies ``SHA256SUMS``. These tests also pin the
coverage the contract promises and that a mislabelled vector fails the build.
"""

from __future__ import annotations

import copy
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


def test_a_mislabelled_vector_is_caught(gen, vectors):
    for vector in vectors["assertion_vectors"]:
        wrong = copy.deepcopy(vector)
        wrong["expect"] = ({"ok": False, "code": 4034, "reason": "uv_required"} if vector["expect"]["ok"]
                           or vector["expect"]["reason"] != "uv_required" else {"ok": True})
        got = gen._verdict(gen.evaluate_assertion, gen.CONTEXTS[wrong["context"]], wrong, {"ok": False, "code": 4034})
        assert got != wrong["expect"], vector["name"]
        assert got == vector["expect"], vector["name"]


def test_every_refusal_reason_has_a_vector(vectors):
    for key, order_key in (("assertion_vectors", "assertion_refusal_order"),
                           ("registration_vectors", "registration_refusal_order")):
        reasons = {v["expect"].get("reason") for v in vectors[key] if not v["expect"]["ok"]}
        assert set(vectors[order_key]) - {"too_many_attempts"} <= reasons, key
    assert vectors["sequence_vectors"][0]["settled_outcome"]["refusal_reason"] == "too_many_attempts"


def test_relay_is_refused_both_ways_including_one_host(vectors):
    reasons = {v["name"]: v["expect"].get("reason") for v in vectors["assertion_vectors"]}
    assert reasons["relay: valid signature for another gateway's base URL"] == "base_url_not_accepted"
    assert reasons["relay: listed base URL claimed, challenge made for another gateway"] == "challenge_mismatch"
    assert reasons["relay between two gateways on one host"] == "base_url_not_accepted"
    assert reasons["relay between two gateways on one host, own base URL claimed"] == "challenge_mismatch"


def test_private_base_urls_need_the_opt_in(vectors):
    contexts = vectors["contexts"]
    assert contexts["only_private"]["derived"]["capability_reason"] == "private_origin"
    assert "http://192.168.1.10:9119" not in contexts["main"]["derived"]["accepted_base_urls"]
    assert "http://192.168.1.10:9119" in contexts["private_allowed"]["derived"]["accepted_base_urls"]
    assert contexts["prefixed"]["derived"]["accepted_rps"]["web"] == []


def test_challenges_cover_every_purpose_and_base_url_kind(vectors):
    challenges = vectors["challenge_vectors"]
    assert {c["purpose"] for c in challenges} == {"confirm", "register", "invite", "revoke"}
    urls = {c["base_url"] for c in challenges}
    assert any(u.startswith("http://[") for u in urls) and any("xn--" in u for u in urls)
    alice = next(c for c in challenges if c["name"] == "confirm, path prefix alice")
    bob = next(c for c in challenges if c["name"].startswith("confirm, path prefix bob"))
    assert alice["challenge"] != bob["challenge"] and alice["nonce"] == bob["nonce"]


def test_challenge_recomputes_from_the_preimage(gen, vectors):
    for c in vectors["challenge_vectors"]:
        assert gen.b64u(gen.sha256(bytes.fromhex(c["preimage_hex"]))) == c["challenge"]


def test_test_keys_are_the_derived_ones(gen, vectors):
    for name, key in vectors["keys"].items():
        derived = gen.Key(name)
        assert key["x"] == gen.b64u(derived.x) and key["y"] == gen.b64u(derived.y)


def test_the_gateways_own_verifier_gives_every_labelled_result(vectors):
    """The production verifier (``hermes_cli/dashboard_auth/passkeys``), not the generator's reference
    evaluator, against every assertion and registration vector."""
    from tests.hermes_cli.test_passkeys_webauthn import _assertion_verdict, _registration_verdict
    for vector in vectors["assertion_vectors"]:
        assert _assertion_verdict(vector) == vector["expect"], vector["name"]
    for vector in vectors["registration_vectors"]:
        assert _registration_verdict(vector) == vector["expect"], vector["name"]
