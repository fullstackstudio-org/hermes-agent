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
    for vector in vectors["assertion_vectors"] + vectors["assertion_vectors_v2"]:
        assert _assertion_verdict(vector) == vector["expect"], vector["name"]
    for vector in vectors["registration_vectors"]:
        assert _registration_verdict(vector) == vector["expect"], vector["name"]


# ── fresh-authentication grants (README §7.2) ────────────────────────────────────────────────────


def test_every_grant_failure_has_a_freshness_vector(vectors):
    failures = {v["expect"].get("failure") for v in vectors["reauth_freshness_vectors"]}
    assert set(vectors["reauth_failure_order"]) <= failures
    assert {v["expect"]["state"] for v in vectors["reauth_freshness_vectors"]} == {"fresh", "failed"}


@pytest.mark.parametrize("client", ["web", "native"])
def test_the_stores_freshness_rule_gives_every_labelled_result(vectors, tmp_path, client):
    """The production store (``PasskeyStore.complete_grant``), not the generator's reference evaluator,
    against every freshness vector, completed the way each kind of client completes a grant."""
    from hermes_cli.dashboard_auth.passkeys.store import (
        PasskeyStore, new_reauth_secret, reauth_secret_hash)

    for index, vector in enumerate(vectors["reauth_freshness_vectors"]):
        grant, session = vector["grant"], vector["session"]
        store = PasskeyStore(tmp_path / f"{client}-{index}.db", clock=lambda created=grant["created_at"]: created)
        secret = new_reauth_secret()
        opened = store.open_grant(grant["user_id"], grant["provider"], client,
                                  reauth_secret_hash(secret) if client == "web" else None)
        assert opened.created_at == grant["created_at"] and opened.expires_at == grant["created_at"] + 600
        done = store.complete_grant(
            opened.id, session_user=session["user_id"], session_provider=session["provider"],
            auth_time=session["auth_time"], client=client, secret=secret if client == "web" else None,
            use_secret_hash=reauth_secret_hash(new_reauth_secret()) if client == "native" else None,
            accept_missing=vector["accept_missing_auth_time"])
        expect = vector["expect"]
        assert done.state == expect["state"], vector["name"]
        if expect["state"] == "failed":
            assert done.failure == expect["failure"], vector["name"]
        else:
            assert done.auth_time_assumed is expect["auth_time_assumed"], vector["name"]


def test_the_self_enrolment_wire_examples_are_all_there(vectors):
    examples = vectors["wire_examples"]
    for key in ("status_self_enrol", "status_self_enrol_cooling_off", "self_enrol_disabled",
                "self_enrol_provider_no_reauth", "reauth_begin_answer_web", "reauth_begin_answer_native",
                "reauth_cookie_set", "reauth_cookie_cleared", "native_token_reauth_fresh",
                "native_token_reauth_failed", "register_begin_request_with_grant_web",
                "register_begin_request_with_grant_native", "register_begin_answer_with_grant",
                "register_finish_request_with_grant_web", "register_finish_request_with_grant_native",
                "register_finish_answer_self", "error_reauth_invalid", "error_reauth_invalid_unknown",
                "error_self_enrol_disabled", "error_provider_no_reauth", "error_insecure_binding",
                "error_origin_not_listed", "error_reauth_rate_limited", "error_exactly_one_authority",
                "sign_in_refused_page", "sign_in_rate_limited_page"):
        assert key in examples, key
    # One authority per enrolment, and a web finish carries no use_secret (its binding is the cookie).
    web, native = (examples[f"register_finish_request_with_grant_{kind}"] for kind in ("web", "native"))
    assert "code" not in web and "code" not in native
    assert "use_secret" not in web and "use_secret" in native
    assert "use_secret" in examples["native_token_reauth_fresh"]["reauth"]
    assert "use_secret" not in examples["native_token_reauth_failed"]["reauth"]


# ── version 2: structured fields (README §4.1) ───────────────────────────────────────────────────


def test_text_digest_v2_vectors_cover_the_promised_cases(gen, vectors):
    texts = {v["name"]: v for v in vectors["text_digest_v2_vectors"]}
    amount = texts["amount with a non-ASCII currency symbol in the label"]
    assert not amount["fields"][0]["label"].isascii() and amount["fields"][0]["kind"] == "amount"
    swapped = texts["same fields, order swapped (differs)"]
    assert swapped["fields"] == list(reversed(amount["fields"])) and swapped["text_digest"] != amount["text_digest"]
    assert texts["label and value boundary: ab|c"]["text_digest"] != texts["label and value boundary: a|bc (differs)"][
        "text_digest"]
    assert len({v["text_digest"] for v in texts.values()}) == len(texts)
    for v in texts.values():
        assert v["text_digest"] != v["text_digest_v1"]
        assert gen.b64u(gen.sha256(bytes.fromhex(v["preimage_hex"]))) == v["text_digest"], v["name"]


def test_version_2_assertion_vectors(vectors):
    by_name = {v["name"]: v for v in vectors["assertion_vectors_v2"]}
    accepted = by_name["version 2: fields signed in the frame's order"]
    assert accepted["expect"]["ok"] and accepted["answer"]["passkey"]["v"] == 2 and accepted["request"]["fields"]
    assert by_name["version 2: signed over the text without the fields"]["expect"]["reason"] == "challenge_mismatch"
    assert by_name["version 2: fields signed in another order"]["expect"]["reason"] == "challenge_mismatch"
    assert by_name["version 2 request answered with v 1"]["expect"]["reason"] == "bad_shape"
    assert by_name["version 1 request answered with v 2"]["expect"]["reason"] == "bad_shape"
    # The version-1 list is unchanged in kind: no fields, every answer v 1.
    for vector in vectors["assertion_vectors"]:
        assert "fields" not in vector["request"], vector["name"]


def test_the_wire_examples_validate_against_the_gateways_models(vectors):
    from tui_gateway.contracts import registry
    wire = vectors["wire_examples"]
    registry.SERVER_REQUESTS["confirm"].params.model_validate(wire["confirm_request_frame_v2"]["params"])
    registry.SERVER_REQUESTS["confirm"].params.model_validate(wire["confirm_request_frame"]["params"])
    registry.METHODS["client.capabilities"].params.model_validate(wire["capabilities_second_call_params_v2"])
    registry.METHODS["client.capabilities"].result.model_validate(wire["capabilities_first_result_v2"])
    registry.METHODS["client.capabilities"].result.model_validate(wire["capabilities_second_result_v2"])
