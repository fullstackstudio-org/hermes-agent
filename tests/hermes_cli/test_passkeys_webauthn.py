"""The confirm-passkey verifier (``hermes_cli/dashboard_auth/passkeys``) against the contract.

Every vector in ``contract/confirm-passkey/vectors.json`` passes or fails with its labelled reason through
the REAL verifier (the generator's reference evaluator is only the generator's own check). On top: a
software authenticator round trip, the memoised validator, and fuzzing: truncations and bit flips at
every offset of every binary field, and random garbage, must give a refusal from the closed list and
never an exception.
"""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

from hermes_cli.dashboard_auth.passkeys import cbor
from hermes_cli.dashboard_auth.passkeys.challenge import (
    GatewayContext, NotABaseUrl, b64u, b64u_decode, challenge, enrolment_code_canonical, enrolment_code_hash,
    field_tuple, is_private, origin_of, serialise_base_url, text_digest, text_digest_v2, user_handle)
from hermes_cli.dashboard_auth.passkeys.webauthn import (
    ASSERTION_REASONS, REGISTRATION_REASONS, AssertionOk, AssertionRequest, PendingRegistration, RegistrationOk,
    Refusal, StoredCredential,
    memoised_assertion_validator, verify_assertion, verify_registration)

from tests.hermes_cli.passkey_soft_authenticator import SoftAuthenticator, web_authenticator

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "contract" / "confirm-passkey" / "vectors.json")
                     .read_text(encoding="utf-8"))


def _context(name: str) -> GatewayContext:
    c = VECTORS["contexts"][name]
    return GatewayContext(gateway_id=b64u_decode(c["gateway_id"]), handle_key=b64u_decode(c["handle_key"]),
                          base_urls=tuple(c["base_urls"]),
                          native_rps={k: tuple(v) for k, v in c["native_rps"].items()},
                          allow_private_base_urls=c["allow_private_base_urls"])


def _stored(record: dict) -> StoredCredential:
    return StoredCredential(credential_id=b64u_decode(record["credential_id"]), user_id=record["user_id"],
                            rp_id=record["rp_id"], public_x=b64u_decode(record["public_key"]["x"]),
                            public_y=b64u_decode(record["public_key"]["y"]), sign_count=record["sign_count"],
                            backup_eligible=record["backup_eligible"], active=record["active"])


def _request(r: dict) -> AssertionRequest:
    return AssertionRequest(user_id=r["user_id"], request_id=r["request_id"], nonce=b64u_decode(r["nonce"]),
                            title=r["title"], summary=r["summary"], detail=r["detail"], session_id=r["session_id"],
                            fields=tuple(field_tuple(f) for f in r.get("fields") or ()))


def _assertion_verdict(vector: dict) -> dict:
    result = verify_assertion(_context(vector["context"]), _request(vector["request"]),
                              [_stored(s) for s in vector["store"]], vector["answer"])
    if not result.ok:
        return {"ok": False, "code": 4034, "reason": result.reason}
    return {"ok": True, "sign_count": result.sign_count, "backup_eligible": result.backup_eligible,
            "backed_up": result.backed_up, "counter_warning": result.counter_warning}


def _pending(begin: dict) -> PendingRegistration:
    return PendingRegistration(registration_id=begin["registration_id"], user_id=begin["user"]["id"],
                               rp_id=begin["rp_id"], base_url=begin["base_url"], name=begin["name"],
                               nonce=b64u_decode(begin["nonce"]))


def _registration_verdict(vector: dict) -> dict:
    result = verify_registration(_context(vector["context"]), _pending(vector["begin"]), vector["finish"])
    if not result.ok:
        return {"ok": False, "status": 422, "error": "attestation_invalid", "reason": result.reason}
    return {"ok": True, "credential_id": b64u(result.credential_id), "rp_id": result.rp_id, "alg": result.alg,
            "public_key": {"x": b64u(result.public_x), "y": b64u(result.public_y)}, "sign_count": result.sign_count,
            "backup_eligible": result.backup_eligible, "backed_up": result.backed_up, "aaguid": b64u(result.aaguid)}


# ── the vectors ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS["assertion_vectors"] + VECTORS["assertion_vectors_v2"], ids=lambda v: v["name"])
def test_assertion_vector(vector):
    assert _assertion_verdict(vector) == vector["expect"]


@pytest.mark.parametrize("vector", VECTORS["registration_vectors"], ids=lambda v: v["name"])
def test_registration_vector(vector):
    assert _registration_verdict(vector) == vector["expect"]


def test_refusal_orders_match_the_contract():
    assert list(ASSERTION_REASONS) + ["too_many_attempts"] == VECTORS["assertion_refusal_order"]
    assert list(REGISTRATION_REASONS) == VECTORS["registration_refusal_order"]


@pytest.mark.parametrize("vector", VECTORS["base_url_vectors"], ids=lambda v: v["name"])
def test_base_url_vector(vector):
    if "error" in vector:
        with pytest.raises(NotABaseUrl):
            serialise_base_url(vector["input"])
        return
    value = serialise_base_url(vector["input"])
    assert value == vector["base_url"] and origin_of(value) == vector["origin"]
    assert is_private(value) is vector["private"]


def test_construction_vectors():
    for v in VECTORS["text_digest_vectors"]:
        assert b64u(text_digest(v["title"], v["summary"], v["detail"])) == v["text_digest"], v["name"]
    for v in VECTORS["text_digest_v2_vectors"]:
        fields = tuple(field_tuple(f) for f in v["fields"])
        assert b64u(text_digest_v2(v["title"], v["summary"], v["detail"], fields)) == v["text_digest"], v["name"]
        assert b64u(text_digest(v["title"], v["summary"], v["detail"])) == v["text_digest_v1"], v["name"]
        request = AssertionRequest(user_id="u", request_id="r", nonce=b"", title=v["title"], summary=v["summary"],
                                   detail=v["detail"], fields=fields)
        assert request.version == 2 and b64u(request.text_digest) == v["text_digest"], v["name"]
    for v in VECTORS["challenge_vectors"]:
        got = challenge(purpose=v["purpose"], base_url=v["base_url"], gateway_id=b64u_decode(v["gateway_id"]),
                        user_id=v["user_id"], session_id=v["session_id"], request_id=v["request_id"],
                        nonce=b64u_decode(v["nonce"]), digest=b64u_decode(v["text_digest"]))
        assert b64u(got) == v["challenge"], v["name"]
    for v in VECTORS["user_handle_vectors"]:
        assert b64u(user_handle(b64u_decode(v["handle_key"]), v["user_id"])) == v["user_handle"]
    for v in VECTORS["enrolment_code_vectors"]:
        assert enrolment_code_canonical(v["input"]) == v["canonical"], v["name"]
        h = enrolment_code_hash(v["input"])
        assert (b64u(h) if h else None) == v["code_hash"]


def test_contexts_derive_as_the_contract_says():
    for name, c in VECTORS["contexts"].items():
        ctx = _context(name)
        assert list(ctx.accepted_base_urls) == c["derived"]["accepted_base_urls"], name
        assert sorted(ctx.native_rp_ids) == c["derived"]["accepted_rps"]["native"], name
        assert sorted(ctx.web_rp_ids) == c["derived"]["accepted_rps"]["web"], name
        assert ctx.capability_reason() == c["derived"]["capability_reason"], name


@pytest.mark.parametrize("bad", ["a=", "a b", "AB+/", "QQ==", "QR", "Q", 7, None, "é"])
def test_strict_base64url(bad):
    with pytest.raises(ValueError):
        b64u_decode(bad)


# ── a software authenticator round trip ─────────────────────────────────────────────────────

GW = "https://gw.example.com"
USER = "self_hosted:7c1f0e2a"


def _live_context() -> GatewayContext:
    return GatewayContext(gateway_id=b"g" * 16, handle_key=b"h" * 32, base_urls=(GW,),
                          native_rps={"confirm.hermie.dev": ("https://confirm.hermie.dev",)})


@pytest.mark.parametrize("make", [
    lambda: SoftAuthenticator(rp_id="confirm.hermie.dev", client_origin="https://confirm.hermie.dev"),
    lambda: web_authenticator(GW, synced=False),
], ids=["native-synced", "web-device-bound"])
def test_register_then_confirm(make):
    ctx, auth = _live_context(), make()
    pending = PendingRegistration(registration_id="reg-1", user_id=USER, rp_id=auth.rp_id, base_url=GW,
                                  name="Alex Example — gw.example.com", nonce=b"n" * 32)
    registered = verify_registration(ctx, pending, auth.register(ctx.gateway_id, pending))
    assert isinstance(registered, RegistrationOk), registered
    stored = StoredCredential(credential_id=registered.credential_id, user_id=USER, rp_id=registered.rp_id,
                              public_x=registered.public_x, public_y=registered.public_y,
                              sign_count=registered.sign_count, backup_eligible=registered.backup_eligible)
    request = AssertionRequest(user_id=USER, request_id="srq-1", nonce=b"m" * 32, title="Pay", summary="Pay 10 EUR.",
                               detail=None, session_id="s1")
    ok = verify_assertion(ctx, request, [stored], auth.assert_(ctx.gateway_id, ctx.handle_key, request, GW))
    assert ok.ok and ok.counter_warning is False
    # The same answer for another request (another nonce) is a challenge mismatch.
    other = AssertionRequest(**{**request.__dict__, "nonce": b"x" * 32})
    assert verify_assertion(ctx, other, [stored], auth.assert_(ctx.gateway_id, ctx.handle_key, request, GW)).reason \
        == "challenge_mismatch"


def test_results_name_the_request_they_were_checked_against():
    """The store commits a result to exactly this request: a step-up by its own id and nonce."""
    ctx, auth = _live_context(), web_authenticator(GW)
    pending = PendingRegistration(registration_id="reg-9", user_id=USER, rp_id=auth.rp_id, base_url=GW, name="n",
                                  nonce=b"r" * 32)
    registered = verify_registration(ctx, pending, auth.register(ctx.gateway_id, pending))
    assert isinstance(registered, RegistrationOk)
    assert (registered.registration_id, registered.user_id, registered.nonce) == ("reg-9", USER, b"r" * 32)
    stored = StoredCredential(credential_id=registered.credential_id, user_id=USER, rp_id=registered.rp_id,
                              public_x=registered.public_x, public_y=registered.public_y, sign_count=0,
                              backup_eligible=True)
    request = AssertionRequest(user_id=USER, request_id="step-1", nonce=b"s" * 32, title="", summary="invite",
                               detail="", purpose="invite")
    ok = verify_assertion(ctx, request, [stored], auth.assert_(ctx.gateway_id, ctx.handle_key, request, GW))
    assert isinstance(ok, AssertionOk)
    assert (ok.user_id, ok.purpose, ok.session_id, ok.request_id, ok.nonce) == (USER, "invite", "", "step-1", b"s" * 32)


@pytest.mark.parametrize("fields", [{-1: True}, {3: False}, {-1: "1"}], ids=["crv-true", "alg-false", "crv-text"])
def test_cose_key_parameters_must_be_integers(fields):
    ctx, auth = _live_context(), web_authenticator(GW)
    pending = PendingRegistration(registration_id="reg-1", user_id=USER, rp_id=auth.rp_id, base_url=GW, name="n",
                                  nonce=b"n" * 32)
    finish = auth.register(ctx.gateway_id, pending, cose_fields=fields)
    result = verify_registration(ctx, pending, finish)
    assert isinstance(result, Refusal) and result.reason == "unsupported_algorithm"


def test_base64url_length_is_checked_before_decoding():
    assert len(b64u_decode("A" * 43, 32, 32)) == 32
    with pytest.raises(ValueError, match="not base64url"):
        b64u_decode("A" * 44, 32, 32)  # one character over: refused on length alone
    with pytest.raises(ValueError):
        b64u_decode("A" * 1_000_000, 1, 1023)


def test_a_step_up_assertion_uses_its_purpose():
    ctx = _live_context()
    auth = web_authenticator(GW)
    pending = PendingRegistration("reg-2", USER, auth.rp_id, GW, "n", b"n" * 32)
    reg = verify_registration(ctx, pending, auth.register(ctx.gateway_id, pending))
    stored = StoredCredential(reg.credential_id, USER, reg.rp_id, reg.public_x, reg.public_y, reg.sign_count,
                              reg.backup_eligible)
    invite = AssertionRequest(user_id=USER, request_id="stp-1", nonce=b"s" * 32, title="", summary="invite",
                              detail="", purpose="invite")
    answer = auth.assert_(ctx.gateway_id, ctx.handle_key, invite, GW)
    assert verify_assertion(ctx, invite, [stored], answer).ok
    revoke = AssertionRequest(**{**invite.__dict__, "purpose": "revoke"})
    assert verify_assertion(ctx, revoke, [stored], answer).reason == "challenge_mismatch"


def test_the_memoised_validator_verifies_once_per_answer(monkeypatch):
    from hermes_cli.dashboard_auth.passkeys import webauthn
    vector = VECTORS["assertion_vectors"][0]
    calls = []
    real = webauthn.verify_assertion
    monkeypatch.setattr(webauthn, "verify_assertion", lambda *a: calls.append(1) or real(*a))
    validate = memoised_assertion_validator(_context(vector["context"]), _request(vector["request"]),
                                            [_stored(s) for s in vector["store"]])
    first, second = validate(vector["answer"]), validate(copy.deepcopy(vector["answer"]))
    assert first is second and first.ok and len(calls) == 1
    assert validate({"decision": "declined"}).reason == "bad_shape" and len(calls) == 2


# ── fuzzing: garbage is always a reason ─────────────────────────────────────────────────────

_BINARY = ("credential_id", "authenticator_data", "client_data_json", "signature", "user_handle")


def _mutations(raw: bytes, rng: random.Random):
    for cut in range(len(raw)):
        yield raw[:cut]
    for offset in range(len(raw)):
        yield raw[:offset] + bytes([raw[offset] ^ (1 << rng.randrange(8))]) + raw[offset + 1:]


@pytest.mark.parametrize("field", _BINARY)
def test_truncated_and_flipped_assertion_fields_are_refused_with_a_reason(field):
    rng = random.Random(field)
    vector = VECTORS["assertion_vectors"][0]
    ctx, request = _context(vector["context"]), _request(vector["request"])
    store = [_stored(s) for s in vector["store"]]
    raw = b64u_decode(vector["answer"]["passkey"][field])
    for mutated in _mutations(raw, rng):
        answer = copy.deepcopy(vector["answer"])
        answer["passkey"][field] = b64u(mutated)
        result = verify_assertion(ctx, request, store, answer)
        assert result.ok is False and result.reason in ASSERTION_REASONS, (field, mutated)


def test_truncated_and_flipped_registrations_never_raise():
    """A registration carries no signature over the attestation object (attestation ``none``, any ``fmt``
    accepted), so a flip in a field the contract ignores (``fmt``, ``attStmt``, the AAGUID, an unknown
    clientDataJSON key) legitimately still verifies. What must hold: never an exception, and a refusal is
    always from the closed list; the credential id, key, rpIdHash, flags and challenge are each covered."""
    rng = random.Random(1)
    vector = VECTORS["registration_vectors"][0]
    ctx, pending = _context(vector["context"]), _pending(vector["begin"])
    accepted = 0
    for field in ("attestation_object", "client_data_json", "id"):
        raw = b64u_decode(vector["finish"]["credential"][field])
        for mutated in _mutations(raw, rng):
            finish = copy.deepcopy(vector["finish"])
            finish["credential"][field] = b64u(mutated)
            result = verify_registration(ctx, pending, finish)
            if result.ok:
                accepted += 1
                assert result.credential_id == b64u_decode(finish["credential"]["id"])
            else:
                assert result.reason in REGISTRATION_REASONS, (field, mutated)
    assert accepted < 120  # only ignored bytes may change without a refusal


def _random_json(rng: random.Random, depth: int = 0):
    choice = rng.randrange(8 if depth < 3 else 5)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice([True, False, 0, 1, -1, 2 ** 70, 1.5])
    if choice == 2:
        return "".join(rng.choice("ab=_-+/é{}\"") for _ in range(rng.randrange(12)))
    if choice == 3:
        return b64u(rng.randbytes(rng.randrange(80)))
    if choice == 4:
        return rng.choice(["confirmed", "passkey", "declined", "webauthn.get"])
    if choice == 5:
        return [_random_json(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = ["decision", "method", "passkey", "v", "rp_id", "base_url", "credential_id", "authenticator_data",
            "client_data_json", "signature", "user_handle", "x"]
    return {rng.choice(keys): _random_json(rng, depth + 1) for _ in range(rng.randrange(8))}


def test_random_answers_are_refused_with_a_reason():
    rng = random.Random(2026)
    vector = VECTORS["assertion_vectors"][0]
    ctx, request = _context(vector["context"]), _request(vector["request"])
    store = [_stored(s) for s in vector["store"]]
    for _ in range(3000):
        answer = _random_json(rng)
        if rng.random() < 0.5:
            answer = {"decision": "confirmed", "method": "passkey", "passkey": {
                **copy.deepcopy(vector["answer"]["passkey"]), **(answer if isinstance(answer, dict) else {})}}
        result = verify_assertion(ctx, request, store, answer)
        if answer == vector["answer"]:
            assert result.ok  # nothing was changed
        else:
            assert result.ok is False and result.reason in ASSERTION_REASONS, answer
        registration = verify_registration(ctx, _pending(VECTORS["registration_vectors"][0]["begin"]), answer)
        assert registration.ok is False and registration.reason in REGISTRATION_REASONS


def test_random_client_data_is_refused_with_a_reason():
    rng = random.Random(7)
    vector = VECTORS["assertion_vectors"][0]
    ctx, request = _context(vector["context"]), _request(vector["request"])
    store = [_stored(s) for s in vector["store"]]
    samples = [b"", b"{", b"[]", b"null", b'{"a":1,"a":2}', b'{"type":{"type":1}}', b"\xff\xfe", b"\xef\xbb\xbf{}",
               b'{"type":"webauthn.get","challenge":"' + b"A" * 3000 + b'"}', b"[" * 2000 + b"]" * 2000]
    samples += [rng.randbytes(rng.randrange(1, 200)) for _ in range(500)]
    for raw in samples:
        answer = copy.deepcopy(vector["answer"])
        answer["passkey"]["client_data_json"] = b64u(raw[:4096]) if raw else "A"
        result = verify_assertion(ctx, request, store, answer)
        assert result.ok is False and result.reason in ASSERTION_REASONS, raw[:40]


def test_the_cbor_decoder_raises_only_its_own_error():
    rng = random.Random(12)
    samples = [b"", b"\xbf", b"\x9f", b"\x5f", b"\x7f", b"\xc0\x00", b"\xf9\x00\x00", b"\xf7", b"\x1c",
               b"\x9b" + b"\xff" * 8, b"\xbb" + b"\xff" * 8, b"\x5b" + b"\xff" * 8, b"\x81" * 10 + b"\x00",
               b"\xa1\xf4\x00", b"\xa2\x01\x00\x01\x00", b"\x63\xff\xfe\xfd"]
    samples += [rng.randbytes(rng.randrange(1, 64)) for _ in range(5000)]
    for raw in samples:
        try:
            cbor.decode_exactly(raw)
        except cbor.CborError:
            pass
    assert cbor.decode_exactly(b"\xa2\x01\x02\x61a\xf5") == {1: 2, "a": True}
    with pytest.raises(cbor.CborError):
        cbor.decode_exactly(b"\x81" * 5 + b"\x00")  # depth 6
