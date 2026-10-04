"""The self-enrolment wire objects of ``contract/confirm-passkey`` (``vectors.json`` → ``wire_examples``) against
what the passkey routes really answer.

The contract's examples are what the native app, the browser client and the fake gateway are built and tested
against; this is the place where the gateway itself is held to them. Values that differ by nature (ids,
timestamps, secrets) are not compared, everything else is: the field names and kinds of an object, the exact
body of every error answer, and the attributes of the binding cookie.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.passkeys import routes
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider
from tests.hermes_cli.test_passkey_routes import (  # noqa: F401 - the fixtures and helpers the routes tests share
    ALICE,
    BASE,
    BOB,
    _http_gateway,
    begin_with_grant,
    fresh,
    finish_body,
    finish_with_grant,
    make_gateway,
    make_self_gateway,
    native,
    open_grant,
    reauth_cookie_of,
    self_enrol,
    sgw,
    web_headers,
)

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "contract" / "confirm-passkey" / "vectors.json")
                     .read_text(encoding="utf-8"))
EXAMPLES = VECTORS["wire_examples"]


def matches(actual, example, path: str = "") -> None:
    """*actual* has the fields and kinds of *example* (an empty list on either side matches any list)."""
    if isinstance(example, dict):
        assert isinstance(actual, dict), path
        assert set(actual) == set(example), f"{path}: {sorted(actual)} != {sorted(example)}"
        for key in example:
            matches(actual[key], example[key], f"{path}.{key}")
    elif isinstance(example, list):
        assert isinstance(actual, list), path
        if actual and example:
            matches(actual[0], example[0], f"{path}[0]")
    elif example is None:
        assert actual is None, path
    else:
        assert type(actual) is type(example), f"{path}: {actual!r} is not a {type(example).__name__}"


def answer(response) -> dict:
    """An error answer in the contract's form."""
    return {"status": response.status_code, "body": response.json()}


def cookie_attributes(header: str) -> set[str]:
    return {part.strip().lower() for part in header.split(";")[1:]}


def test_the_status_route_gives_the_documented_self_enrolment_objects(make_gateway, make_self_gateway):
    sgw = make_self_gateway()
    assert sgw.get().json()["self_enrol"] == EXAMPLES["status_self_enrol"]["self_enrol"]
    self_enrol(sgw, native())
    matches(sgw.get().json(), EXAMPLES["status_self_enrol"])
    assert sgw.get().json()["credentials"][0]["created_via"] == "self"

    cooling = make_self_gateway({"self_enrol": {"enabled": True, "cooling_off_s": 600}})
    assert cooling.get().json()["self_enrol"] == EXAMPLES["status_self_enrol_cooling_off"]["self_enrol"]
    self_enrol(cooling, native(), BOB)  # both gateways share this test's store file: another person's credential
    body = cooling.get(BOB).json()
    matches(body, EXAMPLES["status_self_enrol_cooling_off"])
    assert body["credentials"][0]["usable_from"] == int(cooling.clock.t) + 600

    assert make_self_gateway({"self_enrol": {"enabled": False}}).get().json()["self_enrol"] == \
        EXAMPLES["self_enrol_disabled"]
    plain = make_gateway()
    clear_providers()
    register_provider(StubAuthProvider())
    assert plain.get().json()["self_enrol"] == EXAMPLES["self_enrol_provider_no_reauth"]


def test_reauth_begin_answers_and_the_binding_cookie(sgw):
    web = sgw.post("/reauth/begin", EXAMPLES["reauth_begin_request"], headers=web_headers(sgw))
    assert web.status_code == 200
    body = web.json()
    matches(body, EXAMPLES["reauth_begin_answer_web"])
    for source in (body, EXAMPLES["reauth_begin_answer_web"]):  # the same template in the real answer and the example
        assert source["login_path"] == f"/auth/login?provider={source['provider']}&reauth={source['grant_id']}"
    assert body["expires_at"] - int(sgw.clock.t) == 600
    cookie = next(c for c in web.headers.get_list("set-cookie") if "hermes_reauth" in c)
    example = EXAMPLES["reauth_cookie_set"]
    assert cookie.split("=", 1)[0] == example.split("=", 1)[0]
    assert cookie_attributes(cookie) == cookie_attributes(example)
    assert len(cookie.split(";", 1)[0].split("=", 1)[1]) == len(example.split(";", 1)[0].split("=", 1)[1])

    app = sgw.post("/reauth/begin", EXAMPLES["reauth_begin_request"])
    assert app.status_code == 200
    matches(app.json(), EXAMPLES["reauth_begin_answer_native"])
    assert "set-cookie" not in app.headers


@pytest.mark.parametrize("kind", ["web", "native"])
def test_register_with_a_grant_has_the_documented_shapes(sgw, kind):
    auth = native()
    grant_id = open_grant(sgw, web=kind == "web")["grant_id"]
    fresh(sgw, grant_id)
    begin_body = {"rp_id": auth.rp_id, "base_url": BASE, "name": "Laptop"}
    request = EXAMPLES[f"register_begin_request_with_grant_{kind}"]
    # The request a client sends has the documented fields (the example's values are the vector's own).
    assert set(request) == set(begin_body) | {"grant_id"} | ({"use_secret"} if kind == "native" else set())

    begun = begin_with_grant(sgw, auth, grant_id)
    assert begun.status_code == 200, begun.text
    matches(begun.json(), EXAMPLES["register_begin_answer_with_grant"])
    assert begun.json()["grant"]["expires_at"] == int(sgw.clock.t) + 600

    body = finish_body(sgw, auth, begun.json())
    sent = body | {"grant_id": grant_id}
    sent_keys = set(sent) | ({"use_secret"} if kind == "native" else set())
    assert sent_keys == set(EXAMPLES[f"register_finish_request_with_grant_{kind}"])
    finished = finish_with_grant(sgw, auth, begun.json(), grant_id)
    assert finished.status_code == 200, finished.text
    matches(finished.json(), EXAMPLES["register_finish_answer_self"])
    cleared = [c for c in finished.headers.get_list("set-cookie") if "hermes_reauth" in c]
    if kind == "web":
        assert len(cleared) == 1
        example = EXAMPLES["reauth_cookie_cleared"]
        # An empty value is written as ="" by the framework: the same cookie.
        assert cleared[0].split(";", 1)[0].replace('"', "") == example.split(";", 1)[0]
        assert cookie_attributes(cleared[0]) == cookie_attributes(example)
    else:
        assert cleared == []


def test_every_error_answer_is_the_documented_one(make_gateway, make_self_gateway, sgw):
    # reauth_invalid: a web grant whose sign-in came back too old, then one nobody completed (native).
    web = open_grant(sgw, web=True)["grant_id"]
    fresh(sgw, web, auth_time=int(sgw.clock.t) - 3600)
    assert answer(begin_with_grant(sgw, native(), web)) == EXAMPLES["error_reauth_invalid"]
    app = open_grant(sgw)["grant_id"]
    assert answer(begin_with_grant(sgw, native(), app)) == EXAMPLES["error_reauth_invalid_unknown"]

    # Exactly one authority.
    auth = native()
    grant_id = open_grant(sgw)["grant_id"]
    fresh(sgw, grant_id)
    begun = begin_with_grant(sgw, auth, grant_id).json()
    both = finish_body(sgw, auth, begun) | {"grant_id": grant_id, "code": "x"}
    assert answer(sgw.post("/register/finish", both)) == EXAMPLES["error_exactly_one_authority"]

    # origin_not_listed: a cookie write without a listed Origin.
    assert answer(sgw.post("/reauth/begin", {}, headers=sgw.cookie(ALICE))) == EXAMPLES["error_origin_not_listed"]

    # rate_limited: the sixth opening in ten minutes (this test opened some already; start the budget again).
    routes.reset_for_tests()
    limited = make_self_gateway()
    statuses = [limited.post("/reauth/begin", {}) for _ in range(6)]
    assert [r.status_code for r in statuses] == [200] * 5 + [429]
    assert answer(statuses[-1]) == EXAMPLES["error_reauth_rate_limited"]
    assert statuses[-1].headers["retry-after"] == "600"

    # self_enrol_disabled and provider_no_reauth.
    off = make_self_gateway({"self_enrol": {"enabled": False}})
    assert answer(off.post("/reauth/begin", {})) == EXAMPLES["error_self_enrol_disabled"]
    plain = make_gateway()
    clear_providers()
    register_provider(StubAuthProvider())
    assert answer(plain.post("/reauth/begin", {})) == EXAMPLES["error_provider_no_reauth"]


def test_insecure_binding_is_the_documented_answer(make_self_gateway):
    gw, client = _http_gateway(make_self_gateway, ["http://gw.example.com"])
    r = client.post(f"{routes.PREFIX}/reauth/begin", json={},
                    headers=web_headers(gw, origin="http://gw.example.com"))
    assert answer(r) == EXAMPLES["error_insecure_binding"]
