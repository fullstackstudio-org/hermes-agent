"""The device requests ``device.location``, ``device.contact``, ``device.calendar``, ``device.scan``, the signature
``input.signature`` and the voice note (``input.file`` with ``accept: audio``) (``tui_gateway/interactive_device.py``,
``interactive.py``, ``interactive_validate.py``; plan ``request-types-v2`` task P3-F1, contract ``contract/requests``
§5.1 and §8-§12).

What is pinned here: a location is rounded by the gateway whatever the client sent (two decimals and at least 1,000 m
for ``approximate``, six decimals for ``precise``) and a client cannot share more than was asked; a contact reaches the
agent with only the keys the request asked for, cleaned, and the validator refuses any other key before that; a scanned
value is untrusted text, cleaned, and reaches the agent with a flag when cleaning changed it; a signature's answer must
carry the SHA-256 of the exact statement shown and its two files are checked on disk to be a PNG and a plain SVG; a
calendar entry comes back as ``saved`` only; the agent's text is cleaned or refused, never passed through; only a client
that advertised the method is sent the frame, and only the person's own connection when the gateway can name them (a
shared session that names nobody gets nothing for a device request or a signature); one request is open at a time
across ``input.*`` / ``review.*`` / ``device.*`` and ``device.*`` is limited to six per ten minutes, ``input.*`` and
``review.*`` keep their twelve; no logger and no audit record ever sees a coordinate, a contact, a scanned value or a
statement. Every payload is a harmless marker.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

import pytest

from tests.tui_gateway.test_interactive_request import (  # noqa: F401 - fixtures are used by name
    MARKER, ROBIN, SAM, _WS, _as, _ask, _capable, _caps, _contract_accepts, _entry, _finish, _frame, _open_id, _put,
    _rpc, _session, _start, audit_records, build, cancels, clock, server)
from tui_gateway import interactive_device as dev, interactive_validate as v
from tui_gateway.contracts.server_requests import INTERACTIVE_METHODS

DEVICE = ("device.location", "device.contact", "device.calendar", "device.scan")
ALL = tuple(INTERACTIVE_METHODS)
STATEMENT = "I agree to the terms of " + MARKER + "."
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"marker-png"
SVG_BYTES = b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0L1 1"/></svg>'


def _sig(build, **kwargs):
    kwargs.setdefault("summary", "Please sign.")
    kwargs.setdefault("statement", STATEMENT)
    return build.build_signature_params("s1", **kwargs)


def _loc(build, **kwargs):
    kwargs.setdefault("summary", "Where are you?")
    return build.build_location_params("s1", **kwargs)


def _contact(build, **kwargs):
    kwargs.setdefault("summary", "Pick the plumber.")
    kwargs.setdefault("fields", ["name", "phones"])
    return build.build_contact_params("s1", **kwargs)


ITEM = {"title": "Dentist", "start": "2026-10-12T09:30+02:00", "end": "2026-10-12T10:00+02:00"}


def _calendar(build, **kwargs):
    kwargs.setdefault("summary", "Put it in your calendar.")
    kwargs.setdefault("kind", "event")
    kwargs.setdefault("item", ITEM)
    return build.build_calendar_params("s1", **kwargs)


def _scan(build, **kwargs):
    kwargs.setdefault("summary", "Scan the code.")
    return build.build_scan_params("s1", **kwargs)


def _start_with_default_timeout(build, method, params):
    """``interactive.request`` with no timeout of its own, on a thread inside a copy of this context."""
    import contextvars
    import threading
    box: dict = {}
    ctx = contextvars.copy_context()
    thread = threading.Thread(target=lambda: box.setdefault("outcome", ctx.run(build.request, "s1", method, params)),
                              daemon=True)
    thread.start()
    box["thread"] = thread
    return box


def _device_capable(server, *peers, **kwargs):
    """Every peer lists every method. ``_capable`` makes the session anew, so the working directory the ``build``
    fixture gave it (files go below it) is put back: a file must never land in the checkout."""
    kwargs.setdefault("methods", ALL)
    sid = kwargs.get("sid", "s1")
    cwd = (server._sessions.get(sid) or {}).get("cwd")
    result = _capable(server, *peers, **kwargs)
    if cwd:
        server._sessions[sid]["cwd"] = cwd
    return result


# ── pure: what the agent receives of a location ─────────────────────────────────────────────────


def _fix(**over):
    return {"status": "answered", "lat": 52.3731, "lon": 4.8922, "accuracy_m": 35.0, "at": 1791119300,
            "precision": "approximate", **over}


def test_an_approximate_location_is_rounded_to_two_decimals_with_at_least_a_kilometre_of_accuracy():
    assert dev.round_location(_fix(), "approximate") == {
        "lat": 52.37, "lon": 4.89, "accuracy_m": 1000.0, "at": 1791119300, "precision": "approximate"}
    # a fix that is already coarser than the floor keeps its own accuracy
    assert dev.round_location(_fix(accuracy_m=2500.55), "approximate")["accuracy_m"] == 2500.6
    assert dev.round_location(_fix(accuracy_m=0), "approximate")["accuracy_m"] == 1000.0


@pytest.mark.parametrize("lat, lon, want", [
    (52.3749, 4.8851, (52.37, 4.89)), (-33.8688, 151.2093, (-33.87, 151.21)), (0.004, -0.004, (0.0, 0.0)),
    (89.999, -179.999, (90.0, -180.0)), (-0.0, 0.0, (0.0, 0.0))])
def test_rounding_to_two_decimals_never_leaves_a_negative_zero(lat, lon, want):
    out = dev.round_location(_fix(lat=lat, lon=lon), "approximate")
    assert (out["lat"], out["lon"]) == want
    assert str(out["lat"]) == str(want[0]) and str(out["lon"]) == str(want[1])


def test_a_precise_location_keeps_six_decimals_and_one_of_accuracy():
    out = dev.round_location(_fix(lat=52.37312345678, lon=4.89220099999, accuracy_m=8.4999, precision="precise"),
                             "precise")
    assert out == {"lat": 52.373123, "lon": 4.892201, "accuracy_m": 8.5, "at": 1791119300, "precision": "precise"}


def test_a_client_that_shares_more_than_was_asked_is_treated_as_having_shared_what_was_asked():
    out = dev.round_location(_fix(lat=52.373123, lon=4.892201, accuracy_m=5, precision="precise"), "approximate")
    assert out["precision"] == "approximate" and (out["lat"], out["lon"], out["accuracy_m"]) == (52.37, 4.89, 1000.0)
    assert dev.effective_precision("precise", "approximate") == "approximate"
    assert dev.effective_precision("precise", "precise") == "precise"
    assert dev.precision_problem("approximate", "precise") == "precision:too_precise"
    assert dev.precision_problem("precise", "approximate") is None
    assert dev.precision_problem("approximate", "approximate") is None


# ── pure: a contact ─────────────────────────────────────────────────────────────────────────────


def test_a_contact_is_cut_to_the_requested_keys_in_a_fixed_order_and_cleaned():
    contact = {"organization": "Acme\u202e BV", "phones": ["+31 6 1234\u200b5678", "  ", "+31 20 555"],
               "name": "Bram\x00 de   Vries", "emails": ["b@x.nl"], "birthday": "--02-29"}
    out = dev.present_contact(contact, ["name", "phones", "birthday", "organization"])
    assert list(out) == ["name", "phones", "birthday", "organization"]
    assert out == {"name": "Bram de Vries", "phones": ["+31 6 12345678", "+31 20 555"], "birthday": "--02-29",
                   "organization": "Acme BV"}
    assert "emails" not in out


def test_a_postal_address_keeps_its_line_breaks_and_empty_values_are_left_out():
    out = dev.present_contact({"postal": ["Keizersgracht 12\n\n\n1015 CS  Amsterdam", "\u200b"], "name": "\u200b",
                               "phones": []}, ["name", "phones", "postal"])
    assert out == {"postal": ["Keizersgracht 12\n\n1015 CS Amsterdam"]}


def test_the_lists_of_a_contact_are_capped_even_if_the_model_let_more_through():
    out = dev.present_contact({"phones": [str(n) for n in range(9)], "postal": ["a"] * 5}, ["phones", "postal"])
    assert out == {"phones": ["0", "1", "2", "3", "4"], "postal": ["a", "a", "a"]}


def test_an_unrequested_key_is_found_in_a_fixed_order_whatever_its_value():
    asked = ["name", "phones"]
    assert dev.unrequested_key({"name": "x", "phones": ["1"]}, asked) is None
    assert dev.unrequested_key({"name": "x", "emails": ["e"], "birthday": "--01-01"}, asked) == "emails"
    assert dev.unrequested_key({"name": "x", "birthday": None}, asked) == "birthday"
    assert dev.unrequested_key({}, asked) is None


@pytest.mark.parametrize("value, ok", [("1984-03-17", True), ("--02-29", True), ("2024-02-29", True),
                                        ("2026-02-29", False), ("2026-02-30", False), ("--02-30", False),
                                        ("--04-31", False), ("0000-01-01", False), ("1984-13-01", False)])
def test_a_birthday_must_be_a_day_that_exists(value, ok):
    assert (dev.birthday_problem(value) is None) is ok


# ── pure: a scanned value ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw, want", [
    ("WIFI:T:WPA;S:my  net;P:pass word;;", "WIFI:T:WPA;S:my  net;P:pass word;;"),     # spacing is kept
    ("https://exa\u200bmple.com/\u202etxt.exe", "https://example.com/txt.exe"),          # zero-width, bidi override
    ("a\x1b[31mred\x07", "a[31mred"),                                                     # ESC and BEL go
    ("a\tb\u00a0c\u3000d", "a b c d"),                                                    # tab and every Zs: a space
    ("a\r\nb\rc\u2028d\u2029e\x0bf", "a\nb\nc\nd\nef"),                                    # line breaks (VT is a control)
    ("a\u2066b\u2069", "ab"), ("a\ufeffb", "ab"), ("a\U000e0041b", "ab"), ("a\u3164b", "ab"),
    ("a\ue000b", "ab"),                                                                   # private use
    ("e" + "́" * 6, "e" + "́" * 4),                                             # stacked marks capped
    ("  padded  ", "  padded  "), ("", ""), (None, ""),
])
def test_a_scanned_value_is_cleaned_without_being_trimmed_or_collapsed(raw, want):
    assert dev.clean_scan_value(raw) == want
    assert dev.clean_scan_value(dev.clean_scan_value(raw)) == want, "cleaning twice changes nothing"


def test_a_value_of_nothing_visible_cleans_to_nothing_but_spaces():
    assert dev.clean_scan_value("\u200b\u202e\x00").strip() == ""


# ── pure: the statement hash and the two files ──────────────────────────────────────────────────


def test_the_statement_hash_is_sha256_of_the_exact_utf8_bytes():
    assert dev.statement_sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    text = "Gelezen en akkoord — café ✓"
    assert dev.statement_sha256(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert dev.statement_sha256("a") != dev.statement_sha256("a\n") != dev.statement_sha256("a ")
    # no normalisation: precomposed and decomposed are different statements
    assert dev.statement_sha256("é") != dev.statement_sha256("é")


NS = b'xmlns="http://www.w3.org/2000/svg"'


PLAIN = b"<svg " + b'xmlns="http://www.w3.org/2000/svg"' + b"><path d='M0 0'/></svg>"


def _svg(inner=b"", attrs=b""):
    return b"<svg " + NS + (b" " + attrs if attrs else b"") + b">" + inner + b"</svg>"


@pytest.mark.parametrize("mime, head, ok", [
    ("image/png", b"\x89PNG\r\n\x1a\nrest", True), ("image/png", b"\x89PNG\r\n", False), ("image/png", b"GIF89a", False),
    ("image/png", b"", False), ("image/jpeg", b"\xff\xd8\xff", False),
    # what a pad draws
    ("image/svg+xml", SVG_BYTES, True), ("image/svg+xml", b"<svg " + NS + b"/>", True),
    ("image/svg+xml", b"\xef\xbb\xbf" + SVG_BYTES, True),
    ("image/svg+xml", b"<!-- c -->" + _svg(b"<title/><desc></desc>"), True),
    ("image/svg+xml", _svg(b"<title>Sign</title>"), False), ("image/svg+xml", _svg(b"<desc>x</desc>"), False),
    ("image/svg+xml", b"\xef\xbb\xbf\xef\xbb\xbf" + SVG_BYTES, False),
    ("image/svg+xml", _svg(b'<g transform="scale(2)"><path d="M0 0L1 1" fill="none" stroke="#000" stroke-width="2" '
                           b'stroke-linecap="round"/><polyline points="0,0 1,1"/><polygon points="0,0 1,1 2,0"/>'
                           b'<line x1="0" y1="0" x2="1" y2="1"/><circle cx="1" cy="1" r="1"/>'
                           b'<ellipse cx="1" cy="1" rx="2" ry="1"/><rect x="0" y="0" width="1" height="1"/></g>',
                           b'viewBox="0 0 10 10" width="10" height="10" version="1.1"'), True),
    ("image/svg+xml", b'<?xml version="1.0" encoding="UTF-8"?>' + PLAIN, True),
    ("image/svg+xml", b'<?xml version="1.0" encoding="utf-8" standalone="no"?>\n' + PLAIN, True),
    # not an SVG, not XML, not UTF-8
    ("image/svg+xml", b"", False), ("image/svg+xml", b"\x89PNG\r\n\x1a\n", False),
    ("image/svg+xml", b"<html><svg></svg></html>", False), ("image/svg+xml", b"<svgx/>", False),
    ("image/svg+xml", b"<svg " + NS + b"><path</svg>", False), ("image/svg+xml", b"<!-- never closed <svg>", False),
    ("image/svg+xml", _svg(b"\xff\xfe"), False), ("image/svg+xml", SVG_BYTES.decode().encode("utf-16"), False),
    ("image/svg+xml", b'<?xml version="1.0" encoding="ISO-2022-JP"?><svg ' + NS + b"><scr\x1b(Bipt>alert(1)</scr\x1b(Bipt>"
                      b"</svg>", False),
    ("image/svg+xml", b'<?xml version="1.0" encoding="ISO-8859-1"?>' + PLAIN, False),
    ("image/svg+xml", b'<?xml version="1.0" encoding="UTF-16"?>' + PLAIN, False),
    ("image/svg+xml", b"<svg " + NS + b"/><script>x</script>", False), ("image/svg+xml", SVG_BYTES + SVG_BYTES, False),
    ("image/svg+xml", SVG_BYTES + b"<!-- after -->", True),
    # the prologue: nothing but a declaration at the very start and comments
    ("image/svg+xml", b"<?xml-stylesheet href='x.css'?>" + PLAIN, False),
    ("image/svg+xml", b" <?xml version='1.0'?>" + PLAIN, False),
    ("image/svg+xml", b"<?xml version='1.0'?><!DOCTYPE svg PUBLIC 'x' 'y'>" + PLAIN, False),
    ("image/svg+xml", b"<!DOCTYPE svg [<!ENTITY a 'b'>]>" + _svg(b"&a;"), False),
    ("image/svg+xml", b"<!DOCTYPE svg>" + PLAIN, False),
    ("image/svg+xml", SVG_BYTES + b"<?php x ?>", False),
    # a namespace the root must carry, and only the root
    ("image/svg+xml", b"<svg><path d='M0 0'/></svg>", False),
    ("image/svg+xml", b'<svg xmlns="http://www.w3.org/1999/xhtml"><path d="M0 0"/></svg>', False),
    ("image/svg+xml", _svg(b'<g xmlns="http://www.w3.org/2000/svg"/>'), False),
    ("image/svg+xml", _svg(b'<path xmlns="http://www.w3.org/1999/xhtml"/>'), False),
    # script, handlers, prefixes (the reviewer's vectors)
    ("image/svg+xml", _svg(b"<script>alert(1)</script>"), False), ("image/svg+xml", _svg(b"<SCRIPT src=x></SCRIPT>"), False),
    ("image/svg+xml", b"<svg " + NS + b' xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></svg>', False),
    ("image/svg+xml", b"<svg " + NS + b' xmlns:h="http://www.w3.org/1999/xhtml"><h:script>alert(1)</h:script></svg>', False),
    ("image/svg+xml", b"<svg " + NS + b' xmlns:s="http://www.w3.org/2000/svg"><s:foreignObject/></svg>', False),
    ("image/svg+xml", b"<svg " + NS + b' xmlns:s="http://www.w3.org/2000/svg"><s:path d="M0 0"/></svg>', False),
    ("image/svg+xml", _svg(b"<path/>", b"onload=alert(1)"), False), ("image/svg+xml", _svg(b"<path onclick = 'x'/>"), False),
    ("image/svg+xml", b"<svg " + NS + b"\tonload='x'></svg>", False),
    ("image/svg+xml", _svg(b"<foreignObject/>"), False), ("image/svg+xml", _svg(b"<image href='x'/>"), False),
    ("image/svg+xml", _svg(b"<a href='javascript:x'><path/></a>"), False),
    ("image/svg+xml", b"<svg " + NS + b' xmlns:x="http://www.w3.org/1999/xlink"><a x:href="&#106;avascript:alert(1)">'
                      b"<path d='M0 0'/></a></svg>", False),
    ("image/svg+xml", _svg(b"<a><set attributeName='href' to='&#x6a;avascript:alert(1)'/><path d='M0 0'/></a>"), False),
    ("image/svg+xml", _svg(b'<a href="data:text/html;base64,AAAA"><path/></a>'), False),
    ("image/svg+xml", _svg(b'<filter id="f"><feImage href="https://example.invalid/x.png"/></filter>'), False),
    ("image/svg+xml", _svg(b"<use href='#a'/>"), False), ("image/svg+xml", _svg(b'<USE xlink:href="#a"/>'), False),
    ("image/svg+xml", _svg(b"<use href='http://x/y.svg#a'/>"), False),
    ("image/svg+xml", _svg(b"<iframe/>"), False), ("image/svg+xml", _svg(b"<embed/>"), False),
    ("image/svg+xml", _svg(b"<animate attributeName='x' to='1'/>"), False),
    # CSS and references
    ("image/svg+xml", _svg(b"<style>path{fill:url(https://example.invalid/a.svg#g)}</style>"), False),
    ("image/svg+xml", _svg(b"<style>@import 'x.css';</style>"), False),
    ("image/svg+xml", _svg(b'<path style="fill:url(https://example.invalid/a#b)"/>'), False),
    ("image/svg+xml", _svg(b'<path style="fill:red"/>'), False), ("image/svg+xml", _svg(b'<path class="a"/>'), False),
    ("image/svg+xml", _svg(b'<path fill="url(#g)"/>'), False), ("image/svg+xml", _svg(b'<path fill="URL(#g)"/>'), False),
    ("image/svg+xml", _svg(b'<path d="M0 0" xlink:href="#a"/>'), False),
    ("image/svg+xml", _svg(b'<path d="M0 0" xml:space="preserve"/>'), False),
    # no entities or references anywhere
    ("image/svg+xml", _svg(b"<title>a &amp; b</title>"), False), ("image/svg+xml", _svg(b"<title>&#65;</title>"), False),
    ("image/svg+xml", _svg(b'<path d="M0 0" fill="&#x23;000"/>'), False),
    ("image/svg+xml", _svg(b"<![CDATA[x]]>"), False), ("image/svg+xml", _svg(b"<title><![CDATA[x]]></title>"), False),
    # text outside a title or a description
    ("image/svg+xml", _svg(b"hello"), False), ("image/svg+xml", _svg(b"<g>hello</g>"), False),
    ("image/svg+xml", _svg(b"<title></title>\n  <desc/>\n"), True),
    # depth
    ("image/svg+xml", _svg(b"<g>" * 30 + b"</g>" * 30), True), ("image/svg+xml", _svg(b"<g>" * 40 + b"</g>" * 40), False),
    # CSS escapes spell url( without writing it (the second review's vectors) and every value has a grammar
    ("image/svg+xml", _svg(b'<path fill="\\75rl(https://example.invalid/x#a)"/>'), False),
    ("image/svg+xml", _svg(b'<path fill="\\75 rl(https://example.invalid/x#a)"/>'), False),
    ("image/svg+xml", _svg(b'<path stroke="u\\rl(https://example.invalid/x#a)"/>'), False),
    ("image/svg+xml", _svg(b'<path fill="\\000075rl(x)"/>'), False), ("image/svg+xml", _svg(b'<path d="M0 0\\"/>'), False),
    ("image/svg+xml", _svg(b'<path fill="src(https://example.invalid/x)"/>'), False),
    ("image/svg+xml", _svg(b"<path fill=\"image-set('https://example.invalid/x' 1x)\"/>"), False),
    ("image/svg+xml", _svg(b'<path fill="var(--x)"/>'), False), ("image/svg+xml", _svg(b'<path fill="attr(d)"/>'), False),
    ("image/svg+xml", _svg(b'<path fill="calc(1 + 2)"/>'), False), ("image/svg+xml", _svg(b'<path fill="red blue"/>'), False),
    ("image/svg+xml", _svg(b'<rect width="calc(1px + 2px)"/>'), False), ("image/svg+xml", _svg(b'<rect width="1e"/>'), False),
])
def test_a_signature_svg_refuses_what_the_reviewers_vectors_spell(mime, head, ok):
    assert (dev.png_or_svg_problem(mime, head) is None) is ok


@pytest.mark.parametrize("attr, value, ok", [
    # paints
    ("fill", "none", True), ("fill", "currentcolor", True), ("fill", "red", True), ("fill", "rebeccapurple", True), ("stroke", "#000", True), ("stroke", "#0008", True), ("stroke", "#a1b2c3", True),
    ("stroke", "#a1b2c3d4", True), ("stroke", "rgb(0,0,0)", True), ("stroke", "rgba(0, 0, 0, 0.5)", True),
    ("stroke", "rgb(10%, 20%, 30%)", True),
    ("fill", "#12", False), ("fill", "#12345", False), ("fill", "#1234567", False), ("fill", "#ggg", False),
    ("fill", "notacolour", False), ("fill", "rgb(0,0)", False), ("fill", "rgb(0,0,0,0,0)", False),
    ("fill", "rgb(var(--a),0,0)", False), ("fill", "rgb(0 0 0)", False), ("fill", "", False), ("fill", " red", False),
    # numbers and lengths
    ("stroke-width", "2", True), ("stroke-width", "2.5px", True), ("stroke-width", ".5", True),
    ("stroke-width", "-1e-3", True), ("opacity", "0.5", True), ("opacity", "50%", True), ("width", "10", True),
    ("width", " 10 ", False), ("x", "1.", True), ("cx", "+3", True), ("stroke-dashoffset", "4", True),
    ("stroke-width", "two", False), ("stroke-width", "1 2", False), ("stroke-width", "1px2", False),
    ("opacity", "var(--o)", False), ("width", "auto", False), ("r", "1e", False), ("r", "--1", False),
    ("r", "1;2", False), ("r", "1 \n", False), ("r", "\t1", False),
    # lists
    ("stroke-dasharray", "none", True), ("stroke-dasharray", "4", True), ("stroke-dasharray", "4, 2 1", True),
    ("stroke-dasharray", "4, x", False), ("points", "0,0 1,1", True), ("points", "0 0 1 1", True),
    ("points", "", True), ("points", "0,0 a", False), ("points", "0,0;1,1", False),
    ("viewBox", "0 0 10 10", True), ("viewBox", "0,0,10,10", True), ("viewBox", " 0 0 10.5 -10 ", False), ("viewBox", "0 0 10.5 -10", True),
    ("viewBox", "0 0 10", False), ("viewBox", "0 0 10 10 10", False), ("viewBox", "0 0 a b", False),
    # paths
    ("d", "M0 0L1 1", True), ("d", "M0,0 c1.5-2 3 4 5 6z", True), ("d", "M1e3 2E-3Z", True), ("d", "", True),
    ("d", "M0 0 X", False), ("d", "M0 0 url", False), ("d", "M0 0;", False), ("d", "M0 0'", False),
    # transforms
    ("transform", "scale(2)", True), ("transform", "translate(1 1)", True), ("transform", "translate(1,1) rotate(45)", True),
    ("transform", "matrix(1 0 0 1 0 0)", True), ("transform", "skewX(10) skewY(-5)", True),
    ("transform", "scale(2),translate(1)", True), ("transform", "rotate(45 10 10)", True),
    ("transform", "scale()", False), ("transform", "scale(a)", False), ("transform", "scale(1", False),
    ("transform", "perspective(1)", False), ("transform", "scale(1) junk", False), ("transform", "", False),
    ("transform", "url(#a)", False), ("transform", "scale(var(--a))", False),
    # words
    ("fill-rule", "evenodd", True), ("fill-rule", "inherit", False), ("stroke-linecap", "round", True),
    ("stroke-linecap", "arrow", False), ("stroke-linejoin", "bevel", True), ("stroke-linejoin", "arcs", False),
    ("preserveAspectRatio", "xMidYMid meet", True), ("preserveAspectRatio", "none", True),
    ("preserveAspectRatio", "xMidYMid  slice", False), ("preserveAspectRatio", "xMidYMid url", False),
    ("version", "1.1", True), ("version", "1.0", True), ("version", "2.0", False),
])
def test_every_svg_attribute_value_must_match_its_grammar(attr, value, ok):
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><path ' + attr.encode() + b'="' + value.encode() + b'"/></svg>'
    assert (dev.png_or_svg_problem("image/svg+xml", svg) is None) is ok, (attr, value)


@pytest.mark.parametrize("blob, ok", [
    (SVG_BYTES.decode().encode("utf-16-be"), False), (SVG_BYTES.decode().encode("utf-16-le"), False),
    (SVG_BYTES.decode().encode("utf-16"), False), (SVG_BYTES.decode().encode("utf-32"), False),
    (_svg(b"<!-- \x00 -->"), False), (_svg(b"<!-- \x1b -->"), False), (_svg(b"<!-- \x08 -->"), False),
    (_svg(b"<!-- \xe2\x80\xae -->"), False), (_svg(b"<!-- \xe2\x80\x8b -->"), False),
    (_svg(b"<path d='M0 0'/>\t\r\n"), True),
])
def test_control_and_hidden_characters_in_an_svg_are_refused(blob, ok):
    assert (dev.png_or_svg_problem("image/svg+xml", blob) is None) is ok


def test_an_svg_value_check_is_linear():
    for value in ("1" * 500_000 + "x", "1." * 250_000 + "x", "1 " * 250_000 + "x", "M0 0 " * 80_000 + "X",
                  "scale(" + "1 " * 200_000 + "x)", "translate(1) " * 40_000 + "x", "rgb(" + "1," * 200_000 + ")"):
        for attr in ("stroke-width", "d", "transform", "stroke", "viewBox", "points", "stroke-dasharray"):
            svg = b'<svg xmlns="http://www.w3.org/2000/svg"><path ' + attr.encode() + b'="' + value.encode() + b'"/></svg>'
            started = time.monotonic()
            dev.png_or_svg_problem("image/svg+xml", svg)
            assert time.monotonic() - started < 2.0, (attr, value[:12])


# ── pure: the calendar item the agent passes ────────────────────────────────────────────────────


class _Refused(ValueError):
    pass


def _item(**over):
    return dev.build_calendar_item({**ITEM, **over}, _Refused)


def test_a_calendar_item_is_cleaned_and_only_what_was_given_is_in_it():
    assert _item() == ITEM
    out = _item(title="Den\u202e tist\n2", notes="Bring  it\n\n\n\nnow\u200b", location="Room\n4", all_day=False,
                url="https://example.com/a", alarm_minutes=15)
    assert out["title"] == "Den tist 2" and out["notes"] == "Bring it\n\nnow" and out["location"] == "Room 4"
    assert "all_day" not in out and out["alarm_minutes"] == 15 and out["url"] == "https://example.com/a"
    assert dev.build_calendar_item({"title": "Only a title"}, _Refused) == {"title": "Only a title"}


@pytest.mark.parametrize("item, message", [
    ("Dentist", "item must be an object"), ([], "item must be an object"), (None, "item must be an object"),
    ({}, "item.title is required"), ({"title": "\u200b"}, "item.title is required"), ({"title": 5}, "must be a string"),
    ({"title": "x" * 121}, "item.title is 121 characters; the limit is 120"),
    ({"title": "x", "notes": "n" * 2001}, "item.notes is 2001 characters; the limit is 2000"),
    ({"title": "x", "location": "l" * 201}, "item.location is 201 characters; the limit is 200"),
    ({"title": "x", "attendees": ["a"]}, "keys that are not part of a calendar item: 'attendees'"),
    ({"title": "x", "all_day": "yes"}, "item.all_day must be true or false"),
    ({"title": "x", "alarm_minutes": True}, "item.alarm_minutes must be a whole number"),
    ({"title": "x", "alarm_minutes": 1.5}, "item.alarm_minutes must be a whole number"),
    ({"title": "x", "start": 5}, "item.start must be a string"),
    ({"title": "x", "start": "2026-10-12T09:30"}, "item: start"),                  # no offset: the model refuses it
    ({"title": "x", "start": "2026-10-12"}, "a timed item takes instants"),
    ({"title": "x", "all_day": True, "start": "2026-10-12T09:30+02:00"}, "an all-day item takes dates"),
    ({"title": "x", "end": "2026-10-12T09:30+02:00"}, "end needs start"),
    ({**ITEM, "end": "2026-10-12T09:00+02:00"}, "end is before start"),
    ({"title": "x", "alarm_minutes": 5}, "alarm_minutes needs start"),
    ({"title": "x", "url": "javascript:alert(1)"}, "item: url"),
    ({"title": "x", "url": "https://a b"}, "item: url"),
    ({"title": "x", "all_day": True, "start": "2026-02-30"}, "item"),
])
def test_a_calendar_item_that_cannot_be_shown_is_refused_with_what_to_fix(item, message):
    with pytest.raises(_Refused, match=message):
        dev.build_calendar_item(item, _Refused)


def test_a_calendar_item_error_never_echoes_the_agents_value():
    with pytest.raises(_Refused) as raised:
        dev.build_calendar_item({"title": "x", "url": "ftp://" + MARKER}, _Refused)
    assert MARKER not in str(raised.value)


# ── the validator: each method ──────────────────────────────────────────────────────────────────

_ENV = {"session_id": "s", "v": 1, "title": "T", "summary": "S", "expires_at": 0, "optional": True}
_DIR = "/w/uploads/hermie/2026-10-04"


def _sig_params(**over):
    return {**_ENV, "statement": STATEMENT, "upload": {"dir": _DIR, "max_bytes": 1048576, "max_total_bytes": 2097152,
                                                       "max_files": 2, "strip_metadata": False}, **over}


def _sig_answer(statement=STATEMENT, **over):
    png = {"path": f"{_DIR}/aaaaaaaaaaaaaaaa-s.png", "name": "s.png", "mime": "image/png", "bytes": 10,
           "sha256": "0" * 64}
    svg = {**png, "path": f"{_DIR}/bbbbbbbbbbbbbbbb-s.svg", "name": "s.svg", "mime": "image/svg+xml"}
    return {"status": "answered", "files": [png, svg], "signed_at": 1, "statement_sha256": dev.statement_sha256(statement),
            **over}


def test_a_signature_answer_passes_and_every_problem_has_its_own_reason_in_order():
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer()) is None
    assert v.validate_answer("input.signature", _sig_params(), {"status": "skipped"}) is None
    assert v.validate_answer("input.signature", _sig_params(optional=False), {"status": "skipped"}) == "not_optional"
    files = _sig_answer()["files"]
    bad_dir = {**files[0], "path": f"{_DIR}/../x.png"}
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=[bad_dir, files[1]])) == \
        "file:0:outside_dir"
    big = {**files[1], "bytes": 1048577}
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=[files[0], big])) == "file:1:too_large"
    two_big = [{**f, "bytes": 1048576} for f in files]
    assert v.validate_answer("input.signature", _sig_params(upload={**_sig_params()["upload"],
                                                                    "max_total_bytes": 2097151}),
                             _sig_answer(files=two_big)) == "files:too_large"
    # the types come before the hash: both wrong is the type
    twin = [files[0], {**files[0], "path": f"{_DIR}/cccccccccccccccc-t.png"}]
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=twin,
                                                                           statement_sha256="0" * 64)) == \
        "files:not_png_and_svg"
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(statement_sha256="0" * 64)) == \
        "statement:mismatch"


def test_the_statement_hash_must_be_that_of_the_request_not_of_something_close():
    params = _sig_params(statement="Line one\nLine two")
    assert v.validate_answer("input.signature", params, _sig_answer("Line one\nLine two")) is None
    for other in ("Line one\r\nLine two", "Line one\nLine two\n", "Line one\nLine two ", "line one\nLine two"):
        assert v.validate_answer("input.signature", params, _sig_answer(other)) == "statement:mismatch", repr(other)


def test_a_signature_with_other_keys_or_the_wrong_number_of_files_is_bad_shape():
    one = _sig_answer()
    for bad in ({**one, "files": one["files"][:1]}, {**one, "extra": 1}, {**one, "statement_sha256": "x"}):
        assert v.validate_answer("input.signature", _sig_params(), bad) == "bad_shape"


def test_a_location_cannot_be_more_precise_than_asked():
    ask = lambda p: {**_ENV, "precision": p}  # noqa: E731
    assert v.validate_answer("device.location", ask("approximate"), _fix()) is None
    assert v.validate_answer("device.location", ask("approximate"), _fix(precision="precise")) == \
        "precision:too_precise"
    assert v.validate_answer("device.location", ask("precise"), _fix(precision="precise")) is None
    assert v.validate_answer("device.location", ask("precise"), _fix(precision="approximate")) is None
    assert v.validate_answer("device.location", {**ask("precise"), "optional": False}, {"status": "skipped"}) == \
        "not_optional"
    for bad in (_fix(lat=91), _fix(lon=-181), _fix(accuracy_m=-1), _fix(lat="52"), _fix(lat=True),
                _fix(at=-1), _fix(at=1.5)):
        assert v.validate_answer("device.location", ask("approximate"), bad) == "bad_shape", bad


def _contact_answer(**contact):
    return {"status": "answered", "contact": contact}


def test_a_contact_is_refused_for_a_key_that_was_not_asked_for_and_for_nothing_usable():
    params = {**_ENV, "fields": ["name", "phones"]}
    ok = _contact_answer(name="Bram", phones=["1"])
    assert v.validate_answer("device.contact", params, ok) is None
    assert v.validate_answer("device.contact", params, _contact_answer(phones=["1"])) is None
    # every key not asked for is refused, in the fixed order: the first one found names the reason
    assert v.validate_answer("device.contact", params, _contact_answer(name="B", emails=["e"], birthday="--01-01")) == \
        "contact:emails:not_requested"
    for key, value in (("emails", ["e@x.nl"]), ("postal", ["a"]), ("birthday", "--01-01"), ("organization", "Acme")):
        assert v.validate_answer("device.contact", params, _contact_answer(name="B", **{key: value})) == \
            f"contact:{key}:not_requested"
    assert v.validate_answer("device.contact", params, _contact_answer(name="B", emails=None)) == \
        "contact:emails:not_requested", "a null counts: the client was told what to leave out"
    assert v.validate_answer("device.contact", params, _contact_answer()) == "contact:empty"
    assert v.validate_answer("device.contact", params, _contact_answer(name="\u200b", phones=[" "])) == "contact:empty"
    assert v.validate_answer("device.contact", params, _contact_answer(name=None)) == "contact:empty"
    assert v.validate_answer("device.contact", params, _contact_answer(phones=[])) == "contact:empty"


def test_a_birthday_that_is_no_day_is_refused_after_the_keys_and_before_emptiness():
    params = {**_ENV, "fields": ["name", "birthday"]}
    assert v.validate_answer("device.contact", params, _contact_answer(birthday="2024-02-29")) is None
    assert v.validate_answer("device.contact", params, _contact_answer(birthday="2026-02-29")) == \
        "contact:birthday:invalid"
    assert v.validate_answer("device.contact", params, _contact_answer(birthday="--02-30")) == \
        "contact:birthday:invalid"
    assert v.validate_answer("device.contact", params, _contact_answer(phones=["1"], birthday="2026-02-30")) == \
        "contact:phones:not_requested"


def test_a_scan_is_refused_for_a_symbology_not_asked_for_and_for_nothing_visible():
    params = {**_ENV, "formats": ["ean13", "ean8"]}
    ok = {"status": "answered", "value": "4006381333931", "symbology": "ean13"}
    assert v.validate_answer("device.scan", params, ok) is None
    assert v.validate_answer("device.scan", params, {**ok, "symbology": "qr"}) == "symbology:not_requested"
    assert v.validate_answer("device.scan", _ENV, {**ok, "symbology": "qr"}) is None, "no formats: every one will do"
    assert v.validate_answer("device.scan", _ENV, {**ok, "value": "\u200b\u202e \n"}) == "scan:empty"
    assert v.validate_answer("device.scan", _ENV, {**ok, "value": "x" * 4097}) == "bad_shape"
    assert v.validate_answer("device.scan", {**_ENV, "optional": False}, {"status": "skipped"}) == "not_optional"


def test_a_calendar_answer_is_done_or_skipped_and_nothing_else():
    params = {**_ENV, "kind": "event", "item": {"title": "T"}}
    assert v.validate_answer("device.calendar", params, {"status": "done"}) is None
    assert v.validate_answer("device.calendar", params, {"status": "skipped"}) is None
    assert v.validate_answer("device.calendar", {**params, "optional": False}, {"status": "skipped"}) == "not_optional"
    for bad in ({"status": "answered"}, {"status": "done", "event_id": "x"}, {}, "done", None):
        assert v.validate_answer("device.calendar", params, bad) == "bad_shape", bad


@pytest.mark.parametrize("method", [m for m in ALL if m.startswith("device.") or m == "input.signature"])
def test_the_validator_never_raises_for_garbage(method):
    for junk in (None, 0, "x", [], {}, {"status": None}, {"status": "answered"}, {"status": ["answered"]},
                 {"status": "answered", "contact": 3}, {"status": "answered", "files": "x"}):
        assert v.validate_answer(method, {}, junk) == "bad_shape", (method, junk)


# ── the builders ────────────────────────────────────────────────────────────────────────────────


def test_every_builder_is_registered_and_the_params_are_valid_frames(build):
    assert set(build.BUILDERS) == set(INTERACTIVE_METHODS)
    for method, params in (("input.signature", _sig(build)), ("device.location", _loc(build)),
                           ("device.contact", _contact(build)), ("device.calendar", _calendar(build)),
                           ("device.scan", _scan(build)), ("device.scan", _scan(build, formats=["qr"]))):
        _contract_accepts(method, params)
        assert params["optional"] is True and params["v"] == 1 and params["acting_user"]["id"] == ROBIN


def test_the_default_titles_and_the_reminder_title(build):
    assert _sig(build)["title"] == "Sign" and _loc(build)["title"] == "Share your location"
    assert _contact(build)["title"] == "Share a contact" and _scan(build)["title"] == "Scan a code"
    assert _calendar(build)["title"] == "Add to your calendar"
    assert _calendar(build, kind="reminder", item={"title": "x", "start": ITEM["start"]})["title"] == "Add a reminder"
    assert _calendar(build, kind="reminder", item={"title": "x"}, title="Passport")["title"] == "Passport"


def test_a_location_is_approximate_unless_the_agent_asks_for_precise(build):
    assert _loc(build)["precision"] == "approximate"
    assert _loc(build, precision="precise")["precision"] == "precise"
    for bad in ("exact", None, 5, "Approximate"):
        with pytest.raises(build.InteractiveParamsError, match="precision must be one of: approximate, precise"):
            _loc(build, precision=bad)


@pytest.mark.parametrize("fields, message", [
    (None, "fields must be a list of 1 to 6 of"), ([], "fields must be a list"), ("name", "fields must be a list"),
    (["name", "name"], "lists the same entry twice"), (["nickname"], "fields entry must be one of"),
    (["name", 3], "fields entry must be one of"),
    (["name", "phones", "emails", "postal", "birthday", "organization", "name"], "limit is 6"),
])
def test_a_contact_request_names_one_to_six_distinct_known_fields(build, fields, message):
    with pytest.raises(build.InteractiveParamsError, match=message):
        _contact(build, fields=fields)
    assert _contact(build, fields=["emails"])["fields"] == ["emails"]


@pytest.mark.parametrize("formats, message", [
    ([], "formats must be a list of 1 to 7"), ("qr", "formats must be a list"), (["qr", "qr"], "lists the same entry"),
    (["upc"], "formats entry must be one of"),
    (["qr", "ean13", "ean8", "code128", "pdf417", "datamatrix", "aztec", "qr"], "limit is 7"),
])
def test_a_scan_request_names_known_distinct_formats_or_none(build, formats, message):
    with pytest.raises(build.InteractiveParamsError, match=message):
        _scan(build, formats=formats)
    assert "formats" not in _scan(build) and _scan(build, formats=["qr", "aztec"])["formats"] == ["qr", "aztec"]


def test_a_calendar_request_refuses_a_bad_kind_and_a_reminder_with_an_end(build):
    with pytest.raises(build.InteractiveParamsError, match="kind must be one of: event, reminder"):
        _calendar(build, kind="task")
    with pytest.raises(build.InteractiveParamsError, match="a reminder has one time"):
        _calendar(build, kind="reminder")
    with pytest.raises(build.InteractiveParamsError, match="item.title is required"):
        _calendar(build, item={})
    assert _calendar(build, item={**ITEM, "url": "https://example.com/x", "notes": "n"})["item"]["url"]


def test_the_signature_statement_is_shown_verbatim_so_it_is_stripped_or_refused_never_rewritten(build):
    params = _sig(build, statement="I agree.  \r\nTo all of it.\t \n\n", signer_name="Ada\u200b  Lovelace\n")
    assert params["statement"] == "I agree.\nTo all of it." and params["signer_name"] == "Ada Lovelace"
    assert dev.statement_sha256(params["statement"]) == hashlib.sha256(b"I agree.\nTo all of it.").hexdigest()
    for bad, message in (("a\tb", "cannot be shown verbatim"), ("a\u202eb", "cannot be shown verbatim"),
                         ("a\u200bb", "cannot be shown verbatim"), ("a" + " " * 40 + "b", "spaces in a row"),
                         ("", "statement is required"), ("  \n ", "statement is required"), (None, "statement is required"),
                         (5, "statement is required"), ("x" * 501, "limit is 500")):
        with pytest.raises(build.InteractiveParamsError, match=message):
            _sig(build, statement=bad)
    assert len(_sig(build, statement="x" * 500)["statement"]) == 500
    with pytest.raises(build.InteractiveParamsError, match="limit is 80"):
        _sig(build, signer_name="n" * 81)


def test_the_signature_gets_room_for_two_small_files_in_the_upload_dir(build, tmp_path):
    upload = _sig(build)["upload"]
    assert upload["max_files"] == 2 and upload["max_bytes"] == 1024 * 1024 and upload["max_total_bytes"] == 2 * 1024 * 1024
    assert upload["strip_metadata"] is False and Path(upload["dir"]).is_dir()
    assert upload["dir"].startswith(str(tmp_path.resolve()) + "/uploads/hermie/")


def test_every_device_builder_cleans_and_bounds_the_envelope(build):
    for make in (_loc, _contact, _calendar, _scan, _sig):
        with pytest.raises(build.InteractiveParamsError, match="summary is required"):
            make(build, summary="")
        with pytest.raises(build.InteractiveParamsError, match="the limit is 500"):
            make(build, summary="x" * 501)
        params = make(build, title="Wh\u202eere\n", detail=" more\n\n\n\ninfo ", summary="Why \u200b now")
        assert params["title"] == "Where" and params["detail"] == "more\n\ninfo" and params["summary"] == "Why now"
        assert make(build, optional=False)["optional"] is False
        with pytest.raises(build.InteractiveParamsError, match="optional must be true or false"):
            make(build, optional="no")


def test_the_timeout_is_180_seconds_for_a_device_request_and_300_for_the_rest(build):
    assert build.timeout_for("device.location") == 180.0 and build.timeout_for("device.scan") == 180.0
    assert build.timeout_for("input.signature") == 300.0 and build.timeout_for("input.form") == 300.0
    now = time.time()
    assert abs(_loc(build, timeout=180.0)["expires_at"] - (now + 180)) < 5


# ── asking: the answer the agent receives ───────────────────────────────────────────────────────


def test_a_location_is_rounded_on_the_gateway_whatever_the_client_sent(server, build, audit_records):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    rid, outcome = _ask(server, build, "device.location", _loc(build), peer=phone, answer=_fix())
    assert outcome.status == "answered"
    assert outcome.payload == {"lat": 52.37, "lon": 4.89, "accuracy_m": 1000.0, "at": 1791119300,
                               "precision": "approximate"}
    frame = phone.requests("device.location")[0]
    assert frame["id"] == rid and frame["params"]["precision"] == "approximate"
    assert [event for event, _ in audit_records] == ["interactive_request", "interactive_outcome"]


@pytest.mark.parametrize("method, make, seconds", [
    ("device.location", _loc, 180), ("device.contact", _contact, 180), ("device.calendar", _calendar, 180),
    ("device.scan", _scan, 180), ("input.signature", _sig, 300), ("input.form", None, 300)])
def test_a_request_without_a_timeout_of_its_own_waits_180_seconds_for_a_device_and_300_for_the_rest(
        server, build, method, make, seconds):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = make(build) if make else build.build_form_params("s1", summary="x", fields=[
        {"id": "n", "kind": "text", "label": "N"}])
    box = _start_with_default_timeout(build, method, params)
    rid = _open_id(method)
    assert seconds - 5 <= phone.requests(method)[0]["params"]["expires_at"] - time.time() <= seconds + 1
    _frame(server, phone, rid, result={"status": "skipped"})
    assert _finish(box).status == "skipped"


def test_a_precise_request_the_person_lowered_says_so(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    rid, lowered = _ask(server, build, "device.location", _loc(build, precision="precise"), peer=phone, answer=_fix())
    assert lowered.payload["precision"] == "approximate" and lowered.payload["lowered"] is True
    assert (lowered.payload["lat"], lowered.payload["lon"]) == (52.37, 4.89)
    rid, exact = _ask(server, build, "device.location", _loc(build, precision="precise"), peer=phone,
                      answer=_fix(lat=52.373123456, lon=4.892201, accuracy_m=8.0, precision="precise"))
    assert exact.payload == {"lat": 52.373123, "lon": 4.892201, "accuracy_m": 8.0, "at": 1791119300,
                             "precision": "precise"}


def test_a_client_that_shares_more_than_asked_is_refused_and_the_request_stays_open(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box = _start(build, "s1", "device.location", _loc(build))
    rid = _open_id("device.location")
    reply = _rpc(server, phone, "request.answer", {"id": rid, "result": _fix(precision="precise")})
    assert reply["error"]["data"]["reason"] == "precision:too_precise"
    _frame(server, phone, rid, result=_fix())
    assert _finish(box).payload["precision"] == "approximate"


def test_a_contact_reaches_the_agent_with_the_requested_keys_only(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    answer = {"status": "answered", "contact": {"name": "Bram\u202e de Vries", "phones": ["+31 6 1\u200b2345678"]}}
    rid, outcome = _ask(server, build, "device.contact", _contact(build), peer=phone, answer=answer)
    assert outcome.status == "answered"
    assert outcome.payload == {"contact": {"name": "Bram de Vries", "phones": ["+31 6 12345678"]}}
    assert answer["contact"]["name"].endswith("Vries") and "\u202e" in answer["contact"]["name"], "the answer is not edited"


def test_a_contact_key_the_request_did_not_ask_for_never_settles_it(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box = _start(build, "s1", "device.contact", _contact(build))
    rid = _open_id("device.contact")
    reply = _rpc(server, phone, "request.answer", {"id": rid, "result": {
        "status": "answered", "contact": {"name": "Bram", "emails": ["bram@example.com"]}}})
    assert reply["error"]["data"]["reason"] == "contact:emails:not_requested"
    assert _rpc(server, phone, "request.answer", {"id": rid, "result": {
        "status": "answered", "contact": {}}})["error"]["data"]["reason"] == "contact:empty"
    _frame(server, phone, rid, result={"status": "answered", "contact": {"name": "Bram"}})
    assert _finish(box).payload == {"contact": {"name": "Bram"}}


def test_the_hand_off_filters_the_keys_again_even_if_a_forged_answer_got_through(build):
    """The validator refuses an unrequested key; this is the second line, on the way out."""
    outcome = build._device_outcome("s1", "device.contact", {"fields": ["name"]},
                                    {"status": "answered", "contact": {"name": "B", "emails": ["e@x.nl"],
                                                                       "phones": ["1"]}}, None)
    assert outcome.payload == {"contact": {"name": "B"}}


def test_a_calendar_entry_comes_back_as_saved_and_nothing_else(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _calendar(build, item={**ITEM, "notes": "NOTES-" + MARKER})
    rid, saved = _ask(server, build, "device.calendar", params, peer=phone, answer={"status": "done"})
    assert (saved.status, saved.payload) == ("answered", {"saved": True, "kind": "event"})
    assert saved.as_dict() == {"outcome": "answered", "saved": True, "kind": "event"}
    frame = phone.requests("device.calendar")[0]
    assert frame["params"]["item"]["title"] == "Dentist" and frame["params"]["kind"] == "event"
    rid, reminder = _ask(server, build, "device.calendar", _calendar(build, kind="reminder",
                                                                     item={"title": "x", "start": ITEM["start"]}),
                         peer=phone, answer={"status": "done"})
    assert reminder.payload["kind"] == "reminder"
    rid, skipped = _ask(server, build, "device.calendar", params, peer=phone, answer={"status": "skipped"})
    assert (skipped.status, skipped.payload) == ("skipped", {})


def test_a_scanned_value_is_cleaned_and_flagged_when_cleaning_changed_it(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    rid, clean = _ask(server, build, "device.scan", _scan(build), peer=phone, answer={
        "status": "answered", "value": "WIFI:T:WPA;S:Home 5G;P:" + MARKER + ";;", "symbology": "qr"})
    assert clean.payload == {"value": "WIFI:T:WPA;S:Home 5G;P:" + MARKER + ";;", "symbology": "qr", "cleaned": False}
    rid, dirty = _ask(server, build, "device.scan", _scan(build), peer=phone, answer={
        "status": "answered", "value": "https://exa\u200bmple.com/\u202e\x1b[0m", "symbology": "qr"})
    assert dirty.payload == {"value": "https://example.com/[0m", "symbology": "qr", "cleaned": True}


def test_a_scan_of_a_symbology_not_asked_for_or_of_nothing_visible_is_refused(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box = _start(build, "s1", "device.scan", _scan(build, formats=["ean13"]))
    rid = _open_id("device.scan")
    for value, symbology, reason in (("x", "qr", "symbology:not_requested"), ("\u200b", "ean13", "scan:empty")):
        reply = _rpc(server, phone, "request.answer", {"id": rid, "result": {
            "status": "answered", "value": value, "symbology": symbology}})
        assert reply["error"]["data"]["reason"] == reason
    _frame(server, phone, rid, result={"status": "answered", "value": "4006381333931", "symbology": "ean13"})
    assert _finish(box).payload["value"] == "4006381333931"


def _signature_files(params, png=PNG_BYTES, svg=SVG_BYTES):
    root = Path(params["upload"]["dir"])
    a, b = _put(root, "0123456789abcdef-signature.png", png), _put(root, "fedcba9876543210-signature.svg", svg)
    return a, b, [_entry(a, png, name="signature.png", mime="image/png"),
                  _entry(b, svg, name="signature.svg", mime="image/svg+xml")]


def test_a_signature_round_trip_carries_the_hash_and_both_files(server, build, tmp_path):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _sig(build, signer_name="Ada Lovelace")
    png, svg, files = _signature_files(params)
    answer = {"status": "answered", "files": files, "signed_at": 1791119310,
              "statement_sha256": dev.statement_sha256(STATEMENT)}
    before = int(time.time())
    rid, outcome = _ask(server, build, "input.signature", params, peer=phone, answer=answer)
    assert outcome.status == "answered"
    payload = outcome.payload
    assert payload["signed"] is True and payload["statement_sha256"] == dev.statement_sha256(STATEMENT)
    assert payload["signed_at"] == 1791119310 and before <= payload["received_at"] <= int(time.time()) + 1
    assert payload["signer_name"] == "Ada Lovelace"
    assert [f["path"] for f in payload["files"]] == [str(png.resolve()), str(svg.resolve())]
    assert [f["mime"] for f in payload["files"]] == ["image/png", "image/svg+xml"]
    assert all(f["sha256"] and f["bytes"] and "ref_text" in f for f in payload["files"])
    frame = phone.requests("input.signature")[0]
    assert frame["params"]["statement"] == STATEMENT and frame["params"]["signer_name"] == "Ada Lovelace"


def test_a_signature_for_another_statement_is_refused_and_the_request_stays_open(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _sig(build)
    box = _start(build, "s1", "input.signature", params)
    rid = _open_id("input.signature")
    png, svg, files = _signature_files(params)
    wrong = {"status": "answered", "files": files, "signed_at": 1, "statement_sha256": dev.statement_sha256("I agree.")}
    assert _rpc(server, phone, "request.answer", {"id": rid, "result": wrong})["error"]["data"]["reason"] == \
        "statement:mismatch"
    _frame(server, phone, rid, result={**wrong, "statement_sha256": dev.statement_sha256(STATEMENT)})
    assert _finish(box).status == "answered"


@pytest.mark.parametrize("png, svg, problem", [
    (b"GIF89a-not-a-png", SVG_BYTES, "file:0:type"),
    (PNG_BYTES, b"<html>not an svg</html>", "file:1:type"),
    (PNG_BYTES, b"<svg><script>alert(1)</script></svg>", "file:1:type"),
    (PNG_BYTES, b"<svg onload='x'/>", "file:1:type"),
])
def test_a_signature_file_that_is_not_what_it_says_is_unavailable_bad_upload(server, build, png, svg, problem):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _sig(build)
    a, b, files = _signature_files(params, png, svg)
    answer = {"status": "answered", "files": files, "signed_at": 1, "statement_sha256": dev.statement_sha256(STATEMENT)}
    rid, outcome = _ask(server, build, "input.signature", params, peer=phone, answer=answer)
    assert (outcome.status, outcome.reason) == ("unavailable", "bad_upload")
    assert outcome.payload == {"problem": problem} and "files" not in outcome.payload
    assert a.exists() and b.exists(), "nothing is deleted"


def test_a_signature_whose_files_do_not_check_out_on_disk_is_never_an_answer(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _sig(build)
    a, b, files = _signature_files(params)
    files[1] = {**files[1], "sha256": "0" * 64}
    answer = {"status": "answered", "files": files, "signed_at": 1, "statement_sha256": dev.statement_sha256(STATEMENT)}
    rid, outcome = _ask(server, build, "input.signature", params, peer=phone, answer=answer)
    assert (outcome.status, outcome.reason, outcome.payload) == ("unavailable", "bad_upload", {"problem": "file:1:hash"})


@pytest.mark.parametrize("method, make", [("device.location", _loc), ("device.contact", _contact),
                                          ("device.calendar", _calendar), ("device.scan", _scan),
                                          ("input.signature", _sig)])
def test_every_device_request_and_the_signature_can_be_skipped_only_when_offered(server, build, method, make):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    rid, skipped = _ask(server, build, method, make(build), peer=phone, answer={"status": "skipped"})
    assert (skipped.status, skipped.payload) == ("skipped", {})
    box = _start(build, "s1", method, make(build, optional=False))
    rid = _open_id(method)
    reply = _rpc(server, phone, "request.answer", {"id": rid, "result": {"status": "skipped"}})
    assert reply["error"]["data"]["reason"] == "not_optional"
    # ...and the person who does not want to share says so with a decline, which is never an answer
    error = {"code": 4041, "message": "cannot_show", "data": {"reason": "declined"}}
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": rid, "error": error}, phone)
    assert _finish(box).reason == "cannot_show:declined"


@pytest.mark.parametrize("reason", ["permission_denied", "no_camera", "location_unavailable", "no_microphone",
                                    "not_supported_on_device", "declined"])
def test_the_cannot_show_reasons_of_the_device_sheets_reach_the_agent(server, build, reason):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box = _start(build, "s1", "device.location", _loc(build))
    rid = _open_id("device.location")
    error = {"code": 4041, "message": "cannot_show", "data": {"reason": reason}}
    _as(phone, server.dispatch, {"jsonrpc": "2.0", "id": rid, "error": error}, phone)
    outcome = _finish(box)
    assert (outcome.status, outcome.reason, outcome.payload) == ("unavailable", f"cannot_show:{reason}", {})


# ── asking: who is sent what ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method, make", [("device.location", _loc), ("device.contact", _contact),
                                          ("device.calendar", _calendar), ("device.scan", _scan),
                                          ("input.signature", _sig)])
def test_only_a_client_that_advertised_the_method_is_sent_the_frame(server, build, monkeypatch, method, make):
    monkeypatch.setattr(build, "PARK_SECONDS", 0.1)
    others = tuple(m for m in ALL if m != method)
    phone, web = _WS("phone", ROBIN), _WS("web", ROBIN)
    _session(server, "s1", phone, web, creator=ROBIN)
    _caps(server, phone, requests=list(others))
    _caps(server, web, requests=None)       # a client from before these methods
    outcome = build.request("s1", method, make(build), timeout=5)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_capable_client")
    assert phone.requests(method) == [] and web.requests(method) == []
    assert build._device_limiter.sent == {} and build._limiter.sent == {}, "nobody saw it: not counted"
    _caps(server, phone, requests=list(ALL))
    rid, answered = _ask(server, build, method, make(build), peer=phone, answer={"status": "skipped"})
    assert answered.status == "skipped" and len(phone.requests(method)) == 1 and web.requests(method) == []


def test_the_frame_goes_only_to_the_acting_users_connection(server, build, monkeypatch):
    from tui_gateway import server_requests
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _session(server, "s1", robin, sam, creator=ROBIN)
    _caps(server, robin, requests=list(ALL))
    _caps(server, sam, requests=list(ALL))
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (ROBIN, False))
    for method, make in (("device.location", _loc), ("input.signature", _sig)):
        box = _start(build, "s1", method, make(build))
        rid = _open_id(method)
        assert len(robin.requests(method)) == 1 and sam.requests(method) == []
        assert _rpc(server, sam, "request.answer", {"id": rid, "result": {"status": "skipped"}}).get("error"), \
            "another login cannot answer it"
        _frame(server, robin, rid, result={"status": "skipped"})
        assert _finish(box).status == "skipped"


@pytest.mark.parametrize("method, make", [("device.location", _loc), ("device.contact", _contact),
                                          ("device.calendar", _calendar), ("device.scan", _scan),
                                          ("input.signature", _sig)])
def test_in_a_shared_session_that_names_nobody_nothing_is_sent_for_what_is_personal(server, build, audit_records,
                                                                                    method, make):
    robin, sam = _WS("robin", ROBIN), _WS("sam", SAM)
    _device_capable(server, robin, sam)
    outcome = build.request("s1", method, make(build), timeout=5)
    assert (outcome.status, outcome.reason) == ("unavailable", "no_acting_user")
    assert robin.requests(method) == [] and sam.requests(method) == []
    assert build._device_limiter.sent == {} and build._limiter.sent == {}


def test_the_strict_acting_user_rule_covers_what_is_personal_and_not_a_form(server, monkeypatch):
    from tui_gateway import server_requests
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (None, True))
    for method in (*DEVICE, "input.signature", "review.draft", "review.diff"):
        assert server_requests.acting_user_target("s1", method).refusal == server_requests.NO_ACTING_USER, method
    for method in ("input.form", "input.file"):
        assert server_requests.acting_user_target("s1", method).refusal is None, method
    monkeypatch.setattr(server_requests, "_acting_user", lambda sid: (None, False))
    for method in ALL:
        assert server_requests.acting_user_target("s1", method).refusal is None, method


def test_turn_isolation_fails_closed_for_the_device_requests(server, build, monkeypatch):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    monkeypatch.setenv("HERMES_COMPUTE_HOST_CHILD", "1")
    for method, make in (("device.location", _loc), ("input.signature", _sig)):
        outcome = build.request("s1", method, make(build), timeout=5)
        assert (outcome.status, outcome.reason) == ("unavailable", "turn_isolation")
    assert phone.requests("device.location") == [] and phone.requests("input.signature") == []


# ── limits ──────────────────────────────────────────────────────────────────────────────────────


def test_device_requests_are_six_per_window_and_the_others_keep_their_twelve(server, build, monkeypatch):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    for _ in range(6):
        assert build.request("s1", "device.scan", _scan(build), timeout=0.01).status == "timeout"
    limited = build.request("s1", "device.location", _loc(build), timeout=5)
    assert (limited.status, limited.reason) == ("unavailable", "rate_limited")
    assert len(phone.requests("device.scan")) == 6 and phone.requests("device.location") == []
    # the forms are a family of their own: still twelve
    for _ in range(12):
        assert build.request("s1", "input.form", build.build_form_params(
            "s1", summary="x", fields=[{"id": "n", "kind": "text", "label": "N"}]), timeout=0.01).status == "timeout"
    assert build.request("s1", "input.signature", _sig(build), timeout=5).reason == "rate_limited"
    clock = time.monotonic() + build.WINDOW_SECONDS + 1
    monkeypatch.setattr(build.time, "monotonic", lambda: clock)
    assert build.request("s1", "device.scan", _scan(build), timeout=0.01).status == "timeout"


def test_one_request_is_open_at_a_time_across_the_families(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box = _start(build, "s1", "device.location", _loc(build))
    rid = _open_id("device.location")
    for method, make in (("device.scan", _scan), ("input.signature", _sig)):
        second = build.request("s1", method, make(build), timeout=5)
        assert (second.status, second.reason) == ("unavailable", "already_pending"), method
        assert phone.requests(method) == []
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)
    box = _start(build, "s1", "input.signature", _sig(build))
    rid = _open_id("input.signature")
    third = build.request("s1", "device.contact", _contact(build), timeout=5)
    assert (third.status, third.reason) == ("unavailable", "already_pending") and phone.requests("device.contact") == []
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)
    assert build._limiter.pending == {} and build._device_limiter.pending == {}


def test_two_conversations_do_not_share_the_device_limit(server, build):
    phone, other = _WS("phone", ROBIN), _WS("other", ROBIN)
    _device_capable(server, phone)
    _device_capable(server, other, sid="s2")
    for _ in range(6):
        assert build.request("s1", "device.scan", _scan(build), timeout=0.01).status == "timeout"
    assert build.request("s2", "device.scan", build.build_scan_params("s2", summary="x"), timeout=0.01).status == \
        "timeout"


# ── nothing personal in a log or an audit record ────────────────────────────────────────────────


def test_no_logger_and_no_audit_record_sees_a_coordinate_a_contact_a_scan_or_a_statement(server, build, audit_records,
                                                                                         caplog):
    caplog.set_level(logging.DEBUG)
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    rid, location = _ask(server, build, "device.location", _loc(build, summary="WHERE-" + MARKER), peer=phone,
                         answer=_fix(lat=12.3456, lon=65.4321))
    rid, contact = _ask(server, build, "device.contact", _contact(build, summary="CONTACT-" + MARKER), peer=phone,
                        answer={"status": "answered", "contact": {"name": "NAME-" + MARKER, "phones": ["0612345678"]}})
    rid, scan = _ask(server, build, "device.scan", _scan(build, summary="SCAN-" + MARKER), peer=phone,
                     answer={"status": "answered", "value": "VALUE-" + MARKER, "symbology": "qr"})
    rid, calendar = _ask(server, build, "device.calendar", _calendar(build, item={"title": "TITLE-" + MARKER}),
                         peer=phone, answer={"status": "done"})
    params = _sig(build, statement="STATEMENT-" + MARKER)
    png, svg, files = _signature_files(params)
    rid, signed = _ask(server, build, "input.signature", params, peer=phone, answer={
        "status": "answered", "files": files, "signed_at": 1,
        "statement_sha256": dev.statement_sha256("STATEMENT-" + MARKER)})
    assert [o.status for o in (location, contact, scan, calendar, signed)] == ["answered"] * 5
    # a refused answer is logged nowhere either
    box = _start(build, "s1", "device.scan", _scan(build))
    rid = _open_id("device.scan")
    _rpc(server, phone, "request.answer", {"id": rid, "result": {"status": "answered", "value": "BAD-" + MARKER,
                                                                  "symbology": "nope"}})
    _frame(server, phone, rid, result={"status": "skipped"})
    _finish(box)
    assert MARKER not in json.dumps(audit_records) and "12.3456" not in json.dumps(audit_records)
    assert MARKER not in caplog.text and "12.3456" not in caplog.text and "0612345678" not in caplog.text
    methods = [fields["method"] for event, fields in audit_records if event == "interactive_request"]
    assert methods[:5] == ["device.location", "device.contact", "device.scan", "device.calendar", "input.signature"]


# ── the tool bridge ─────────────────────────────────────────────────────────────────────────────


def test_the_tool_bridge_builds_asks_and_returns_what_the_person_shared(server, build):
    import contextvars
    import threading
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    box: dict = {}
    ctx = contextvars.copy_context()
    thread = threading.Thread(target=lambda: box.setdefault("o", ctx.run(
        build.request_from_tool, "s1", "device.location", summary="Where are you?", precision="approximate")),
        daemon=True)
    thread.start()
    rid = _open_id("device.location")
    _frame(server, phone, rid, result=_fix())
    thread.join(10)
    assert box["o"].as_dict() == {"outcome": "answered", "lat": 52.37, "lon": 4.89, "accuracy_m": 1000.0,
                                  "at": 1791119300, "precision": "approximate"}
    with pytest.raises(build.InteractiveParamsError):
        build.request_from_tool("s1", "device.contact", summary="x", fields=["nickname"])
    with pytest.raises(build.InteractiveParamsError):
        build.request_from_tool("s1", "device.calendar", summary="x", kind="event", item={})
    assert phone.requests("device.contact") == [] and phone.requests("device.calendar") == []


# ── input.file: a voice note ────────────────────────────────────────────────────────────────────


def _voice(build, **kwargs):
    kwargs.setdefault("summary", "Record your answer.")
    kwargs.setdefault("accept", "audio")
    kwargs.setdefault("capture", "audio")
    return build.build_file_params("s1", **kwargs)


def test_a_voice_request_asks_for_audio_with_nothing_to_strip(build):
    params = _voice(build)
    assert (params["accept"], params["capture"], params["multiple"]) == ("audio", "audio", False)
    assert params["upload"]["strip_metadata"] is False and params["upload"]["max_files"] == 1
    _contract_accepts("input.file", params)
    assert "capture" not in _voice(build, capture=None), "accept audio alone is allowed: the person picks a recording"
    # an image still has its EXIF stripped, and a document request is as it was
    assert build.build_file_params("s1", summary="x", accept="image", capture="photo")["upload"][
        "strip_metadata"] is True


@pytest.mark.parametrize("accept, capture", [("audio", "photo"), ("audio", "scan"), ("image", "audio"),
                                             ("document", "audio"), ("any", "audio")])
def test_a_recording_goes_with_audio_and_only_with_audio(build, accept, capture):
    with pytest.raises(build.InteractiveParamsError, match="capture audio records a voice note and goes with accept "
                                                           "audio"):
        _voice(build, accept=accept, capture=capture)


@pytest.mark.parametrize("mime, ok", [("audio/mp4", True), ("audio/x-caf", True), ("audio/webm", True),
                                      ("audio/mpeg", True), ("audio/ogg", True),
                                      ("audio/webm;codecs=opus", False), ("audio/", False), ("audio", False),
                                      ("video/mp4", False), ("image/jpeg", False), ("application/octet-stream", False),
                                      ("AUDIO/mp4", False), ("audio/mp4\n", False), ("", False)])
def test_a_voice_notes_files_must_be_audio_without_parameters(mime, ok):
    params = {**_ENV, "accept": "audio", "capture": "audio", "multiple": False,
              "upload": {"dir": _DIR, "max_bytes": 100, "max_total_bytes": 100, "max_files": 1,
                         "strip_metadata": False}}
    file = {"path": f"{_DIR}/a07e5d21c4b98f13-reply.m4a", "name": "reply.m4a", "mime": mime or "x", "bytes": 10,
            "sha256": "0" * 64}
    if not mime:
        file["mime"] = ""
    reason = v.validate_answer("input.file", params, {"status": "answered", "files": [file]})
    assert reason == (None if ok else ("bad_shape" if not mime else "file:0:not_audio")), mime


def test_an_audio_files_other_problems_come_before_its_type_and_the_total_after():
    params = {**_ENV, "accept": "audio", "capture": "audio", "multiple": True,
              "upload": {"dir": _DIR, "max_bytes": 100, "max_total_bytes": 150, "max_files": 3,
                         "strip_metadata": False}}

    def file(n, mime="audio/mp4", size=100, path=None):
        return {"path": path or f"{_DIR}/00000000000000{n}0-r.m4a", "name": "r.m4a", "mime": mime, "bytes": size,
                "sha256": "0" * 64}

    ask = lambda *files: v.validate_answer("input.file", params, {"status": "answered", "files": list(files)})  # noqa: E731
    assert ask(file(1, size=50), file(2, size=50)) is None
    assert ask(file(1, "video/mp4", path="/elsewhere/x.m4a")) == "file:0:outside_dir"
    assert ask(file(1, "video/mp4", size=101)) == "file:0:too_large"
    assert ask(file(1), file(2, "image/png")) == "file:1:not_audio"
    assert ask(file(1), file(2)) == "files:too_large"
    assert ask(file(1, "image/png", size=100), file(2, size=100)) == "file:0:not_audio", "the type before the total"


@pytest.mark.parametrize("accept, ok", [("audio", True), ("any", True), ("image", False), ("document", False)])
def test_a_transcript_belongs_to_a_recording_not_to_an_image_or_a_document(accept, ok):
    capture = {"audio": "audio"}.get(accept)
    params = {**_ENV, "accept": accept, "multiple": False,
              "upload": {"dir": _DIR, "max_bytes": 100, "max_total_bytes": 100, "max_files": 1,
                         "strip_metadata": True}, **({"capture": capture} if capture else {})}
    mime = "audio/mp4" if accept in ("audio", "any") else "image/jpeg"
    answer = {"status": "answered", "text": "Tuesday at ten.", "files": [{
        "path": f"{_DIR}/a07e5d21c4b98f13-reply.m4a", "name": "reply", "mime": mime, "bytes": 10, "sha256": "0" * 64}]}
    assert v.validate_answer("input.file", params, answer) == (None if ok else "text:not_audio")
    without = {k: val for k, val in answer.items() if k != "text"}
    assert v.validate_answer("input.file", params, without) is None
    assert v.validate_answer("input.file", params, {**answer, "text": "x" * 4001}) == "bad_shape"


def test_a_voice_note_round_trip_gives_the_recording_and_a_cleaned_transcript(server, build, tmp_path):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _voice(build)
    root = Path(params["upload"]["dir"])
    audio = b"marker-audio"
    path = _put(root, "0123456789abcdef-reply.m4a", audio)
    answer = {"status": "answered", "text": "Tuesday‮ at   ten\n\n\n\nworks.",
              "files": [_entry(path, audio, name="reply.m4a", mime="audio/mp4")]}
    rid, outcome = _ask(server, build, "input.file", params, peer=phone, answer=answer)
    assert outcome.status == "answered" and outcome.payload["text"] == "Tuesday at ten\n\nworks."
    assert outcome.payload["files"][0]["mime"] == "audio/mp4" and outcome.payload["files"][0]["bytes"] == len(audio)
    # a browser cannot transcribe: no text key at all
    path2 = _put(root, "fedcba9876543210-reply.webm", audio)
    rid, plain = _ask(server, build, "input.file", params, peer=phone, answer={
        "status": "answered", "files": [_entry(path2, audio, name="reply.webm", mime="audio/webm")]})
    assert plain.status == "answered" and "text" not in plain.payload


def test_a_voice_answer_that_is_not_audio_is_refused_and_the_request_stays_open(server, build):
    phone = _WS("phone", ROBIN)
    _device_capable(server, phone)
    params = _voice(build)
    box = _start(build, "s1", "input.file", params)
    rid = _open_id("input.file")
    root = Path(params["upload"]["dir"])
    path = _put(root, "0123456789abcdef-reply.jpg", b"jpeg")
    reply = _rpc(server, phone, "request.answer", {"id": rid, "result": {
        "status": "answered", "files": [_entry(path, b"jpeg", mime="image/jpeg")]}})
    assert reply["error"]["data"]["reason"] == "file:0:not_audio"
    _frame(server, phone, rid, result={"status": "skipped"})
    assert _finish(box).status == "skipped"


@pytest.mark.parametrize("blob", [b"<!---->" * 150_000 + b"x", b"<use " * 200_000, b" on" + b"a" * 1_000_000,
                                  b"<!--" * 250_000, b"<svg " + b"onx " * 250_000, b" " * 1_000_000 + b"<svg>"])
def test_checking_a_signature_file_is_linear_in_its_size(blob):
    """A client can send a million bytes of anything: no pattern may backtrack over it."""
    started = time.monotonic()
    dev.png_or_svg_problem("image/svg+xml", blob)
    assert time.monotonic() - started < 2.0


# ── review round 1: url, names, transcripts, short reads, formats ───────────────────────────────


@pytest.mark.parametrize("url, ok", [
    ("https://example.com/a", True), ("http://example.com/a@b", True), ("https://example.com?mail=a@b.nl", True),
    ("https://bank.nl@evil.example/login", False), ("https://user:pw@host/", False), ("https://@host/", False),
    ("https://evil.example\\@bank.nl/", False), ("https://evil.example\\.bank.nl/", False),
    ("https://example.com/a\\b", True),
    ("https://example.com/\u202etxt.exe", False), ("https://exa\u200bmple.com/", False),
    ("https://\u2066example.com/", False), ("https://example.com/\ue000", False), ("https://example.com/\u00ad", False),
    ("https://example.com/\ufeff", False), ("https://example.com/\u3164", False), ("https://example.com/\U000e0041", False),
    ("https://example.com/\u0378", False),      # unassigned
    ("https://example.com/a b", False), ("javascript:alert(1)", False), ("ftp://example.com/", False)])
def test_a_calendar_url_has_no_user_information_and_no_hidden_character(url, ok):
    if ok:
        assert dev.build_calendar_item({"title": "x", "url": url}, _Refused)["url"] == url
    else:
        with pytest.raises(_Refused, match="item: url") as raised:
            dev.build_calendar_item({"title": "x", "url": url}, _Refused)
        assert "bank" not in str(raised.value) and MARKER not in str(raised.value)


def test_a_url_the_agent_hides_text_in_is_refused_with_a_sentence_it_can_act_on(build):
    with pytest.raises(build.InteractiveParamsError, match="url cannot be shown as it is"):
        _calendar(build, item={**ITEM, "url": "https://example.com/\u202etxt.exe"})
    with pytest.raises(build.InteractiveParamsError, match="item: url"):
        _calendar(build, item={**ITEM, "url": "https://bank.nl@evil.example/"})


def test_the_signature_files_names_must_say_what_they_are():
    files = _sig_answer()["files"]
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer()) is None
    upper = [{**files[0], "path": files[0]["path"].replace(".png", ".PNG")},
             {**files[1], "path": files[1]["path"].replace(".svg", ".Svg")}]
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=upper)) is None, "case does not matter"
    png_as_svg = {**files[0], "path": files[0]["path"].replace(".png", ".svg")}
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=[png_as_svg, files[1]])) == \
        "file:0:extension"
    svg_as_png = {**files[1], "path": files[1]["path"].replace(".svg", ".png")}
    assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=[files[0], svg_as_png])) == \
        "file:1:extension"
    for name in ("noextension", "x.png.exe", "x.svgz", "x.png "):
        odd = {**files[0], "path": f"{_DIR}/aaaaaaaaaaaaaaaa-{name}"}
        assert v.validate_answer("input.signature", _sig_params(), _sig_answer(files=[odd, files[1]])) == \
            "file:0:extension", name


@pytest.mark.parametrize("accept, mime, ok", [
    ("any", "audio/mp4", True), ("any", "application/pdf", False), ("any", "image/jpeg", False),
    ("audio", "audio/mp4", True), ("image", "image/jpeg", False), ("document", "application/pdf", False)])
def test_a_transcript_needs_a_recording_in_the_same_answer(accept, mime, ok):
    params = {**_ENV, "accept": accept, "multiple": False,
              "upload": {"dir": _DIR, "max_bytes": 100, "max_total_bytes": 100, "max_files": 1, "strip_metadata": True}}
    if accept == "audio":
        params["capture"] = "audio"
    answer = {"status": "answered", "text": "Tuesday.", "files": [{
        "path": f"{_DIR}/a07e5d21c4b98f13-x", "name": "x", "mime": mime, "bytes": 10, "sha256": "0" * 64}]}
    assert v.validate_answer("input.file", params, answer) == (None if ok else "text:not_audio")


def test_a_short_read_does_not_shorten_what_a_signature_file_is_judged_on(build, tmp_path, monkeypatch):
    """``os.read`` may return less than asked: the whole file is still collected (up to a MiB) before it is sniffed."""
    params = _sig(build)
    png, svg, files = _signature_files(params, svg=_svg_bytes(b"<path d='M0 0'/>" * 2000))
    real = build.os.read
    monkeypatch.setattr(build.os, "read", lambda fd, n: real(fd, min(n, 7)))
    assert build.verify_files(params, files, sniff=build._signature_sniff)[0] == ""
    # a script placed after the first 7 bytes (and the first short read) is still seen
    png, svg, files = _signature_files(params, svg=_svg_bytes(b"<path d='M0 0'/>" * 2000 + b"<script/>"))
    assert build.verify_files(params, files, sniff=build._signature_sniff)[0] == "file:1:type"


def _svg_bytes(inner: bytes) -> bytes:
    return b'<svg xmlns="http://www.w3.org/2000/svg">' + inner + b"</svg>"


def test_a_signature_file_that_was_not_read_whole_is_refused_not_judged_on_its_start():
    from tui_gateway import interactive
    head = _svg_bytes(b"<path d='M0 0'/>")
    assert interactive._signature_sniff({"mime": "image/svg+xml", "bytes": len(head)}, head) is None
    assert interactive._signature_sniff({"mime": "image/svg+xml", "bytes": len(head) + 1}, head) == "type"
    assert interactive._signature_sniff({"mime": "image/png", "bytes": len(PNG_BYTES)}, PNG_BYTES) is None



def test_a_calendar_item_error_names_what_is_wrong_once_without_doubling_the_prefix():
    for item, message in (({**ITEM, "end": "2026-10-12T09:00+02:00"}, "item: end is before start"),
                          ({"title": "x", "alarm_minutes": 5}, "item: alarm_minutes needs start"),
                          ({"title": "x", "url": "ftp://a"}, "item: url: ")):
        with pytest.raises(_Refused) as raised:
            dev.build_calendar_item(item, _Refused)
        assert str(raised.value).startswith(message), str(raised.value)
        assert "item: item" not in str(raised.value) and "calendar item:" not in str(raised.value)


def _attr_ok(attr: str, value: str) -> bool:
    svg = ('<svg xmlns="http://www.w3.org/2000/svg"><path ' + attr + '="' + value + '"/></svg>').encode()
    return dev.png_or_svg_problem("image/svg+xml", svg) is None


_NOT_ASCII_SPACES = ("\u00a0", "\u3000", "\u2028", "\u2029", "\u0085", "\u2003", "\u202f", "\u1680", "\x0b", "\x0c")
_SPACED = [("stroke-dasharray", "1{}2"), ("viewBox", "0{0}0{0}1{0}1"), ("points", "0,0{}1,1"), ("d", "M0{}0"),
           ("transform", "translate(1{}1)"), ("transform", "scale(1){}rotate(1)"), ("stroke", "rgb(0,{}0,0)"),
           ("stroke-width", "{}1"), ("stroke-width", "1{}"), ("preserveAspectRatio", "xMidYMid{}meet")]


@pytest.mark.parametrize("attr, pattern", _SPACED)
def test_only_ascii_whitespace_separates_svg_values(attr, pattern):
    for space in (" ", "\t", "\r", "\n"):
        if attr not in ("stroke-width", "preserveAspectRatio"):
            assert _attr_ok(attr, pattern.format(space)), (attr, repr(space))
    for odd in _NOT_ASCII_SPACES:
        # XML itself would normalise some of these in an attribute; none of them may reach the grammar as a separator
        value = pattern.format(odd)
        svg = ('<svg xmlns="http://www.w3.org/2000/svg"><path ' + attr + '="' + value + '"/></svg>').encode()
        if odd in ("\x0b", "\x0c"):      # control characters: refused before the parse
            assert dev._svg_problem(svg) == "control", repr(odd)
        else:
            assert dev.png_or_svg_problem("image/svg+xml", svg) is not None, (attr, repr(odd))


@pytest.mark.parametrize("attr, value", [(a, v) for a, v in [
    ("d", "M0\u00a00"), ("d", "M0\u30000"), ("d", "M0\u20280"), ("points", "0\u00a00"), ("points", "0\u30000"),
    ("points", "0\u20280"), ("stroke-dasharray", "1\u00a02"), ("viewBox", "0\u00a00\u00a01\u00a01"),
    ("transform", "scale(1)\u00a0rotate(1)"), ("transform", "scale(1\u00a02)"), ("stroke", "rgb(0,\u00a00,0)"),
    ("stroke", "rgb(\u30000,0,0)"), ("width", "1\u00a0"), ("width", "\u00a01")]])
def test_a_no_break_or_ideographic_space_or_line_separator_is_never_a_separator(attr, value):
    assert not _attr_ok(attr, value), (attr, value)


@pytest.mark.parametrize("attr, value", [
    ("d", "M0 0 "), ("d", " M0 0"), ("d", "\tM0 0"), ("d", "M0 0\n"), ("points", " 0,0"), ("points", "0,0 "),
    ("viewBox", " 0 0 1 1"), ("viewBox", "0 0 1 1 "), ("transform", " scale(1)"), ("transform", "scale(1) "),
    ("stroke-dasharray", " 1"), ("stroke-dasharray", "1 "), ("stroke", " red"), ("stroke", "red "),
    ("stroke", " #000"), ("stroke", "rgb(0,0,0) "), ("width", " 1"), ("width", "1 "), ("opacity", "1\n"),
    ("fill-rule", " evenodd"), ("stroke-linecap", "round "), ("preserveAspectRatio", " none"), ("version", "1.1 "),
])
def test_no_svg_value_has_whitespace_at_its_start_or_end(attr, value):
    assert not _attr_ok(attr, value), (attr, value)
    assert _attr_ok(attr, value.strip(" \t\r\n")), (attr, value)


def test_whitespace_at_the_end_of_xmlns_is_refused_too():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg "/>'
    assert dev.png_or_svg_problem("image/svg+xml", svg) is not None


@pytest.mark.parametrize("attr, template", [
    ("stroke-width", "{}"), ("opacity", "{}"), ("x", "{}px"), ("stroke-dasharray", "{} {}"), ("viewBox", "{} 0 1 1"),
    ("viewBox", "0 0 {} 1"), ("transform", "scale({})"), ("transform", "translate(1 {})"), ("stroke", "rgb({},0,0)"),
    ("stroke", "rgba(0,0,0,{})"),
])
def test_a_number_of_more_than_32_characters_is_refused(attr, template):
    at_limit = "1" * 31 + "5"                 # 32 characters
    too_long = "1" * 32 + "5"                 # 33
    assert len(at_limit) == 32 and len(too_long) == 33
    assert _attr_ok(attr, template.format(at_limit, at_limit)), attr
    assert not _attr_ok(attr, template.format(too_long, too_long)), attr


@pytest.mark.parametrize("number, ok", [("1" * 32, True), ("1" * 33, False), ("-" + "1" * 31, True),
                                         ("-" + "1" * 32, False), ("0." + "1" * 30, True), ("0." + "1" * 31, False),
                                         ("1." + "0" * 30, True), ("." + "1" * 31, True), ("." + "1" * 32, False),
                                         ("1e" + "1" * 30, True), ("1e" + "1" * 31, False), ("1e-" + "1" * 29, True)])
def test_the_number_cap_counts_every_character_of_the_number(number, ok):
    assert _attr_ok("stroke-width", number) is ok, (number, len(number))


def test_in_a_path_and_in_points_no_run_of_number_characters_exceeds_32():
    assert _attr_ok("d", "M" + "1" * 32 + " " + "2" * 32) and not _attr_ok("d", "M" + "1" * 33)
    assert _attr_ok("d", "M" + "1" * 15 + "-" + "1" * 16) and not _attr_ok("d", "M" + "1" * 15 + "-" + "1" * 17)
    assert _attr_ok("points", "1" * 32 + "," + "2" * 32) and not _attr_ok("points", "1" * 33 + ",1")
    assert _attr_ok("d", "M0 0" + "L1 1" * 1000)           # many short numbers are fine
    assert _attr_ok("d", "M" + "e" * 32) and not _attr_ok("d", "M" + "e" * 33)


@pytest.mark.parametrize("attr, value, ok", [
    ("fill", "red", True), ("fill", "Red", False), ("fill", "RED", False), ("fill", "rEd", False),
    ("fill", "none", True), ("fill", "None", False), ("fill", "NONE", False), ("fill", "currentcolor", True),
    ("fill", "currentColor", False), ("fill", "CURRENTCOLOR", False), ("fill", "Transparent", False),
    ("fill", "RebeccaPurple", False), ("fill", "rebeccapurple", True), ("fill", "DarkSlateGray", False),
    ("fill", "darkslategray", True),
    ("stroke", "rgb(0,0,0)", True), ("stroke", "RGB(0,0,0)", False), ("stroke", "Rgb(0,0,0)", False),
    ("stroke", "rgba(0,0,0,1)", True), ("stroke", "RGBA(0,0,0,1)", False),
    ("stroke", "#abc", True), ("stroke", "#ABC", True), ("stroke", "#AbCdEf", True),       # digits, not words
    ("stroke-width", "1e3", True), ("stroke-width", "1E3", True),                          # an exponent is a digit
    ("stroke-width", "2px", True), ("stroke-width", "2PX", False), ("stroke-width", "2Px", False),
    ("stroke-width", "2MM", False), ("stroke-width", "2mm", True),
    ("fill-rule", "evenodd", True), ("fill-rule", "EvenOdd", False), ("fill-rule", "NONZERO", False),
    ("stroke-linecap", "round", True), ("stroke-linecap", "Round", False), ("stroke-linecap", "BUTT", False),
    ("stroke-linejoin", "bevel", True), ("stroke-linejoin", "Bevel", False), ("stroke-linejoin", "MITER", False),
    ("preserveAspectRatio", "xMidYMid meet", True), ("preserveAspectRatio", "xMidYMid Meet", False),
    ("preserveAspectRatio", "xMidYMid SLICE", False), ("preserveAspectRatio", "NONE", False),
    ("preserveAspectRatio", "xmidymid meet", False), ("preserveAspectRatio", "XMidYMid meet", False),
    ("transform", "scale(1)", True), ("transform", "Scale(1)", False), ("transform", "SCALE(1)", False),
    ("transform", "translate(1)", True), ("transform", "Translate(1)", False), ("transform", "MATRIX(1 0 0 1 0 0)", False),
    ("transform", "skewX(1)", True), ("transform", "skewx(1)", False), ("transform", "SkewX(1)", False),
    ("transform", "skewY(1)", True), ("transform", "skewy(1)", False), ("transform", "Rotate(1)", False),
    ("stroke-dasharray", "none", True), ("stroke-dasharray", "None", False), ("stroke-dasharray", "1PX 2", False),
    ("d", "M0 0L1 1", True), ("d", "m0 0l1 1", True),                                      # a command letter is its case
])
def test_keywords_and_function_names_are_lowercase_and_svgs_own_camel_case_is_exact(attr, value, ok):
    assert _attr_ok(attr, value) is ok, (attr, value)
