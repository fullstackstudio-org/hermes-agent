"""``tui_gateway/sources.py`` (plan rich-answers T3): the pages a reply used, from the turn's own web tool results.

Pinned here: which results count (``web_search`` results are ``found``; ``web_extract`` pages without an error
are ``read``; every other tool nothing); deduplication with ``read`` winning; ``read`` first, then first
appearance; the cap of 24; URLs refused when they are not ``http``/``https`` with a host and no user info or are
too long; titles cleaned and cut; descriptions and page content never kept; the turn collector is turn-scoped.
"""

from __future__ import annotations

import json
import threading

import pytest

from tui_gateway import sources


def _search(*items):
    return json.dumps({"success": True, "data": {"web": [
        {"title": title, "url": url, "description": "marker description", "position": i}
        for i, (url, title) in enumerate(items, 1)]}})


def _extract(*items):
    return json.dumps({"results": [
        {"url": url, "title": title, "content": "marker content", "error": error}
        for url, title, error in items]})


def test_search_results_are_found_and_extracted_pages_are_read():
    assert sources.collect("web_search", _search(("https://a.example/", "A"))) == [
        {"url": "https://a.example/", "title": "A", "via": "found"}]
    assert sources.collect("web_extract", _extract(("https://b.example/", "B", None))) == [
        {"url": "https://b.example/", "title": "B", "via": "read"}]


def test_a_page_that_failed_or_was_blocked_was_not_read():
    result = {"results": [
        {"url": "https://a.example/", "title": "", "content": "", "error": "403"},
        {"url": "https://b.example/", "title": "", "content": "", "error": None, "blocked_by_policy": True},
        {"url": "https://c.example/", "title": "C", "content": "x", "error": ""},
    ]}
    assert [e["url"] for e in sources.collect("web_extract", result)] == ["https://c.example/"]


@pytest.mark.parametrize("name", ["terminal", "browser_navigate", "read_file", "web_search_x", ""])
def test_other_tools_contribute_nothing(name):
    assert sources.collect(name, _search(("https://a.example/", "A"))) == []


@pytest.mark.parametrize("result", ["not json", "[]", "{}", json.dumps({"success": False, "error": "x"}),
                                    json.dumps({"data": {"web": "x"}}), json.dumps({"data": []}), None, 3,
                                    json.dumps({"results": [1, None, "x"]})])
def test_any_other_shape_contributes_nothing(result):
    assert sources.collect("web_search", result) == [] and sources.collect("web_extract", result) == []


@pytest.mark.parametrize("url", [
    "ftp://a.example/", "javascript:alert(1)", "data:text/html,x", "file:///etc/hosts", "https://", "https:///x",
    "https://user:pw@a.example/", "https://user@a.example/", "https://a.example/a b", "https://a.example/\x00",
    "//a.example/", "a.example", "", "https://a.example/" + "x" * 2048, 42, None,
])
def test_a_url_that_is_not_a_web_page_is_left_out(url):
    assert sources.clean_url(url) is None
    assert sources.collect("web_search", {"success": True, "data": {"web": [{"url": url, "title": "x"}]}}) == []


def test_scheme_and_host_become_lower_case_ascii_and_the_rest_is_kept():
    assert sources.clean_url("  HTTPS://A.example/Path?q=1#f  ") == "https://a.example/Path?q=1#f"
    assert sources.clean_url("https://B\u00fccher.Example/K\u00fcche?q=\u00fc") == \
        "https://xn--bcher-kva.example/K\u00fcche?q=\u00fc"
    assert sources.clean_url("https://a.example/" + "x" * (2048 - 18)) is not None
    assert sources.clean_url("http://[2001:DB8::1]:8443/p") == "http://[2001:db8::1]:8443/p"
    assert sources.clean_url("http://192.168.0.1:65535/x") == "http://192.168.0.1:65535/x"
    assert sources.clean_url("https://a.example./x") == "https://a.example/x"
    # A look-alike name is not refused (IDNA accepts it) but can no longer pass for the real one.
    assert sources.clean_url("https://p\u0430ypal.com/") == "https://xn--pypal-4ve.com/"


@pytest.mark.parametrize("url", [
    "https://a.example/\u202egnp.exe", "https://a.exa\u202emple/", "https://a.example/a\u200bb",
    "https://a.example/\u2066x", "https://a.example/\u00ad", "https://a.example/\ufeff", "https://a.example/\U000e0041",
    "https://a.example/\x85", "https://a.example/\x9f", "https://a.example/\x1b", "https://a.example/\ud800",
    "https://a.example:70000/", "https://a.example:65536/", "https://a.example:http/", "https://a.example:/x",
    "https://a.example:-1/", "https://xn--zz.example/", "https://a_b.example/", "https://-a.example/",
    "https://a..example/", "https://" + "a" * 64 + ".example/", "https://a.example\u3000/",
])
def test_a_url_with_a_hidden_character_a_bad_port_or_a_bad_host_is_left_out(url):
    assert sources.clean_url(url) is None


def test_a_title_is_cleaned_and_cut():
    assert sources.clean_title("  A\n\tB​ C‮⁦ ") == "A B C"
    assert sources.clean_title("x" * 400) == "x" * 160
    assert sources.clean_title(None) == "" and sources.clean_title(12) == ""


def test_read_wins_and_comes_first_then_first_appearance():
    candidates = [
        *sources.collect("web_search", _search(("https://one.example/", "One"), ("https://two.example/", "Two"),
                                               ("https://one.example/", "One again"))),
        *sources.collect("web_extract", _extract(("https://two.example/", "Two read", None),
                                                 ("https://three.example/", "", None))),
    ]
    assert sources.merge(candidates) == [
        {"url": "https://two.example/", "title": "Two read", "via": "read"},
        {"url": "https://three.example/", "title": "", "via": "read"},
        {"url": "https://one.example/", "title": "One", "via": "found"},
    ]


def test_a_read_page_without_a_title_keeps_the_found_one():
    merged = sources.merge([{"url": "https://a.example/", "title": "Found title", "via": "found"},
                            {"url": "https://a.example/", "title": "", "via": "read"}])
    assert merged == [{"url": "https://a.example/", "title": "Found title", "via": "read"}]


def test_the_list_is_capped_at_24():
    found = [{"url": f"https://f{i}.example/", "title": "", "via": "found"} for i in range(30)]
    read = [{"url": "https://late.example/", "title": "Late", "via": "read"}]
    merged = sources.merge(found + read)
    assert len(merged) == sources.MAX_SOURCES == 24
    assert merged[0]["url"] == "https://late.example/"  # a late read page still wins a place
    assert len({e["url"] for e in merged}) == 24


def test_merge_rechecks_what_it_is_given():
    assert sources.merge([{"url": "ftp://x/", "title": "", "via": "read"}, {"url": "https://a.example/",
                          "title": "x", "via": "cited"}, "junk", None]) == []
    assert sources.clean_sources("junk") is None and sources.clean_sources([]) is None


def test_the_turn_collector_is_thread_safe_and_bounded():
    collector = sources.TurnSources("turn-1")
    many = _search(*((f"https://p{i}.example/", "") for i in range(100)))
    threads = [threading.Thread(target=collector.add, args=("web_search", many)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(collector._candidates) == sources.MAX_CANDIDATES
    assert len(collector.sources()) == 24
    assert sources.TurnSources("t").sources() is None


def test_no_description_or_content_is_kept():
    collector = sources.TurnSources("t")
    collector.add("web_search", _search(("https://a.example/", "A")))
    collector.add("web_extract", _extract(("https://b.example/", "B", None)))
    assert "marker" not in json.dumps(collector.sources())


# ── the hand-off from tool.complete ─────────────────────────────────────────────────────────────


def test_only_the_running_turns_collector_receives_results():
    import tui_gateway.server as server
    session = {"turn_id": "turn-2", "_turn_sources": sources.TurnSources("turn-1")}
    server._collect_turn_sources(session, "web_search", json.loads(_search(("https://a.example/", "A"))))
    assert session["_turn_sources"].sources() is None  # a stale collector of an earlier turn
    session["_turn_sources"] = sources.TurnSources("turn-2")
    server._collect_turn_sources(session, "web_search", json.loads(_search(("https://a.example/", "A"))))
    server._collect_turn_sources(session, "terminal", {"url": "https://b.example/"})
    server._collect_turn_sources(None, "web_search", {})
    server._collect_turn_sources({"turn_id": "x"}, "web_search", {})
    assert session["_turn_sources"].sources() == [{"url": "https://a.example/", "title": "A", "via": "found"}]
