"""The pages a reply used: what ``web_search`` found and ``web_extract`` read during the turn (``contract/sources``).

The list is a gateway fact, built from the tool results the gateway already holds, never from the model's
words. Two tiers: ``read`` (a page ``web_extract`` fetched without an error) and ``found`` (a result
``web_search`` returned). Deduplicated by URL with ``read`` winning, ordered ``read`` first and then by first
appearance, capped at :data:`MAX_SOURCES`. It reaches a client on ``message.complete.sources`` and on the
reply's stored row as ``display_metadata.sources``, which ``session.history`` forwards with the rest of the
row's metadata. Absent (never ``[]``) when the turn used no web tool or none of its results qualified.

A tool result is itself untrusted (a page can claim any title): a URL must be ``http``/``https`` with a host
and no user info, at most :data:`MAX_URL_CHARS`, and is kept as the tool returned it (trimmed, not
normalised); a title goes through ``request_text.clean_text`` (control, format and invisible characters out,
whitespace collapsed) and is cut at :data:`MAX_TITLE_CHARS`. No page content or description leaves the
gateway, and nothing but counts is logged.

Which tools count is :data:`SOURCE_TOOLS`, in one place, so ``browser_*`` or ``x_search`` can join later.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Iterable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: Tool name -> the tier its results are.
SOURCE_TOOLS: dict[str, str] = {"web_extract": "read", "web_search": "found"}
VIA = ("read", "found")
MAX_SOURCES = 24
MAX_URL_CHARS = 2048
MAX_TITLE_CHARS = 160
#: The ``display_metadata`` key of a reply's sources.
METADATA_KEY = "sources"
#: How many candidates one turn keeps before :func:`merge` (a bound on memory, far above the cap: a later
#: ``read`` must still be able to win over an early flood of ``found``).
MAX_CANDIDATES = 512


def clean_url(value: Any) -> str | None:
    """*value* as a source URL, or None when it is not one (see the module docstring)."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url or len(url) > MAX_URL_CHARS or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or "@" in parts.netloc:
        return None
    return url


def clean_title(value: Any) -> str:
    """*value* as a source title: cleaned text of at most :data:`MAX_TITLE_CHARS` characters ("" when none)."""
    if not isinstance(value, str):
        return ""
    from tui_gateway.request_text import clean_text
    return clean_text(value, multiline=False)[:MAX_TITLE_CHARS].rstrip()


def _parsed(result: Any) -> Any:
    if isinstance(result, (dict, list)):
        return result
    if isinstance(result, (str, bytes)):
        try:
            return json.loads(result)
        except (TypeError, ValueError):
            return None
    return None


def _entry(url: Any, title: Any, via: str) -> dict | None:
    if (clean := clean_url(url)) is None:
        return None
    return {"url": clean, "title": clean_title(title), "via": via}


def collect(name: str, result: Any) -> list[dict]:
    """The source candidates in one tool result (the parsed JSON or its text), in the order the tool gave
    them; [] for a tool outside :data:`SOURCE_TOOLS` or a result of any other shape."""
    via = SOURCE_TOOLS.get(name)
    if via is None:
        return []
    data = _parsed(result)
    if not isinstance(data, dict):
        return []
    found: list[dict] = []
    if via == "found":
        web = data.get("data", {}).get("web") if isinstance(data.get("data"), dict) else None
        for item in web if isinstance(web, list) else ():
            if isinstance(item, dict) and (entry := _entry(item.get("url"), item.get("title"), via)):
                found.append(entry)
    else:
        results = data.get("results")
        for item in results if isinstance(results, list) else ():
            if not isinstance(item, dict) or item.get("error") or item.get("blocked_by_policy"):
                continue
            if entry := _entry(item.get("url"), item.get("title"), via):
                found.append(entry)
    return found


def merge(candidates: Iterable[dict]) -> list[dict]:
    """*candidates* (in the order they were seen) as the list a reply carries: one entry per URL, ``read``
    winning over ``found`` (the read page's title kept unless it has none), ``read`` first then first
    appearance, at most :data:`MAX_SOURCES`."""
    by_url: dict[str, dict] = {}
    first_seen: dict[str, int] = {}
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict) or candidate.get("via") not in VIA:
            continue
        url = clean_url(candidate.get("url"))
        if url is None:
            continue
        entry = {"url": url, "title": clean_title(candidate.get("title")), "via": candidate["via"]}
        current = by_url.get(url)
        if current is None:
            by_url[url], first_seen[url] = entry, index
        elif current["via"] == "found" and entry["via"] == "read":
            by_url[url] = {**entry, "title": entry["title"] or current["title"]}
        elif not current["title"] and entry["title"] and current["via"] == entry["via"]:
            current["title"] = entry["title"]
    ordered = sorted(by_url, key=lambda url: (by_url[url]["via"] != "read", first_seen[url]))
    return [by_url[url] for url in ordered[:MAX_SOURCES]]


class TurnSources:
    """The candidates one turn's web tools produced. Tools may run in parallel, so it locks."""

    def __init__(self, turn_id: str | None) -> None:
        self.turn_id = turn_id
        self._lock = threading.Lock()
        self._candidates: list[dict] = []

    def add(self, name: str, result: Any) -> int:
        """Collect from one tool result; returns how many candidates it gave."""
        found = collect(name, result)
        with self._lock:
            room = MAX_CANDIDATES - len(self._candidates)
            if room > 0:
                self._candidates.extend(found[:room])
        return len(found)

    def sources(self) -> list[dict] | None:
        """The merged list, or None when there is nothing to carry."""
        with self._lock:
            merged = merge(self._candidates)
        if merged:
            logger.debug("sources: %d of %d candidates kept for the reply", len(merged), len(self._candidates))
        return merged or None


def clean_sources(value: Any) -> list[dict] | None:
    """A stored or received ``sources`` list re-checked as :func:`merge` would build it, or None when it holds
    nothing valid."""
    if not isinstance(value, list):
        return None
    return merge(value) or None
