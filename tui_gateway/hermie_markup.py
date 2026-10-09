"""What a model is told about the Hermie blocks the submitting connection draws: one paragraph per block.

``client_markup`` keeps the block names each connection advertised; a turn binds the submitter's names
(``client_markup.TURN_MARKUP``) and ``prompt_turn._invoke_agent`` stages :func:`turn_guide` on the agent,
which appends it to the system message at API time only (``agent/prompt_additions.py``). It is never written
into the session's cached system prompt, a row or a transcript, so a later turn from another client (an older
build, the desktop app) or a replay after a resume carries none of it.

The text is static: chosen by name from :data:`GUIDE` in the fixed order :data:`ORDER`; nothing a client sends
is ever interpolated. Every number in it is the one in ``contract/markup`` (a test reads the schemas and finds
them here). The whole guide stays under :data:`MAX_GUIDE_CHARS`.
"""

from __future__ import annotations

from typing import Iterable

#: The session sources whose turns may carry the guide: a Hermie chat. A Telegram or desktop session opened
#: from a Hermie app keeps its own platform's conventions, because its history is replayed on that platform.
GUIDE_SOURCES: frozenset[str] = frozenset({"hermie"})
MAX_GUIDE_CHARS = 2_500

INTRO = (
    "The app this person is using draws the blocks described below inside your reply. Use one only when it "
    "makes the answer clearer, and say in words what it shows too; not every reader sees it drawn. A block "
    "that breaks any rule below is shown as raw text, so follow the format exactly."
)

GUIDE: dict[str, str] = {
    "chart": (
        "Chart, for numbers a person would rather see than read (a trend, a comparison, a share of a whole): a "
        "fenced code block with the language hermie-chart holding one JSON object {\"type\": \"bar\" | \"line\" | "
        "\"pie\", \"title\"?, \"unit\"?, \"x\": [categories], \"series\": [{\"name\", \"values\": [numbers]}]}. "
        "At most 8 series and 100 points; a pie has one series and at most 24 slices. Every values list is as "
        "long as x. Names at most 60 characters, title at most 120, unit at most 12. Values are numbers: no "
        "strings, no null, no extra keys."
    ),
    "cards": (
        "Cards, for a plan, a setup, steps or options as a picture: a fenced code block with the language "
        "hermie-cards holding one JSON object {\"title\"?, \"layout\"?: \"stack\" | \"grid\", \"connector\"?: "
        "\"arrow\" | \"line\" | \"none\", \"cards\": [{\"title\", \"subtitle\"?, \"icon\"?, \"tags\"?: [strings], "
        "\"highlight\"?: true, \"next\"?: \"label on the arrow to the next card\"}]}. 2 to 12 cards. Card title "
        "1 to 60 characters, subtitle at most 140, block title at most 120, at most 6 different tags of 1 to 24 "
        "characters, next at most 40, at most one highlighted card. connector and next only in a stack, and "
        "never next on the last card. icon is one word such as server, database, cloud, globe, lock, code, "
        "gear, document, people or chart; another word draws a plain glyph. Every text is a JSON string; no "
        "extra keys."
    ),
    "alerts": (
        "Callouts, for something the reader must not miss: a quote whose first line is exactly [!NOTE], [!TIP], "
        "[!IMPORTANT], [!WARNING] or [!CAUTION], upper case and alone on that line, with the text on the next "
        "lines, for example:\n> [!WARNING]\n> Make a backup first.\nUse them sparingly."
    ),
}
ORDER: tuple[str, ...] = ("chart", "cards", "alerts")


def guide_for(names: Iterable[str]) -> str:
    """The guide for *names*: :data:`INTRO` and one paragraph per known name in :data:`ORDER`, or "" for none."""
    wanted = set(names)
    paragraphs = [GUIDE[name] for name in ORDER if name in wanted]
    return "\n\n".join([INTRO, *paragraphs]) if paragraphs else ""


def turn_guide(source: str | None, names: Iterable[str]) -> str:
    """The guide a turn of a session with *source* carries for the submitter's accepted *names*: "" outside
    :data:`GUIDE_SOURCES`."""
    return guide_for(names) if str(source or "").strip().lower() in GUIDE_SOURCES else ""
