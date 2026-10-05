"""What an UNTRUSTED session import may set (HERM-127).

``POST /api/sessions/import`` is open to every signed-in user of a dashboard, so whatever its payload says
is that user's statement, never the gateway's. Hermes trusts some stored fields because only Hermes
writes them, and replays or obeys them later:

* ``api_content``: the sidecar a user row replays to the model verbatim. The genuine turn note lives
  there, so lookalike relabelling skips it (``agent/turn_sender.py``).
* ``display_metadata``: ``author`` / ``replayed_by`` (who wrote a row, HERM-83), ``reactions`` (announced
  to the model on the next turn), the compaction and delivery markers, shared-file attachments.
* ``display_kind``: a gateway notice, a hidden scaffolding row (stored, sent, never shown), a steer.
* ``_compressed_summary`` / ``observed`` / ``platform_message_id``: the compaction summary carrier,
  observed group context framed apart, the platform's own message identity.
* ``effect_disposition``: Hermes' verdict on whether a tool's side effect happened.
* ``reasoning_details`` / ``codex_reasoning_items`` / ``codex_message_items``: provider replay items
  sent back as they are, which can hold items of any role.
* Rows of any role but user / assistant / tool (``system``, ``session_meta``): bookkeeping.
* On the session: ``system_prompt`` (replayed verbatim on resume when its identity lines match, the
  gateway's own voice), ``model_config`` (resume restores provider/base URL/reasoning from it, the CLI
  re-enables YOLO from it), ``user_id`` (the login a reopened session is attached to and audited
  against), and ``parent_session_id`` pointing at a session the payload did not bring.

An untrusted import keeps none of them. Each message keeps only :data:`_UNTRUSTED_MESSAGE_FIELDS`; a
user row names the importer as its author (nobody when no person is signed in); the text of every
row has Hermes' control frames (``agent.prompt_builder.CONTROL_FRAME_OPENERS``, the turn note among
them) and any note-shaped text relabelled, so no imported word speaks in the gateway's voice wherever
it is replayed, summarised or titled. ``user_id`` becomes the importer's login, the system prompt and
``model_config`` are left empty (rebuilt on the next turn), and a parent outside the payload is not
linked. Tool rows and assistant text stay the importer's data: the model already treats them as not
the user's channel.

A local operator restore (``hermes sessions import --from hermes``) and the gateway's own lineage
adoption pass ``keep_provenance=True`` and store everything as before.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

#: The only message keys an untrusted import stores.
_UNTRUSTED_MESSAGE_FIELDS = frozenset({
    "role", "content", "tool_call_id", "tool_calls", "tool_name", "timestamp", "token_count", "finish_reason",
    "reasoning", "reasoning_content",
})
_UNTRUSTED_ROLES = frozenset({"user", "assistant", "tool"})
#: Stands in for the ``[`` of a control frame in imported text: the words stay, the trusted shape does not.
IMPORTED_FRAME_RELABEL = "[imported "


def relabel_imported_text(text: Any) -> Any:
    """``text`` with every Hermes control frame and note-shaped opener relabelled; non-strings unchanged."""
    if not isinstance(text, str) or not text:
        return text
    from agent.prompt_builder import CONTROL_FRAME_RE
    from agent.turn_sender import relabel_note_lookalikes

    return relabel_note_lookalikes(CONTROL_FRAME_RE.sub(IMPORTED_FRAME_RELABEL, text))


def _relabel_content(content: Any) -> Any:
    if isinstance(content, str):
        return relabel_imported_text(content)
    if isinstance(content, list):
        return [{**part, "text": relabel_imported_text(part["text"])}
                if isinstance(part, dict) and isinstance(part.get("text"), str) else part for part in content]
    return content


def untrusted_messages(messages: List[Dict[str, Any]], author: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """The rows an untrusted import stores for *messages* (see the module docstring); *author* is the
    importer's row author (``tui_gateway.row_author.row_author``) or None."""
    kept: List[Dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role not in _UNTRUSTED_ROLES:
            continue
        clean = {key: value for key, value in message.items() if key in _UNTRUSTED_MESSAGE_FIELDS}
        clean["content"] = _relabel_content(clean.get("content"))
        for key in ("reasoning", "reasoning_content"):
            if key in clean:
                clean[key] = relabel_imported_text(clean[key])
        if role == "user" and author:
            clean["display_metadata"] = {"author": dict(author)}
        kept.append(clean)
    return kept


def untrusted_session(session: Dict[str, Any], importer_id: Optional[str]) -> Dict[str, Any]:
    """*session* without the session-level fields only Hermes may set; ``user_id`` names the importer."""
    return {**session, "system_prompt": None, "model_config": None, "user_id": importer_id or None}
