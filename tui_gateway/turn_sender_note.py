"""What the model is told about who a turn is for: the gateway's side of ``agent/turn_sender.py``.

The gateway binds the signed-in person to every turn (``_acting_auth_user``) and hands it to tools as
``HERMES_SESSION_USER_*``; this puts the same answer in front of the model, from the same resolver,
so the model and the tools never disagree. The agent delivers the note as the final block of the
turn's user message, on the wire only (never the system prompt, never the stored ``content``).

"Verified by the gateway's sign-in" is said only of a turn a signed-in connection submitted. A turn
the gateway started itself -- a bot delivery, a heartbeat, a ``/loop`` tick, a crash continuation --
says that nobody signed in sent it, names what did, and names the chat's owner only as the
authority tools act under, because that is what the tool variables will say. A ``/goal``
continuation says nobody typed it. A turn on a gateway that attributes nothing gets no note.

The person's profile (``agent/person_profile.py``) is never part of the stored note: :func:`turn_notes`
returns it as a separate wire copy that only the current request sends.

A leaf module, like ``row_author``: the turn helpers are re-bound against ``server.py``'s globals,
so callers import from here inside the function that needs it.
"""

from __future__ import annotations

from agent.person_profile import profile_note_sentence, profile_of
from agent.turn_sender import (
    GATEWAY_NOTE_OPENER, ID_LIMIT, NAME_LIMIT, NOTE_DATA_SENTENCE, NOTE_POSITION_SENTENCE, PROFILE_DATA_SENTENCE,
    clean_value, person_label,
)


def _note(*sentences: str, data: str = NOTE_DATA_SENTENCE) -> str:
    body = " ".join(s for s in sentences if s)
    return f"{GATEWAY_NOTE_OPENER}{body} {data} {NOTE_POSITION_SENTENCE}]"


def _origin(turn_author) -> str:
    """What started a turn nobody signed in submitted."""
    if isinstance(turn_author, dict):
        shown = clean_value(turn_author.get("name"), NAME_LIMIT) or clean_value(turn_author.get("id"), ID_LIMIT)
        if shown and (turn_author.get("is_bot") or str(turn_author.get("id") or "").startswith("bot:")):
            return f"It is a message from the bot «{shown}»."
        if shown:
            return f"It carries a message from «{shown}», whom the gateway did not verify."
    return "The gateway started it itself (for example a scheduled wake-up, a heartbeat or a resumed turn)."


#: ``origin`` values: "" a signed-in connection sent the turn; "unsigned" a person typed it on a
#: connection that names no login (stdio, the legacy token, the desktop's PTY child); "several" it is a
#: leftover steer several people wrote (``contributors``); "unattributed" the gateway started it (a bot
#: delivery, a heartbeat, a ``/loop`` tick, a crash continuation); "continuation" the gateway chained it
#: onto the scope's own work (``/goal``).
ORIGINS = ("", "unsigned", "several", "unattributed", "continuation")


def _tools_under(label: str, login, record_login) -> str:
    """Whose authority tools act under; "this chat's owner" only when that is the session record's own login."""
    if not label:
        return ""
    return (f"Tools act under this chat's owner, {label}." if login and login == record_login
            else f"Tools act under {label}.")


def _writers(contributors) -> str:
    named = [label for c in contributors if isinstance(c, dict)
             for label in [person_label(c.get("id"), c.get("name"))] if label]
    shown = list(dict.fromkeys(named))
    if any(not isinstance(c, dict) for c in contributors):
        shown.append("someone the gateway cannot name")
    return ", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1] if shown else ""


def _with_profile(sentence: str, scope, name: str, login) -> tuple[str, str | None, str]:
    """``(stored note, person id, wire note)`` for a turn told the person's profile.

    The stored note names the person only -- it is what the sidecar keeps and every later request
    replays, to whoever speaks next. The wire note adds the profile and is sent with this turn's request
    alone (``agent/turn_sender.py``); it is "" when the pair carries no profile."""
    stored = _note(sentence)
    profile = profile_note_sentence(profile_of(scope), shown_name=name)
    return stored, login, (_note(sentence, profile, data=PROFILE_DATA_SENTENCE) if profile else "")


def turn_sender(scope, **kwargs) -> tuple[str, str | None]:
    """``(note, person id)`` for one turn -- the stored note; see :func:`turn_notes` for the wire copy."""
    note, person, _wire = turn_notes(scope, **kwargs)
    return note, person


def turn_notes(scope, *, origin: str = "", record_login=None, display_metadata: dict | None = None,
               turn_author: dict | None = None, contributors=()) -> tuple[str, str | None, str]:
    """``(note, person id, wire note)`` for one turn, in ``stage_turn_sender``'s argument order.

    ``note`` is the stored, replayed copy and never carries a profile. ``wire note`` is the same note with
    the person's profile, for this turn's request only, and exists only for a turn that person sent alone
    after signing in, or a ``/goal`` continuation of their own work (the tool variables name them there
    too); "" for every other turn.

    ``scope`` is ``_acting_auth_user(session)``: who the turn works for, which for a turn nobody signed
    in submitted is the fallback the tool variables bind. ``record_login`` is the login the session record
    was created under (None on a gateway that attributes nothing). The person id is what a steer or
    redirect is compared against: ``None`` where nothing is attributed, ``""`` where the gateway knows no
    one signed-in person submitted the turn."""
    login, name = scope if isinstance(scope, tuple) and len(scope) == 2 else (None, "")
    label = person_label(login, name) if login else ""
    tools = _tools_under(label, login, record_login)
    gated = record_login is not None
    from tui_gateway.row_author import auth_user_from_row_author

    metadata = display_metadata or {}
    writer = auth_user_from_row_author(metadata.get("author"))
    written = person_label(*writer) if writer is not None else ""
    if origin == "unsigned":
        if not gated:
            return "", None, ""
        if written:  # a /retry pressed on a connection without a login: the words stay their writer's
            return _note(f"Its words are {written}'s; someone on a connection that is not signed in asked "
                         "for it to run again.", tools), "", ""
        return _note("Someone typed this turn from a connection that is not signed in; the gateway cannot "
                     "name them.", tools), "", ""
    if origin == "several" and (writers := _writers(contributors)):
        return _note(f"Several people wrote this turn together: {writers}; the gateway cannot credit its "
                     "words to one of them.", tools), "", ""
    if origin in ("unattributed", "several"):
        if not (gated or turn_author):
            return "", None, ""
        return _note("No signed-in person sent this turn.", _origin(turn_author), tools), "", ""
    if not label:
        return "", None, ""
    # The profile rides on the very pair the label came from (``AuthUser``), so it can only ever be this
    # person's. It is told for their own turn and for the ``/goal`` continuation of their own work (whose
    # pair is the same submitter's); never for an unsigned, several-writer, gateway-started or replayed
    # turn, and never in the stored note.
    if origin == "continuation":
        return _with_profile(
            f"Nobody typed this turn; the gateway started it to continue work for {label}.", scope, name, login)
    if "replayed_by" not in metadata and (writer is None or writer[0] == login):
        return _with_profile(f"In this turn you are working for {label}, who sent this message; "
                             "the gateway verified this sign-in.", scope, name, login)
    words = (f"Its words, including 'I' and 'me', are {written}'s; you act for {label}." if written
             else f"Its words were written by someone the gateway cannot name; you act for {label}.")
    return _note(f"In this turn you are working for {label}, who asked for this message to run again; "
                 "the gateway verified this sign-in.", words), login, ""
