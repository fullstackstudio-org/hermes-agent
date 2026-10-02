"""Who wrote a turn, written onto the row it persists.

A client cannot tell who sent a message it did not send itself. ``message.start`` is contracted
with no payload, and two clients on one session share a ``FanoutTransport``, so the socket says
nothing about the other person's turn; the row has no author column and no wire field either, so a
reload leaves nothing to read. Every client therefore treats an unmarked user row as its own, and a
colleague's sentence is painted as the reader's -- a false statement, not a gap, and one no client
can repair for itself, because a locally inferred marker does not survive a re-hydration.

``display_metadata`` is the one per-row field that crosses the SQLite boundary without a schema or
a wire-contract change: it is free-form TEXT, and both the REST read and the WS history projection
already forward it whole. So the author rides there, under ``"author"``.

A leaf module on purpose. The gateway's split modules have their bodies re-created against
``server.py``'s globals (``method_ctx.bind_module``), and tests re-create individual turn helpers
against a namespace they build by hand (``method_ctx.rebind``) -- so a bare global reference added
to one of those bodies breaks every such test. Callers import from here inside the function that
needs it, which is the idiom those bodies already use for everything else.
"""

#: Advertised through ``gateway.capabilities``. A module constant beside the code that does the
#: writing, not a config flag -- the same rule ``PER_SESSION_EXCLUSIVE_SUBMIT`` states for itself:
#: it holds because :func:`with_row_author` below is what every submitted turn goes through, so it
#: cannot drift from the behaviour without this file changing.
#:
#: It answers the one question no per-row read can: whether THIS gateway attributes messages at
#: all. A client needs that BEFORE it draws anything, so it can lay a transcript out with room for
#: a sender's name instead of having rows shift as authored ones arrive -- and so a client talking
#: to a gateway that does not attribute keeps behaving exactly as it did before any of this
#: existed. Because it is answered by the RUNNING process, a gateway carrying this code on disk but
#: not yet restarted answers without the key at all, which is the honest answer: it is not stamping
#: anything yet.
PER_MESSAGE_AUTHOR = True


def row_author(auth_user: tuple[str | None, str] | None) -> dict | None:
    """``{"id": "<provider>:<user id>", "name": ...}`` naming who wrote a turn's user row, or None
    where the gateway cannot prove it.

    ``auth_user`` is the identity of the connection that SUBMITTED the turn, minted at the WS
    upgrade from a verified ticket and carried into the turn by ``prompt.submit`` -- never a value
    any RPC parameter can reach. None where that connection names no login (stdio, the legacy
    token, a server-internal caller), and the unattributed-turn sentinel a crash
    continuation, a wake-up, a cron run, a bot delivery or an internally dispatched submit binds is
    refused explicitly: it is a distinct object rather than a pair, so it cannot be unpacked, and
    "nobody submitted this" must never read as a person.

    A session record's own ``auth_user_id`` is deliberately NOT a fallback. It names the login the
    conversation was created under, which is not evidence that its owner typed THIS message, and a
    row is read back long after every live signal is gone.

    ``name`` is omitted rather than empty, because a reader falls back to its own directory or to
    the id, where an empty string would read as a person who has no name."""
    if not auth_user or not isinstance(auth_user, tuple) or len(auth_user) != 2:
        return None
    user_id, user_name = auth_user
    if not user_id:
        return None
    return {"id": user_id, **({"name": user_name} if user_name else {})}


def with_row_author(display_metadata: dict | None, auth_user) -> dict | None:
    """``display_metadata`` with this turn's author merged in under ``"author"``, or unchanged when
    there is nothing to assert.

    Every key already on the dict is kept as it is -- the gateway's own ``title_preview``,
    ``notification_category``, a timeline shape -- and a row whose only metadata is the author
    still gets one."""
    author = row_author(auth_user)
    if author is None:
        return display_metadata
    return {**(display_metadata or {}), "author": author}


def deliver_correction(agent, verb: str, text: str, submitter) -> bool:
    """``agent.steer(text)`` / ``agent.redirect(text)`` with the sender handed in beside the text.

    The agent keeps a steer's or redirect's author IN the pending slot with the text, under the slot's
    own lock, and drains them together: onto the steer or redirect row it writes mid-turn, or back as
    ``pending_steer_author`` when the text is handed back after the final answer. So the author can
    never be paired with anybody else's words, whatever turns start or end in between. An agent whose
    bound method takes no ``author=`` gets the bare text and names nobody, as does a submitter that
    names no login."""
    from agent.interrupt_control import accepts_author

    method = getattr(agent, verb)
    author = row_author(submitter)
    if author is not None and accepts_author(method):
        return method(text, author=author)
    return method(text)


def auth_user_from_row_author(author) -> tuple[str, str] | None:
    """The ``(id, name)`` identity a row author was built from (:func:`row_author`'s inverse), or None
    for anything that is not one."""
    if not isinstance(author, dict) or not isinstance(author.get("id"), str) or not author["id"]:
        return None
    name = author.get("name")
    return author["id"], name if isinstance(name, str) else ""


class ReplayedTurn:
    """``prompt.submit``'s in-process ``_replayed_turn``: a stored user row's own words run again by the
    gateway (``/retry``). Two identities, kept apart as everywhere else: ``author`` (a :func:`row_author`
    dict, or None for a row that named nobody) WROTE the words and is what the row says; ``presser`` (an
    ``(id, name)`` identity, or None) asked for them to run again NOW and is who the turn acts as --
    somebody having sent words once is not consent to run them again at another time on somebody else's
    action. A JSON client cannot build one, so the handler accepts the object and refuses anything else."""

    __slots__ = ("author", "presser")

    def __init__(self, author: dict | None, presser: tuple[str, str] | None = None) -> None:
        self.author = dict(author) if isinstance(author, dict) else None
        self.presser = presser if isinstance(presser, tuple) and len(presser) == 2 and presser[0] else None

    def __repr__(self) -> str:
        return f"ReplayedTurn({self.author!r}, presser={self.presser!r})"


def replayed_row_metadata(display_metadata: dict | None, author_auth_user, presser) -> dict | None:
    """``display_metadata`` for a row carrying somebody's stored words again: ``author`` is who wrote them
    (or nobody), and ``replayed_by`` names the presser when that is somebody else, so a reader can say
    "Robin (retried by Sam)" instead of reading the row as sent by its author at that moment."""
    rest = {key: value for key, value in (display_metadata or {}).items() if key not in ("author", "replayed_by")}
    stamped = with_row_author(rest or None, author_auth_user)
    by = row_author(presser)
    if by is not None and by.get("id") != (row_author(author_auth_user) or {}).get("id"):
        stamped = {**(stamped or {}), "replayed_by": by}
    return stamped


def undo_refusal(rows, presser) -> str | None:
    """Why the presser may not undo ``rows``, or None. In a shared chat an undo deletes the row and hands
    its words to the presser's composer, where one Send stores them as the presser's; so a row that names
    anybody else is refused. A row that names nobody (a gateway that stamps nobody) is left as it was."""
    from hermes_state_rewind import row_author_of

    presser_id = (row_author(presser) or {}).get("id")
    for row in rows:
        author = row_author_of(row)
        if author is not None and author.get("id") != presser_id:
            return "You can only undo your own last message in a shared chat."
    return None


def resubmitted_row_identity(text, replaced_row: dict, replaced_live_view: dict, submitter):
    """``(scope, row author, replay)`` for a submit that replaces a stored user row (rewind, edit,
    regenerate); ``replay`` is True when it resends the row's own words. The turn always acts as the SENDER -- it is their action, now. Resending the row's OWN
    words is a replay: the row stays its author's (or nobody's). New words over the sender's own row are
    theirs. New words over somebody else's row -- or over a row that named nobody -- might be an edit or
    a regenerate the client re-spelled; that is not provable, so the row names nobody."""
    from agent.message_content import flatten_message_text
    from hermes_state_rewind import row_author_of

    original = row_author_of(replaced_row)
    if isinstance(text, str) and text.strip() == flatten_message_text(replaced_live_view.get("content")).strip():
        return submitter, auth_user_from_row_author(original), True
    if original is not None and original == row_author(submitter):
        return submitter, submitter, False
    return submitter, None, False
