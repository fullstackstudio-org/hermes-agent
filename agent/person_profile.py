"""The signed-in person's profile: what an identity provider asserts about them, as Hermes carries it.

A login is minted into the WS credential with the provider's verified display name beside it; this is
the rest of what the same verified ID token says about that person (email, job title, groups, locale,
time zone, ...). It travels as ONE object with the login it belongs to, from the token to the turn:

    ID token -> Session.profile -> WS ticket / PTY credential -> auth_identity["profile"]
             -> AuthUser(login, name, profile) -> the turn's sender note and HERMES_SESSION_USER_*

Every value is untrusted text. :func:`coerce_profile` is the one gate: it keeps only the allowlisted
keys, runs each string through ``clean_value`` (NFKC, no control / bidi / zero-width / line-separator
characters, no bracket that could close the quoted slot, one line), relabels anything shaped like the
gateway note, caps every value, caps the list of groups, and drops everything else. It is applied where
the profile is built from claims, where a credential is stamped onto a socket and where an isolated child
receives it over the pipe, so whatever reaches the note or a tool's environment has passed it.

A leaf module, stdlib only, so the auth layer, the gateway and the agent can all import it.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from agent.turn_sender import NAME_LIMIT, clean_value, relabel_note_lookalikes

#: ``(key, label in the note, per-value cap)``, in the order the note lists them. When the note would grow
#: past :data:`PROFILE_NOTE_LIMIT` the later ones are left out first.
_STRING_FIELDS: tuple[tuple[str, str, int], ...] = (
    ("email", "email", 254),
    ("job_title", "job title", 120),
    ("preferred_username", "username", NAME_LIMIT),
    ("name", "full name", NAME_LIMIT),
    ("given_name", "given name", NAME_LIMIT),
    ("middle_name", "middle name", NAME_LIMIT),
    ("family_name", "family name", NAME_LIMIT),
    ("nickname", "nickname", NAME_LIMIT),
    ("locale", "locale", 35),
    ("zoneinfo", "time zone", 64),
    ("birthdate", "birthdate", 32),
    ("phone_number", "phone number", 32),
    ("address", "address", 200),
    ("website", "website", 200),
    ("profile", "profile page", 200),
    ("gender", "gender", 32),
)
_STRING_KEYS = frozenset(key for key, _label, _limit in _STRING_FIELDS)
GROUPS_KEY = "groups"
#: A flag only: the picture URL itself is never carried (a client loading it would tell the provider whose
#: conversation it is looking at -- see ``Session.picture``).
PICTURE_KEY = "picture"
GROUP_LIMIT = 64
GROUPS_MAX = 10
#: Cap on the profile sentence in the note, so a provider that sends every claim at full length still adds
#: a bounded amount to every turn.
PROFILE_NOTE_LIMIT = 900

PROFILE_KEYS = frozenset({*_STRING_KEYS, GROUPS_KEY, PICTURE_KEY})
#: ``(key, label)`` in note order: the groups right after the job title, which is what they qualify.
_NOTE_FIELDS: tuple[tuple[str, str], ...] = tuple(
    pair for key, label, _limit in _STRING_FIELDS
    for pair in ((key, label), *(((GROUPS_KEY, "groups"),) if key == "job_title" else ())))


def _clean(value: Any, limit: int) -> str:
    # Relabel note-shaped text, then cap again: the relabel can lengthen the value.
    return clean_value(relabel_note_lookalikes(clean_value(value, limit)), limit)


def _groups(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    kept: list[str] = []
    for item in value:
        shown = _clean(item, GROUP_LIMIT)
        if shown and shown not in kept:
            kept.append(shown)
        if len(kept) >= GROUPS_MAX:
            break
    return kept


def coerce_profile(value: Any) -> dict[str, Any]:
    """``value`` reduced to a clean profile: allowlisted keys only, every string cleaned and capped,
    ``groups`` a capped list of cleaned strings, ``picture`` ``True`` or absent. Empty values are dropped,
    so ``{}`` means "nothing to say". Anything that is not a mapping is ``{}``."""
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, _label, limit in _STRING_FIELDS:
        if shown := _clean(value.get(key), limit):
            out[key] = shown
    if groups := _groups(value.get(GROUPS_KEY)):
        out[GROUPS_KEY] = groups
    if value.get(PICTURE_KEY) is True:
        out[PICTURE_KEY] = True
    return out


class AuthUser(tuple):
    """``(login, display name)`` -- the pair every identity check in the gateway unpacks -- carrying the
    profile of THAT login beside it.

    A tuple subclass so all existing unpacking, comparison and JSON code keeps working unchanged: equality
    and ``repr`` see the two items only (a profile never reaches a log line through ``repr``), JSON writes
    the two items only (a profile is never persisted with a queued prompt or a record), and anything that
    rebuilds a plain tuple simply drops the profile, which degrades to today's name-only behaviour. The
    profile can only travel with the login it was minted with, never be attached to another one."""

    def __new__(cls, login: Any, name: Any, profile: Mapping[str, Any] | None = None) -> "AuthUser":
        self = super().__new__(cls, (login, name))
        self._profile = MappingProxyType(dict(profile) if isinstance(profile, Mapping) else {})
        return self

    @property
    def profile(self) -> Mapping[str, Any]:
        return self._profile

    def __reduce__(self):
        return (AuthUser, (self[0], self[1], dict(self._profile)))


def profile_of(scope: Any) -> Mapping[str, Any]:
    """The profile an identity pair carries; empty for a plain tuple, ``None`` or anything else."""
    profile = getattr(scope, "profile", None)
    return profile if isinstance(profile, Mapping) else {}


def profile_note_sentence(profile: Mapping[str, Any], *, shown_name: str = "") -> str:
    """The sentence the turn note gives the profile, "" when there is nothing to say.

    Values are re-cleaned here (a no-op for a coerced profile) and quoted in «», the slot the note's data
    sentence covers. ``name`` is left out when it is the display name the note already shows."""
    profile = coerce_profile(profile)
    parts: list[str] = []
    budget = PROFILE_NOTE_LIMIT

    def add(part: str) -> None:
        nonlocal budget
        cost = len(part) + 2
        if cost <= budget:
            parts.append(part)
            budget -= cost

    for key, label in _NOTE_FIELDS:
        value = profile.get(key)
        if not value or (key == "name" and value == clean_value(shown_name, NAME_LIMIT)):
            continue
        add((f"{label} " + ", ".join(f"«{g}»" for g in value)) if key == GROUPS_KEY else f"{label} «{value}»")
    if profile.get(PICTURE_KEY):
        add("a profile picture is set")
    if not parts:
        return ""
    return "Their identity provider asserts this profile for them: " + "; ".join(parts) + "."


def profile_env(profile: Mapping[str, Any]) -> dict[str, str]:
    """The profile fields tools receive as ``HERMES_SESSION_USER_*``; every value one clean line, ""
    when absent (so a binding always clears what an earlier turn set)."""
    profile = coerce_profile(profile)
    return {
        "user_email": str(profile.get("email") or ""),
        "user_locale": str(profile.get("locale") or ""),
        "user_timezone": str(profile.get("zoneinfo") or ""),
        "user_groups": ",".join(profile.get(GROUPS_KEY) or ()),
    }
