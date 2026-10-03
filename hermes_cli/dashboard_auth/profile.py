"""The person's profile from verified OpenID Connect claims (``Session.profile``).

Only standard OIDC profile claims are read, from the verified ID token the session is built from, and
only through an allowlist: ``name``, ``given_name``, ``family_name``, ``middle_name``, ``nickname``,
``preferred_username``, ``email``, ``job_title``, ``groups``, ``locale``, ``zoneinfo``, ``birthdate``,
``phone_number``, ``address``, ``website``, ``profile``, ``gender`` and whether a ``picture`` was sent.
Nothing else is carried -- not ``sub`` (already the login), not ``updated_at``, ``nonce``, ``at_hash``,
``amr``, ``auth_time``, ``acr``, ``sid``, and never a token.

Two claims count only when the provider vouches for them:

* ``email`` is dropped when ``email_verified`` is false (as ``Session.email`` already is); an absent flag
  keeps it, because the provider asserted the address and did not say otherwise.
* ``phone_number`` is kept only when ``phone_number_verified`` is true. An unverified number is dropped
  rather than labelled: a label is one more sentence a model can overlook, while a missing number cannot be
  mistaken for a checked one.

``address`` becomes one line: its ``formatted`` member, else the other members joined. The values are then
reduced by :func:`agent.person_profile.coerce_profile` (cleaned, capped, groups capped).
"""

from __future__ import annotations

from typing import Any, Mapping

from agent.person_profile import coerce_profile

_PLAIN_CLAIMS = (
    "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "job_title",
    "locale", "zoneinfo", "birthdate", "website", "profile", "gender",
)
_ADDRESS_PARTS = ("street_address", "postal_code", "locality", "region", "country")


def _flag(claims: Mapping[str, Any], key: str) -> bool | None:
    """A boolean claim as the provider meant it; some send ``"true"`` / ``"false"`` strings."""
    value = claims.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def _address(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, Mapping):
        return ""
    formatted = value.get("formatted")
    if isinstance(formatted, str) and formatted.strip():
        return formatted
    parts = [value.get(key) for key in _ADDRESS_PARTS]
    return ", ".join(p.strip() for p in parts if isinstance(p, str) and p.strip())


def profile_from_claims(claims: Mapping[str, Any]) -> dict[str, Any]:
    """The allowlisted, cleaned profile of the person ``claims`` (a VERIFIED token's claims) describe."""
    if not isinstance(claims, Mapping):
        return {}
    raw: dict[str, Any] = {key: claims.get(key) for key in _PLAIN_CLAIMS if isinstance(claims.get(key), str)}
    if _flag(claims, "email_verified") is not False:
        raw["email"] = claims.get("email")
    if _flag(claims, "phone_number_verified") is True:
        raw["phone_number"] = claims.get("phone_number")
    raw["address"] = _address(claims.get("address"))
    raw["groups"] = claims.get("groups")
    picture = claims.get("picture")
    raw["picture"] = isinstance(picture, str) and bool(picture.strip())
    return coerce_profile(raw)
