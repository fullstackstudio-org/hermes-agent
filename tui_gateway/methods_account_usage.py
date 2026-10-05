"""``account.usage``: the provider account limits and credit balances of one profile, as fields.

The text ``/usage`` and ``session.usage``'s ``account_lines`` render the same snapshots for a person to read;
this is the structured twin for an app. The work (which providers, the entry shape, the cache, the fetch
floor, the per-provider bound) is ``agent/account_usage_view.py``; this module only binds the profile.
Bodies are rebound onto server.py's globals (method_ctx.bind_module) and reference them bare.
"""

from .method_ctx import HandlerRegistry, bind_module

_registry = HandlerRegistry()
method = _registry.method
_profile_scoped = _registry.profile_scoped


@method("account.usage")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Per provider the profile's configured models run on: plan, quota windows, credits, or why there is
    nothing (``available: false`` + ``unavailable_reason``). Never a credential, a header or a raw provider
    body. ``profile`` selects the profile whose credentials are used (default: the launch profile); a fetch is
    cached for about a minute per (profile, provider) and ``refresh`` skips that at most once per 15 s."""
    from agent import account_usage_view as view
    try:
        providers = view.configured_providers(_load_cfg())
        entries = view.collect(str(get_hermes_home()), providers, refresh=is_truthy_value(params.get("refresh", False)))
    except Exception as exc:
        logger.warning("account.usage failed: %s", type(exc).__name__)
        return _err(rid, 5097, "could not read the account usage of this profile")
    return _ok(rid, {"ok": True, "profile": _response_profile_name(params.get("profile")), "providers": entries})


def register(server) -> None:
    bind_module(globals(), server, skip=("_",))
    server._LONG_HANDLERS = server._LONG_HANDLERS | _registry.names()
