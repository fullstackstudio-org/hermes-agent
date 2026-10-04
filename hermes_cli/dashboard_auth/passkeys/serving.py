"""Which gateway serves a process that runs as a profile of its own (``hermes -p <name> ...``).

Inside the gateway, ``paths.gateway_home`` is the answer: the gateway's own launch home, whatever profile a
turn is scoped to. A SEPARATE process started for a profile (``hermes -p techsupport chat``, a kanban worker
with ``HERMES_HOME`` on the profile, ``hermes -p techsupport dashboard passkey ...``) has that profile as its
own home, while its passkeys, ``confirm.passkey`` and the operator's rules are those of the host gateway that
multiplexes it. :func:`serving_gateway_home` names that gateway's home from the runtime records (for the
operator CLI, which reports and writes there), or None when the process's own home is the gateway's.
:func:`host_root` is the structural answer the security paths use: runtime records are writable by a turn.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

#: How long a policy-path answer is reused (it runs per command and per tool call).
TTL_S = 10.0
_cache: dict[str, tuple[float, Optional[str]]] = {}
_cache_lock = threading.Lock()


def reset_for_tests() -> None:
    with _cache_lock:
        _cache.clear()


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def host_root(home: Optional[Path] = None) -> Optional[Path]:
    """The default root when *home* (default: the scoped ``get_hermes_home()``) is a named profile under it
    that is not ``gateway.standalone``, else None. Structural only: no runtime record (``gateway_state.json``,
    ``gateway.pid``) is read, because a turn in that profile can write those, and it must not be able to
    make the root's rules disappear. ``gateway.standalone`` lives in the profile's own config.yaml, which
    the file tools refuse to write (``tools.file_tools_write_guards``)."""
    from hermes_constants import get_default_hermes_root, get_hermes_home, named_profile_home
    home = Path(home if home is not None else get_hermes_home())
    named = named_profile_home(home)
    if named is None:
        return None
    root = Path(get_default_hermes_root())
    if not _same(named.parent.parent, root):
        return None
    from hermes_cli.profiles import profile_is_standalone
    return None if profile_is_standalone(named) else root


def _decide(home: Path, *, probe_dashboard: bool) -> Optional[Path]:
    from hermes_constants import get_default_hermes_root, profile_name_for_home
    if profile_name_for_home(home) in (None, "default"):
        return None
    root = Path(get_default_hermes_root())
    if _same(root, home):
        return None
    from hermes_cli.profiles import profile_is_standalone
    if profile_is_standalone(home):
        return None
    from gateway.status import live_gateway_pid_for_home
    if live_gateway_pid_for_home(home) is not None:
        return None  # this profile runs a gateway of its own (a host gateway started from it)
    if probe_dashboard:
        from hermes_cli.main_dashboard import _find_stale_dashboard_pids
        if _find_stale_dashboard_pids(scope_home=str(home)):
            return None  # this profile runs a dashboard of its own: its sign-in, its passkeys
    from hermes_cli.gateway_multiplex_mode import default_gateway_multiplexes
    if default_gateway_multiplexes(root):
        return root
    if probe_dashboard:  # (the scan above, for the default home this time)
        # A dashboard (``hermes dashboard`` / ``hermes serve``) of the default home holds the sign-in the
        # passkeys belong to, even while its gateway is stopped and the multiplex flag is unset.
        from hermes_cli.main_dashboard import _find_stale_dashboard_pids
        if _find_stale_dashboard_pids(scope_home=str(root)):
            return root
    return None


def serving_gateway_home(*, probe_dashboard: bool = False) -> Optional[Path]:
    """The home of the gateway that serves this process's own profile, when that is not the profile itself.

    None for the default home, a ``gateway.standalone`` profile, a profile whose own gateway is running (a
    host gateway started from that profile), or a host whose default gateway does not serve every profile;
    also when it cannot be decided (the process's own home, as before). *probe_dashboard* also counts a
    running dashboard of the default home (a process scan: the operator CLI only). Without it the answer is
    reused for :data:`TTL_S` seconds."""
    from hermes_constants import get_routing_process_hermes_home
    home = Path(get_routing_process_hermes_home())
    key = str(home)
    if not probe_dashboard:
        with _cache_lock:
            hit = _cache.get(key)
        if hit is not None and time.monotonic() - hit[0] < TTL_S:
            return Path(hit[1]) if hit[1] else None
    try:
        found = _decide(home, probe_dashboard=probe_dashboard)
    except Exception:  # noqa: BLE001 - undecidable: the process's own home
        found = None
    if not probe_dashboard:
        with _cache_lock:
            _cache[key] = (time.monotonic(), str(found) if found else None)
    return found
