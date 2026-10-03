"""Tests for the Phase 4 s6 dispatch helper in hermes_cli.gateway.

`_dispatch_via_service_manager_if_s6` decides whether a
`hermes gateway start/stop/restart` invocation should be routed to
the in-container S6ServiceManager instead of falling through to the
host systemd/launchd/windows code path.
"""
from __future__ import annotations


import pytest


class _CallRecorder:
    """Minimal stand-in for S6ServiceManager."""
    kind = "s6"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def start(self, name: str) -> None:
        self.calls.append(("start", name))

    def stop(self, name: str) -> None:
        self.calls.append(("stop", name))

    def restart(self, name: str) -> None:
        self.calls.append(("restart", name))




# ---------------------------------------------------------------------------
# _dispatch_all_via_service_manager_if_s6 — --all under s6
# ---------------------------------------------------------------------------


class _ListingRecorder(_CallRecorder):
    """_CallRecorder that also exposes a profile list."""

    def __init__(self, profiles: list[str]) -> None:
        super().__init__()
        self._profiles = profiles

    def list_profile_gateways(self) -> list[str]:
        return list(self._profiles)


def test_dispatch_all_handles_partial_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A failure on one profile must not skip the others; the helper
    reports each failure and the success count."""
    from hermes_cli import gateway as gw

    class _FailOnWriter(_ListingRecorder):
        def stop(self, name: str) -> None:
            if name == "gateway-writer":
                raise RuntimeError("supervise FIFO permission denied")
            super().stop(name)

    rec = _FailOnWriter(["coder", "writer", "assistant"])
    monkeypatch.setattr(
        "hermes_cli.service_manager.detect_service_manager", lambda: "s6",
    )
    monkeypatch.setattr(
        "hermes_cli.service_manager.get_service_manager", lambda: rec,
    )
    assert gw._dispatch_all_via_service_manager_if_s6("stop") is True
    # The two successful ones were called; writer raised before recording.
    assert ("stop", "gateway-coder") in rec.calls
    assert ("stop", "gateway-assistant") in rec.calls
    assert ("stop", "gateway-writer") not in rec.calls
    out = capsys.readouterr().out
    assert "Stopped 2 profile gateway(s)" in out
    assert "Could not stop gateway-writer" in out
    assert "supervise FIFO permission denied" in out


# ---------------------------------------------------------------------------
# Friendly error rendering — GatewayNotRegisteredError / S6CommandError
# (PR #30136 review item I2)
# ---------------------------------------------------------------------------




# =============================================================================
# `_maybe_redirect_run_to_s6_supervision`: the "upgrade old `gateway run`
# invocation to supervised semantics inside an s6 container" helper.
# =============================================================================


class _Args:
    """Lightweight argparse-like namespace for the helper."""

    def __init__(self, no_supervise: bool = False) -> None:
        self.no_supervise = no_supervise


def _stub_s6(monkeypatch: pytest.MonkeyPatch, *, on_s6: bool) -> _CallRecorder:
    """Wire up service-manager stubs so the underlying dispatcher will
    fire (on_s6=True) or return False (on_s6=False)."""
    rec = _CallRecorder()
    monkeypatch.setattr(
        "hermes_cli.service_manager.detect_service_manager",
        lambda: "s6" if on_s6 else "systemd",
    )
    monkeypatch.setattr(
        "hermes_cli.service_manager.get_service_manager", lambda: rec,
    )
    return rec




def _raise_missing_sleep(file: str, args: list[str]) -> None:
    raise FileNotFoundError(2, "No such file or directory", file)


def test_redirect_falls_back_when_sleep_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression guard for issue #36208: when ``os.execvp("sleep", ...)``
    raises (no `sleep` on a clobbered/empty PATH, or a minimal image
    without it), the redirect must NOT crash the container — it falls
    back to the in-process ``_block_until_terminated`` heartbeat so the
    container keeps running.
    """
    from hermes_cli import gateway as gw

    rec = _stub_s6(monkeypatch, on_s6=True)
    monkeypatch.setattr("hermes_cli.gateway._profile_suffix", lambda: "")

    monkeypatch.setattr("hermes_cli.gateway.os.execvp", _raise_missing_sleep)
    block_calls: list[bool] = []
    monkeypatch.setattr(
        "hermes_cli.gateway._block_until_terminated",
        lambda: block_calls.append(True),
    )
    monkeypatch.delenv("HERMES_S6_SUPERVISED_CHILD", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_NO_SUPERVISE", raising=False)

    # Must not raise FileNotFoundError — that was the #36208 crash.
    result = gw._maybe_redirect_run_to_s6_supervision(_Args())

    assert result is True
    assert rec.calls == [("start", "gateway-default")]
    # Fell back to the in-process heartbeat instead of crashing.
    assert block_calls == [True]
    err = capsys.readouterr().err
    assert "`sleep` is unavailable" in err


def _armed_watchdog(monkeypatch: pytest.MonkeyPatch):
    """Arm the real watchdog as hermes_cli.main's argv fast-path does; the long timeout keeps the
    deadline out of the test, only the handle state at handoff is under test."""
    import hermes_startup_watchdog as sw

    monkeypatch.delenv(sw.ENV_STARTUP_WATCHDOG, raising=False)
    monkeypatch.delenv("HERMES_S6_SUPERVISED_CHILD", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_NO_SUPERVISE", raising=False)
    monkeypatch.setattr("hermes_cli.gateway._profile_suffix", lambda: "")
    sw._reset_for_tests()
    handle = sw.arm_startup_watchdog(timeout_s=3600)
    assert handle is not None and handle.is_alive()
    return sw, handle


def test_redirect_disarms_startup_watchdog_before_parking(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #102000: the CMD process never reaches a GatewayRunner, so the #36208 in-process
    heartbeat must not park under an armed watchdog (it would os._exit(75) a healthy container)."""
    from hermes_cli import gateway as gw

    sw, handle = _armed_watchdog(monkeypatch)
    try:
        _stub_s6(monkeypatch, on_s6=True)
        monkeypatch.setattr("hermes_cli.gateway.os.execvp", _raise_missing_sleep)
        disarmed_at_park: list[bool] = []
        monkeypatch.setattr(
            "hermes_cli.gateway._block_until_terminated",
            lambda: disarmed_at_park.append(handle.disarmed),
        )

        assert gw._maybe_redirect_run_to_s6_supervision(_Args()) is True

        assert disarmed_at_park == [True]
        assert sw._handle is None
    finally:
        sw._reset_for_tests()
    capsys.readouterr()


def test_redirect_not_taken_leaves_startup_watchdog_armed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside s6 the gateway still boots in-process, so GatewayRunner's own disarm must govern."""
    from hermes_cli import gateway as gw

    sw, handle = _armed_watchdog(monkeypatch)
    try:
        _stub_s6(monkeypatch, on_s6=False)

        assert gw._maybe_redirect_run_to_s6_supervision(_Args()) is False

        assert sw._handle is handle and handle.is_alive() and not handle.disarmed
    finally:
        sw._reset_for_tests()


# ---------------------------------------------------------------------------
# On-demand slot registration — a profile dir that exists but was never registered (#111720)
# ---------------------------------------------------------------------------


class _UnregisteredRecorder(_CallRecorder):
    """Recorder whose slot is missing until ``register_profile_gateway`` runs."""

    def __init__(self) -> None:
        super().__init__()
        self.registered: list[tuple[str, bool]] = []
        self._slots: set[str] = set()

    def _svc(self, action: str, name: str) -> None:
        from hermes_cli.service_manager import GatewayNotRegisteredError
        if name not in self._slots:
            raise GatewayNotRegisteredError(name.removeprefix("gateway-"))
        self.calls.append((action, name))

    def start(self, name: str) -> None:
        self._svc("start", name)

    def stop(self, name: str) -> None:
        self._svc("stop", name)

    def register_profile_gateway(self, profile: str, *, start_now: bool = True) -> None:
        self.registered.append((profile, start_now))
        self._slots.add(f"gateway-{profile}")


def _arrange(monkeypatch, tmp_path, mgr, *, profile: str, seed_soul: bool):
    """Force the s6 branch and make ``tmp_path`` the shared HERMES_HOME the slot maps back to."""
    from hermes_cli import gateway as gw
    from hermes_cli import service_manager as sm

    monkeypatch.setattr(sm, "detect_service_manager", lambda: "s6")
    monkeypatch.setattr(sm, "get_service_manager", lambda: mgr)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    profile_dir = tmp_path / "profiles" / profile
    profile_dir.mkdir(parents=True)
    if seed_soul:
        (profile_dir / "SOUL.md").write_text("# soul\n", encoding="utf-8")
    return gw


def test_start_registers_a_missing_slot_for_a_real_profile(monkeypatch, tmp_path, capsys):
    """A profile created from the host against a bind-mounted home has a directory (SOUL.md) but
    no s6 slot. ``gateway start`` must register it and come up instead of demanding a container
    restart; the registration is ``down`` so the ordinary ``start`` owns the desired-state write."""
    mgr = _UnregisteredRecorder()
    gw = _arrange(monkeypatch, tmp_path, mgr, profile="coder", seed_soul=True)

    assert gw._dispatch_via_service_manager_if_s6("start", "coder") is True

    assert mgr.registered == [("coder", False)]
    assert mgr.calls == [("start", "gateway-coder")]
    assert "registered the s6 gateway slot" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("action", "seed_soul"),
    [
        pytest.param("stop", True, id="stop-never-registers"),
        pytest.param("start", False, id="no-soul-marker-mints-nothing"),
    ],
)
def test_missing_slot_stays_an_error_outside_the_repair_case(
    monkeypatch, tmp_path, capsys, action, seed_soul
):
    """Only ``start`` on a real profile self-heals: stopping an unregistered profile and starting a
    mistyped/stray directory (no SOUL.md) keep the original ✗ + exit 1 and mint no slot."""
    mgr = _UnregisteredRecorder()
    gw = _arrange(monkeypatch, tmp_path, mgr, profile="coder", seed_soul=seed_soul)

    with pytest.raises(SystemExit) as excinfo:
        gw._dispatch_via_service_manager_if_s6(action, "coder")

    assert excinfo.value.code == 1
    assert mgr.registered == []
    assert mgr.calls == []
    assert "no such gateway 'coder'" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# HERM-131: HERMES_MESSAGING_GATEWAY=off refuses a start with an explanation
# ---------------------------------------------------------------------------


def test_start_refuses_and_explains_when_messaging_gateway_is_off(monkeypatch, capsys):
    """`hermes gateway start` (default or named profile) must not silently un-down the s6 slot that
    02-reconcile-profiles deliberately left down; it explains the container-level switch instead."""
    from hermes_cli import gateway as gw
    from hermes_cli import service_manager as sm

    rec = _CallRecorder()
    monkeypatch.setattr(sm, "detect_service_manager", lambda: "s6")
    monkeypatch.setattr(sm, "get_service_manager", lambda: rec)
    monkeypatch.setenv("HERMES_MESSAGING_GATEWAY", "off")

    with pytest.raises(SystemExit) as excinfo:
        gw._dispatch_via_service_manager_if_s6("start", "coder")

    assert excinfo.value.code == 1
    assert rec.calls == [], "must not touch the s6 slot at all"
    out = capsys.readouterr().out
    assert "HERMES_MESSAGING_GATEWAY=off" in out
    assert "messaging gateway off" in out.lower()


def test_stop_and_restart_are_unaffected_by_messaging_gateway_off(monkeypatch):
    """The switch only gates starting a new gateway; stop/restart of whatever happens to be up
    (e.g. started before the switch was flipped on) must keep working normally."""
    from hermes_cli import gateway as gw
    from hermes_cli import service_manager as sm

    rec = _CallRecorder()
    monkeypatch.setattr(sm, "detect_service_manager", lambda: "s6")
    monkeypatch.setattr(sm, "get_service_manager", lambda: rec)
    monkeypatch.setenv("HERMES_MESSAGING_GATEWAY", "off")

    assert gw._dispatch_via_service_manager_if_s6("stop", "coder") is True
    assert gw._dispatch_via_service_manager_if_s6("restart", "coder") is True
    assert rec.calls == [("stop", "gateway-coder"), ("restart", "gateway-coder")]


def test_start_is_unaffected_when_messaging_gateway_is_on_or_unset(monkeypatch):
    """No behaviour change for an operator who never set the variable, or set it explicitly to on."""
    from hermes_cli import gateway as gw
    from hermes_cli import service_manager as sm

    for value in (None, "on"):
        rec = _CallRecorder()
        monkeypatch.setattr(sm, "detect_service_manager", lambda: "s6")
        monkeypatch.setattr(sm, "get_service_manager", lambda: rec)
        if value is None:
            monkeypatch.delenv("HERMES_MESSAGING_GATEWAY", raising=False)
        else:
            monkeypatch.setenv("HERMES_MESSAGING_GATEWAY", value)

        assert gw._dispatch_via_service_manager_if_s6("start", "coder") is True
        assert rec.calls == [("start", "gateway-coder")]


# ---------------------------------------------------------------------------
# HERM-133: `gateway run` as the container command with HERMES_MESSAGING_GATEWAY=off parks instead
# of exiting 1 (which crash-looped the container and took the dashboard down with it).
# ---------------------------------------------------------------------------


class _Execd(Exception):
    """Raised by the stubbed ``os.execvp``: a real exec never returns to the caller."""


def _run_args(no_supervise: bool = False):
    from types import SimpleNamespace

    return SimpleNamespace(gateway_command="run", no_supervise=no_supervise, verbose=0, quiet=False,
                           replace=False, force=False, external_supervisor=False)


def _wire_run(monkeypatch, *, s6: bool, container: bool, switch: str | None):
    """Stub everything ``_cmd_run`` can reach; returns (s6 recorder, execvp calls, run_gateway calls)."""
    rec = _stub_s6(monkeypatch, on_s6=s6)
    monkeypatch.setattr("hermes_cli.gateway.is_container", lambda: container)
    monkeypatch.setattr("hermes_cli.gateway._profile_suffix", lambda: "")
    monkeypatch.delenv("HERMES_S6_SUPERVISED_CHILD", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_NO_SUPERVISE", raising=False)
    if switch is None:
        monkeypatch.delenv("HERMES_MESSAGING_GATEWAY", raising=False)
    else:
        monkeypatch.setenv("HERMES_MESSAGING_GATEWAY", switch)
    execs: list[tuple[str, list[str]]] = []

    def _fake_execvp(file, argv):
        execs.append((file, list(argv)))
        raise _Execd

    monkeypatch.setattr("hermes_cli.gateway.os.execvp", _fake_execvp)
    runs: list[bool] = []
    monkeypatch.setattr("hermes_cli.gateway.run_gateway", lambda *a, **k: runs.append(True))
    return rec, execs, runs


@pytest.mark.parametrize("switch", ["off", "OFF", "0", "false", "no"])
def test_run_parks_in_s6_container_when_messaging_gateway_is_off(monkeypatch, capsys, switch):
    """The image's documented command: idle as `sleep infinity`, one stderr line, no slot touched."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch=switch)

    with pytest.raises(_Execd):
        gw._cmd_run(_run_args())

    assert execs == [("sleep", ["sleep", "infinity"])]
    assert rec.calls == [], "the s6 gateway slot must stay down"
    assert runs == [], "no foreground gateway either"
    captured = capsys.readouterr()
    assert captured.out == "", "stdout stays clean for scripts"
    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "HERMES_MESSAGING_GATEWAY=off" in lines[0]
    assert "not starting the messaging gateway" in lines[0]


def test_run_parks_even_with_no_supervise_when_messaging_gateway_is_off(monkeypatch, capsys):
    """--no-supervise opts out of supervision, not of the container's kill switch."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch="off")
    monkeypatch.setenv("HERMES_GATEWAY_NO_SUPERVISE", "1")

    with pytest.raises(_Execd):
        gw._cmd_run(_run_args(no_supervise=True))

    assert execs and rec.calls == [] and runs == []
    capsys.readouterr()


def test_run_parks_in_container_without_s6_when_messaging_gateway_is_off(monkeypatch, capsys):
    """The non-PID-1 entrypoint fallback (docker run --init, Fly) has no s6, so the redirect is not
    taken; the switch must still keep the gateway from running in the foreground."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=False, container=True, switch="off")

    with pytest.raises(_Execd):
        gw._cmd_run(_run_args())

    assert execs == [("sleep", ["sleep", "infinity"])]
    assert rec.calls == [] and runs == []
    capsys.readouterr()


def test_run_outside_a_container_ignores_the_switch(monkeypatch, capsys):
    """Outside a container the variable means nothing: `gateway run` starts the gateway as always."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=False, container=False, switch="off")

    gw._cmd_run(_run_args())

    assert runs == [True]
    assert execs == [] and rec.calls == []
    assert "HERMES_MESSAGING_GATEWAY" not in capsys.readouterr().err


@pytest.mark.parametrize("switch", [None, "on"])
def test_run_in_s6_container_redirects_as_before_when_switch_on_or_unset(monkeypatch, capsys, switch):
    """No behaviour change for a container that never set the variable or set it to on."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch=switch)

    with pytest.raises(_Execd):
        gw._cmd_run(_run_args())

    assert rec.calls == [("start", "gateway-default")]
    assert execs == [("sleep", ["sleep", "infinity"])]
    assert runs == []
    assert "running under s6 supervision" in capsys.readouterr().err


def test_supervised_child_is_not_parked_by_the_switch(monkeypatch, capsys):
    """The s6 slot's own process is governed by boot reconcile and `gateway start`, not this path."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch="off")
    monkeypatch.setenv("HERMES_S6_SUPERVISED_CHILD", "1")

    gw._cmd_run(_run_args())

    assert runs == [True]
    assert execs == [] and rec.calls == []
    capsys.readouterr()


def test_parked_run_falls_back_in_process_and_disarms_watchdog(monkeypatch, capsys):
    """Without `sleep` on PATH the idle path uses the in-process heartbeat, with the startup watchdog
    disarmed first (#102000), so a switched-off container is not os._exit(75)ed as a deadlock."""
    from hermes_cli import gateway as gw

    sw, handle = _armed_watchdog(monkeypatch)
    try:
        rec, _execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch="off")
        monkeypatch.setattr("hermes_cli.gateway.os.execvp", _raise_missing_sleep)
        disarmed_at_park: list[bool] = []
        monkeypatch.setattr("hermes_cli.gateway._block_until_terminated",
                            lambda: disarmed_at_park.append(handle.disarmed))

        gw._cmd_run(_run_args())

        assert disarmed_at_park == [True]
        assert sw._handle is None
        assert rec.calls == [] and runs == []
    finally:
        sw._reset_for_tests()
    assert "`sleep` is unavailable" in capsys.readouterr().err


def test_gateway_start_still_refuses_when_switch_is_off_after_herm133(monkeypatch, capsys):
    """HERM-133 only changes `gateway run`; an explicit `gateway start` keeps exiting non-zero."""
    from hermes_cli import gateway as gw

    rec, execs, runs = _wire_run(monkeypatch, s6=True, container=True, switch="off")

    with pytest.raises(SystemExit) as excinfo:
        gw._dispatch_via_service_manager_if_s6("start")

    assert excinfo.value.code == 1
    assert rec.calls == [] and execs == [] and runs == []
    capsys.readouterr()
