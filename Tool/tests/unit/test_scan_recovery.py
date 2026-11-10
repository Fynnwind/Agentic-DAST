"""Target self-recovery: restart a wedged target and retry the scan.

Cacti is the only target that needs it (its CVE RCE leaks MariaDB connections
and its 342-endpoint seed flakes ~1 in 3), so recovery is opt-in per target and
every other target scans exactly once, as before. Hermetic: docker and the
login probe are stubbed; the live restart is the e2e tier's / operator's job.
"""

from __future__ import annotations

import subprocess
import time

import httpx
import pytest

from dast_orchestrator.adapters.zap_client import ZapError
from dast_orchestrator.stages.scan import driver, pipeline


# -- recover_target: restart the containers, then wait for the login form ----


class _Restart:
    """A ``subprocess.run`` stub recording the argv, optionally failing."""

    def __init__(self, fail: bool = False):
        self.calls: list[list[str]] = []
        self.fail = fail

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if self.fail:
            raise subprocess.CalledProcessError(1, argv, stderr="no such container")

        class _Done:
            returncode, stdout, stderr = 0, "", ""

        return _Done()


def _fetch_returning(*responses):
    """A ``container_fetch`` factory whose fetch yields ``(status, '', body)``
    from ``responses`` in turn (the last repeats)."""
    seq, state = list(responses), {"i": 0}

    def factory(*a, **k):
        def fetch(method, url, timeout):
            status, body = seq[min(state["i"], len(seq) - 1)]
            state["i"] += 1
            return status, "", body
        return fetch

    return factory


def test_recover_restarts_the_containers_then_waits_for_the_login_form(monkeypatch):
    restart = _Restart()
    monkeypatch.setattr(subprocess, "run", restart)
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    # 500 while the DB is still wedged, then the login form (the password field).
    monkeypatch.setattr(pipeline.auth, "container_fetch",
                        _fetch_returning((500, "error"), (200, "name='login_password'")))
    assert pipeline.recover_target("cacti", delay=0) is True
    assert restart.calls[0][:2] == ["docker", "restart"]
    assert "target-cacti" in restart.calls[0] and "target-cacti-db" in restart.calls[0]


def test_recover_is_a_noop_for_a_target_without_a_recovery_block(monkeypatch):
    restart = _Restart()
    monkeypatch.setattr(subprocess, "run", restart)
    assert pipeline.recover_target("gitea") is False
    assert restart.calls == []            # nothing is restarted


def test_recover_returns_false_when_the_restart_fails(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _Restart(fail=True))
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    assert pipeline.recover_target("cacti", delay=0) is False


def test_recover_gives_up_if_the_login_form_never_returns(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _Restart())
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    monkeypatch.setattr(pipeline.auth, "container_fetch",
                        _fetch_returning((500, "still wedged")))
    assert pipeline.recover_target("cacti", attempts=3, delay=0) is False


# -- the driver retries a recovery-capable target exactly once ---------------


def test_a_recovery_target_restarts_and_retries_on_a_dropped_connection(monkeypatch):
    calls = {"scan": 0, "recover": 0}

    def flaky_scan(*a, **k):
        calls["scan"] += 1
        if calls["scan"] == 1:
            raise httpx.RemoteProtocolError("server disconnected without sending a response")

    monkeypatch.setattr(driver, "run_scan", flaky_scan)
    monkeypatch.setattr(driver, "recover_target",
                        lambda name: calls.__setitem__("recover", calls["recover"] + 1) or True)
    rc = driver.main(["cacti", "--api-key", "x", "--auth", "none"])
    assert rc == 0
    assert calls["scan"] == 2 and calls["recover"] == 1


def test_a_recovery_target_gives_up_if_it_cannot_be_recovered(monkeypatch):
    calls = {"scan": 0}

    def always_drops(*a, **k):
        calls["scan"] += 1
        raise httpx.RemoteProtocolError("server disconnected")

    monkeypatch.setattr(driver, "run_scan", always_drops)
    monkeypatch.setattr(driver, "recover_target", lambda name: False)
    rc = driver.main(["cacti", "--api-key", "x", "--auth", "none"])
    assert rc == 1
    assert calls["scan"] == 1            # one attempt, recovery failed, no retry


def test_a_non_recovery_target_does_not_retry(monkeypatch):
    calls = {"scan": 0, "recover": 0}

    def failing_scan(*a, **k):
        calls["scan"] += 1
        raise ZapError("zap fell over")

    monkeypatch.setattr(driver, "run_scan", failing_scan)
    monkeypatch.setattr(driver, "recover_target",
                        lambda name: calls.__setitem__("recover", calls["recover"] + 1) or True)
    rc = driver.main(["gitea", "--api-key", "x", "--auth", "none"])
    assert rc == 1
    assert calls["scan"] == 1 and calls["recover"] == 0    # ran once, as before
