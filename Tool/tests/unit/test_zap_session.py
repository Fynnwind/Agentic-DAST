"""The file-backed session: where a scan's messages live, and who cleans up.

The pipeline asked ZAP for an *unnamed* session from the day it was written, and
an unnamed session keeps its message store in the JVM heap. A 45-minute Gitea
scan sends over 100,000 messages, so the heap filled on every run — the daemon's
own logs record 96%, 97%, 99% and 99% across four that survived, and one that
did not, where the Insights add-on shut ZAP down and discarded a completed
scan's alerts before they could be fetched.

Three earlier fixes each raised a ceiling under that growth (disable rule 10104,
`-Xmx8g`, the Docker VM to 18 GB). Naming the session removes the growth instead.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.adapters import zap_session


def test_the_session_path_is_the_runs_own_directory():
    """ZAP writes six files and a `.tmp` dir beside any session it is given.

    One directory per run, so cleanup is a single explicit path rather than a
    glob over a folder that may also hold sessions a person saved by hand.
    """
    path = zap_session.session_path("20260908T120000Z-gitea-abc123")
    assert path.startswith(zap_session.CONTAINER_SESSION_DIR + "/")
    assert "20260908T120000Z-gitea-abc123" in path
    assert path.endswith("/" + zap_session.SESSION_BASENAME)
    assert zap_session.container_dir("x") in zap_session.session_path("x")


def test_two_runs_never_share_a_session_directory():
    """A second scan writing into the first's session would corrupt both."""
    assert zap_session.container_dir("run-a") != zap_session.container_dir("run-b")


def test_a_directory_that_is_not_ours_is_never_removed(monkeypatch):
    """The destructive call is guarded by the prefix this module puts there.

    The path is always built here from a run id, so the check should be
    unreachable — which is exactly the argument that preceded `rm -rf
    data/harness/*10-baseline` destroying two scans. It costs nothing.
    """
    calls: list[tuple] = []
    monkeypatch.setattr(zap_session, "_docker",
                        lambda *a, **k: calls.append(a) or "")
    monkeypatch.setattr(zap_session, "container_dir",
                        lambda _run: "/home/zap/.ZAP/session")
    zap_session.discard("run-a", "dast-zap")
    assert not calls, "removed a path without this tool's own prefix"


def _recording_docker(listing: str = ""):
    """A fake ``_docker`` that records argv and answers ``ls`` with ``listing``."""
    calls: list[tuple] = []

    def fake(*argv, what, check=True, timeout=None):
        calls.append(argv)
        return listing if "ls" in argv else ""

    return fake, calls


def test_keeping_the_session_sets_it_aside_but_removes_nothing(monkeypatch):
    """`keep=True` moves the directory out of the `dast-run-` namespace.

    It must not delete anything, and the rename is what protects a deliberately
    kept session from the next run's stale-session sweep.
    """
    fake, calls = _recording_docker()
    monkeypatch.setattr(zap_session, "_docker", fake)
    zap_session.discard("run-a", "dast-zap", keep=True)
    verbs = [a[2] for a in calls]
    assert "rm" not in verbs
    assert verbs == ["mv"]
    src, dst = calls[0][3], calls[0][4]
    assert src == zap_session.container_dir("run-a")
    assert dst.endswith(f"{zap_session.KEPT_PREFIX}dast-run-run-a")


def test_cleanup_failure_is_reported_and_never_fails_the_run(monkeypatch):
    """The scan is over and its artifacts are written by the time this runs.

    Losing a finished 45-minute scan to a housekeeping step is the worst trade
    in this pipeline — it is why `new_session` has its own long timeout — so a
    leftover directory is a warning, not an exception.
    """
    def explode(*_a, **_k):
        raise zap_session.SessionError("docker said no")

    monkeypatch.setattr(zap_session, "_docker", explode)
    zap_session.discard("run-a", "dast-zap")     # must not raise


def test_a_directory_that_cannot_be_created_stops_the_run(monkeypatch):
    """Falling back to the in-heap temporary session must never be silent.

    The run would look identical and be the one that runs out of memory — which
    is precisely the failure that went unnoticed for the project's whole history.
    """
    def explode(*_a, **_k):
        raise zap_session.SessionError("docker said no")

    monkeypatch.setattr(zap_session, "_docker", explode)
    with pytest.raises(zap_session.SessionError):
        zap_session.prepare("run-a", "dast-zap")


def test_the_client_passes_the_name_through(monkeypatch):
    """`new_session()` with no argument is still the release call.

    Releasing a named session IS a switch back to a temporary one, so the empty
    default is correct and must keep working.
    """
    from dast_orchestrator.adapters import zap_client

    seen: dict = {}

    class Fake(zap_client.ZapClient):
        def __init__(self):
            pass

        def _get(self, path, timeout=None, **params):
            seen.update({"path": path, **params})
            return {}

    Fake().new_session("/home/zap/.ZAP/session/dast-run-x/session")
    assert seen["name"] == "/home/zap/.ZAP/session/dast-run-x/session"
    Fake().new_session()
    assert seen["name"] == ""


def test_a_stale_session_from_a_crashed_run_is_swept(monkeypatch):
    """A `docker restart` does not reclaim an on-disk session, so each run sweeps
    every other `dast-run-` directory — the leftovers that filled the VM disk."""
    listing = ("dast-run-old-a\ndast-run-old-b\ndast-run-run-a\n"
               "kept-dast-run-saved\nsome-hand-saved-session\n")
    fake, calls = _recording_docker(listing)
    monkeypatch.setattr(zap_session, "_docker", fake)
    zap_session.sweep_stale("dast-zap", keep_run_id="run-a")
    removed = [a[4] for a in calls if a[2] == "rm"]
    assert removed == [
        f"{zap_session.CONTAINER_SESSION_DIR}/dast-run-old-a",
        f"{zap_session.CONTAINER_SESSION_DIR}/dast-run-old-b",
    ]
    # this run's own dir, a kept session and a hand-saved one are left alone
    assert all("dast-run-run-a" not in p for p in removed)
    assert all("kept-dast-run-saved" not in p for p in removed)
    assert all("some-hand-saved-session" not in p for p in removed)


def test_prepare_sweeps_before_it_creates_this_runs_directory(monkeypatch):
    """The sweep runs at the start of a run, so a prior timeout self-heals."""
    listing = "dast-run-old\ndast-run-run-a\n"
    fake, calls = _recording_docker(listing)
    monkeypatch.setattr(zap_session, "_docker", fake)
    zap_session.prepare("run-a", "dast-zap")
    verbs = [a[2] for a in calls]
    assert verbs == ["ls", "rm", "mkdir"]          # sweep, then create
    assert calls[1][4].endswith("dast-run-old")    # not this run's own dir


def test_the_sweep_never_raises(monkeypatch):
    """Housekeeping: a daemon that cannot be reached must not fail the run."""
    def explode(*_a, **_k):
        raise zap_session.SessionError("docker said no")

    monkeypatch.setattr(zap_session, "_docker", explode)
    zap_session.sweep_stale("dast-zap", keep_run_id="run-a")   # must not raise


def test_a_stale_dir_that_will_not_delete_is_warned_not_raised(monkeypatch):
    def fake(*argv, what, check=True, timeout=None):
        if "ls" in argv:
            return "dast-run-old\n"
        raise zap_session.SessionError("rm timed out")

    monkeypatch.setattr(zap_session, "_docker", fake)
    zap_session.sweep_stale("dast-zap", keep_run_id="run-a")   # must not raise
