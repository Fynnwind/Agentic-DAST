"""Give ZAP a named session at an explicit on-disk path, one directory per run, removed
afterwards.

An unnamed ZAP session is temporary and keeps every request/response in the JVM heap — the
actual cause of every ZAP OOM here — while a named session puts the store on disk. Cleanup
releases the session (``newSession`` with no name) then removes the directory by its full
explicit path (no glob; see CLAUDE.md); the raw session is not copied into ``data/`` (it is
gigabytes and duplicates the message sidecar), and ``keep=True`` sets it aside for ZAP
Desktop. A ``docker restart`` between runs gives a fresh *process* (clearing the heap) but
keeps the container's writable layer, so a cleanup that timed out leaves its directory
behind; :func:`sweep_stale`, run by :func:`prepare` at the start of each run, reclaims those
so the disk cannot fill. → DECISIONS.md.
"""

from __future__ import annotations

import subprocess

from dast_orchestrator.foundation import ui

#: Where ZAP keeps sessions inside the container image. Its own default
#: directory, so nothing here depends on a mount that may not exist.
CONTAINER_SESSION_DIR = "/home/zap/.ZAP/session"

#: Basename of the session file inside the run's directory. The directory
#: carries the run id; this stays constant so the paths are predictable.
SESSION_BASENAME = "session"

#: A kept session (``--keep-zap-session``, for ZAP Desktop) is moved under this
#: prefix so :func:`sweep_stale` — which reclaims only ``dast-run-`` directories
#: — never deletes a session a person deliberately asked to keep.
KEPT_PREFIX = "kept-"

#: docker exec/ls/mkdir/mv return in well under a minute; only a destructive rm
#: of a multi-gigabyte session store (a Grafana active scan is ~24 GB) can run
#: long on a loaded VM, so it gets its own larger budget rather than being killed
#: mid-delete at the default — which is how the gigabytes were left behind.
QUICK_TIMEOUT_SECONDS = 60
RM_TIMEOUT_SECONDS = 600


class SessionError(RuntimeError):
    """Raised when the run's session directory cannot be created or removed."""


def container_dir(run_id: str) -> str:
    """The run's own session directory inside the ZAP container.

    Prefixed, because this path is removed at the end of the run and the prefix
    is what distinguishes a directory this tool created from a session a person
    saved by hand in the same folder.
    """
    return f"{CONTAINER_SESSION_DIR}/dast-run-{run_id}"


def session_path(run_id: str) -> str:
    """The full path handed to ``core/action/newSession``."""
    return f"{container_dir(run_id)}/{SESSION_BASENAME}"


def _docker(*argv: str, what: str, check: bool = True,
            timeout: float = QUICK_TIMEOUT_SECONDS) -> str:
    try:
        result = subprocess.run(["docker", *argv], capture_output=True,
                                text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SessionError(f"could not {what}: {exc}") from exc
    if check and result.returncode != 0:
        raise SessionError(
            f"could not {what}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def prepare(run_id: str, container: str) -> str:
    """Create the run's session directory and return the session path.

    First sweeps any session directory an earlier run left behind
    (:func:`sweep_stale`), so a cleanup that timed out one run self-heals on the
    next rather than accumulating until the Docker VM disk fills.

    :raises SessionError: if the directory cannot be created. Deliberately fatal:
        continuing would silently fall back to the in-heap temporary session
        that this module exists to stop using, and the run would look identical
        while being the one that runs out of memory.
    """
    sweep_stale(container, keep_run_id=run_id)
    _docker("exec", container, "mkdir", "-p", container_dir(run_id),
            what=f"create the session directory in {container}")
    return session_path(run_id)


def sweep_stale(container: str, *, keep_run_id: str | None = None) -> None:
    """Remove every prior run's session directory still in the container.

    :func:`discard` clears a run's own directory when that run ends, but a
    cleanup that timed out — a slow daemon still flushing a multi-gigabyte store
    — or a crashed run leaves it behind, and
    :meth:`~dast_orchestrator.adapters.zap_client.ZapClient.restart_daemon` does
    not reclaim it: a ``docker restart`` replaces the process (clearing the heap
    and the site tree) but keeps the container's writable layer. Left to
    accumulate they fill the Docker VM disk and the daemon dies (a Grafana
    active-scan session is ~24 GB). Swept at the start of each run — after the
    restart, before this run creates its own directory — so a prior failure
    self-heals on the next scan.

    Safe by construction: one scan runs per daemon at a time (it is restarted
    per run), so every other ``dast-run-`` directory is a leftover, never a live
    peer. Each is removed by its full explicit path — listed first, never a glob
    (CLAUDE.md) — the tool's own ``dast-run-`` prefix only, never this run's own
    directory, and never a ``kept-`` session. Never raises: housekeeping,
    reported not fatal.
    """
    try:
        listing = _docker("exec", container, "ls", "-1", CONTAINER_SESSION_DIR,
                          what=f"list ZAP sessions in {container}", check=False)
    except SessionError as exc:
        ui.warn(f"could not list ZAP sessions to sweep ({exc})")
        return
    keep_name = f"dast-run-{keep_run_id}" if keep_run_id else None
    stale = sorted(
        name for name in listing.split()
        if name.startswith("dast-run-") and name != keep_name
    )
    reclaimed = 0
    for name in stale:
        path = f"{CONTAINER_SESSION_DIR}/{name}"
        try:
            _docker("exec", container, "rm", "-rf", path,
                    what=f"reclaim the stale session directory {name} in {container}",
                    timeout=RM_TIMEOUT_SECONDS)
            reclaimed += 1
        except SessionError as exc:
            ui.warn(f"{exc} — remove {path!r} by hand if this daemon is long-lived")
    if reclaimed:
        ui.item("zap session", f"reclaimed {reclaimed} stale session "
                               f"director{'y' if reclaimed == 1 else 'ies'} in {container}")


def discard(run_id: str, container: str, keep: bool = False) -> None:
    """Remove the run's session directory, if it is ours and we may.

    Never raises: the scan is over by the time this runs and its artifacts are
    written, so failing here must not fail the run. A directory left behind is
    reported, because disk filling up quietly is how a developer's daemon dies
    three weeks later.

    :param keep: leave the session in place — for reopening the run in ZAP
        Desktop. The directory then accumulates, which is why it is not the
        default.
    """
    if keep:
        # Move it out of the `dast-run-` namespace so the next run's sweep does
        # not reclaim a session a person deliberately kept.
        src = container_dir(run_id)
        dst = f"{CONTAINER_SESSION_DIR}/{KEPT_PREFIX}dast-run-{run_id}"
        try:
            _docker("exec", container, "mv", src, dst,
                    what=f"set the kept session aside in {container}")
            ui.item("zap session",
                    f"kept at {dst} inside {container} (--keep-zap-session)")
        except SessionError as exc:
            ui.warn(f"{exc} — the kept session stays at {src}")
        return
    path = container_dir(run_id)
    # Belt and braces on a destructive call: the path is built by this module
    # from a run id and always carries the prefix, but the check costs nothing
    # and the failure it prevents is deleting somebody's saved session.
    if "/dast-run-" not in path:
        ui.warn(f"refusing to remove {path!r}: not a path this tool creates")
        return
    try:
        _docker("exec", container, "rm", "-rf", path,
                what=f"remove the run's session directory from {container}",
                timeout=RM_TIMEOUT_SECONDS)
    except SessionError as exc:
        ui.warn(f"{exc} — remove it by hand if this daemon is long-lived "
                "(the next run's sweep will reclaim it)")
