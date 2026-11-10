"""The stage lock: one file per stage+suffix in the run directory
(``.lock-verify-hybrid``), holding pid/host/start/command so a refusal names what is
already running.

Stage AND suffix, because two ``--out-suffix`` variants legitimately share a run
directory and may run together while two of the same suffix write one file and may not.
A stale lock is reclaimed (liveness is ``os.kill(pid, 0)``, so a pid from another host is
treated as live); it is a guard rail not a scheduler (``--force`` overrides), claimed
inside each stage's ``main`` where the run dir is known. → DECISIONS.md.
"""

from __future__ import annotations

import functools
import json
import os
import socket
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from dast_orchestrator.foundation import ui

#: Lock files are dotfiles so they never look like an artifact of the run, and
#: so `ls data/<run>` still shows exactly what the stages produced.
LOCK_PREFIX = ".lock-"

#: Exit code for a refused start. The same code every other "this cannot run"
#: refusal uses — an unknown target, an unsatisfiable sequence — as opposed to
#: 1, which means a stage ran and failed.
BUSY_EXIT = 2


class Busy(RuntimeError):
    """A live process already holds this stage's lock on this run directory.

    Raised by :func:`claim`; turned into a message and :data:`BUSY_EXIT` by
    :func:`guarded`, so no stage has to format the refusal itself.
    """


def lock_name(stage: str, suffix: str = "") -> str:
    """``("verify", "hybrid")`` -> ``".lock-verify-hybrid"``."""
    stage = str(stage).strip()
    suffix = str(suffix).strip()
    return LOCK_PREFIX + (f"{stage}-{suffix}" if suffix else stage)


def lock_path(run_dir: "Path | str", stage: str, suffix: str = "") -> Path:
    return Path(run_dir) / lock_name(stage, suffix)


def _record(stage: str, suffix: str) -> dict[str, Any]:
    """What a lock file says about its holder.

    The command line is recorded whole because "which of my four terminals is
    this?" is the actual question a refusal has to answer, and a pid alone does
    not answer it.
    """
    return {
        "stage": stage,
        "suffix": suffix,
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": " ".join(sys.argv),
    }


def _read(path: Path) -> dict[str, Any]:
    """A lock file's record, or ``{}`` if it is gone, empty or unparseable.

    An unreadable lock is deliberately *not* an error: it is treated as held by
    something unknown (see :func:`_alive`), which is the safe reading of a file
    a stage wrote and this one cannot understand.
    """
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


def _alive(record: dict[str, Any]) -> bool:
    """Whether the process named by a lock record still exists.

    Three cases resolve to "assume live", because each means *this* process
    cannot prove otherwise and proceeding is the destructive answer: a lock from
    another host (a pid number there says nothing here), a record with no usable
    pid (an empty or truncated file), and a pid owned by another user
    (``PermissionError`` from ``kill``, which is proof it exists).
    """
    if record.get("host") != socket.gethostname():
        return True
    pid = record.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def describe(record: dict[str, Any]) -> str:
    """The holder, as two indented lines for a refusal or a warning."""
    host = record.get("host") or "?"
    where = "on this machine" if host == socket.gethostname() else f"on {host}"
    lines = [f"pid {record.get('pid', '?')} {where}, "
             f"started {record.get('started', 'at an unrecorded time')}"]
    if record.get("command"):
        lines.append(f"`{record['command']}`")
    return "\n".join(f"  {line}" for line in lines)


def _busy(path: Path, record: dict[str, Any], stage: str) -> Busy:
    return Busy(
        f"{stage} is already running on {path.parent.name}"
        + (f" (--out-suffix {record['suffix']})" if record.get("suffix") else "")
        + ":\n" + describe(record) + "\n"
        + f"  lock: {ui.short_path(path)}\n"
        "Two of them would race to write the same artifact, probe one target "
        "at once and spend the same key. Wait for it to finish, run the other "
        "one under a different --out-suffix, or pass --force to run anyway."
    )


def _acquire(path: Path, stage: str, suffix: str, force: bool) -> Path:
    """Create the lock file, reclaiming a stale one, or raise :class:`Busy`.

    Two passes at most: the second exists only so that reclaiming a stale lock
    can then compete for it honestly. If someone else won that competition, the
    second pass sees a *live* holder and refuses, which is the right answer.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in (1, 2):
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            held = _read(path)
            if not held and not path.exists():
                continue                  # released between the create and the
                                          # read; try for it properly
            if _alive(held) and not force:
                raise _busy(path, held, stage)
            ui.warn(
                (f"--force: taking over {ui.short_path(path)} from\n"
                 if _alive(held) else
                 f"reclaiming the stale lock {ui.short_path(path)}, left by\n")
                + describe(held)
            )
            try:
                path.unlink()
            except FileNotFoundError:
                pass                      # someone else cleared it first — fine
            continue
        with os.fdopen(handle, "w") as stream:
            json.dump(_record(stage, suffix), stream, indent=2)
        return path
    raise _busy(path, _read(path), stage)


def claim(run_dir: "Path | str", stage: str, suffix: str = "",
          force: bool = False) -> Path:
    """Take this stage's lock on ``run_dir``, or raise :class:`Busy`.

    Inside a :func:`guarded` ``main`` — which is where every stage calls it —
    the lock is released when that call returns, however it returns. Outside
    one, the caller owns the lock and must :func:`release` it; :func:`held` is
    the version that does so for you.
    """
    path = _acquire(lock_path(run_dir, stage, suffix), stage, suffix, force)
    if _scopes:
        _scopes[-1].append(path)
    return path


def release(path: "Path | str") -> None:
    """Remove a lock this process holds. Never removes anyone else's.

    The pid check matters in exactly one case: another process reclaimed this
    lock (as stale, or with ``--force``) while this one was still running.
    Deleting the file then would hand a third process a directory that two are
    already writing to.
    """
    path = Path(path)
    record = _read(path)
    if record and record.get("pid") != os.getpid():
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


#: One list of held locks per :func:`guarded` call, innermost last. A stack
#: rather than a single list so a stage that calls another stage's ``main``
#: in-process releases only what it claimed itself.
_scopes: list[list[Path]] = []


@contextmanager
def held(run_dir: "Path | str", stage: str, suffix: str = "",
         force: bool = False) -> Iterator[Path]:
    """:func:`claim` with a scope of its own, for callers that are not a stage."""
    path = _acquire(lock_path(run_dir, stage, suffix), stage, suffix, force)
    try:
        yield path
    finally:
        release(path)


def guarded(main: Callable[..., int]) -> Callable[..., int]:
    """Wrap a stage's ``main``: release its locks, and refuse rather than raise.

    Two things, both of which every stage would otherwise repeat. A
    :class:`Busy` raised anywhere inside the stage — including from deep in a
    helper, which is where ``scan`` claims — becomes one ``ERROR:`` and
    :data:`BUSY_EXIT`, rather than a traceback. And every lock claimed during
    the call is released on the way out, so no stage needs a ``try``/``finally``
    around a body that is hundreds of lines long and has a dozen early returns.

    Release is tied to the *call*, not to process exit, because ``dast`` runs a
    sequence of stages in one process: a lock freed only at exit would make
    ``dast triage verify latest`` hold ``triage``'s lock through the whole
    verification, and would refuse a second row that a single process ran back
    to back.
    """

    @functools.wraps(main)
    def wrapper(*args: Any, **kwargs: Any) -> int:
        _scopes.append([])
        try:
            return main(*args, **kwargs)
        except Busy as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return BUSY_EXIT
        finally:
            for path in reversed(_scopes.pop()):
                release(path)

    return wrapper
