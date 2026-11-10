#!/usr/bin/env python3
"""Run the rescan corpus end to end: every sheet in order, and the steps between.

One sheet at a time (never two harnesses at once: the harness cost ceiling is
tree-wide), in the order of ``rerun-README.md`` §"Order and gate" and NEXT_SESSION
§6, with the steps a person used to do between sheets:

- **reclaim** before every scanning step (``RERUN-FREEZE.md`` §"Docker VM disk"):
  truncate the four targets' container logs, recreate ``dast-zap``, and refuse to
  go on with less than ``--min-free-gb`` free on the Docker VM disk.
- **Cacti, one ceiling per invocation** through ``rerun-cacti-ceiling-driver.sh 1``
  (restart + login probe before each), then ``--restart-only`` after the group,
  so the next Cacti scan does not meet a target its OOB probe left wedged.
- **rewire** G5/G6/G7/G9 to this G1's admin-blind runs (``rerun-rewire-refs.py``).
- **reset each target once** before G5 and again before G6, whose deferred verify
  probes the live target without a reset of its own.

Usage, from ``Tool/``, by the OPERATOR (recreating ``dast-zap`` needs the key the
sandbox withholds from an agent)::

    python scripts/rerun-chain.py --list            # the steps, nothing run
    python scripts/rerun-chain.py --dry-run         # every sheet's own --dry-run
    python scripts/rerun-chain.py --to g1           # G1, then read it (the gate)
    python scripts/rerun-chain.py --from g2         # everything after it

**When it stops.** A step whose sheets completed at least one row but failed
others is *partial*: the harness already ran the other rows, so the chain records
the failed ones for a top-up and goes on (a single Cacti seed flake must not idle
the night). It stops on anything that says the environment is broken: a step in
which every row failed (the 2026-10-30 full-disk launch failed 35 of 35; for the
one-row Cacti ceilings, all of a group's runs), a sheet that reached its cost
ceiling or left no results, a sheet that would not load (exit 2), or any action
between sheets that fails (reclaim, Cacti restart, rewire, target reset). It
prints the ``--from`` step to resume at. Exit 0 = all ok, 1 = finished with
failed rows to top up, 2 = stopped.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]                 # the Tool/ directory
REPO = ROOT.parent
HARNESS_DIR = "config/harness"
DRIVER = f"{HARNESS_DIR}/rerun-cacti-ceiling-driver.sh"
TARGETS = ("grafana", "wordpress", "cacti", "gitea")
#: What the step between sheets reclaims, and the image it truncates logs with
#: (the commands of RERUN-FREEZE.md §"Docker VM disk", unchanged).
TARGET_CONTAINERS = tuple(f"target-{t}" for t in TARGETS)
ALPINE = "alpine:3.20"
ZAP_RECREATE = ["docker", "compose", "-f", "docker/ephemeral.yml",
                "--env-file", "config/scanner/.env", "up", "-d", "--force-recreate"]
#: A sheet runs for up to a day and cannot reclaim mid-sheet; the repeats sheet
#: filled a 46 GB disk on 2026-10-30. After a reclaim the VM has ~100 GB.
MIN_FREE_GB = 40.0

OK, PARTIAL, STOP = "ok", "partial", "stopped"


@dataclass
class Action:
    """One command of a step, or the reclaim (``reclaim=True``, no argv)."""

    label: str
    argv: list[str] = field(default_factory=list)
    #: The harness sheet this action runs, judged from its ``results.json``.
    sheet: str = ""
    #: What ``--dry-run`` runs instead; empty = only print the action.
    dry_argv: list[str] = field(default_factory=list)
    reclaim: bool = False


@dataclass
class Step:
    name: str
    what: str
    actions: list[Action]


def _harness(sheet: str) -> list[str]:
    return ["uv", "run", "dast", "harness", f"{HARNESS_DIR}/{sheet}"]


def _sheet(sheet: str) -> Action:
    return Action(sheet, _harness(sheet), sheet=sheet,
                  dry_argv=_harness(sheet) + ["--dry-run"])


def _cacti_ceiling(sheet: str, label: str) -> Action:
    return Action(label, ["bash", DRIVER, "1", f"{HARNESS_DIR}/{sheet}"], sheet=sheet,
                  dry_argv=_harness(sheet) + ["--dry-run"])


RECLAIM = Action("reclaim: truncate target logs, recreate dast-zap, check free disk",
                 reclaim=True)
CACTI_RESTART = Action("restart Cacti (clears the connections the OOB probe leaked)",
                       ["bash", DRIVER, "--restart-only"])


def plan() -> list[Step]:
    """The corpus, in execution order. The smoke gate runs before this, apart."""
    reset = [Action(f"reset {t} to its clean snapshot",
                    ["bash", str(REPO / "Targets" / t / "env" / "reset.sh")])
             for t in TARGETS]
    return [
        Step("g1", "G1 blind matrix, 12 cells (the reported corpus)",
             [_sheet("rerun-g1-blind-matrix.yml")]),
        Step("g2", "G2 ceiling matrix, 9 cells",
             [RECLAIM, _sheet("rerun-g2-ceiling-matrix.yml")]),
        Step("g2-cacti", "G2's 3 Cacti ceilings, one per invocation",
             [RECLAIM,
              _cacti_ceiling("rerun-cacti-ceiling-none.yml", "Cacti ceiling, none"),
              _cacti_ceiling("rerun-cacti-ceiling-user.yml", "Cacti ceiling, user"),
              _cacti_ceiling("rerun-cacti-ceiling.yml", "Cacti ceiling, admin "
                             "(also the Cacti ceiling band's 4th sample)"),
              CACTI_RESTART]),
        Step("repeats", "the reproducibility band, 3 per row (+ G1/G2's admin cell)",
             [RECLAIM, _sheet("rerun-repeats.yml")]),
        Step("repeats-cacti", "the Cacti ceiling band's 3 runs, one per invocation",
             [RECLAIM]
             + [_cacti_ceiling("rerun-cacti-ceiling.yml", f"Cacti ceiling band {i}/3")
                for i in (1, 2, 3)]
             + [CACTI_RESTART]),
        Step("g4", "G4 crawl only, scan only, x2",
             [RECLAIM, _sheet("rerun-g4-crawl.yml")]),
        Step("rewire", "point G6/G7/G9 at this G1's admin-blind runs",
             [Action("rerun-rewire-refs.py",
                     [sys.executable, "scripts/rerun-rewire-refs.py"])]),
        Step("g5", "G5 model repeats on G1's admin-blind scans (deferred verify, reset "
             "targets)", [RECLAIM, *reset, _sheet("rerun-g5-model-repeats.yml")]),
        Step("g6", "G6 verify configs (deferred verify on the live, reset targets)",
             [*reset, _sheet("rerun-g6-verify-configs.yml")]),
        Step("g7", "G7 context re-triage (offline)", [_sheet("rerun-g7-context.yml")]),
        Step("g9", "G9 static analysis", [_sheet("rerun-g9-static.yml")]),
    ]


def select(steps: list[Step], start: str | None, stop: str | None) -> list[Step]:
    """The steps from ``start`` through ``stop``, both inclusive and optional."""
    names = [s.name for s in steps]
    for name in (start, stop):
        if name is not None and name not in names:
            raise SystemExit(f"no step {name!r}; the steps are: {', '.join(names)}")
    first = names.index(start) if start else 0
    last = names.index(stop) if stop else len(names) - 1
    if first > last:
        raise SystemExit(f"--from {start} comes after --to {stop}")
    return steps[first:last + 1]


def _sheet_dir_time(name: str) -> datetime | None:
    try:
        return datetime.strptime(name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass
class Judged:
    """What one harness run of a sheet recorded."""

    completed: int = 0
    failed: list[str] = field(default_factory=list)
    #: Why the chain must stop regardless of the counts; empty = it need not.
    stop: str = ""


def judge(data_dir: Path, sheet: str, started: datetime) -> Judged:
    """The newest run of ``sheet`` begun since ``started``, from its ``results.json``.

    A row failed when the harness recorded a ``failed_stage`` or a ``reason`` (its
    own test for a clean sheet). Stops outright when there is no such run or the
    sheet reached its cost ceiling.
    """
    stem = Path(sheet).stem
    since = started - timedelta(seconds=5)
    found = sorted(
        (d for d in data_dir.glob(f"*Z-{stem}")
         if (t := _sheet_dir_time(d.name)) and t >= since
         and (d / "results.json").is_file()),
        key=lambda d: d.name)
    if not found:
        return Judged(stop=f"no results.json for {stem} since {started:%H:%M:%SZ}")
    executions = json.loads((found[-1] / "results.json").read_text()).get("executions") or []
    failed = [e for e in executions if e.get("failed_stage") or e.get("reason")]
    judged = Judged(
        completed=len(executions) - len(failed),
        failed=[f"{found[-1].name}: {e.get('row')} #{e.get('repeat')} "
                f"({e.get('failed_stage') or '-'}: {e.get('reason')})" for e in failed])
    if any("cost ceiling" in str(e.get("reason")) for e in failed):
        judged.stop = f"{stem} reached its cost ceiling"
    return judged


Runner = Callable[[list[str]], int]
Capture = Callable[[list[str]], "tuple[int, str]"]


def _run(argv: list[str]) -> int:
    return subprocess.run(argv, cwd=ROOT, check=False).returncode


def _capture(argv: list[str]) -> tuple[int, str]:
    done = subprocess.run(argv, cwd=ROOT, check=False, capture_output=True, text=True)
    return done.returncode, done.stdout


@dataclass
class Chain:
    data_dir: Path = ROOT / "data" / "harness"
    min_free_gb: float = MIN_FREE_GB
    run: Runner = _run
    capture: Capture = _capture
    say: Callable[[str], None] = lambda text: print(text, flush=True)
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def reclaim(self) -> tuple[str, str]:
        """Truncate the target logs, recreate ZAP, then check the free space."""
        for container in TARGET_CONTAINERS:
            rc, path = self.capture(["docker", "inspect", container,
                                     "--format", "{{.LogPath}}"])
            if rc != 0 or not path.strip():
                return STOP, f"could not find {container}'s log"
            rc = self.run(["docker", "run", "--rm", "-v",
                           "/var/lib/docker/containers:/var/lib/docker/containers",
                           ALPINE, "truncate", "-s", "0", path.strip()])
            if rc != 0:
                return STOP, f"truncating {container}'s log failed (exit {rc})"
        if (rc := self.run(ZAP_RECREATE)) != 0:
            return STOP, f"recreating dast-zap failed (exit {rc})"
        rc, df = self.capture(["docker", "run", "--rm", ALPINE, "df", "-Pk", "/"])
        try:
            free_gb = int(df.strip().splitlines()[-1].split()[3]) / 1024 ** 2
        except (IndexError, ValueError):
            return STOP, f"could not read the free space (exit {rc}): {df[-200:]!r}"
        if free_gb < self.min_free_gb:
            return STOP, (f"{free_gb:.1f} GB free on the Docker VM, under "
                          f"{self.min_free_gb:.0f} GB: reclaim by hand first")
        return OK, f"{free_gb:.1f} GB free"

    def act(self, action: Action, dry_run: bool) -> Judged:
        """Run one action. A non-sheet action that fails stops the chain."""
        if dry_run:
            if action.dry_argv:
                rc = self.run(action.dry_argv)
                return Judged(stop="" if rc == 0 else f"dry run exited {rc}")
            self.say("    (dry run: not run) "
                     + (" ".join(action.argv) if action.argv else action.label))
            return Judged()
        if action.reclaim:
            outcome, note = self.reclaim()
            self.say(f"    {note}")
            return Judged(stop="" if outcome == OK else note)
        started = self.now()
        rc = self.run(action.argv)
        if not action.sheet or rc not in (0, 1):
            return Judged(stop="" if rc == 0 else f"{action.label} exited {rc}")
        judged = judge(self.data_dir, action.sheet, started)
        if rc == 1 and not judged.failed and not judged.stop:
            judged.stop = f"{action.label} exited 1 with no failed row recorded"
        return judged

    def execute(self, steps: list[Step], dry_run: bool = False) -> int:
        summary: list[tuple[str, str, str]] = []
        to_top_up: list[str] = []
        for step in steps:
            began = self.now()
            self.say(f"\n=== [{began:%Y-%m-%d %H:%M:%SZ}] {step.name}: {step.what}")
            completed, failed, stop, left = 0, [], "", []
            for index, action in enumerate(step.actions):
                self.say(f"--> {action.label}")
                judged = self.act(action, dry_run)
                completed += judged.completed
                failed += judged.failed
                for row in judged.failed:
                    self.say(f"    failed: {row}")
                if judged.stop:
                    stop, left = judged.stop, step.actions[index:]
                    break
            # Rows failed and none completed: the environment, not one flake.
            if not stop and failed and not completed:
                stop = f"every row of {step.name} failed"
            if stop:
                summary.append((step.name, STOP, _took(began, self.now())))
                self._close(summary, to_top_up)
                self.say(f"STOPPED in {step.name}: {stop}. Fix it, then resume with "
                         f"--from {step.name}, which runs the whole step again.")
                if left and len(left) < len(step.actions):
                    # A group's earlier runs may have landed; finishing it by hand
                    # and resuming at the next step avoids running them twice.
                    self.say("  or finish this step by hand, from the action that "
                             "stopped, and resume at the next:")
                    for action in left:
                        self.say("    " + (" ".join(action.argv) if action.argv
                                           else action.label))
                return 2
            to_top_up += failed
            summary.append((step.name, PARTIAL if failed else OK,
                            _took(began, self.now())))
        self._close(summary, to_top_up)
        return 1 if to_top_up else 0

    def _close(self, summary: list[tuple[str, str, str]], to_top_up: list[str]) -> None:
        self.say("\n=== chain summary")
        for name, outcome, took in summary:
            self.say(f"  {name:14s} {outcome:8s} {took}")
        if to_top_up:
            self.say("  rows to top up (the harness ran the rest of their sheets):")
            for row in to_top_up:
                self.say(f"    {row}")


def _took(began: datetime, ended: datetime) -> str:
    minutes = (ended - began).total_seconds() / 60
    return f"{minutes / 60:.1f} h" if minutes >= 90 else f"{minutes:.0f} min"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--from", dest="start", metavar="STEP",
                        help="first step to run (default: the first)")
    parser.add_argument("--to", dest="stop", metavar="STEP",
                        help="last step to run, inclusive (default: the last)")
    parser.add_argument("--dry-run", action="store_true",
                        help="run every sheet's own --dry-run; touch no container")
    parser.add_argument("--list", action="store_true", help="print the steps and exit")
    parser.add_argument("--min-free-gb", type=float, default=MIN_FREE_GB,
                        help=f"stop before a sheet with less free (default {MIN_FREE_GB:.0f})")
    args = parser.parse_args(argv)
    steps = select(plan(), args.start, args.stop)
    if args.list:
        for step in steps:
            print(f"{step.name:14s} {step.what}")
            for action in step.actions:
                print(f"{'':14s}   - {action.label}")
        return 0
    return Chain(min_free_gb=args.min_free_gb).execute(steps, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
