"""The configuration harness: a sheet of runs (``config/harness/<name>.yml``) executed
unattended into one comparison table.

Its own package beside ``dast_orchestrator`` — it drives the pipeline one-way and is
never imported by it — and the reproducible, non-interactive counterpart to the ``dast``
CLI, sharing only ``dast_orchestrator.stages``. A row is an env overlay (base config plus
the few vars it changes, archived beside the run): a row starting with ``scan`` mints its
run while one that does not acts on a stored run (so the scan is paid once), a broken row
is recorded failed without stopping the sheet, and a live-LLM row spends the key so
starting one is the user's call. → DECISIONS.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation import ui
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.stages import table as stage_table

REPO_ROOT = Path(__file__).resolve().parents[2]
#: The data *root*. A sheet never writes here directly: it makes its own
#: directory under it and points every stage at that.
DATA_ROOT = run_paths.DATA_ROOT

#: Where the committed sheets live — beside the scanner's env files, since
#: both are the same thing: what this system is set up to do right now.
SHEETS_DIR = REPO_ROOT / "config" / "harness"

#: Where a sheet's own artifacts live: the merged env overlay per row, the
#: machine-readable results, and the comparison table. Under ``data/`` so a
#: sheet's output sits with the runs it produced, but in its own directory —
#: ``RunLayout.runs`` lists only names that *are* run ids, so this is never
#: mistaken for one.
HARNESS_DIR_NAME = "harness"

#: A row that hangs must not hold the sheet forever. Generous, because a real
#: active scan is 45 minutes and a triage of it can be another 30; this is a
#: backstop against a wedged container, not a budget.
DEFAULT_STAGE_TIMEOUT_MINUTES = 240

#: Default ceiling on what one sheet may spend, in USD. A sheet is the thing
#: most likely to run unattended for hours, so it gets a real number rather than
#: :data:`screening.UNLIMITED`. The measured sheets so far cost $0.44 and
#: $0.55, so this is ~10x headroom on a normal night and still bounds a mistake.
#: A sheet that needs more says ``max_cost_usd:`` in its ``defaults:``.
DEFAULT_SHEET_MAX_COST_USD = 5.0


class SheetError(ValueError):
    """The sheet is malformed, or names something that does not exist."""


@dataclass
class Row:
    """One experiment: a sequence of stages under one configuration.

    :param stages: the stages to run, in the order written.
    :param run: which stored run to act on, for a row that does not begin by
        scanning. ``"latest"`` (the default) means the newest run holding what
        the row's first stage requires, resolved when the row starts rather than
        when the sheet is read — so a row can act on a run an earlier row made.
    :param repeat: how many times to execute the row. This is the variance
        instrument: the same configuration N times stops run-to-run spread being
        an anecdote and makes it an error bar.
    :param env: the variables this row changes, overlaid on the sheet's base
        configuration. Everything else is inherited, so a row shows only its
        difference — which is also what makes the sheet readable as a design.
    """

    name: str
    stages: tuple[str, ...]
    run: str = run_paths.LATEST
    #: Which target a scanning row attacks. Named in the sheet rather than left
    #: to an environment variable: the sheet is the record of what a night's
    #: experiments were, and "which system was this run against" is the first
    #: thing that record has to say.
    target: str = ""
    #: Which *stored* correlation variant a consuming stage reads, for a row
    #: that does not run ``correlate`` itself. Empty means the base
    #: ``triage.json``. Ignored when the row produces its own.
    correlation: str = ""
    repeat: int = 1
    env: dict[str, str] = field(default_factory=dict)
    timeout_minutes: int = DEFAULT_STAGE_TIMEOUT_MINUTES

    @property
    def mints_run(self) -> bool:
        return bool(self.stages) and stage_table.STAGES[self.stages[0]].mints_run

    def label(self, repeat_index: int) -> str:
        """The artifact suffix for one execution of this row.

        The row's name, plus the repeat number when there is more than one — so
        three variance repeats leave ``triage-var-1.json``,
        ``triage-var-2.json`` and ``triage-var-3.json`` side by side
        instead of overwriting each other. The *first* repeat is numbered too:
        an unnumbered artifact among numbered ones reads as the baseline rather
        than as sample one of three, and it would not match the numbered env
        overlay archived beside it. A row that mints its own run needs no suffix
        at all — the directory already distinguishes it.
        """
        if self.mints_run:
            return ""
        return self.name if self.repeat == 1 else f"{self.name}-{repeat_index}"


@dataclass
class Sheet:
    """A parsed task sheet: the base configuration and the rows over it."""

    path: Path
    base_env: Path
    rows: list[Row]
    #: Ceiling on what the whole sheet may spend, in USD; -1 means none.
    #: Defaults to :data:`DEFAULT_SHEET_MAX_COST_USD` rather than to unlimited,
    #: because a sheet is the thing most likely to run unattended for hours.
    #: Checked *between* executions rather than inside one: a sheet's row is an
    #: experiment, and half an experiment is not a cheaper experiment, it is a
    #: wasted one.
    max_cost_usd: float = -1.0

    @property
    def name(self) -> str:
        return self.path.stem


def load_sheet(path: "str | Path", env_dir: "Path | None" = None) -> Sheet:
    """Parse and validate a sheet, raising before anything is executed.

    Everything knowable without touching a run directory is checked here: that
    every stage name exists, that a row's sequence does not contain a gap no
    step fills, and that a row which mints a run does not also name one to act
    on. Whether a *stored* run holds what a row needs cannot be known yet — an
    earlier row may still produce it — so that check belongs to the row's start.
    """
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SheetError(f"cannot read sheet {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SheetError(f"sheet {path} must be a mapping with a `rows:` list")

    defaults = raw.get("defaults") or {}
    base_env = Path(
        defaults.get("base_env")
        or ((env_dir or config.DEFAULT_ENV_DIR) / config.CONFIG_FILE)
    )
    if not base_env.is_absolute():
        base_env = (REPO_ROOT / base_env).resolve()
    if not base_env.is_file():
        raise SheetError(f"sheet {path}: base env file {base_env} does not exist")

    shared_env = {str(k): str(v) for k, v in (defaults.get("env") or {}).items()}
    shared_target = str(defaults.get("target") or "")
    sheet_cap = float(defaults.get("max_cost_usd", DEFAULT_SHEET_MAX_COST_USD))
    entries = raw.get("rows")
    if not isinstance(entries, list) or not entries:
        raise SheetError(f"sheet {path}: `rows:` must be a non-empty list")

    rows: list[Row] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise SheetError(f"sheet {path}: row {index} must be a mapping")
        name = str(entry.get("name") or f"row{index}")
        if name in seen:
            # Row names become artifact suffixes, so a duplicate would have one
            # row silently overwrite another's results.
            raise SheetError(f"sheet {path}: duplicate row name {name!r}")
        seen.add(name)
        names = entry.get("stages") or list(stage_table.FULL_CHAIN)
        if isinstance(names, str):
            names = names.split()
        try:
            stage_table.resolve(names)
        except stage_table.StageError as exc:
            raise SheetError(f"sheet {path}, row {name!r}: {exc}") from exc
        row = Row(
            name=name,
            stages=tuple(str(n).strip().lower() for n in names),
            run=str(entry.get("run") or run_paths.LATEST),
            target=str(entry.get("target") or shared_target or ""),
            correlation=str(entry.get("correlation") or ""),
            repeat=int(entry.get("repeat") or 1),
            env={**shared_env,
                 **{str(k): str(v) for k, v in (entry.get("env") or {}).items()}},
            timeout_minutes=int(
                entry.get("timeout_minutes") or DEFAULT_STAGE_TIMEOUT_MINUTES
            ),
        )
        if row.mints_run and entry.get("run"):
            raise SheetError(
                f"sheet {path}, row {name!r}: begins with `scan`, which mints its "
                "own run — remove `run:` rather than naming one it would ignore"
            )
        if row.mints_run and not row.target:
            raise SheetError(
                f"sheet {path}, row {name!r}: begins with `scan` and names no "
                "target. Add `target: <name>` to the row or to `defaults:`."
            )
        if row.repeat < 1:
            raise SheetError(f"sheet {path}, row {name!r}: repeat must be >= 1")
        if row.correlation and "triage" in row.stages:
            raise SheetError(
                f"sheet {path}, row {name!r}: names `correlation:` but also runs "
                "`correlate`, which writes its own. Remove one — a row that "
                "produces a correlation and reads a different one is two "
                "experiments wearing one name."
            )
        # The gap check that *is* knowable now: a sequence whose own steps
        # cannot supply each other, e.g. `scan` then `report`.
        if row.mints_run:
            problems = stage_table.unsatisfied(stage_table.plan(row.stages))
            if problems:
                raise SheetError(
                    f"sheet {path}, row {name!r} cannot complete: "
                    + "; ".join(problems)
                )
        rows.append(row)
    return Sheet(path=path, base_env=base_env, rows=rows,
                 max_cost_usd=sheet_cap)


# -- env overlays ----------------------------------------------------------


def _over(spent: float, cap: float) -> bool:
    """Whether a sheet has reached its ceiling.

    A negative cap is no cap, matching :data:`dast_orchestrator.foundation.config.NO_LIMIT`.

    ``spent > 0`` is load-bearing for the ``max_cost_usd: 0.0`` case, which is
    how a **scan-only sheet** says "this must not spend anything": with a plain
    ``spent >= cap`` a sheet that had spent nothing was refused before its first
    row on the grounds that it had reached a ceiling of zero. Nothing had been
    spent, so nothing had been reached — and the sheet that wants to say "free,
    and hold me to it" is exactly the one that could not run.
    """
    return cap is not None and cap >= 0 and spent > 0 and spent >= cap


def merge_env(base_env: Path, overlay: dict[str, str]) -> dict[str, str]:
    """The base configuration with this row's variables replaced.

    A **complete** file, not a delta, because ``--env-file`` names the one
    configuration file a stage reads — the default ``.env`` is then not loaded,
    so an overlay carrying only the differences would silently drop every
    inherited setting.

    **No credential is ever in it.** The overlay is archived into a run
    directory, and the rule that no key reaches a ``data/`` artifact is not
    relaxed for a file that happens to be configuration. The keys a row's stages
    need are handed to the subprocess through its environment instead
    (:func:`secret_env`), where they are visible to that process and to nothing
    on disk.
    """
    values = {
        k: v for k, v in config.parse_env_file(base_env).items()
        if k not in config.SECRET_VARS
    }
    values.update(overlay)
    return values


def secret_env(base_env: Path) -> dict[str, str]:
    """Credentials from the base configuration, for the subprocess only.

    The pair is the base env file and its ``secrets.env`` neighbour — the same
    pairing a stage's own :func:`config.load_stage_env` uses — because a stage
    the harness spawns is given ``--env-file <overlay>``, whose neighbour is the
    overlay's own directory (which has no ``secrets.env``, by design), *not*
    ``config/scanner/secrets.env``. So the stage cannot load the account
    credential for itself the way a bare ``dast triage`` does; the harness reads
    it here and hands it to the child through its environment, where it is
    visible to that process and to nothing on disk (:func:`build_env` keeps every
    :data:`config.SECRET_VARS` out of the archived overlay). ``SCAN_ZAP_API_KEY``
    conventionally lives in the base ``.env`` (a local daemon token) and
    ``SHARED_OPENROUTER_API_KEY`` in ``secrets.env`` (an account credential);
    reading both files here delivers whichever a row's stages need.

    A value already in the real environment wins, matching how every stage
    resolves configuration: an export on the command line outranks a file.
    """
    values: dict[str, str] = {}
    for path in config.config_and_secrets(base_env):
        values.update(config.parse_env_file(path))
    return {
        k: v for k, v in values.items()
        if k in config.SECRET_VARS and k not in os.environ
    }


def write_env_file(path: Path, values: dict[str, str], header: str) -> Path:
    """Write one row's merged configuration, with a header saying what it is."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {line}" for line in header.splitlines()]
    lines += [f"{k}={v}" for k, v in sorted(values.items())]
    path.write_text("\n".join(lines) + "\n")
    return path


# -- executing a row -------------------------------------------------------


@dataclass
class Execution:
    """What one execution of one row did — the harness's own record of it."""

    row: str
    repeat: int
    label: str
    stages: list[str]
    run_id: str | None = None
    failed_stage: str | None = None
    reason: str = ""
    seconds: float = 0.0
    env_file: str = ""

    @property
    def ok(self) -> bool:
        return self.failed_stage is None and not self.reason

    def as_dict(self) -> dict[str, Any]:
        return {
            "row": self.row, "repeat": self.repeat, "label": self.label,
            "stages": self.stages, "run": self.run_id,
            "failed_stage": self.failed_stage, "reason": self.reason,
            "seconds": round(self.seconds, 3), "env_file": self.env_file,
        }


def row_command(stages: "list[str]", env_file: Path, positional: str,
                label: str, data_dir: Path,
                in_suffix: "str | None" = None) -> list[str]:
    """The one ``dast`` invocation that runs a whole row's chain.

    The row is spawned as a single chain — ``python -m dast_orchestrator.cli
    <stages> <positional> ...`` — so its stdout *is* the run's own log (wrapper,
    Plan, per-stage headers, Run summary) and the harness adds only the sheet
    frame and the comparison around it. ``dast`` routes each shared flag to the
    stages that own it, so ``--out-suffix`` reaches triage/verify/report and
    never ``scan`` (which rejects a suffix), and ``--in-suffix`` reaches
    verify/report.

    Spawned as ``python -m`` rather than the console script, so it runs under
    whatever interpreter the sheet was started with — the one the results should
    be attributed to — without depending on entry points being on ``PATH``.

    :param positional: what the row acts on — the target for a minting row, the
        run id otherwise. ``dast`` threads the minted id to later stages itself.
    :param in_suffix: the *stored* triage variant a verify/report-only row reads,
        passed explicitly because it differs from the output suffix; ``None``
        when the row produces its own triage and the default is right.
    """
    argv = [sys.executable, "-m", "dast_orchestrator.cli", *stages, positional,
            "--env-file", str(env_file), "--data-dir", str(data_dir)]
    if label and any(stage_table.STAGES[s].suffix_flag for s in stages):
        argv += ["--out-suffix", label]
    if in_suffix is not None:
        argv += ["--in-suffix", in_suffix]
    return argv


def row_in_suffix(row: "Row") -> "str | None":
    """The stored triage variant this row's verify/report reads, or ``None``.

    ``None`` means "let the stage default it to the output suffix", right for a
    row that runs ``triage`` itself — there the same suffix names the triage it
    wrote and the verification about to be written. A verify/report-only row acts
    on a *stored* triage the output suffix says nothing about, so its
    ``correlation`` (empty for the base) is passed explicitly rather than left to
    a name that means something else.
    """
    reads_stored = (any(s in ("verify", "report") for s in row.stages)
                    and "triage" not in row.stages)
    return row.correlation if reads_stored else None


def _failed_stage(run_id: "str | None", stages: "list[str]") -> "str | None":
    """The stage a failed row broke at, when it can be named *reliably*.

    One subprocess per row gives the harness only the row's exit code; which
    stage ``dast`` stopped at is named in the run's own streamed log. The one
    case the harness can attribute without guessing is a minting row that created
    no run directory at all — its ``scan`` never produced. Anything else is left
    ``None`` (recorded as a plain row failure, the stage read off the row's log):
    inferring from which artifacts are present would misattribute an in-place
    re-run, which leaves the previous run's output on disk.
    """
    if run_id is None and stages and stage_table.STAGES[stages[0]].mints_run:
        return stages[0]
    return None


def previous_sheet_dirs(data_root: Path) -> list[Path]:
    """Every earlier sheet's directory, newest first.

    A run id is unique wherever it lives, so naming one explicitly should find
    it — including a corpus an *earlier* sheet produced. Without this, the
    obvious next step after a night of experiments ("re-triage that same corpus
    with the fix in") is impossible to express: the run is not in ``data/runs``
    and not in this sheet, so it cannot be named at all. Searched last and only
    for an explicitly named run, never for ``latest``: "the newest run anywhere"
    is not a thing a sheet should silently resolve to.
    """
    harness_root = Path(data_root) / run_paths.HARNESS_DIR_NAME
    if not harness_root.is_dir():
        return []
    return sorted((p for p in harness_root.iterdir() if p.is_dir()), reverse=True)


def _resolve_run(row: Row, first: stage_table.Stage, sheet_dir: Path,
                 manual_dir: Path,
                 named_only: "tuple[Path, ...]" = ()) -> "run_paths.RunLayout | None":
    """The stored run a non-scanning row acts on, resolved at the row's start.

    Searched in order — **this sheet's own directory first, then the manual
    runs** — because both are legitimate and they mean different things. A
    model-comparison sheet scans in row 1 and re-triages it in rows 2+, so
    ``latest`` must find the sheet's own run; a prompt-A/B sheet re-triages a
    corpus somebody scanned last week, so ``latest`` must reach ``data/runs``.

    ``named_only`` — earlier sheets' directories — is searched last and **only
    for a run the row names explicitly**. A run id is unique wherever it lives,
    so naming last night's corpus should find it; but "the newest run anywhere"
    is not something a sheet should silently resolve to, and letting ``latest``
    wander into another sheet's output would make a row's subject depend on what
    else happens to be on disk.

    The layout that comes back carries the directory it was found in, and that
    is what the stage is pointed at: a re-triage belongs beside the scan it
    triaged, not beside the sheet that ordered it.
    """
    if run_paths.is_latest(row.run):
        for base in (sheet_dir, manual_dir):
            found = run_paths.RunLayout.latest_with(base, *first.requires)
            if found is not None:
                return found
        return None

    for base in (sheet_dir, manual_dir, *named_only):
        try:
            found = run_paths.RunLayout.resolve(base, row.run)
        except ValueError as exc:
            raise SheetError(str(exc)) from exc
        if found.dir.is_dir():
            return found
    return None


def run_row(row: Row, repeat_index: int, sheet: Sheet, sheet_dir: Path,
            manual_dir: Path, dry_run: bool = False,
            extra_search: "tuple[Path, ...]" = ()) -> Execution:
    """Execute one row once: resolve its run, write its env, run its stages.

    :param sheet_dir: this sheet's directory. A row that *mints* a run creates
        it here, so the sheet's runs are nested under the sheet.
    :param manual_dir: ``data/runs``, searched second when a row names a stored
        run — see :func:`_resolve_run`.
    :param extra_search: earlier sheets' directories, searched last, so a row
        can name a corpus a previous night produced.

    Every stage subprocess is given this sheet execution's id and this row's
    name in its environment, so each metrics record it writes states its harness
    membership. ``sheet_dir.name`` *is* that id — ``<timestamp>-<sheet>`` — so
    there is no second identifier to keep in step with the directory.
    """
    label = row.label(repeat_index)
    suffix = f"-{repeat_index}" if row.repeat > 1 else ""
    env_path = sheet_dir / f"{row.name}{suffix}.env"
    execution = Execution(
        row=row.name, repeat=repeat_index, label=label, stages=list(row.stages),
        env_file=str(env_path),
    )
    write_env_file(
        env_path, merge_env(sheet.base_env, row.env),
        f"harness row {row.name!r} (execution {repeat_index} of {row.repeat})\n"
        f"sheet: {sheet.path}\nbase:  {sheet.base_env}\n"
        f"stages: {' '.join(row.stages)}\n"
        "This file is the complete configuration the run below was made with.",
    )

    first = stage_table.STAGES[row.stages[0]]
    layout = (None if first.mints_run
              else _resolve_run(row, first, sheet_dir, manual_dir, extra_search))
    # Where this row's stages write: its own new run goes under the sheet, and a
    # row acting on a stored run writes beside that run wherever it lives.
    data_dir = sheet_dir if first.mints_run else (layout.data_dir if layout else sheet_dir)
    positional = row.target if first.mints_run else ""
    if not first.mints_run and layout is None:
        execution.reason = (
            f"no stored run holds {', '.join(first.requires)} for `{first.name}`"
        )
        return execution
    run_id = layout.run_id if layout else None
    positional = positional or (run_id or "")

    steps = stage_table.plan(row.stages, layout.dir if layout else None)
    problems = stage_table.unsatisfied(steps)
    # The row's own `dast` output carries the Plan and per-stage headers, so the
    # harness prints only what the run cannot know: which stored run this row
    # acts on and which overlay configured it. The `dast` chain is refused before
    # spending too, but a satisfiability check here skips a doomed row without
    # even spawning it.
    ui.item("started", ui.now())
    ui.item("acts on", run_id or "a new run this row will mint")
    if label:
        ui.item("artifact suffix", label)
    ui.item("configuration", ui.short_path(env_path))
    if problems:
        execution.reason = "; ".join(problems)
        ui.warn(f"row {row.name} skipped: {execution.reason}")
        return execution

    argv = row_command(row.stages, env_path, positional, label, data_dir,
                       row_in_suffix(row))
    if dry_run:
        ui.step(ui.short_command(argv))
        return execution

    # ONE subprocess per row: `dast` runs the whole chain, threads the run id it
    # mints from stage to stage, and its stdout *is* the run's own log. The
    # harness learns the minted id by diffing run directories across the row, and
    # attributes a failure to a stage by which artifacts landed (`_failed_stage`).
    started = time.monotonic()
    before = set(run_paths.RunLayout.runs(data_dir))
    ui.step(ui.short_command(argv))
    try:
        completed = subprocess.run(
            argv, cwd=REPO_ROOT, timeout=row.timeout_minutes * 60,
            env={**os.environ, **secret_env(sheet.base_env),
                 # So every metrics record the stages write names the sheet
                 # execution it belongs to. Without it the only trace of harness
                 # membership was which directory the index landed in, which a
                 # row joined at writing time cannot recover.
                 run_metrics.HARNESS_ID_VAR: sheet_dir.name,
                 run_metrics.HARNESS_ROW_VAR: row.name},
        )
        code = completed.returncode
    except subprocess.TimeoutExpired:
        code = None
    execution.seconds = time.monotonic() - started

    if first.mints_run:
        run_id = stage_table.new_run_id(data_dir, before) or run_id
    execution.run_id = run_id

    if code != 0:
        execution.failed_stage = _failed_stage(run_id, row.stages)
        execution.reason = (
            f"timed out after {row.timeout_minutes} min" if code is None
            else f"exited {code}"
        )
        where = (f"`{execution.failed_stage}`" if execution.failed_stage
                 else "the row")
        ui.warn(f"row {row.name}: {where} {execution.reason}")

    # Close every execution the same way, whatever happened to it: a night's log
    # is scrolled for "how long did N take" and "which one broke", and both
    # answers should be on the last line of the execution rather than inferred
    # from the next divider's timestamp.
    mark = "✓" if execution.ok else "✗"
    ui.step(f"{mark} {execution.label or execution.row} finished in "
            f"{_duration(execution.seconds)} at {ui.now()}"
            + ("" if execution.ok else f" — {execution.reason}"))

    # Archived last, into the directory the run actually landed in, so the
    # configuration travels with the artifacts rather than only with the sheet.
    if execution.run_id:
        target_dir = run_paths.RunLayout(data_dir, execution.run_id).dir
        if target_dir.is_dir():
            shutil.copyfile(env_path, target_dir / f"harness-{env_path.name}")
    return execution


def _duration(seconds: float) -> str:
    """``42s`` / ``9.1m`` / ``3.7h`` — one unit, matching the rest of the output."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


# -- the comparison table --------------------------------------------------

#: Which numbers make two runs of one kind comparable — the same per-kind
#: definition ``dast``'s cross-stage summary uses, so the two tables can never
#: disagree about what a triage's headline numbers are.
TABLE_COLUMNS = run_metrics.TABLE_COLUMNS


def _row_identity(row: dict[str, Any]) -> tuple:
    """What makes one index row distinct from another."""
    return (str(row.get("run")), str(row.get("kind")),
            str(row.get("label") or ""), str(row.get("started_at")))


def index_delta(before: list[dict[str, Any]],
                after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The index rows this sheet added.

    A diff rather than a timestamp filter: the indexes are append-only, so what a
    sheet produced is exactly what was not there when it started. A filter on
    ``started_at`` would also sweep up a run someone began in another terminal
    while the sheet was going.

    Compared by identity rather than by position. A sheet reads *two* indexes —
    its own and the manual one, since a row may re-triage a manual run — and
    once two lists are concatenated, "everything after the old length" is no
    longer the same thing as "what is new".
    """
    seen = {_row_identity(row) for row in before}
    return [row for row in after if _row_identity(row) not in seen]


def comparison_table(executions: list[Execution],
                     rows: list[dict[str, Any]]) -> str:
    """One table joining every row of the sheet to what its stages recorded."""
    by_run: dict[tuple[str, str, str], dict[str, Any]] = {
        (str(r.get("run")), str(r.get("kind")), str(r.get("label") or "")): r
        for r in rows
    }
    out: list[str] = []
    for kind, columns in TABLE_COLUMNS.items():
        matching = [
            (ex, by_run[(str(ex.run_id), kind, ex.label)])
            for ex in executions
            if (str(ex.run_id), kind, ex.label) in by_run
        ]
        if not matching:
            continue
        header = (f"{'row':22s} {'run':34s} {'cfg':8s} {'time':>8s} "
                  f"{'cost':>9s} " + " ".join(f"{c[:13]:>13s}" for c in columns))
        out += [f"\n{kind}", "-" * len(header), header, "-" * len(header)]
        for ex, row in matching:
            cost = row.get("cost_usd")
            out.append(
                f"{(ex.label or ex.row)[:22]:22s} {str(ex.run_id)[:34]:34s} "
                f"{str(row.get('config_digest') or '-'):8s} "
                f"{float(row.get('total_seconds') or 0) / 60:7.1f}m "
                f"{('$%.4f' % cost) if cost is not None else '-':>9s} "
                + " ".join(f"{str(row.get(c, '-'))[:13]:>13s}" for c in columns)
            )
    failed = [ex for ex in executions if not ex.ok]
    if failed:
        out.append("\nrows that did not complete")
        out.append("-" * 40)
        for ex in failed:
            where = f"at `{ex.failed_stage}`" if ex.failed_stage else "before starting"
            out.append(f"{ex.label or ex.row:22s} {where}: {ex.reason}")
    if not out:
        return "no rows produced a metrics record."
    return "\n".join(out)


def variance(executions: list[Execution], rows: list[dict[str, Any]],
             kind: str = "triage") -> dict[str, dict[str, Any]]:
    """Spread of each repeated row's headline counters, keyed by row name.

    Only rows executed more than once, because a spread over one sample is not a
    spread. This is the instrument for the question the project cannot answer
    today: two identical triages of one scan gave ``both`` 11 and 16, and a
    single run's agreement counts are therefore a sample, not a measurement.
    """
    by_key = {
        (str(r.get("run")), str(r.get("kind")), str(r.get("label") or "")): r
        for r in rows
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    for ex in executions:
        row = by_key.get((str(ex.run_id), kind, ex.label))
        if row is not None:
            grouped.setdefault(ex.row, []).append(row)

    out: dict[str, dict[str, Any]] = {}
    for name, records in grouped.items():
        if len(records) < 2:
            continue
        spread: dict[str, Any] = {"executions": len(records)}
        for column in TABLE_COLUMNS.get(kind, ()):
            values = [r.get(column) for r in records]
            numbers = [float(v) for v in values if isinstance(v, (int, float))]
            if len(numbers) == len(records) and numbers:
                spread[column] = {
                    "min": min(numbers), "max": max(numbers),
                    "mean": round(sum(numbers) / len(numbers), 3),
                }
        out[name] = spread
    return out


def sheet_report(sheet: Sheet, executions: list[Execution],
                 rows: list[dict[str, Any]], spread: dict[str, Any],
                 table: str, started: str, elapsed: float = 0.0,
                 started_at: str = "", dry_run: bool = False) -> str:
    """The sheet's own human-readable report, in the shape the others use.

    Overview first, then a section per topic, then the metrics — the same order
    as ``report.md`` and ``static-analysis.md``, because a reader moving between the
    three should not have to learn three documents. What it adds over
    ``results.json`` is the part a person actually needs: which rows completed,
    what differed between them, and **how wide the spread is**, since a
    difference smaller than the spread is not a difference.
    """
    ok = [e for e in executions if e.ok]
    failed = [e for e in executions if not e.ok]
    cost = sum(float(r.get("cost_usd") or 0) for r in rows)
    # The sheet's own wall clock, not the sum of its stages': the difference is
    # container start-up, ZAP polling and the gaps between rows, and a reader
    # planning the next night needs the number that includes them.
    stage_seconds = sum(float(r.get("total_seconds") or 0) for r in rows)
    runs = sorted({str(e.run_id) for e in ok if e.run_id})

    lines = [
        f"# Harness — {sheet.name}",
        "",
        "One sheet, executed unattended. Every row below is one configuration; "
        "rows acting on the same run differ only in what the sheet changed, "
        "which is what makes them comparable at all.",
        "",
        "## Overview",
        "",
        "| | |",
        "|---|---|",
        f"| sheet | `{sheet.path.name}` |",
        f"| started | {started}{f' ({started_at})' if started_at else ''} |",
        f"| base configuration | `{sheet.base_env.name}` |",
        f"| rows | {len(sheet.rows)} ({len(executions)} executions) |",
        f"| completed | {len(ok)} of {len(executions)} |",
        f"| runs touched | {len(runs)} |",
        f"| wall time | {_duration(elapsed)}"
        + (f" (stages {_duration(stage_seconds)}) |" if stage_seconds else " |"),
        f"| model spend | ${cost:.4f} |",
    ]
    if dry_run:
        lines += ["", "> **Dry run — nothing was executed.** The rows below are "
                  "what *would* run; no artifact was produced and no number here "
                  "describes a scan."]
    elif failed:
        lines += ["", f"> **{len(failed)} of {len(executions)} executions did not "
                  "complete.** Rows are independent experiments, so the sheet "
                  "carried on; the numbers below cover only what ran. See "
                  "*Rows that did not complete*."]
    else:
        lines += ["", "> **Every row completed.** The comparison below is over a "
                  "full set."]

    sections: list[tuple[str, list[str]]] = [
        ("What each row produced", ["```", table, "```"] if table.strip() else []),
        ("Spread across repeated rows", _spread_section(spread)),
        ("Rows that did not complete", _failure_section(failed)),
        ("Where the artifacts are", [
            f"- Runs this sheet created are nested in this directory: "
            f"{', '.join(f'`{r}`' for r in runs) or '_none_'}.",
            "- Each row's complete configuration is archived beside them as "
            "`<row>.env`, and inside the run directory as `harness-<row>.env`.",
            "- `results.json` carries every execution, every metrics row and the "
            "spread, for anything this document does not answer.",
        ]),
    ]
    lines += _numbered_sections(sections)
    return "\n".join(lines) + "\n"


def _spread_section(spread: dict[str, Any]) -> list[str]:
    """Min/max/mean per repeated row — the yardstick every other row is read by.

    Reported as a table rather than as raw JSON because it is the number a
    reader has to *compare against*, not one to look up: run-to-run variance at
    temperature 0 is real, and a difference smaller than this spread is not a
    difference.
    """
    if not spread:
        return []
    lines = ["| row | metric | min | max | mean | spread |",
             "|---|---|---|---|---|---|"]
    for name, metrics in sorted(spread.items()):
        for metric, values in sorted(metrics.items()):
            if not isinstance(values, dict):
                continue
            width = values["max"] - values["min"]
            lines.append(
                f"| `{name}` | {metric} | {values['min']:g} | {values['max']:g} "
                f"| {values['mean']:g} | {width:g} |"
            )
    lines += ["", "*A difference between two configurations smaller than the "
              "spread of one configuration repeated is not a difference.*"]
    return lines


def _failure_section(failed: list[Execution]) -> list[str]:
    if not failed:
        return []
    lines = ["| row | failed at | why |", "|---|---|---|"]
    for execution in failed:
        where = f"`{execution.failed_stage}`" if execution.failed_stage else "before starting"
        lines.append(f"| `{execution.label or execution.row}` | {where} "
                     f"| {execution.reason} |")
    return lines


def _numbered_sections(sections: list[tuple[str, list[str]]]) -> list[str]:
    """Only the sections with something in them, numbered in order.

    Same rule as the DAST report: a topic with nothing to say has no heading,
    so a shorter sheet reads as a shorter document rather than one with holes.
    """
    lines: list[str] = []
    number = 0
    for title, body in sections:
        if not [line for line in body if line.strip()]:
            continue
        number += 1
        lines += ["", f"## {number}. {title}", ""] + body
    return lines


# -- entry point -----------------------------------------------------------


def run_sheet(sheet: Sheet, data_root: Path, dry_run: bool = False,
              smoke: bool = False) -> dict[str, Any]:
    """Execute every row of a sheet and write the sheet's own artifacts.

    :param data_root: the data *root*. The sheet makes its own directory under
        ``data/harness/`` and every run it mints is nested there, so last night's
        experiments are one folder rather than a set of ids to reassemble.
    :param smoke: this is the bundled plumbing check, not a real experiment — so
        it lands in the ephemeral ``data/scratch/`` namespace (like a dry run),
        never among the real corpora.
    """
    started = run_paths.now_timestamp()
    started_at = ui.now()
    started_clock = time.monotonic()
    # Dry runs (plan only) and smoke checks (throwaway) never belong among the
    # real corpora: they go to data/scratch/, to be cleaned on a clean finish.
    ephemeral = dry_run or smoke
    dir_for = run_paths.scratch_runs_dir if ephemeral else run_paths.harness_runs_dir
    sheet_dir = dir_for(f"{started}-{sheet.name}", data_root)
    sheet_dir.mkdir(parents=True, exist_ok=True)
    manual_dir = run_paths.default_runs_dir(data_root)
    # Searched last, and only for a run a row names explicitly.
    earlier_sheets = tuple(d for d in previous_sheet_dirs(data_root)
                           if d != sheet_dir)

    total = sum(r.repeat for r in sheet.rows)
    ui.session(
        f"Harness run — {sheet.name}",
        f"{total} execution(s) across {len(sheet.rows)} row(s)"
        + ("  ·  DRY RUN, nothing will be executed" if dry_run else "  ·  unattended"),
        {
            "sheet": ui.short_path(sheet.path),
            "base configuration": ui.short_path(sheet.base_env),
            "output": ui.short_path(sheet_dir),
        },
    )

    # **Every index a row could write to**, not just this sheet's. A row writes
    # beside the run it acts on, and that run may live in this sheet, in
    # data/runs, or in an *earlier* sheet — the last case is the whole point of
    # naming a previous night's corpus. Reading only the first two produced a
    # report that said "no rows produced a metrics record" for a sheet whose
    # nine executions had all succeeded, with `model spend $0.0000` beside it.
    index_dirs = [sheet_dir, manual_dir, *earlier_sheets]

    def index_rows() -> list[dict[str, Any]]:
        return [row for directory in index_dirs
                for row in run_metrics.read_index(directory)]

    before = index_rows()
    executions: list[Execution] = []
    done = 0
    stopped = False
    stop_reason = ""
    for row in sheet.rows:
        for index in range(1, row.repeat + 1):
            done += 1
            # Checked between executions, never inside one. A row is an
            # experiment; stopping half way through leaves an artifact that
            # looks complete and is not, which is worse than one row fewer.
            spent = sum(float(r.get("cost_usd") or 0)
                        for r in index_delta(before, index_rows()))
            if not stopped and _over(spent, sheet.max_cost_usd):
                stopped = True
                stop_reason = f"sheet cost ceiling (${sheet.max_cost_usd:.4f})"
                ui.warn(
                    f"sheet cost ceiling reached: ${spent:.4f} of "
                    f"${sheet.max_cost_usd:.4f}. The remaining "
                    f"{sum(r.repeat for r in sheet.rows) - done + 1} "
                    "execution(s) are recorded as not run."
                )
            # There is deliberately no *loop*-level ceiling here. A budget
            # across a SERIES of sheets is a development concern — how much an
            # optimisation cycle with the agent costs — not a property of the
            # tool, so it does not live in the tool. The sheet's own
            # ``max_cost_usd`` above is the only ceiling the harness enforces;
            # tallying a whole loop's spend is `scripts/loop-cost.py`, run by
            # hand between sheets.
            if stopped:
                executions.append(Execution(
                    row=row.name, repeat=index, label=row.label(index),
                    stages=list(row.stages),
                    reason=f"not run — {stop_reason} reached",
                ))
                continue
            # One divider per *execution*, not per row: a repeated row is three
            # separate runs, and a log that grouped them under one header would
            # hide exactly the boundary a reader scrolls for.
            ui.session_divider(
                f"{done}/{total}  {row.label(index) or row.name}"
                f"  ·  {' → '.join(row.stages)}"
            )
            try:
                executions.append(
                    run_row(row, index, sheet, sheet_dir, manual_dir, dry_run,
                            extra_search=earlier_sheets)
                )
            except SheetError as exc:
                # One row's misconfiguration is not the sheet's: record it and
                # carry on, so a night of rows is not lost to a typo in one.
                executions.append(Execution(
                    row=row.name, repeat=index, label=row.label(index),
                    stages=list(row.stages), reason=str(exc),
                ))
                ui.warn(f"row {row.name}: {exc}")

    after = index_rows()
    new_rows = index_delta(before, after)
    table = comparison_table(executions, new_rows)
    spread = variance(executions, new_rows)

    report = sheet_report(sheet, executions, new_rows, spread, table, started,
                          elapsed=time.monotonic() - started_clock,
                          started_at=started_at, dry_run=dry_run)
    results = {
        "sheet": str(sheet.path),
        "started_at": started,
        "base_env": str(sheet.base_env),
        "dry_run": dry_run,
        "executions": [e.as_dict() for e in executions],
        "metrics_rows": new_rows,
        "variance": spread,
        # For the caller's scratch cleanup (kept out of the schema — internal).
        "sheet_dir": str(sheet_dir),
        "ephemeral": ephemeral,
        "smoke": smoke,
    }
    (sheet_dir / "results.json").write_text(json.dumps(results, indent=2))
    (sheet_dir / "comparison.md").write_text(report)

    summary = ui.open_phase("Comparison")
    print(table)
    summary.close(files=["results.json", "comparison.md"])

    # One line per execution, in order, before the closing banner. The
    # comparison table above is organised by *stage kind*, which is the right
    # shape for reading results and the wrong one for answering "what did this
    # night actually do, and which part of it took the time".
    roll_up = ui.open_phase("Executions planned" if dry_run else "Executions")
    for number, execution in enumerate(executions, start=1):
        # A dry run executed nothing, so it gets neither a tick nor a duration:
        # "12 of 12 completed" against an empty data directory is exactly the
        # kind of line that is believed months later.
        mark = "·" if dry_run else ("✓" if execution.ok else "✗")
        ui.step(f"{mark} {number:>2}/{len(executions)}  "
                f"{(execution.label or execution.row):<22} "
                f"{' → '.join(execution.stages):<44} "
                f"{'' if dry_run else _duration(execution.seconds):>7}"
                + ("" if execution.ok else f"   {execution.reason}"))
    roll_up.close()

    elapsed = time.monotonic() - started_clock
    failed = [e for e in executions if not e.ok]
    ui.session_end(
        (f"Harness dry run — {sheet.name}" if dry_run
         else f"Harness run complete — {sheet.name}"),
        {
            "executions": (
                f"{len(executions)} planned, none executed" if dry_run else
                f"{len(executions) - len(failed)} of {len(executions)} completed"
                + (f", {len(failed)} did not" if failed else "")
            ),
            "elapsed": f"{_duration(elapsed)}  ({started_at} → {ui.now()})",
            "model spend": f"${sum(float(r.get('cost_usd') or 0) for r in new_rows):.4f}",
            "runs touched": len({str(e.run_id) for e in executions if e.run_id}),
            "report": ui.short_path(sheet_dir / "comparison.md"),
        },
    )
    return results


#: The bundled sheet ``--smoke`` runs: the whole chain at tiny budgets with the
#: control arm only. Free, no key, ~4 minutes.
SMOKE_SHEET = SHEETS_DIR / "smoke.yml"

#: Numbered sheets are the optimisation series; ``smoke.yml`` is not one of them.
SHEET_SERIES_RE = re.compile(r"^(\d+)-.+\.yml$")


def default_sheet(sheets_dir: Path = SHEETS_DIR) -> Path:
    """The highest-numbered sheet in ``sheets_dir`` — the current experiment.

    A hard-coded default name goes stale the moment the series moves on, and it
    goes stale *silently*: ``dast harness`` would keep re-running the question
    that was answered two sheets ago. Selecting the highest number instead means
    the default is whatever the investigation has reached, maintained by the act
    of adding the next sheet rather than by remembering to edit a constant.

    :raises SheetError: if the series is empty, since there is then nothing a
        bare ``dast harness`` could sensibly mean.
    """
    numbered = [
        (int(m.group(1)), path)
        for path in sorted(sheets_dir.glob("*.yml"))
        if (m := SHEET_SERIES_RE.match(path.name))
    ]
    if not numbered:
        raise SheetError(
            f"no numbered sheet in {ui.short_path(sheets_dir)} — name one to "
            "run, or add NN-<question>.yml (see that directory's README)."
        )
    return max(numbered)[1]


def _cleanup_scratch(results: dict[str, Any], ok: bool, clean: bool) -> None:
    """Remove (or keep) an ephemeral sheet's scratch dir after it finishes.

    Dry-run: removed when the run was clean (no failed row, no warning) — it was
    only ever a plan preview. Smoke: removed only if a person, at an interactive
    terminal, says yes; an unattended/harness invocation keeps it (nobody to ask,
    and blocking on a prompt is exactly what must not happen). Anything not clean
    is always kept, for inspection. Never touches anything outside data/scratch/.
    """
    if not results.get("ephemeral"):
        return
    sheet_dir = Path(results["sheet_dir"])
    if run_paths.SCRATCH_DIR_NAME not in sheet_dir.parts:   # safety belt
        return
    shown = ui.short_path(sheet_dir)
    if not (ok and clean):
        ui.step(f"scratch kept for inspection (not clean): {shown}")
        return
    if results.get("dry_run"):
        shutil.rmtree(sheet_dir, ignore_errors=True)
        ui.step(f"dry-run scratch removed: {shown}")
        return
    if results.get("smoke") and sys.stdin.isatty():
        try:
            answer = input(f"  Smoke run clean. Delete {shown}? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer in ("y", "yes"):
            shutil.rmtree(sheet_dir, ignore_errors=True)
            ui.step(f"smoke scratch removed: {shown}")
            return
    ui.step(f"scratch kept: {shown}")


def build_parser() -> argparse.ArgumentParser:
    """The ``dast harness`` parser, built without parsing — so ``dast commands``
    can read its flags from the one definition ``main`` also uses."""
    parser = argparse.ArgumentParser(
        prog="dast harness", description=config.command_description(__doc__))
    parser.add_argument(
        "sheet", nargs="?", metavar="<sheet>",
        help="Task sheet (YAML) to execute. Default: the highest-numbered sheet "
             "in config/harness/ — the current experiment in the series.",
    )
    parser.add_argument(
        "--smoke", action="store_true",
        help=f"Run the bundled {SMOKE_SHEET.name} instead: the whole chain at "
             "tiny budgets with the control arm only. Free, no key, ~4 minutes "
             "— the thing to run before committing a night to a real sheet.",
    )
    parser.add_argument(
        "--max-cost", type=float, default=None,
        help="Ceiling on what the whole SHEET may spend, in USD (-1 = none, "
             "the default). Overrides `defaults.max_cost_usd` in the sheet. "
             "Checked between executions: a row is an experiment, and half an "
             "experiment is a wasted one rather than a cheaper one.",
    )
    parser.add_argument("--data-dir", type=Path, default=run_paths.DATA_ROOT,
                        help="The data *root*; the sheet makes its own directory "
                             "under data/harness/ and nests its runs there.")
    parser.add_argument(
        "--env-dir", type=Path, default=config.DEFAULT_ENV_DIR,
        help="Where the base configuration lives when the sheet names none.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Write every row's env overlay and print the commands, run "
             "nothing. Costs no money and no time; the form to check a sheet "
             "with before committing a night to it.",
    )
    config.normalize_metavars(parser)
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    if args.smoke and args.sheet:
        print("ERROR: --smoke runs the bundled smoke sheet; do not also name one.",
              file=sys.stderr)
        return 2
    try:
        chosen = (SMOKE_SHEET if args.smoke
                  else Path(args.sheet) if args.sheet
                  else default_sheet())
        sheet = load_sheet(chosen, args.env_dir)
    except SheetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.max_cost is not None:
        sheet.max_cost_usd = args.max_cost
    warnings_before = ui.warning_count()
    results = run_sheet(sheet, args.data_dir, args.dry_run, smoke=args.smoke)
    ok = all(e["failed_stage"] is None and not e["reason"]
             for e in results["executions"])
    _cleanup_scratch(results, ok, clean=ui.warning_count() == warnings_before)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
