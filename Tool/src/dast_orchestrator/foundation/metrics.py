"""Central run metrics: every stage measured the same way, one
``data/<run>/<kind>-metrics.json`` per stage; the cross-run table (``dast costs``)
is derived on read, with no stored index.

The thesis answers "what does a DAST-plus-LLM stage cost in CI" with numbers across
components that otherwise report nothing comparable. Rules: measured never estimated (the
unmeasurable is ``null``, so a missing measurement and a measured zero never look alike),
every metric names its run, provenance (image tags, versions, host) travels with the
numbers, and secrets never appear. → DECISIONS.md.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

METRICS_SCHEMA_VERSION = 1

#: Set by the harness on every stage subprocess it spawns, so each record it
#: produces names the sheet execution it belongs to. Environment rather than
#: flags: these are facts about *where the process is running*, not settings a
#: person would choose, which is the same reason ``CI`` has no flag.
HARNESS_ID_VAR = "HARNESS_ID"
HARNESS_ROW_VAR = "HARNESS_ROW"


@dataclass
class StageTiming:
    """Wall time and free-form counters for one pipeline stage.

    :param name: stage identifier, e.g. ``"noir"``, ``"spider"``, ``"active_scan"``.
    :param seconds: measured duration; ``None`` while the stage is still running.
    :param counters: stage-specific numbers (URLs seeded, alerts found, ...)
        kept next to the duration so throughput is derivable without a join.
    """

    name: str
    seconds: float | None = None
    counters: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"seconds": self.seconds, **self.counters}


class RunMetrics:
    """Collects metrics for one run and writes them as a single artifact.

    Usage mirrors how the pipeline is structured — one context manager per
    stage, so a stage that raises still records the time it burned before
    failing:

    .. code-block:: python

        metrics = RunMetrics(timestamp)
        with metrics.stage("noir") as stage:
            ...
            stage.counters["endpoints"] = 354
        metrics.write(data_dir)
    """

    def __init__(self, run_id: str, kind: str = "scan", label: str = "") -> None:
        """
        :param run_id: the run's ``<timestamp>-<target>`` id — the directory
            every artifact of the run shares, so metrics join back to results.
        :param kind: which command produced the record — ``"scan"``,
            ``"triage"``, ``"verify"``, or ``"analysis"`` for the standalone
            SAST/SCA static-analysis findings. Each command records separately, since they
            execute independently against the same run directory.
        :param label: distinguishes repeated runs of the same kind against one
            scan, mirroring the result artifact's suffix. Without it a
            model-comparison run overwrites the baseline's metrics file while
            its result artifact survives — a silent, partial loss.
        """
        self.run_id = run_id
        self.kind = kind
        self.label = label
        # Which harness sheet this execution belongs to, or "" for a run a
        # person started. Read from the environment rather than passed as an
        # argument because every stage is a separate subprocess the harness
        # spawns, and threading a parameter through five `main(argv)` signatures
        # to record one fact would be five chances to forget it.
        self.harness_id = os.getenv(HARNESS_ID_VAR, "")
        self.harness_row = os.getenv(HARNESS_ROW_VAR, "")
        self.started_at = datetime.now(timezone.utc)
        self._start = time.monotonic()
        self.stages: dict[str, StageTiming] = {}
        self.tools: dict[str, Any] = {}
        self.results: dict[str, Any] = {}
        self.config: dict[str, Any] = {}
        #: How the stage ended. ``None`` while it is running and on a clean
        #: finish; a ``{"type", "reason"}`` object once :meth:`record_abort` has
        #: classified an exception. Persisted so a crashed stage still leaves a
        #: record — see :meth:`guard`.
        self.abort: "dict[str, str] | None" = None

    @contextmanager
    def stage(self, name: str) -> Iterator[StageTiming]:
        """Time a stage, recording the duration even if the body raises."""
        timing = StageTiming(name)
        self.stages[name] = timing
        started = time.monotonic()
        try:
            yield timing
        finally:
            timing.seconds = round(time.monotonic() - started, 3)

    def record_tool(self, name: str, **facts: Any) -> None:
        """Attach provenance for one tool (image tag, version, model id)."""
        self.tools[name] = {k: v for k, v in facts.items() if v is not None}

    def record_config(self, config: dict[str, Any]) -> None:
        """Attach the *effective* configuration this stage ran with.

        Every value the stage resolved after flags, env files and defaults have
        been reconciled — not what any one of those said. Two things depend on
        it. A run id's configuration digest
        (:func:`dast_orchestrator.foundation.run_paths.config_digest`) is computed from
        this same mapping, so the short name in the directory can always be
        expanded into the settings behind it; and the harness's comparison table
        reads it to say what actually differed between two rows, rather than
        trusting that the sheet and the run agree.

        Never pass a credential: :data:`dast_orchestrator.foundation.config.SECRET_VARS`
        are excluded by the callers, and this record is written to disk.
        """
        self.config.update(config)

    def record_results(self, **facts: Any) -> None:
        """Attach the headline outcome numbers this run produced."""
        self.results.update(facts)

    #: LlmError.kind values that name a *controlled* stop rather than a crash, so
    #: an abort persisted for one reads as the deliberate stop it was — not an
    #: "error" the reader has to open the record to understand.
    _ABORT_KINDS = {"budget": "budget-ceiling"}

    def record_abort(self, exc: BaseException) -> None:
        """Classify a stage-ending exception into :attr:`abort`.

        A cancellation (Ctrl-C, a cancelled task) is its own type; an
        :class:`~dast_orchestrator.analysis.screening.LlmError` whose ``kind`` names a
        controlled stop (a cost ceiling) is recorded as that stop; anything else
        is a plain ``error``. The reason keeps the exception's type and message,
        because "Server disconnected" alone does not say whether the model
        refused, the schema failed or the transport dropped.
        """
        import asyncio

        if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError)):
            kind = "cancelled"
        else:
            kind = self._ABORT_KINDS.get(getattr(exc, "kind", ""), "error")
        self.abort = {"type": kind, "reason": f"{type(exc).__name__}: {exc}"}

    @contextmanager
    def guard(self, data_dir: "Path") -> "Iterator[RunMetrics]":
        """Guarantee this record is written once — on a clean finish OR a crash.

        The whole point of a metrics file is to say what a stage cost; a stage
        that dies mid-run costs the most and, before this, wrote nothing at all.
        So the record is always written: on the way out of the ``with`` block on
        success, and — after :meth:`record_abort` fills :attr:`abort` — on the way
        out by exception, which is then re-raised so the failure still surfaces.
        """
        try:
            yield self
        except BaseException as exc:
            if self.abort is None:
                self.record_abort(exc)
            raise
        finally:
            self.write(data_dir)

    @property
    def filename(self) -> str:
        """The basename this record writes to, without writing it — so a summary
        can name the file the :meth:`guard` will produce."""
        from dast_orchestrator.foundation import run_paths

        return run_paths.metrics_basename(self.kind, self.label)

    @property
    def total_seconds(self) -> float:
        return round(time.monotonic() - self._start, 3)

    def as_dict(self) -> dict[str, Any]:
        stages = {name: t.as_dict() for name, t in self.stages.items()}
        return {
            "schema_version": METRICS_SCHEMA_VERSION,
            "run": self.run_id,
            "kind": self.kind,
            "label": self.label,
            "harness_id": self.harness_id,
            "harness_row": self.harness_row,
            "started_at": self.started_at.isoformat(),
            "total_seconds": self.total_seconds,
            "host": host_facts(),
            "config": self.config,
            "tools": self.tools,
            "stages": stages,
            "results": self.results,
            # Always present: null on a clean finish, a {type, reason} object once
            # a stage aborts. So a reader never has to tell "no abort" apart from
            # "this record predates abort tracking" by its absence.
            "abort": self.abort,
            # The ceilings and degradations this stage hit, normalised from the
            # signals above so neither a reader nor the report has to know each
            # stage's idiom. Always present; `[]` when the stage ran to
            # completion. See :func:`derive_limits`.
            "limits": derive_limits(self.kind, stages, self.results, self.abort),
        }

    def files(self, data_dir: Path) -> list[str]:
        """Every file this run's directory holds, for the index row.

        Recorded as a list rather than the single artifact a stage happened to
        write last, because a run directory accumulates: the scan's alerts, both
        triage arms, the verification, the report, the SAST/SCA static-analysis findings. One
        name answered "what did this command write"; the list answers "what does
        this run consist of", which is the question anyone reading the index
        across runs is actually asking — and it makes an incomplete run visible
        at a glance (no ``scan-zap-alerts.json`` means the scan did not finish).
        """
        from dast_orchestrator.foundation import run_paths

        directory = run_paths.RunLayout(data_dir, self.run_id).dir
        if not directory.is_dir():
            return []
        # Dotfiles are excluded because the stage locks
        # (:mod:`dast_orchestrator.foundation.run_lock`) are dotfiles precisely so that
        # bookkeeping a run holds while it runs never reads as an artifact of it.
        return sorted(p.name for p in directory.iterdir()
                      if p.is_file() and not p.name.startswith("."))

    def write(self, data_dir: Path) -> Path:
        """Write the per-run record into the run's folder.

        The record lands in ``data/<run>/<kind>-metrics.json`` alongside the
        artifacts it describes. There is no separate index to update:
        :func:`read_index` derives the cross-run table from these files on read.
        """
        from dast_orchestrator.foundation import manifest, run_paths

        layout = run_paths.RunLayout(data_dir, self.run_id).ensure()
        # A standalone `dast verify` of a harness run has HARNESS_ID/HARNESS_ROW
        # unset — those live only in the subprocess env the harness spawns — so
        # its record would orphan from the sheet and the analyzer would drop it
        # from the verify views. But which sheet the run belongs to is a fact of
        # the path (``data/harness/<sheet>/<run>/``), so recover it from there.
        # The row is not in the path; fall back to the artifact label, the same
        # row identity the analyzer already parses when ``harness_row`` is absent.
        if not self.harness_id and layout.dir.parent.parent.name == run_paths.HARNESS_DIR_NAME:
            self.harness_id = layout.dir.parent.name
            if not self.harness_row:
                self.harness_row = self.label
        record = self.as_dict()
        path = layout.metrics(self.kind, self.label)
        path.write_text(json.dumps(record, indent=2))
        # Refresh the run's self-description. Every stage records metrics, so this
        # is the one chokepoint that keeps manifest.json current. Best-effort: a
        # convenience file must never fail the stage that produced real artifacts.
        try:
            manifest.write_manifest(layout)
        except OSError:
            pass
        return path

    def print_summary(self, files: "list[str] | None" = None) -> None:
        """Close a command: per-stage timings, the files written, the total.

        Only scalar counters are shown. Nested structures — the per-call log,
        the resource samples — belong in the artifact, not on a terminal.

        :param files: artifacts this command wrote, named here so every command
            ends the same way a phase does.
        """
        from dast_orchestrator.foundation import ui

        ui.phase(f"Run metrics — {self.kind}")
        for name, timing in self.stages.items():
            scalars = " ".join(
                f"{k}={v}"
                for k, v in timing.counters.items()
                if isinstance(v, (int, float, str, bool)) and not isinstance(v, bool)
            )
            seconds = "?" if timing.seconds is None else f"{timing.seconds:.1f}s"
            ui.item(name, f"{seconds:>9s}  {scalars}".rstrip())
        # Files second to last, time last — the same close as every phase.
        for name in files or []:
            ui.wrote(name)
        ui.done(self.total_seconds, "total")
        ui.finished(f"{self.kind} of {self.run_id}")


#: Which numbers make two records of one kind comparable. Used twice, from one
#: definition: the harness's table across *runs*, and ``dast``'s summary across
#: the *stages* of one run. A table that tried to carry every recorded counter
#: would be unreadable, and the full record is one file away in each case.
#:
#: **The order is significant, most important first.** The harness prints every
#: column, because comparing configurations is what it exists for; the run
#: summary prints only the first :data:`SUMMARY_COLUMNS`, because one line per
#: stage has to stay one line.
TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "scan": ("auth_mode", "urls_before_active_scan", "alerts",
             "active_scanner_alerts"),
    "triage": ("findings", "deterministic_rescans", "llm_rescans",
               "llm_findings_asked", "llm_findings_unanswered",
               "correlated_findings", "self_contradictions", "self_comparisons",
               "code_context_endpoints_handler_located"),
    "verify": ("dispatched", "confirmed", "refuted", "inconclusive",
               "not_attempted"),
    "report": ("results", "zap_rules", "synthesis_rules"),
    "analysis": ("findings", "security_findings"),
}


#: How many of a kind's columns fit on one line of the run summary.
SUMMARY_COLUMNS = 4


def read_run_records(data_dir: Path, run_id: str) -> list[dict[str, Any]]:
    """Every metrics record in one run's directory, oldest first.

    Read off disk rather than accumulated in memory, because the stages of a run
    are separate processes — which is the whole point of the pipeline being
    re-runnable stage by stage.
    """
    from dast_orchestrator.foundation import run_paths

    directory = run_paths.RunLayout(data_dir, run_id).dir
    if not directory.is_dir():
        return []
    records = []
    for path in sorted(directory.glob("*-metrics*.json")):
        try:
            records.append(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(records, key=lambda r: str(r.get("started_at", "")))


def run_cost_so_far(data_dir: Path, run_id: str, label: str = "") -> float:
    """What the stages of *this experiment* have already spent, in USD.

    Read off the run's metrics records rather than accumulated in memory,
    because the stages are separate processes — which is what makes a run-wide
    cost ceiling enforceable at all. A record with no ``cost_usd`` contributes
    nothing: a stage that called no model did not spend, and a stage that could
    not measure records ``None`` rather than a guess.

    **Scoped by label, and that is load-bearing.** A run directory is not the
    unit of spending it looks like: the harness re-triages one stored corpus
    dozens of times, and every row writes its metrics *beside that corpus*. Summed
    across the directory, a well-used corpus therefore accumulates the cost of
    every experiment ever run against it — and the ceiling then blocks all future
    model work on the most valuable run in the project, permanently — a
    heavily-re-triaged corpus can sit near a $1 cap and refuse the next stage its
    headroom.

    The label is what separates them. A stage records the ``--out-suffix`` it ran
    under, a harness row's stages share one, and a re-run overwrites its own
    record rather than adding to it — so this sums one experiment's stages and
    nothing else. A plain sequence has the empty label and is unaffected, which
    is the case the ceiling was written for.
    """
    total = 0.0
    for record in read_run_records(data_dir, run_id):
        if str(record.get("label") or "") != label:
            continue
        cost = (record.get("results") or {}).get("cost_usd")
        if isinstance(cost, (int, float)):
            total += float(cost)
    return round(total, 6)


def run_summary(data_dir: Path, run_id: str) -> str:
    """One table for one run: what each stage cost and what it produced.

    The close of a ``dast`` sequence. Four separate metrics blocks, one per
    stage, answer "what did this stage cost" four times and "what did this run
    cost" not at all — which is the question the CI argument actually asks.
    """
    records = read_run_records(data_dir, run_id)
    if not records:
        return ""
    header = f"{'stage':12s} {'time':>9s} {'cost':>9s}  results"
    lines = [header, "-" * max(len(header), 60)]
    total_seconds = total_cost = 0.0
    for record in records:
        kind = str(record.get("kind", "?"))
        label = str(record.get("label") or "")
        results = record.get("results") or {}
        seconds = float(record.get("total_seconds") or 0)
        cost = results.get("cost_usd")
        total_seconds += seconds
        total_cost += float(cost or 0)
        shown = " ".join(
            f"{column}={results[column]}"
            for column in TABLE_COLUMNS.get(kind, ())[:SUMMARY_COLUMNS]
            if column in results
        )
        lines.append(
            f"{(kind + (f'/{label}' if label else ''))[:12]:12s} "
            f"{_minutes(seconds):>9s} "
            f"{('$%.4f' % cost) if cost is not None else '-':>9s}  {shown}"
        )
    lines.append("-" * max(len(header), 60))
    lines.append(f"{'total':12s} {_minutes(total_seconds):>9s} "
                 f"{'$%.4f' % total_cost:>9s}")
    return "\n".join(lines)


def _fit(text: str, width: int) -> str:
    """Truncate visibly. A silently cut id is one a reader will mistake for a
    different, shorter one."""
    return text if len(text) <= width else text[:width - 1] + "…"


def _minutes(seconds: float) -> str:
    """Seconds under a minute, minutes above — a 45-minute stage in seconds is
    a number nobody reads."""
    return f"{seconds:.1f}s" if seconds < 60 else f"{seconds / 60:.1f}m"


def index_row(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten a metrics record into one comparable row for the costs table.

    Deliberately shallow: the row is meant to be read as a table across many
    runs, so it carries identity, totals and the handful of outcome numbers that
    make two runs comparable, not the full nested structure.
    """
    stages = record.get("stages", {})
    return {
        "run": record["run"],
        "kind": record["kind"],
        "label": record.get("label", ""),
        # Harness membership, recorded rather than inferred. Until now the only
        # trace that a row belonged to a sheet was which directory its index
        # happened to live in, so a row read out of the index — or joined with
        # others at writing time — could not say whether it was part of an
        # experiment or a one-off.
        "harness_id": record.get("harness_id", ""),
        "harness_row": record.get("harness_row", ""),
        # The stage's own configuration digest — not the run id's, which names
        # the *scan* that produced the directory. A triage and its re-run at a
        # different model share a run and differ here, which is what lets the
        # harness table group rows by "same configuration".
        "config_digest": _digest_of(record.get("config") or {}),
        "model": (record.get("tools", {}).get("openrouter") or {}).get("model"),
        # The provider(s) that actually SERVED the calls — recorded per call, not
        # in the tool summary (a model can be served by several). Distinct, in
        # first-seen order; a routing step can move it independently of the model.
        "provider": _served_providers(record),
        "started_at": record["started_at"],
        "total_seconds": record["total_seconds"],
        "stage_seconds": {k: v.get("seconds") for k, v in stages.items()},
        # How the stage ended: "" for a clean finish, else the abort type
        # (error / cancelled / budget-ceiling). Its own column in `dast costs`.
        "abort": _abort_type(record),
        **record.get("results", {}),
    }


def _served_providers(record: dict[str, Any]) -> str:
    """Distinct upstream providers across every logged call, first-seen order."""
    seen: list[str] = []
    for stage in (record.get("stages") or {}).values():
        for call in (stage.get("calls_log") or []):
            provider = call.get("provider")
            if provider and provider not in seen:
                seen.append(provider)
    return ",".join(seen)


def _abort_type(record: dict[str, Any]) -> str:
    """The abort type of a metrics record, or ``""`` for a clean finish.

    Reads the explicit :attr:`RunMetrics.abort` object a crashing stage now
    persists (``{"type", "reason"}``). Falls back to inferring an abort from a
    stage timing that never closed (``seconds`` is null), which is how a record
    written before abort tracking, or truncated on disk, still reads as partial.
    """
    abort = record.get("abort")
    if isinstance(abort, dict) and abort.get("type"):
        return str(abort["type"])
    if any(v.get("seconds") is None for v in (record.get("stages") or {}).values()):
        return "error"
    return ""


def _digest_of(config: dict[str, Any]) -> str:
    """The configuration digest for a metrics record, or ``""`` if it stored none."""
    from dast_orchestrator.foundation import run_paths

    return run_paths.config_digest(config)


def _fmt_failure_kinds(kinds: dict[str, Any]) -> str:
    """Render a ``{"truncated": 2, "empty": 1}`` tally as ``"2 truncated, 1 empty"``."""
    return ", ".join(f"{count} {name}" for name, count in kinds.items())


def derive_limits(
    kind: str,
    stages: dict[str, Any],
    results: dict[str, Any],
    abort: "dict[str, str] | None" = None,
) -> list[dict[str, Any]]:
    """Normalise the ceilings and degradations a stage hit into one list.

    Each entry is ``{"stage", "limit", "detail"}`` where ``limit`` names the
    specific configured ceiling that fired (``active_scan_cap_minutes``,
    ``spider_client_stall``, ``code_context_no_source``, ...). Derived purely
    from signals the record already carries — a *view*, not a new measurement —
    so a measured zero and a missing measurement stay distinct.

    Descriptive only: a limit marks a run **degraded but usable** and never
    changes a verdict or a count. The discipline is deliberate — a stage whose
    artifact would *misrepresent* what ran fails closed instead (the login gate);
    a stage that is honest-but-incomplete records the limit here and the report
    surfaces it, so a drowned scan or a budget-stopped verify is never silently
    averaged in. → DECISIONS.md.
    """
    limits: list[dict[str, Any]] = []

    def add(stage: str, limit: str, detail: str) -> None:
        limits.append({"stage": stage, "limit": limit, "detail": detail})

    # A controlled cost-ceiling stop is a limit by definition; an `error` or
    # `cancelled` abort is the failure it was and stays in `abort` alone.
    if isinstance(abort, dict) and abort.get("type") == "budget-ceiling":
        add(kind, "cost_ceiling",
            abort.get("reason") or "the run-wide cost ceiling stopped the stage")

    if kind == "scan":
        active = stages.get("active_scan") or {}
        if active.get("truncated_by_cap") is True:
            add("active_scan", "active_scan_cap_minutes",
                f"active scan stopped at the {active.get('cap_minutes')}-minute cap "
                f"with {active.get('urls_in_tree')} URLs in the tree — coverage is a "
                "lower bound")
            # Cut off AND it raised nothing: the scanner never reached a
            # parameterised endpoint. A *completed* scan with zero active-scanner
            # alerts is a real measurement, not a limit, so this is gated on the cap.
            if results.get("active_scanner_alerts") == 0:
                add("active_scan", "active_scanner_zero_alerts",
                    "the active scan was cut off before it raised a single "
                    "active-scanner alert")
        spider = stages.get("spider") or {}
        outcome = str(spider.get("poll_outcome")
                      or spider.get("urls_after_outcome") or "")
        if "stall" in outcome:
            add("spider", "spider_client_stall",
                f"the client spider stalled ({outcome}); JS-route discovery is incomplete")
        elif "time-capped" in outcome or "time_capped" in outcome:
            add("spider", "spider_time_capped",
                f"the client spider hit its time cap ({outcome})")

    elif kind == "triage":
        unanswered = results.get("llm_findings_unanswered") or 0
        if unanswered:
            add("llm_screening", "screening_findings_unanswered",
                f"{unanswered} of {results.get('llm_findings_asked')} findings put to "
                "the model came back with no verdict")
        with_source = results.get("code_context_endpoints_with_source")
        without_source = results.get("code_context_endpoints_without_source") or 0
        if with_source == 0 and without_source:
            add("llm_screening", "code_context_no_source",
                f"no handler source resolved for any of {without_source} endpoints; "
                "screening ran without the code grounding it is configured to use")
        for name, stage in stages.items():
            kinds = stage.get("failure_kinds") if isinstance(stage, dict) else None
            if kinds:
                add(name, "llm_call_failures", _fmt_failure_kinds(kinds))

    elif kind == "verify":
        by_reason = results.get("not_attempted_by_reason") or {}
        if by_reason.get("budget"):
            add("dispatch", "verify_dispatch_budget",
                f"{by_reason['budget']} findings were left not-attempted because a "
                "dispatch budget was exhausted")
        for name, stage in stages.items():
            kinds = stage.get("failure_kinds") if isinstance(stage, dict) else None
            if kinds:
                add(name, "llm_call_failures", _fmt_failure_kinds(kinds))

    return limits


def record_limits(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The normalised limits of a metrics record, recomputing for old records.

    Prefers the stored ``limits`` a stage now writes; falls back to
    :func:`derive_limits` over the record's own stages and results, so a report
    built over a corpus written before the field existed still names every
    ceiling those runs hit.
    """
    stored = record.get("limits")
    if isinstance(stored, list):
        return stored
    return derive_limits(
        str(record.get("kind") or ""),
        record.get("stages") or {},
        record.get("results") or {},
        record.get("abort"),
    )


def read_index(data_dir: Path) -> list[dict[str, Any]]:
    """Every recorded execution under ``data_dir``, oldest first, **derived on
    read** from each run's ``<kind>-metrics.json`` — there is no stored index
    file.

    The truth is the per-run metrics records; the index is just a flattened view
    of them (:func:`index_row`). Computing it on demand rather than maintaining a
    separate stored index file means the table can never drift from the runs it
    describes — a deleted run drops out, a re-run appears — and there is nothing
    to append, clear or repair. (This is why there is no ``run-index.jsonl``
    artifact, despite the ``dast costs`` name's history.)
    """
    from dast_orchestrator.foundation import run_paths

    rows: list[dict[str, Any]] = []
    for run_id in run_paths.RunLayout.runs(data_dir):
        directory = run_paths.RunLayout(data_dir, run_id).dir
        artifacts = sorted(p.name for p in directory.iterdir()
                           if p.is_file() and not p.name.startswith("."))
        for record in read_run_records(data_dir, run_id):
            row = index_row(record)
            row["artifacts"] = artifacts
            rows.append(row)
    rows.sort(key=lambda r: str(r.get("started_at") or ""))
    return rows


# -- environment probes ----------------------------------------------------


def host_facts() -> dict[str, Any]:
    """CPU, RAM and OS of the machine that produced the numbers.

    A wall time without the machine behind it is not reproducible, and this
    prototype's headline claim is that the pipeline fits in a CI job on modest
    hardware.
    """
    facts: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": None,
        "memory_gb": None,
    }
    try:
        import os

        facts["cpu_count"] = os.cpu_count()
    except Exception:  # pragma: no cover - platform dependent
        pass
    try:
        total = subprocess.run(
            ["sysctl", "-n", "hw.memsize"], capture_output=True, timeout=5
        )
        if total.returncode == 0:
            facts["memory_gb"] = round(int(total.stdout) / 1024**3, 1)
    except Exception:  # pragma: no cover - non-macOS hosts
        pass
    return facts


def docker_image_digest(image: str) -> str | None:
    """Resolve an image tag to its digest, pinning what actually ran.

    A tag is a promise; the digest is what executed. Returns ``None`` when the
    image is not present locally rather than pulling it.
    """
    if not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode().strip() or None


def container_stats(names: list[str]) -> dict[str, Any]:
    """One instantaneous ``docker stats`` reading for the named containers.

    A spot sample, not a maximum. Use :class:`ResourceSampler` when the peak
    over a long stage is what matters. Absent containers are omitted.
    """
    if not shutil.which("docker") or not names:
        return {}
    try:
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}", *names],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return {}
    if proc.returncode != 0:
        return {}
    stats: dict[str, Any] = {}
    for line in proc.stdout.decode().splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            stats[parts[0]] = {
                "cpu_percent": parts[1],
                "memory": parts[2],
                "memory_percent": parts[3],
            }
    return stats


# -- reporting -------------------------------------------------------------


#: Stage order within one run — scan, then triage, verify, report, analysis —
#: so a run's rows read in the order the pipeline produced them.
_KIND_ORDER = {kind: i for i, kind in enumerate(TABLE_COLUMNS)}


def format_index(rows: list[dict[str, Any]]) -> str:
    """Render the derived run index as a table for the writeup.

    Sorted by run id (newest run at the bottom) and, within one run, by stage
    order (scan → triage → verify → report), so cost and runtime trends read as
    one history without loading anything into a notebook.
    """
    if not rows:
        return ("No runs recorded yet in data/runs or data/harness/*. "
                "Run `uv run dast scan <target>` first.")

    rows = sorted(rows, key=lambda r: (
        str(r.get("run") or ""),
        _KIND_ORDER.get(r.get("kind"), len(_KIND_ORDER)),
        str(r.get("started_at") or ""),
    ))

    # One width per column, shared by the header and every row, and every
    # variable-width column (run id, sheet, model) is sized to the WIDEST value
    # actually present rather than to a guessed constant. The old fixed 30 was
    # narrower than a `<timestamp>-wordpress-<digest>` id (33), so those rows
    # overflowed the first column and shoved every later column off its header.
    def _col(header_text: str, values, cap: int) -> int:
        return min(cap, max(len(header_text), *(len(v) for v in values), 1))

    runs = [str(r.get("run", "?")) for r in rows]
    sheets = [str(r.get("harness_id") or "-") for r in rows]
    models = [str(r.get("model") or "-") for r in rows]
    providers = [str(r.get("provider") or "-") for r in rows]
    aborts = [str(r.get("abort") or "-") for r in rows]
    run_w = _col("run", runs, cap=40)
    sheet_w = _col("sheet", sheets, cap=24)
    model_w = _col("model", models, cap=40)
    prov_w = _col("provider", providers, cap=16)
    # A column of its own rather than a mark on the kind: a clean run reads "-",
    # an aborted one names WHY (error / cancelled / budget-ceiling) at a glance.
    abort_w = _col("abort", aborts, cap=14)
    header = (
        f"{'run':{run_w}s} {'kind':9s} {'sheet':{sheet_w}s} {'total':>8s} "
        f"{'cost':>9s} {'alerts/findings':>15s}  {'model':{model_w}s} "
        f"{'provider':{prov_w}s} {'abort':{abort_w}s}"
    )
    body = []
    for row in rows:
        cost = row.get("cost_usd")
        result = row.get("alerts", row.get("findings", ""))
        # Which sheet a row belongs to, or `-` for a run a person started. The
        # provenance used to be the directory path alone, so a row read out of
        # the index could not say whether it was part of an experiment.
        sheet = _fit(row.get("harness_id") or "-", sheet_w)
        body.append(
            f"{_fit(str(row.get('run', '?')), run_w):{run_w}s} "
            f"{str(row.get('kind', '?')):9s} "
            f"{sheet:{sheet_w}s} {row.get('total_seconds', 0):7.1f}s "
            f"{('$%.4f' % cost) if cost is not None else '-':>9s} "
            f"{str(result):>15s}  {_fit(str(row.get('model') or '-'), model_w):{model_w}s} "
            f"{_fit(str(row.get('provider') or '-'), prov_w):{prov_w}s} "
            f"{_fit(str(row.get('abort') or '-'), abort_w):{abort_w}s}".rstrip()
        )
    total_cost = sum(float(r.get("cost_usd") or 0) for r in rows)
    total_time = sum(float(r.get("total_seconds") or 0) for r in rows)
    width = max(len(header), *(len(line) for line in body))
    rule = "-" * width
    return "\n".join(
        [header, rule, *body, rule,
         f"{len(rows)} runs, {total_time / 60:.1f} min, ${total_cost:.4f} total"]
    )


def read_all_indexes(data_root: Path) -> list[dict[str, Any]]:
    """Every recorded run across `data/runs` AND every harness sheet, oldest first.

    The runs live in two places: a person's runs under ``data/runs/`` and every
    sheet's under ``data/harness/<sheet>/``. Deriving across both is the point —
    half the cost history is in the sheets — and a reader that looked only in
    ``data/`` once printed *"No runs recorded yet"* over 101 rows.

    Reading them all is the right fix rather than pointing at one: the question
    ``dast costs`` answers is "what has this project cost and how long has it
    taken", and half that history is in the sheets. Rows are tagged with
    ``harness_id`` on the way in, so which sheet a row belongs to is a field
    rather than a directory path a reader has to reconstruct.
    """
    from dast_orchestrator.foundation import run_paths

    rows = list(read_index(run_paths.default_runs_dir(data_root)))
    harness_root = Path(data_root) / run_paths.HARNESS_DIR_NAME
    if harness_root.is_dir():
        for sheet in sorted(p for p in harness_root.iterdir() if p.is_dir()):
            for row in read_index(sheet):
                row.setdefault("harness_id", sheet.name)
                rows.append(row)
    # Oldest first across every source, so the table reads as one history rather
    # than as the manual runs followed by the sheets.
    rows.sort(key=lambda r: str(r.get("started_at") or ""))
    return rows


def build_parser() -> "Any":
    """The ``dast costs`` parser, built without parsing — so ``dast commands``
    reads its flags from the one definition :func:`main` also uses."""
    import argparse

    from dast_orchestrator.foundation import config

    parser = argparse.ArgumentParser(
        prog="dast costs", description=config.command_description(main.__doc__))
    parser.add_argument(
        "--data-dir", type=Path,
        default=Path(__file__).resolve().parents[3] / "data",
        help="The data ROOT. Both data/runs and every data/harness/<sheet> "
             "index under it are read.",
    )
    parser.add_argument(
        "--manual-only", action="store_true",
        help="Only runs a person started (data/runs), leaving out every "
             "harness sheet's own rows.",
    )
    config.normalize_metavars(parser)
    return parser


def main(argv: "list[str] | None" = None) -> int:
    """The record of every run this project has produced — one row per stage-run,
    oldest first: wall time, cost, peak resource use and tool provenance. Reads
    data/runs and every data/harness/<sheet> under the data root."""
    args = build_parser().parse_args(argv)
    from dast_orchestrator.foundation import run_paths

    rows = (read_index(run_paths.default_runs_dir(args.data_dir))
            if args.manual_only else read_all_indexes(args.data_dir))
    print(format_index(rows))
    return 0


class ResourceSampler:
    """Poll container CPU and memory in the background and keep the peaks.

    A single ``docker stats`` reading taken after a 60-minute active scan says
    what ZAP was doing in that one second, which is not what a CI capacity
    question asks. This samples throughout a stage and reports peak and mean, so
    "does this fit in a 2 GB runner" has an answer grounded in the whole run.

    Sampling costs one ``docker stats --no-stream`` per interval, so the default
    interval is deliberately slack — the measurement must not distort what it
    measures.

    .. code-block:: python

        with ResourceSampler(["dast-zap"]) as sampler:
            ...  # long stage
        stage.counters["resources"] = sampler.summary()

    Failures are silent by design: a missing docker binary or a container that
    exits mid-run must never take down a scan that is otherwise fine. An empty
    summary then correctly reports that nothing was measured.
    """

    def __init__(self, containers: list[str], interval: float = 15.0) -> None:
        """
        :param containers: container names to watch; missing ones are skipped.
        :param interval: seconds between samples.
        """
        self.containers = containers
        self.interval = interval
        self.samples: dict[str, list[tuple[float, float]]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "ResourceSampler":
        if self.containers and shutil.which("docker"):
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def stop(self) -> None:
        """Stop sampling and wait briefly for the thread to finish."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 5)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            for name, stats in container_stats(self.containers).items():
                cpu = _parse_percent(stats.get("cpu_percent"))
                memory = _parse_memory_mb(stats.get("memory"))
                if cpu is not None and memory is not None:
                    self.samples.setdefault(name, []).append((cpu, memory))
            self._stop.wait(self.interval)

    def summary(self) -> dict[str, Any]:
        """Peak and mean CPU percent and memory (MB) per container."""
        out: dict[str, Any] = {}
        for name, points in self.samples.items():
            cpus = [c for c, _ in points]
            memories = [m for _, m in points]
            out[name] = {
                "samples": len(points),
                "cpu_percent_peak": round(max(cpus), 1),
                "cpu_percent_mean": round(sum(cpus) / len(cpus), 1),
                "memory_mb_peak": round(max(memories), 1),
                "memory_mb_mean": round(sum(memories) / len(memories), 1),
            }
        return out


def _parse_percent(value: str | None) -> float | None:
    """Parse docker's ``"12.34%"`` into a float."""
    if not value:
        return None
    try:
        return float(value.strip().rstrip("%"))
    except ValueError:
        return None


def _parse_memory_mb(value: str | None) -> float | None:
    """Parse the used half of docker's ``"1.2GiB / 7.6GiB"`` into MB."""
    if not value:
        return None
    used = value.split("/")[0].strip()
    units = {"B": 1 / 1024**2, "KIB": 1 / 1024, "MIB": 1.0, "GIB": 1024.0,
             "KB": 1 / 1024, "MB": 1.0, "GB": 1024.0}
    # Longest suffix first: a bare "B" also matches the tail of "GIB".
    for suffix, factor in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if used.upper().endswith(suffix):
            try:
                return float(used[: -len(suffix)].strip()) * factor
            except ValueError:
                return None
    return None
