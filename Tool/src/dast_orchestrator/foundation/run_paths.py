"""The run-directory layout — the single source of truth for where a run's files live.

Every artifact lands under ``data/<run-id>/`` with a stable basename (one run is one
folder), and a downstream variant is a suffixed sibling in the same folder, not a new
directory. ``run-id = <timestamp>-<target>-<config-digest>`` (timestamp first so it sorts;
the target contains no ``-``; the digest covers only global+scan config, so re-triage is a
variant told apart by ``--out-suffix`` — which is why ``scan`` takes no suffix, it *is* the
directory), and a person's runs live in ``data/runs/``, a sheet's under ``data/harness/``.
→ docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NamedTuple

#: The data root, and the three places run directories live under it. Named here
#: so no driver has to know the layout — each just defaults ``--data-dir`` to
#: :func:`default_runs_dir`, and the harness points its stages at
#: :func:`harness_runs_dir` (real sheets) or :func:`scratch_runs_dir` (ephemeral
#: dry-run / smoke) instead.
DATA_ROOT = Path(__file__).resolve().parents[3] / "data"
RUNS_DIR_NAME = "runs"
HARNESS_DIR_NAME = "harness"
#: Ephemeral: dry-run and smoke sheets land here, never among the real corpora, and
#: are cleaned on a clean finish. Nothing that reads the corpus (`dast costs`, the
#: inventory, the analyzer) looks in here.
SCRATCH_DIR_NAME = "scratch"


def default_runs_dir(data_root: "Path | None" = None) -> Path:
    """Where a run a *person* started lives: ``data/runs``."""
    return Path(data_root or DATA_ROOT) / RUNS_DIR_NAME


def harness_runs_dir(sheet_run_id: str, data_root: "Path | None" = None) -> Path:
    """Where the runs of one *sheet* live: ``data/harness/<sheet-id>``.

    Nested under the sheet rather than mixed in with everything else, so a
    night's experiments are one directory to open, archive or delete.
    """
    return Path(data_root or DATA_ROOT) / HARNESS_DIR_NAME / sheet_run_id


def scratch_runs_dir(sheet_run_id: str, data_root: "Path | None" = None) -> Path:
    """Where an *ephemeral* sheet (dry-run / smoke) lives: ``data/scratch/<sheet-id>``.

    Kept out of ``data/harness`` so a plan preview or a plumbing check never
    intermixes with the real corpora, and can be removed on a clean finish
    without ever touching a run someone paid 45 minutes for.
    """
    return Path(data_root or DATA_ROOT) / SCRATCH_DIR_NAME / sheet_run_id

#: Stable basenames, one per artifact kind. Nothing else builds these names.
NOIR_ENDPOINTS = "scan-noir-endpoints.json"
NOIR_AI_CONTEXT = "scan-noir-ai-context.json"
NOIR_SEED_MAP = "scan-noir-seed-map.json"
ZAP_ALERTS = "scan-zap-alerts.json"
#: The HTTP exchanges behind the alerts, keyed by ZAP message id and
#: deduplicated (a corpus of 3877 alerts spans 1931 distinct messages). A
#: gitignored *sidecar*, never inlined into another artifact: one observed
#: response body was 16 KB, so a run's exchanges are an order of magnitude
#: larger than everything else it writes. :mod:`dast_orchestrator.context.evidence`
#: is the only reader.
ZAP_MESSAGES = "scan-zap-messages.json"
#: ZAP's exported context (structural params). A scan sidecar like the rest, kept
#: here — not as a bare literal in zap_context.py — so every artifact name lives in
#: this one module ("nothing else builds these names").
ZAP_CONTEXT = "scan-zap-context.xml"
TRIAGE = "triage.json"
TRIAGE_PROMPTS = "triage-prompts.json"
VERIFICATION = "verification.json"
REPORT_SARIF = "report.sarif.json"
REPORT_MD = "report.md"
SEMGREP_SARIF = "semgrep.sarif.json"
OSV_SARIF = "osv.sarif.json"
ANALYSIS_MD = "static-analysis.md"
#: CVE detection measured against a target's ground-truth markers, joined
#: to this run's alerts/triage/verification. See
#: :mod:`dast_orchestrator.stages.ground_truth`.
CVE_DETECTION = "cve-detection.json"
#: A run's self-description (which artifacts exist + their schema/version), scanned
#: from the directory and refreshed whenever a stage records metrics. See
#: :mod:`dast_orchestrator.foundation.manifest`.
MANIFEST = "manifest.json"

#: How many hex characters of the configuration hash go into a run id. Six is
#: ~16.7M values: long enough that two *different* configurations colliding is
#: not a practical concern for a thesis's worth of runs, short enough that the
#: id stays readable and typable. It is not a security property — a digest here
#: only has to distinguish configurations nobody is trying to make collide.
CONFIG_DIGEST_LEN = 6

#: A run id: ``20260824T103111Z-gitea-a3f19c``. Both trailing fields are
#: optional, so ids recorded before each gained one still parse. The target
#: excludes ``-`` deliberately — the fields are parsed by position, so a hyphen
#: in the middle would make the third field unrecoverable.
RUN_ID_RE = re.compile(
    r"^(?P<timestamp>\d{8}T\d{6}Z)"
    r"(?:-(?P<target>[A-Za-z0-9_.]+))?"
    rf"(?:-(?P<config>[0-9a-f]{{{CONFIG_DIGEST_LEN}}}))?$"
)

TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"


def now_timestamp() -> str:
    """The one place a run's timestamp is minted, so every command agrees."""
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


#: Accepted anywhere a run is named, on every command. It means "the newest run
#: this command can act on" — which differs per command (the newest scan for
#: ``correlate-run``, the newest correlation for ``verify-run``), so each driver
#: resolves it against its own requirement rather than this module guessing.
LATEST = "latest"


def is_latest(ident: str | None) -> bool:
    return (ident or "").strip().lower() == LATEST


def config_digest(config: "Mapping[str, Any] | None") -> str:
    """A short, stable hash of the configuration one run was made with.

    The canonicalisation is the contract, not the hash function, because the
    digest's only job is that **the same configuration always produces the same
    name and a different one does not**:

    * keys are sorted, so the order a caller assembled its dict in is invisible;
    * every value is rendered with :func:`json.dumps` (``sort_keys``), so nested
      mappings canonicalise the same way and ``1`` never collides with ``"1"``;
    * empty values (``None``, ``""``) are **dropped**, so a knob that is left at
      its default by omission and one explicitly set to nothing agree. Adding a
      new knob therefore does not change the digest of a run that does not use
      it — without which every existing id would move the day a stage grows a
      flag.

    Returns ``""`` for an empty configuration, which :func:`make_run_id` renders
    as a two-field id: nothing was recorded, so nothing is claimed.

    The mapping this hashes is the **scan's** configuration
    (:func:`dast_orchestrator.stages.scan.scan_config`) — global and scan-stage values
    only. It is never handed a triage/verify/report setting, because those do not
    define a corpus (see the run-id rule in the module docstring); a downstream
    variant shares the scan's directory and is distinguished by ``--out-suffix``.
    """
    items = {
        str(k): v for k, v in (config or {}).items()
        if v is not None and v != ""
    }
    if not items:
        return ""
    canonical = json.dumps(items, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:CONFIG_DIGEST_LEN]


def make_run_id(timestamp: str, target: str, digest: str = "") -> str:
    """``("20260824T103111Z", "gitea", "a3f19c")`` -> ``"…Z-gitea-a3f19c"``.

    Which target a run was against is part of its identity — two runs of the same
    pipeline against different systems are not comparable — so it belongs in the
    name rather than only inside the artifacts. So is the configuration, for the
    reason in the module docstring; pass the digest :func:`config_digest`
    produced, never a free-text label.

    :raises ValueError: if the target contains ``-``, which the three-field
        grammar cannot represent. Refused at the point of construction rather
        than left to produce an id that parses back into different parts.
    """
    target = str(target).strip()
    if "-" in target:
        raise ValueError(
            f"target {target!r} contains '-', which separates the fields of a "
            "run id. Rename the target (underscores are fine)."
        )
    digest = str(digest).strip()
    return "-".join(part for part in (timestamp, target, digest) if part)


class RunId(NamedTuple):
    """The three fields of a run id. ``target``/``config`` are ``""`` if absent."""

    timestamp: str
    target: str
    config: str


def split_run_id(run_id: str) -> RunId:
    """``"20260824T103111Z-gitea-a3f19c"`` -> its three fields.

    An id that does not match the grammar is returned whole as the timestamp,
    so a caller sorting or displaying it still sees the name it was given.
    """
    match = RUN_ID_RE.match(run_id)
    if not match:
        return RunId(run_id, "", "")
    return RunId(
        match.group("timestamp"),
        match.group("target") or "",
        match.group("config") or "",
    )


#: Suffix values that would collide with a naming convention and so may never be
#: used as a stage ``--out-suffix``. ``metrics`` clashes with the per-stage metrics
#: file (``triage.json`` + suffix ``metrics`` == ``triage-metrics.json``, the triage
#: metrics record); ``prompts`` clashes with the ``triage-prompts.json`` dry-run
#: dump. The flat filename space shares one namespace across suffix / metrics-kind /
#: fixed basenames, so these two are reserved rather than left to collide.
RESERVED_SUFFIXES = frozenset({"metrics", "prompts"})


class SuffixError(ValueError):
    """An ``--out-suffix`` collides with a reserved filename convention."""


def _splice_suffix(basename: str, suffix: str) -> str:
    """``triage.json`` + ``qwen235b`` -> ``triage-qwen235b.json``.

    Splits on the first dot so multi-part extensions survive:
    ``report.sarif.json`` -> ``report-qwen235b.sarif.json``.

    :raises SuffixError: if ``suffix`` is one of :data:`RESERVED_SUFFIXES` — a value
        that would make a variant artifact indistinguishable from a metrics record
        or the prompt dump.
    """
    if not suffix:
        return basename
    if suffix in RESERVED_SUFFIXES:
        raise SuffixError(
            f"--out-suffix {suffix!r} is reserved: it would collide with the "
            f"{suffix} filename convention. Reserved: {sorted(RESERVED_SUFFIXES)}.")
    name, dot, rest = basename.partition(".")
    return f"{name}-{suffix}{dot}{rest}"


def metrics_basename(kind: str, suffix: str = "") -> str:
    """``("triage", "qwen") -> "triage-metrics-qwen.json"``.

    The one place a metrics filename is spelled, so a caller can name the file a
    stage will write (for a summary line) without a :class:`RunLayout` in hand.
    """
    return _splice_suffix(f"{kind}-metrics.json", suffix)


class RunLayout:
    """The directory and named paths for one run under ``data/``."""

    def __init__(self, data_dir: Path, run_id: str) -> None:
        self.data_dir = Path(data_dir)
        self.run_id = run_id
        self.dir = self.data_dir / run_id

    def ensure(self) -> "RunLayout":
        self.dir.mkdir(parents=True, exist_ok=True)
        return self

    def path(self, basename: str, suffix: str = "") -> Path:
        """Absolute path of one artifact in this run, optionally suffixed."""
        return self.dir / _splice_suffix(basename, suffix)

    def has(self, basename: str, suffix: str = "") -> bool:
        return self.path(basename, suffix).is_file()

    def metrics(self, kind: str, suffix: str = "") -> Path:
        """Path of the per-stage metrics record (``<kind>-metrics.json``)."""
        return self.path(metrics_basename(kind, suffix))

    @property
    def timestamp(self) -> str:
        return split_run_id(self.run_id).timestamp

    @property
    def target(self) -> str:
        """Target this run was against, or ``""`` for ids predating the layout."""
        return split_run_id(self.run_id).target

    @property
    def config(self) -> str:
        """Digest of the configuration, or ``""`` for ids predating the field."""
        return split_run_id(self.run_id).config

    # -- discovery ---------------------------------------------------------

    @classmethod
    def runs(cls, data_dir: Path) -> list[str]:
        """Every run id present under ``data_dir``, oldest first.

        Only directories whose name *is* a run id (:data:`RUN_ID_RE`). ``data/``
        holds a little else — the harness keeps its sheets and comparison tables
        in ``data/harness/`` — and a stray directory sorting after every
        timestamp would otherwise be returned as "the newest run" by everything
        that reads this list.
        """
        data_dir = Path(data_dir)
        if not data_dir.is_dir():
            return []
        return sorted(
            p.name for p in data_dir.iterdir()
            if p.is_dir() and RUN_ID_RE.match(p.name)
        )

    @classmethod
    def resolve(cls, data_dir: Path, ident: str) -> "RunLayout":
        """Find the run a user named, by full id or by bare timestamp.

        ``--timestamp 20260818T200609Z`` has to keep working now that the folder
        is ``20260818T200609Z-gitea-a3f19c``: an id that is not a directory is
        completed by prefix, and the prefix may stop after any whole field. An
        ambiguous prefix — the same instant against two targets, or the same
        target under two configurations — raises rather than picking one,
        because silently correlating the wrong run is exactly the kind of error
        nobody catches by reading a summary. That refusal is what makes the
        configuration field safe to add: a short id that used to name one run and
        now names three fails loudly instead of quietly selecting the first.

        A name that matches nothing on disk is returned as-is, so the caller
        reports the missing artifact it was actually looking for.
        """
        data_dir = Path(data_dir)
        if (data_dir / ident).is_dir():
            return cls(data_dir, ident)
        matches = [run for run in cls.runs(data_dir) if run.startswith(f"{ident}-")]
        if len(matches) > 1:
            raise ValueError(
                f"run {ident!r} is ambiguous in {data_dir}: {matches}. "
                "Name the full run id (timestamp-target-config)."
            )
        return cls(data_dir, matches[0] if matches else ident)

    @classmethod
    def latest_with(cls, data_dir: Path, *required: str) -> "RunLayout | None":
        """The newest run whose folder holds all ``required`` basenames, or None."""
        data_dir = Path(data_dir)
        for run_id in reversed(cls.runs(data_dir)):
            layout = cls(data_dir, run_id)
            if all(layout.has(name) for name in required):
                return layout
        return None


#: Help text for the "which run?" **positional**, shared by every stage so they
#: all describe the same concept the same way. It was ``--run``/``--timestamp``
#: once; naming the run is not an option a command can do without,
#: so it is the argument rather than a flag with a default.
RUN_ARG_HELP = (
    "Run to {verb} — its full `<timestamp>-<target>-<config>` id (the directory "
    "name in data/), any whole-field prefix of it such as the bare timestamp "
    "(completed against data/, erroring if more than one run matches), or "
    "`latest`, which means {default}."
)
