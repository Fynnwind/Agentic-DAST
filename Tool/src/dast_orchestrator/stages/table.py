"""One table, :data:`STAGES`, naming the five commands and, per command, the artifacts it
requires in a run directory and the ones it produces — the description the harness and the
CLI share, so the two front ends can never disagree about what a stage is. Nothing here
executes.

Recording requirements is to refuse early: ``scan`` then ``report`` is unsatisfiable
(nothing writes what ``report`` reads), knowable before the first container rather than
after a 45-minute scan (:func:`plan` resolves a sequence as present / produced-earlier /
missing). ``scan`` alone mints a run; every stage locks the directory it writes, and
:meth:`Stage.lock_name` carries the output suffix for the three stages that have one.
→ docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dast_orchestrator.foundation import run_paths

#: Marks a step's input as satisfied by the run directory as it already is.
PRESENT = "present"
#: Satisfied by an earlier step of the same sequence, which has not run yet.
PRODUCED = "produced"
#: Satisfied by nothing — the sequence cannot complete.
MISSING = "missing"


def new_run_id(data_dir: "Path", before: "set[str]") -> str | None:
    """Which run directory appeared since ``before`` was taken, if any.

    How both front ends learn the id a ``scan`` just minted. Read off the
    filesystem rather than re-derived, because the id is computed *inside* the
    stage from its own effective configuration — a caller that recomputed it
    would be duplicating that computation, badly, and would drift the moment the
    digest's inputs changed.

    The newest is returned when a run somehow produced more than one directory,
    so the caller always names something real rather than nothing.
    """
    from dast_orchestrator.foundation import run_paths

    appeared = sorted(set(run_paths.RunLayout.runs(data_dir)) - before)
    return appeared[-1] if appeared else None


@dataclass(frozen=True)
class Stage:
    """One command of the pipeline, described rather than executed.

    :param module: the ``python -m`` target, so a caller spawns the stage the
        same way whether or not the console scripts are on ``PATH``.
    :param requires: basenames that must be in the run directory before it runs.
    :param produces: basenames it writes there.
    :param mints_run: ``True`` only for ``scan``, which creates the directory the
        rest of a sequence inherits.
    :param suffix_flag: the flag that names a variant artifact, or ``""`` for a
        stage that has none. It is what lets a model comparison or a variance
        repeat live inside one run directory instead of re-paying for a scan.
    """

    name: str
    module: str
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    mints_run: bool = False
    suffix_flag: str = ""

    def load(self):
        """Import the stage's module, so its parser and ``main`` are reachable."""
        import importlib

        return importlib.import_module(self.module)

    def parser(self):
        """This stage's :mod:`argparse` parser, for reading the flags it takes."""
        return self.load().build_parser()

    def lock_name(self, suffix: str = "") -> str:
        """The lock file this stage takes in a run directory it writes to.

        The suffix participates only for a stage that declares
        :attr:`suffix_flag`: ``verify --out-suffix hybrid`` and ``verify
        --out-suffix qwen`` write different artifacts and may run at once, while
        ``analyze``, which has no such flag, writes one set of files whatever
        else is happening. See :mod:`dast_orchestrator.foundation.run_lock`.
        """
        from dast_orchestrator.foundation import run_lock

        return run_lock.lock_name(self.name, suffix if self.suffix_flag else "")

    def option_strings(self) -> set[str]:
        """Every flag this stage accepts, e.g. ``{"--auth", "--run", …}``."""
        return {
            option
            for action in self.parser()._actions
            for option in action.option_strings
        }


STAGES: dict[str, Stage] = {
    "scan": Stage(
        "scan", "dast_orchestrator.stages.scan",
        produces=(run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT,
                  run_paths.NOIR_ENDPOINTS, run_paths.NOIR_SEED_MAP),
        mints_run=True,
    ),
    "triage": Stage(
        "triage", "dast_orchestrator.stages.triage",
        # The seed map is deliberately *not* required: a scan predating it still
        # correlates, on the regex tier alone, and says so in its join counts.
        requires=(run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT),
        produces=(run_paths.TRIAGE,),
        suffix_flag="--out-suffix",
    ),
    "verify": Stage(
        "verify", "dast_orchestrator.stages.verify",
        requires=(run_paths.TRIAGE,),
        produces=(run_paths.VERIFICATION,),
        suffix_flag="--out-suffix",
    ),
    "report": Stage(
        "report", "dast_orchestrator.stages.report",
        # The verification is optional: a report of triage alone is a valid
        # report, and one that says so beats one that refuses to exist.
        requires=(run_paths.TRIAGE,),
        produces=(run_paths.REPORT_SARIF, run_paths.REPORT_MD),
        suffix_flag="--out-suffix",
    ),
    "static-analysis": Stage(
        "static-analysis", "dast_orchestrator.stages.static_analysis.analyze",
        # Needs only the target's source tree, which is not a run artifact —
        # which is why the SAST/SCA static-analysis findings can join any run, or none.
        produces=(run_paths.SEMGREP_SARIF, run_paths.OSV_SARIF,
                  run_paths.ANALYSIS_MD),
    ),
}

#: The whole chain, in the only order its dependencies allow. ``analyze`` sits
#: at the end because it depends on nothing the others produce — it is a
#: static-analysis pass over the same source tree, not a stage of the pipeline, and joining
#: a run's directory is the only thing it shares with them.
FULL_CHAIN = ("scan", "triage", "verify", "report")


class StageError(ValueError):
    """An unknown stage name, or a sequence that cannot complete."""


@dataclass(frozen=True)
class Step:
    """One stage of a planned sequence, with where its inputs come from."""

    stage: Stage
    #: ``basename -> PRESENT | PRODUCED | MISSING``, one entry per requirement.
    inputs: dict[str, str]

    @property
    def satisfiable(self) -> bool:
        return MISSING not in self.inputs.values()

    def describe(self) -> str:
        """One line for the echoed plan, naming any input nothing supplies."""
        if not self.inputs:
            return f"{self.stage.name:10s} (no run-directory input)"
        parts = [f"{name} [{state}]" for name, state in sorted(self.inputs.items())]
        return f"{self.stage.name:10s} {', '.join(parts)}"


def resolve(names: "list[str] | tuple[str, ...]") -> list[Stage]:
    """Stage objects for the names given, in the order written.

    :raises StageError: naming the unknown stage and the ones that exist. A
        typo in a sheet row must fail before anything runs, not halfway through.
    """
    stages = []
    for name in names:
        stage = STAGES.get(str(name).strip().lower())
        if stage is None:
            raise StageError(
                f"unknown stage {name!r}; known stages: {', '.join(sorted(STAGES))}"
            )
        stages.append(stage)
    return stages


def plan(names: "list[str] | tuple[str, ...]",
         run_dir: "Path | None" = None) -> list[Step]:
    """Resolve a sequence against a run directory, marking every input's source.

    :param run_dir: the run the sequence acts on, or ``None`` when the sequence
        begins by minting one (``scan`` first) — in which case nothing is
        ``PRESENT`` and every requirement must be met by an earlier step.

    The whole sequence is planned before the caller runs any of it, which is the
    difference between "this cannot work" and "this stopped working 45 minutes
    in".
    """
    stages = resolve(names)
    available: set[str] = set()
    if run_dir is not None and Path(run_dir).is_dir():
        available |= {p.name for p in Path(run_dir).iterdir() if p.is_file()}

    steps: list[Step] = []
    produced: set[str] = set()
    for stage in stages:
        inputs = {
            name: PRESENT if name in available
            else PRODUCED if name in produced
            else MISSING
            for name in stage.requires
        }
        steps.append(Step(stage, inputs))
        produced |= set(stage.produces)
    return steps


def unsatisfied(steps: list[Step]) -> list[str]:
    """Human-readable reasons the sequence cannot complete, empty if it can."""
    reasons = []
    for step in steps:
        for name, state in sorted(step.inputs.items()):
            if state == MISSING:
                producer = next(
                    (s.name for s in STAGES.values() if name in s.produces), "?"
                )
                reasons.append(
                    f"{step.stage.name} needs {name}, which is not in the run "
                    f"directory and no earlier step produces it "
                    f"(it comes from `{producer}`)"
                )
    return reasons
