"""Oracle-guided mode (``--oracle``): hand the pipeline a target's documented
vulnerabilities (``targets/<name>/oracle.md``, prose about the application) and measure
what it still confirms — a CEILING, never a detection number.

The gap from the blind run is the "detectable but missed" set. Kept honest by rule: a
ceiling run never shares a table with a blind one (every artifact carries
``oracle_guided: true``), the oracle text carries no rule id / verdict / finding id (which
is why it is prose, not the ``cve-markers.yml`` answer key), and one source per target is
read identically by triage / synthesis / verification. → DECISIONS.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import prompts
from dast_orchestrator.adapters import targets

#: One file per target, beside ``target.yml`` and ``cve-markers.yml``. Found by
#: convention rather than named in ``target.yml``: a target directory is already
#: "everything this target needs", and a path in YAML would be one more thing to
#: keep in step for no choice anyone wants to make.
ORACLE_FILENAME = "oracle.md"

#: The three stages that can be given the oracle. Each reads the *same* text and
#: is told what to do with it *in its stage* — see :data:`STAGE_PROMPTS`.
STAGES = ("screening", "synthesis", "verify")

#: Stage name -> the prompt that tells that stage what to do with the shared
#: facts. **Versioned files under ``prompts/``, not constants here**, and for
#: the reason every other prompt in this project is: they are sent verbatim to a
#: model, a change to one changes what a run measured, and a constant a person
#: edits in place is a convention rather than a mechanism. A ceiling run records
#: which version of each it sent.
#:
#: Per-stage instruction, shared evidence. The alternative — a hand-written
#: briefing per stage carrying its own facts — would make each stage's ceiling
#: depend on how well its own briefing was phrased, and the whole point of the
#: mode is that the knowledge is held constant while the stage varies.
#:
#: Each one is also a *restraint*. The failure mode of oracle mode is a model
#: that stops analysing and starts agreeing: told a bug exists, it confirms
#: everything, the ceiling reads 100%, and the number means nothing. Every
#: prompt therefore says what the knowledge does not license, and
#: ``tests/unit/test_oracle.py`` fails if one does not.
STAGE_PROMPTS: dict[str, str] = {
    "screening": "oracle-screening",
    "synthesis": "oracle-synthesis",
    "verify": "oracle-verify",
}


def instruction(stage: str) -> "prompts.Prompt":
    """The oracle block for one stage — an unversioned prompt (:func:`prompts.load_oracle`)."""
    if stage not in STAGE_PROMPTS:
        raise OracleError(f"unknown oracle stage {stage!r}; known: {STAGES}")
    return prompts.load_oracle(STAGE_PROMPTS[stage])


#: Said in every block, whatever the stage. The one sentence that keeps a
#: ceiling run from being read as a detection run by whoever opens the artifact.
PROVENANCE_NOTE = (
    "This information came from the target's documented vulnerabilities, not "
    "from the scan. This run is measuring an upper bound on what this pipeline "
    "could detect WITH prior knowledge; its numbers are a ceiling and are never "
    "comparable with a blind run's detection rate."
)


class OracleError(RuntimeError):
    """Raised when ``--ceiling`` is asked for and the target has no oracle."""


def path_for(target: "targets.Target | None") -> "Path | None":
    """Where this target's oracle document lives, whether or not it exists.

    Derived from the target's name rather than stored on it, which is safe
    because :func:`~dast_orchestrator.adapters.targets.load_target` refuses a definition
    whose ``name:`` disagrees with its directory.
    """
    name = getattr(target, "name", None)
    if not name:
        return None
    return targets.TARGETS_DIR / str(name) / ORACLE_FILENAME


def load(target: "targets.Target | None") -> "str | None":
    """The target's oracle document, or ``None`` when it has none.

    ``None`` rather than an exception, because "this target has no documented
    vulnerability write-up" is an ordinary state — a target added for coverage
    rather than for ground truth has nothing to say here. The stages turn it
    into a hard error only when ``--ceiling`` was explicitly asked for, which is
    the one situation where silently running blind would produce a number
    labelled as a ceiling that is nothing of the kind.
    """
    path = path_for(target)
    if path is None or not path.is_file():
        return None
    text = path.read_text().strip()
    return text or None


def require(target: "targets.Target | None") -> str:
    """The oracle document, or an actionable error naming where it should be."""
    text = load(target)
    if text is None:
        name = getattr(target, "name", "?")
        expected = path_for(target) or f"targets/{name}/{ORACLE_FILENAME}"
        raise OracleError(
            f"--ceiling was requested but target {name!r} has no oracle "
            f"document at {expected}. Oracle-guided mode measures a detection "
            "ceiling against the target's documented vulnerabilities; without "
            "them there is nothing to measure a ceiling against, and running "
            "blind would produce a number labelled a ceiling that is not one."
        )


def block(target: "targets.Target | None", stage: str) -> "dict[str, Any] | None":
    """The oracle block one stage's prompt carries, or ``None`` when off.

    :param stage: one of :data:`STAGES`.
    :raises OracleError: on an unknown stage — a typo here would silently strip
        the instruction and leave the facts, which is the one shape of this
        block that teaches a model nothing but to agree.
    """
    prompt = instruction(stage)
    text = load(target)
    if text is None:
        return None
    return {
        "mode": "oracle-guided (ceiling)",
        "what_this_is": PROVENANCE_NOTE,
        "how_to_use_it_here": prompt.text,
        # Which file said so, so a stored artifact can be traced to the wording
        # that produced it even after the file moves — the same rule every other
        # prompt in this pipeline follows.
        "instruction_prompt": prompt.name,
        "known_vulnerabilities": text,
    }
