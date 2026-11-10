"""SAST: one-shot ``docker run --rm`` of the pinned Semgrep over the source tree Noir
analyses, emitting SARIF to ``semgrep.sarif.json``. Standalone by design — see
:mod:`dast_orchestrator.stages.static_analysis`.

The ruleset is the reproducibility problem, not the image: instead of fetching from the
registry at run time it mounts a commit-pinned ``semgrep-rules`` checkout
(:data:`RULES_COMMIT`) read-only. Which rule directories run is target data
(``source_analysis.semgrep_rulesets``), and the container gets ``--network none`` so it
cannot quietly change between runs. → DECISIONS.md.
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from . import (
    StaticAnalysisError,
    ToolRun,
    cwe_ids,
    docker_run,
    parse_sarif_stdout,
    rule_index,
    sarif_results,
    sarif_rules,
    top_rules,
)

#: Pinned, native linux/arm64. Never ``:latest``.
SEMGREP_IMAGE = "semgrep/semgrep:1.140.0"

RULES_REPO = "https://github.com/semgrep/semgrep-rules"
#: The pinned ruleset. ``semgrep-rules`` has no release tags, so the pin is a
#: commit on ``develop`` — fetched by SHA, which GitHub allows.
RULES_COMMIT = "40b8c63f75dc7c22c8a77482d73bfb864b146f7e"
#: Where the checkout is expected, relative to the repo root. Gitignored, like
#: a target's ``src/``: reproducible from :data:`RULES_COMMIT`.
#:
#: Under ``static-analysis-cache/`` with the OSV snapshot, because the two are one
#: the *other* scanners this project's DAST result is read against — and a
#: reader looking for "what do we compare with" should find one directory rather
#: than two repo-root siblings that happen to be adjacent alphabetically.
RULES_DIR_NAME = "static-analysis-cache/semgrep-rules"

#: Semgrep exits 1 when it found something. Anything else is a real failure.
_OK_EXIT_CODES = (0, 1)

#: ``"Ran 262 rules on 3632 files: 346 findings."`` on stderr — the only place
#: Semgrep reports how many files it actually looked at (the SARIF does not).
_RAN_RE = re.compile(r"Ran (\d+) rules? on (\d+) files?: (\d+) findings?")


def rules_checkout_commands(rules_dir: Path) -> str:
    """The exact commands that produce the pinned ruleset checkout.

    Quoted verbatim in the error a missing checkout raises and in the docs, so
    there is one authoritative form of this instruction.
    """
    return (
        f"git init {rules_dir.name} && cd {rules_dir.name} && "
        f"git remote add origin {RULES_REPO} && "
        f"git fetch --depth 1 origin {RULES_COMMIT} && "
        f"git checkout FETCH_HEAD"
    )


def rules_commit(rules_dir: Path) -> str | None:
    """The commit actually checked out, or ``None`` if it cannot be read.

    Recorded next to :data:`RULES_COMMIT` rather than assumed equal to it: a
    number produced by a ruleset that had drifted from the pin must be visible
    as such, not silently attributed to the pin.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(rules_dir), "rev-parse", "HEAD"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - platform
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode().strip() or None


def config_args(rulesets: Iterable[str]) -> list[str]:
    """``["go", "javascript"]`` -> ``["--config", "/rules/go", ...]``.

    A ruleset is a directory under the pinned checkout, so it is spelled as a
    container path and never as a registry shorthand (``p/golang``), which would
    reintroduce the network dependency this module exists to remove.
    """
    args: list[str] = []
    for ruleset in rulesets:
        name = str(ruleset).strip().strip("/")
        if not name:
            continue
        if name.startswith("p/") or name.startswith("r/"):
            raise StaticAnalysisError(
                f"ruleset {ruleset!r} is a Semgrep registry pack; this pass runs "
                f"only directories of the pinned checkout (e.g. 'go', 'javascript')."
            )
        args += ["--config", f"/rules/{name}"]
    if not args:
        raise StaticAnalysisError(
            "no Semgrep rulesets declared; add source_analysis.semgrep_rulesets "
            "to the target's YAML (e.g. [go, javascript])."
        )
    return args


def build_command(
    source_dir: Path,
    rules_dir: Path,
    rulesets: Iterable[str],
    image: str = SEMGREP_IMAGE,
) -> tuple[list[str], list[str], list[str]]:
    """Build ``(volumes, env, semgrep argv)`` for :func:`docker_run`.

    Split out so tests can assert the invocation without a container and the
    writeup can quote it. Notable flags: both mounts are read-only (an analyser
    must not mutate what it analyses), ``--metrics=off`` and
    ``--disable-version-check`` remove Semgrep's two outbound calls, and the
    working directory is the source root with ``.`` as the target so SARIF URIs
    are repository-relative rather than carrying the container's ``/src``.
    """
    volumes = [
        f"{source_dir.resolve()}:/src:ro",
        f"{rules_dir.resolve()}:/rules:ro",
    ]
    # Semgrep writes a cache under $HOME and warns on every run without one.
    env = ["HOME=/tmp"]
    args = [
        "semgrep",
        "--metrics=off",
        "--disable-version-check",
        "--sarif",
        *config_args(rulesets),
        ".",
    ]
    return volumes, env, args


def run_semgrep(
    source_dir: Path,
    rules_dir: Path,
    rulesets: Iterable[str],
    image: str = SEMGREP_IMAGE,
    timeout: float = 3600.0,
) -> tuple[dict[str, Any], ToolRun]:
    """Run Semgrep once and return ``(SARIF, the run it came from)``."""
    if not source_dir.is_dir():
        raise StaticAnalysisError(
            f"source tree not found: {source_dir}\n"
            "Clone the pinned target source first, e.g.\n"
            "  git clone --depth 1 --branch v1.16.0 "
            "https://github.com/go-gitea/gitea targets/gitea/src"
        )
    if not rules_dir.is_dir():
        raise StaticAnalysisError(
            f"pinned Semgrep ruleset not found: {rules_dir}\n"
            "Fetch it once (it is gitignored, like the target source):\n"
            f"  {rules_checkout_commands(rules_dir)}"
        )

    volumes, env, args = build_command(source_dir, rules_dir, rulesets, image)
    run = docker_run(
        image, args, timeout=timeout, volumes=volumes, env=env, workdir="/src"
    )
    if not run.timed_out and run.exit_code not in _OK_EXIT_CODES:
        raise StaticAnalysisError(
            f"semgrep exited {run.exit_code}: {run.stderr[-600:]}"
        )
    return parse_sarif_stdout(run, "semgrep"), run


# -- derived numbers -------------------------------------------------------


def summarise(sarif: dict[str, Any], run: ToolRun | None = None) -> dict[str, Any]:
    """Distil the stored SARIF into the numbers the comparison needs.

    Everything here is computed *from the artifact*, so it can be recomputed
    from what is on disk and can never disagree with it.

    The ``security_findings`` split is the reason the whole language ruleset is
    run: Semgrep tags its own rules, so the security subset — the part
    comparable with a DAST scan — is recoverable without a second run, while
    correctness and best-practice findings stay counted rather than discarded.
    ``by_cwe`` is the axis on which SAST and DAST findings are directly
    comparable at all; ZAP alerts carry CWE ids too.
    """
    results = sarif_results(sarif)
    rules = rule_index(sarif)

    security = 0
    cwes: Counter[str] = Counter()
    levels: Counter[str] = Counter()
    for result in results:
        rule = rules.get(str(result.get("ruleId", "")), {})
        tags = [str(t) for t in ((rule.get("properties") or {}).get("tags") or [])]
        if "security" in tags:
            security += 1
        for cwe in cwe_ids(rule):
            cwes[cwe] += 1
        # Semgrep puts the severity on the *rule* (``defaultConfiguration``) and
        # omits it on the result, which SARIF permits; reading only the result
        # would report every finding as unrated.
        levels[str(
            result.get("level")
            or (rule.get("defaultConfiguration") or {}).get("level")
            or "none"
        )] += 1

    summary: dict[str, Any] = {
        "findings": len(results),
        "security_findings": security,
        "rules_loaded": len(sarif_rules(sarif)),
        "rules_with_findings": len({str(r.get("ruleId", "")) for r in results}),
        "files_with_findings": len({
            (loc.get("physicalLocation", {}).get("artifactLocation", {}) or {}).get("uri")
            for r in results
            for loc in (r.get("locations") or [])
        } - {None}),
        "by_level": dict(levels),
        "by_cwe": dict(cwes.most_common()),
        "top_rules": top_rules(results),
        # Files Semgrep actually scanned: not in the SARIF, only on stderr. Left
        # null when the line is absent rather than back-filled with a guess.
        "files_scanned": None,
        "rules_run": None,
    }
    if run is not None:
        match = _RAN_RE.search(run.stderr)
        if match:
            summary["rules_run"] = int(match.group(1))
            summary["files_scanned"] = int(match.group(2))
    return summary


def provenance(
    sarif: dict[str, Any],
    run: ToolRun,
    rules_dir: Path,
    rulesets: Iterable[str],
    image: str = SEMGREP_IMAGE,
) -> dict[str, Any]:
    """What produced these numbers: image, tool version, ruleset identity.

    ``rules_commit`` is what was on disk; ``rules_commit_pinned`` is what should
    have been, and ``rules_pinned`` says whether they agreed — a drifted
    checkout is a fact about the run, not something to correct silently.
    """
    from dast_orchestrator.foundation import metrics

    driver = (sarif.get("runs") or [{}])[0].get("tool", {}).get("driver", {})
    actual = rules_commit(rules_dir)
    return {
        "image": image,
        "image_digest": metrics.docker_image_digest(image),
        "version": driver.get("semanticVersion") or driver.get("version"),
        "driver_name": driver.get("name"),
        "rules_repo": RULES_REPO,
        "rules_commit_pinned": RULES_COMMIT,
        "rules_commit": actual,
        "rules_pinned": actual == RULES_COMMIT if actual else None,
        "rulesets": list(rulesets),
        "network": "none",
        "command": run.command,
        "exit_code": run.exit_code,
    }
