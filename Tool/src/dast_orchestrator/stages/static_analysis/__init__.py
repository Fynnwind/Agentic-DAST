"""SAST + SCA static-analysis findings, standalone: Semgrep and OSV-Scanner over the target's
``src/`` (the tree Noir reads), emitting SARIF into ``data/`` for the SAST↔DAST and
SCA↔DAST cross-sections.

Not a pipeline stage: nothing is dispatched, correlated, verified or fed to a model, no key
is read, and there is deliberately no feedback loop (these findings do not direct the DAST
scan) — only project infrastructure (``run_paths``/``metrics``/``targets``) is shared. Both
tools run offline (``--network none``) so a number is re-runnable — Semgrep's rules are a
pinned checkout, OSV reads a hashed snapshot — and raw output is written unmodified.
→ DECISIONS.md.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

__all__ = [
    "StaticAnalysisError",
    "ToolRun",
    "docker_run",
    "parse_sarif_stdout",
    "empty_sarif",
    "sarif_results",
    "sarif_rules",
    "rule_index",
    "cwe_ids",
    "top_rules",
]


class StaticAnalysisError(RuntimeError):
    """Raised when a static-analysis tool could not run or did not return SARIF."""


@dataclass(frozen=True)
class ToolRun:
    """One ``docker run`` of a static-analysis tool, before any interpretation.

    :param argv: the exact command executed, kept so the artifact can quote a
        reproducible invocation.
    :param exit_code: the container's exit status, or ``None`` if the timeout
        killed it. Interpreting it is the tool's business — OSV-Scanner exits 1
        for "vulnerabilities found", which is a success, not a failure.
    """

    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False

    @property
    def command(self) -> str:
        return " ".join(self.argv)


def docker_run(
    image: str,
    args: list[str],
    *,
    timeout: float,
    volumes: Iterable[str] = (),
    env: Iterable[str] = (),
    workdir: str | None = None,
    network: str = "none",
) -> ToolRun:
    """Run one pinned analyser image once and capture stdout/stderr.

    The one-shot ``docker run --rm`` idiom of :mod:`~dast_orchestrator.adapters.noir_runner`:
    a batch analyser has no daemon, so a compose service would only idle, and
    keeping the invocation in Python rather than YAML is what lets the writeup
    quote the exact command.

    :param network: ``"none"`` by default — a static-analysis pass that can reach the
        network is one that can silently change between runs. Callers
        override it only for the one-off database download.
    """
    if not shutil.which("docker"):
        raise StaticAnalysisError("docker is not on PATH; both tools run in containers.")
    argv = ["docker", "run", "--rm", "--network", network]
    for volume in volumes:
        argv += ["-v", volume]
    for assignment in env:
        argv += ["-e", assignment]
    if workdir:
        argv += ["-w", workdir]
    argv += [image, *args]

    started = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return ToolRun(
            argv,
            None,
            (exc.stdout or b"").decode(errors="replace"),
            (exc.stderr or b"").decode(errors="replace"),
            round(time.monotonic() - started, 3),
            timed_out=True,
        )
    return ToolRun(
        argv,
        proc.returncode,
        proc.stdout.decode(errors="replace"),
        proc.stderr.decode(errors="replace"),
        round(time.monotonic() - started, 3),
    )


def parse_sarif_stdout(run: ToolRun, tool: str) -> dict[str, Any]:
    """Parse a tool's stdout as SARIF.

    Both tools write SARIF to stdout and progress to stderr, so nothing has to
    be mounted for output and the container needs no write access anywhere —
    the same reason :func:`~dast_orchestrator.adapters.noir_runner.run_noir` captures
    stdout instead of bind-mounting an output directory.
    """
    if run.timed_out:
        raise StaticAnalysisError(f"{tool} timed out after {run.seconds}s")
    try:
        sarif = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        tail = (run.stderr or run.stdout)[-600:]
        raise StaticAnalysisError(
            f"{tool} did not return SARIF on stdout (exit {run.exit_code}): {tail}"
        ) from exc
    if "runs" not in sarif:
        raise StaticAnalysisError(f"{tool} output has no 'runs' key: {list(sarif)[:5]}")
    return sarif


#: SARIF 2.1.0 envelope, matching the shape both tools emit (OASIS schema URI).
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def empty_sarif(tool: str) -> dict[str, Any]:
    """A valid, result-free SARIF 2.1.0 document for a tool that ran but had
    nothing to analyse — e.g. osv-scanner on a manifest-free tree (no SCA
    surface). Lets the readers below return zero uniformly instead of a caller
    treating "nothing to scan" as a failure; the empty document is the honest
    record that the scan ran and found no advisories.
    """
    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [{"tool": {"driver": {"name": tool, "rules": []}}, "results": []}],
    }


# -- SARIF readers ---------------------------------------------------------
#
# Small, shared and read-only: the derived numbers in a run's metrics record are
# computed from the stored SARIF, never from a parallel bookkeeping structure
# that could disagree with it.


def sarif_results(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for run in sarif.get("runs", []) for r in run.get("results", [])]


def sarif_rules(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        rule
        for run in sarif.get("runs", [])
        for rule in (run.get("tool", {}).get("driver", {}).get("rules") or [])
    ]


def rule_index(sarif: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {rule["id"]: rule for rule in sarif_rules(sarif) if "id" in rule}


#: ``"CWE-79: Improper Neutralization ..."`` — Semgrep's tag form. Matched
#: rather than split so a tag that merely mentions a CWE elsewhere is ignored.
_CWE_RE = re.compile(r"^CWE-(\d+)")


def cwe_ids(rule: dict[str, Any]) -> list[str]:
    """CWE identifiers a rule declares, as ``["CWE-89", ...]``.

    The one axis on which a SAST rule and a ZAP alert are directly comparable:
    both label their findings with CWEs, while rule ids, names and severities
    are each tool's own vocabulary.
    """
    tags = (rule.get("properties") or {}).get("tags") or []
    found = []
    for tag in tags:
        match = _CWE_RE.match(str(tag))
        if match:
            found.append(f"CWE-{match.group(1)}")
    return found


def top_rules(results: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """The rules that produced the most findings, most first."""
    counts = Counter(str(r.get("ruleId", "")) for r in results)
    return [{"rule_id": rid, "findings": n} for rid, n in counts.most_common(limit)]
