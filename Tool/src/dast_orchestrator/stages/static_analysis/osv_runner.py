"""SCA: one-shot ``docker run --rm`` of the pinned OSV-Scanner over the source tree Noir
analyses, emitting SARIF to ``osv.sarif.json``. Standalone by design — see
:mod:`dast_orchestrator.stages.static_analysis`.

The one pass whose findings are not about the target's own code: it checks the dependency
sets against the OSV database — the third population the thesis compares (DAST reachable,
SAST first-party, SCA third-party), where little overlap is the expected result.
Reproducibility is about the database, not the image: it reads a downloaded snapshot (hashed
into provenance), run with ``--offline-vulnerabilities`` + ``--network none``.
→ DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import (
    StaticAnalysisError,
    ToolRun,
    docker_run,
    empty_sarif,
    parse_sarif_stdout,
    rule_index,
    sarif_results,
    top_rules,
)

#: Pinned, native linux/arm64. Never ``:latest``.
OSV_IMAGE = "ghcr.io/google/osv-scanner:v2.0.2"

#: Host directory holding the OSV database snapshot, relative to the repo root.
#: Gitignored (it is ~230MB of downloaded zips) and mounted at the cache path
#: the scanner reads.
#: Under ``static-analysis-cache/`` with the pinned Semgrep ruleset: the two are
#: category — the *other* scanners the DAST result is read against — so
#: "what do we compare with" is one directory, not two repo-root siblings.
DB_DIR_NAME = "static-analysis-cache/osv-db"
#: Where the scanner looks inside the container: ``<cache>/osv-scanner/<eco>/all.zip``.
DB_MOUNTPOINT = "/root/.cache"
_DB_SUBDIR = "osv-scanner"

#: 0 = nothing found, 1 = vulnerabilities found. Both are successful scans;
#: only other codes are failures. (Reading 1 as failure would turn every real
#: result into an error.)
_OK_EXIT_CODES = (0, 1)

#: osv-scanner exits 128 on a tree with no manifests at all (WordPress + the WPDM
#: plugin is pure PHP — no lockfile, so no SCA surface). It writes no SARIF and
#: says so on stderr. That is an empty success, not a failure: gated on the exact
#: message so a genuine 128 still raises.
_NO_PACKAGE_SOURCES_EXIT = 128
_NO_PACKAGE_SOURCES_MESSAGE = "no package sources found"


def _is_no_package_sources(run: ToolRun) -> bool:
    return (
        run.exit_code == _NO_PACKAGE_SOURCES_EXIT
        and _NO_PACKAGE_SOURCES_MESSAGE in (run.stderr or "").lower()
    )

#: ``"Package 'minimatch@3.0.4' is vulnerable to 'CVE-...'"`` — the package
#: identity lives only in the message text; the SARIF rule carries the advisory.
_PACKAGE_RE = re.compile(r"Package '([^']+)' is vulnerable")

#: CVSS v3 qualitative bands, applied to the ``security-severity`` score
#: OSV-Scanner puts on each rule. Named here so the buckets in the summary are
#: the standard ones and not an invention of this file.
_SEVERITY_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"))


def db_dir_default(repo_root: Path) -> Path:
    return repo_root / DB_DIR_NAME


def build_command(
    source_dir: Path,
    db_dir: Path,
    image: str = OSV_IMAGE,
    download: bool = False,
) -> tuple[list[str], list[str]]:
    """Build ``(volumes, osv-scanner argv)``.

    :param download: build the *database refresh* invocation instead of the scan
        one. It is the only mode that needs the network, so it is a separate,
        explicitly requested command rather than a fallback inside the scan.
    """
    volumes = [
        f"{source_dir.resolve()}:/src:ro",
        f"{db_dir.resolve()}:{DB_MOUNTPOINT}",
    ]
    args = [
        "scan", "source", "-r",
        "--offline-vulnerabilities",
        "--no-call-analysis", "all",
        "--format", "sarif",
    ]
    if download:
        args.insert(3, "--download-offline-databases")
    args.append("/src")
    return volumes, args


def database_files(db_dir: Path) -> list[Path]:
    """The downloaded ``all.zip`` snapshots, one per ecosystem."""
    root = db_dir / _DB_SUBDIR
    if not root.is_dir():
        return []
    return sorted(root.glob("*/all.zip"))


def database_provenance(db_dir: Path) -> list[dict[str, Any]]:
    """Identify the advisory snapshot exactly: ecosystem, size, hash, date.

    A scanner version alone does not pin an SCA result — the database does. The
    hash is what makes "the same database" checkable rather than assumed.
    """
    entries = []
    for path in database_files(db_dir):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        stat = path.stat()
        entries.append({
            "ecosystem": path.parent.name,
            "bytes": stat.st_size,
            "sha256": digest.hexdigest(),
            "downloaded_at": datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat(),
        })
    return entries


def download_database(
    source_dir: Path,
    db_dir: Path,
    image: str = OSV_IMAGE,
    timeout: float = 1800.0,
) -> ToolRun:
    """Fetch the OSV database snapshot into ``db_dir`` (the one networked step).

    Runs the scanner with ``--download-offline-databases`` on the default bridge
    network; which ecosystems land there follows from the manifests found in
    ``source_dir``. Its scan output is discarded — this call exists for its side
    effect on the cache, and the recorded run is always the offline one.
    """
    db_dir.mkdir(parents=True, exist_ok=True)
    volumes, args = build_command(source_dir, db_dir, image, download=True)
    return docker_run(image, args, timeout=timeout, volumes=volumes, network="bridge")


def run_osv(
    source_dir: Path,
    db_dir: Path,
    image: str = OSV_IMAGE,
    timeout: float = 1800.0,
) -> tuple[dict[str, Any], ToolRun]:
    """Run OSV-Scanner once, offline, and return ``(SARIF, the run)``."""
    if not source_dir.is_dir():
        raise StaticAnalysisError(f"source tree not found: {source_dir}")
    if not database_files(db_dir):
        raise StaticAnalysisError(
            f"no OSV database snapshot in {db_dir}. Download it once:\n"
            "  uv run analyze-run --refresh-db"
        )
    volumes, args = build_command(source_dir, db_dir, image)
    run = docker_run(image, args, timeout=timeout, volumes=volumes)
    if not run.timed_out and run.exit_code not in _OK_EXIT_CODES:
        if _is_no_package_sources(run):
            # No manifests => no SCA surface => no SARIF written. Record the
            # honest empty result so every target reads uniformly through
            # `summarise`/`provenance` instead of this one target erroring.
            return empty_sarif("osv-scanner"), run
        raise StaticAnalysisError(f"osv-scanner exited {run.exit_code}: {run.stderr[-600:]}")
    return parse_sarif_stdout(run, "osv-scanner"), run


# -- derived numbers -------------------------------------------------------


def severity_band(score: str | float | None) -> str:
    """Map a CVSS score onto its qualitative band, ``"unknown"`` when absent."""
    if score is None or score == "":
        return "unknown"
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    for threshold, name in _SEVERITY_BANDS:
        if value >= threshold:
            return name
    return "unknown"


def summarise(sarif: dict[str, Any], run: ToolRun | None = None) -> dict[str, Any]:
    """Distil the stored SARIF: advisories, affected packages, manifests.

    ``findings`` counts advisory-times-package pairs, which is what a SARIF
    result is here; ``advisories`` and ``packages`` are the two populations
    behind it and are reported separately because one vulnerable transitive
    package commonly carries several advisories.
    """
    results = sarif_results(sarif)
    rules = rule_index(sarif)

    packages: Counter[str] = Counter()
    manifests: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    for result in results:
        text = (result.get("message") or {}).get("text", "")
        match = _PACKAGE_RE.search(text)
        if match:
            packages[match.group(1)] += 1
        for location in result.get("locations") or []:
            uri = (location.get("physicalLocation", {})
                   .get("artifactLocation", {}) or {}).get("uri")
            if uri:
                manifests[uri] += 1
        rule = rules.get(str(result.get("ruleId", "")), {})
        severities[severity_band(
            (rule.get("properties") or {}).get("security-severity")
        )] += 1

    return {
        "findings": len(results),
        "advisories": len({str(r.get("ruleId", "")) for r in results}),
        "packages": len(packages),
        "by_severity": dict(severities),
        "by_manifest": dict(manifests),
        "top_packages": [
            {"package": name, "advisories": n} for name, n in packages.most_common(10)
        ],
        "top_advisories": top_rules(results),
    }


def provenance(
    sarif: dict[str, Any],
    run: ToolRun,
    db_dir: Path,
    image: str = OSV_IMAGE,
    refreshed: bool = False,
) -> dict[str, Any]:
    """What produced these numbers: image, scanner version, database snapshot."""
    from dast_orchestrator.foundation import metrics

    driver = (sarif.get("runs") or [{}])[0].get("tool", {}).get("driver", {})
    return {
        "image": image,
        "image_digest": metrics.docker_image_digest(image),
        "version": driver.get("semanticVersion") or driver.get("version"),
        "driver_name": driver.get("name"),
        "database": database_provenance(db_dir),
        "database_refreshed_this_run": refreshed,
        "call_analysis": False,
        "network": "none",
        "command": run.command,
        "exit_code": run.exit_code,
    }
