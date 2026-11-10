"""G9: the SAST (Semgrep) and SCA (OSV) populations and their cross-section with DAST.

The comparable SAST subset is the ``security``-tagged findings, never the raw
total (grafana is 99 of 2340; the rest is i18n/correctness noise, and totals are
incommensurable across language stacks). The cross-section is by weakness class
(CWE): Semgrep flags hundreds of CWE-79 *source* findings that blind DAST confirms
none of — SAST sees the sink in source, DAST is bounded by reach + confirmation.
SCA scales with the dependency tree; wordpress has no scanned manifest, so OSV
no-ops (P4). G10's OOB record is never counted as a pipeline detection.

The SAST/SCA population summaries are read from the analysis stage record
(``analysis-metrics.json``), which is authoritative; the DAST side is computed
from the blind matrix so the join reflects what the pipeline actually confirmed.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pandas as pd

from .findings import load_triage
from .selection import apply_named, default_valid


def _norm_cwe(c: str) -> str:
    c = str(c)
    return c if c.upper().startswith("CWE-") else f"CWE-{c}"


def analysis_record(run_dir: Path | str) -> dict:
    return json.loads((Path(run_dir) / "analysis-metrics.json").read_text())


def _analysis_rows(index: pd.DataFrame) -> pd.DataFrame:
    rows = index[index["stage"] == "analysis"]
    if rows.empty:
        raise ValueError("selection contains no G9 analysis executions")
    return rows


def g9_populations(index: pd.DataFrame) -> pd.DataFrame:
    """Per-target SAST + SCA populations (the honest security-tagged SAST count)."""
    out = []
    for r in _analysis_rows(index).itertuples(index=False):
        rec = analysis_record(r.run_dir)
        res = rec.get("results", {})
        sem = res.get("semgrep") or {}
        osv = res.get("osv") or {}
        top_cwe = max(sem.get("by_cwe", {}).items(), key=lambda kv: kv[1], default=(None, 0))
        out.append(
            {
                "target": r.target,
                "sast_total": sem.get("findings"),
                "sast_security": sem.get("security_findings"),
                "sast_top_cwe": top_cwe[0],
                "sast_top_cwe_n": top_cwe[1],
                "sca_findings": osv.get("findings"),
                "sca_advisories": osv.get("advisories"),
                "sca_packages": osv.get("packages"),
                "sca_no_op": not bool(osv.get("findings")),
                "run": r.run,
            }
        )
    return pd.DataFrame(out).sort_values("target").reset_index(drop=True)


def sast_cwe(index: pd.DataFrame) -> pd.DataFrame:
    """Long table target × CWE of the security-tagged SAST findings."""
    out = []
    for r in _analysis_rows(index).itertuples(index=False):
        sem = analysis_record(r.run_dir).get("results", {}).get("semgrep") or {}
        for cwe, n in (sem.get("by_cwe") or {}).items():
            out.append({"target": r.target, "cwe": _norm_cwe(cwe), "sast_security": int(n)})
    return pd.DataFrame(out)


def dast_cwe(index: pd.DataFrame, confirmed_only: bool = False) -> pd.DataFrame:
    """Long table target × CWE from the blind matrix triage findings.

    ``confirmed_only`` restricts to findings whose verification outcome is
    ``confirmed`` (joined on finding_id) — blind confirms nothing, so that column
    is the honest zero the cross-section turns on.
    """
    blind = apply_named(index, "matrix-blind")
    counts: Counter = Counter()
    for r in blind[blind.stage == "triage"].itertuples(index=False):
        data = load_triage(r.run_dir, getattr(r, "artifact", None))
        confirmed_ids = _confirmed_finding_ids(r.run_dir) if confirmed_only else None
        for f in data.get("findings", []):
            cwe = (f.get("alert") or {}).get("cweid")
            if not cwe or str(cwe) == "-1":
                continue
            if confirmed_only and f.get("finding_id") not in confirmed_ids:
                continue
            counts[(r.target, _norm_cwe(cwe))] += 1
    col = "dast_confirmed" if confirmed_only else "dast_findings"
    # Blind confirms nothing, so the confirmed frame is empty — give it the join
    # columns anyway so the cross-section merge still works.
    return pd.DataFrame(
        [{"target": t, "cwe": c, col: n} for (t, c), n in counts.items()],
        columns=["target", "cwe", col],
    )


def _confirmed_finding_ids(run_dir: Path | str) -> set[str]:
    path = Path(run_dir) / "verification.json"
    if not path.exists():
        return set()
    ver = json.loads(path.read_text())
    ids: set[str] = set()
    for key in ("verifications", "correlated_verifications"):
        for v in ver.get(key, []):
            if v.get("outcome") == "confirmed" and v.get("finding_id"):
                ids.add(v["finding_id"])
    return ids


def sast_dast_cross(index: pd.DataFrame) -> pd.DataFrame:
    """Per target × CWE: SAST security vs DAST findings vs DAST confirmed.

    The load-bearing row is CWE-79: SAST in the hundreds, DAST confirmed 0.
    """
    sast = sast_cwe(index)
    dast = dast_cwe(index, confirmed_only=False)
    conf = dast_cwe(index, confirmed_only=True)
    merged = (
        sast.merge(dast, on=["target", "cwe"], how="outer")
        .merge(conf, on=["target", "cwe"], how="outer")
        .fillna(0)
    )
    for c in ("sast_security", "dast_findings", "dast_confirmed"):
        merged[c] = merged[c].astype(int)
    return merged.sort_values(["target", "sast_security"], ascending=[True, False]).reset_index(
        drop=True
    )


# --------------------------------------------------------------------------- #
# The handler-source join (RUN-PLAN §8 "joined on the handler source"):
# a DAST finding the pipeline REFUTED -> its endpoint's handler source files
# (Noir's endpoint->source map) -> Semgrep SARIF file locations. The cell that
# matters is Semgrep flagging the source *behind a refuted DAST finding*: SAST
# sees a sink in the handler that the dynamic probe could not confirm.
# --------------------------------------------------------------------------- #
def _repo_rel(path: str) -> str:
    """Container/host handler path -> repo-relative (to match SARIF uris).

    Noir records handler paths under the ``/src`` mount (``/src/routers/web/..``)
    while Semgrep's SARIF uris are relative to the repo root (``routers/web/..``),
    so the common key is the path after ``/src/``.
    """
    if "/src/" in path:
        return path.split("/src/", 1)[1]
    return path.lstrip("/")


def _endpoint_sources(run_dir: Path | str) -> dict[str, set[str]]:
    """endpoint_key -> {repo-relative handler source files} from the Noir context."""
    path = Path(run_dir) / "scan-noir-ai-context.json"
    if not path.exists():
        return {}
    ctx = json.loads(path.read_text())
    out: dict[str, set[str]] = {}
    for ep in ctx.get("endpoints", []):
        files: set[str] = set()
        for cp in ep.get("code_paths", []) or []:
            if cp.get("path"):
                files.add(_repo_rel(cp["path"]))
        ai = ep.get("ai_context") or {}
        for bucket in ("guards", "callees", "sources", "sinks", "validators", "signals"):
            for item in ai.get(bucket, []) or []:
                if item.get("path"):
                    files.add(_repo_rel(item["path"]))
        if ep.get("key"):
            out[ep["key"]] = files
    return out


def _semgrep_files(run_dir: Path | str) -> dict[str, set[str]]:
    """repo-relative file -> {CWE} from the Semgrep SARIF of a G9 analysis run."""
    path = Path(run_dir) / "semgrep.sarif.json"
    if not path.exists():
        return {}
    sarif = json.loads(path.read_text())
    out: dict[str, set[str]] = {}
    for run in sarif.get("runs", []):
        rules = {
            r.get("id"): r
            for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", [])
        }
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                uri = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                if not uri:
                    continue
                cwes = _result_cwes(res, rules.get(res.get("ruleId"), {}))
                out.setdefault(uri, set()).update(cwes)
    return out


def _result_cwes(result: dict, rule: dict) -> set[str]:
    """Pull any CWE tags off a SARIF result / its rule metadata."""
    cwes: set[str] = set()
    for tag in (rule.get("properties", {}) or {}).get("tags", []) or []:
        if str(tag).upper().startswith("CWE-"):
            cwes.add(str(tag).split(":")[0])
    return cwes


def handler_source_join(index: pd.DataFrame) -> pd.DataFrame:
    """Per (target, auth): refuted DAST findings whose handler source Semgrep flags.

    For each blind cell, the verification-refuted findings are mapped through the
    scan's Noir endpoint->source context to their handler files, then intersected
    with the files Semgrep flagged for that target (its G9 analysis run). The
    headline is ``refuted_source_in_sast`` -- a DAST false positive sitting on a
    handler Semgrep independently flags. In this corpus it is ~0: the refuted
    findings either carry no endpoint (unmatched ZAP alerts -- wordpress) or
    resolve (via Noir) to the route-registration file rather than the handler
    Semgrep flags (Go/chi -- gitea). ``refuted_mapped`` carries that attrition so
    the zero reads as the join's finding, not a silent miss.

    One row per blind matrix cell (the G3 repeats share a cell, so are excluded).
    """
    blind = apply_named(index, "matrix-blind")
    analyses = default_valid(index)
    analyses = analyses[analyses["stage"] == "analysis"]
    sem_by_target = {
        t: _semgrep_files(analyses[analyses["target"] == t]["run_dir"].iloc[0])
        for t in analyses["target"].dropna().unique()
    }
    out = []
    for r in blind[blind["stage"] == "verify"].itertuples(index=False):
        ver = json.loads((Path(r.run_dir) / "verification.json").read_text())
        refuted = {x["finding_id"] for x in ver.get("verifications", []) if x.get("outcome") == "refuted"}
        if not refuted:
            out.append({"target": r.target, "auth": r.auth, "refuted": 0, "refuted_mapped": 0, "refuted_source_in_sast": 0})
            continue
        # The endpoint map comes from this cell's triage.json (the verify row's
        # own ``artifact`` is verification.json); blind cells are all variant=''.
        tri = load_triage(r.run_dir, "triage.json")
        ep_of = {f["finding_id"]: f.get("endpoint_key") for f in tri.get("findings", []) if f.get("finding_id")}
        ep_sources = _endpoint_sources(r.run_dir)
        sem_files = sem_by_target.get(r.target, {})

        mapped = in_sast = 0
        for fid in refuted:
            sources = ep_sources.get(ep_of.get(fid) or "", set())
            if sources:
                mapped += 1
            if sources & set(sem_files):
                in_sast += 1
        out.append(
            {
                "target": r.target,
                "auth": r.auth,
                "refuted": len(refuted),
                "refuted_mapped": mapped,
                "refuted_source_in_sast": in_sast,
            }
        )
    return pd.DataFrame(out).sort_values(["target", "auth"]).reset_index(drop=True)
