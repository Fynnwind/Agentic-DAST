"""The report's worklist read back over runs: read load, ZAP's risk against the chain, a CI gate, stability.

Reads only each run's ``report.sarif.json``, and skips a report written before the ``worklist_*``
properties rather than guess at it. Blind and ceiling never share a row, because a ceiling is
never a detection rate. None of this measures that the order brings a true finding up sooner.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pandas as pd

from .selection import default_valid
from .spread import TARGET_ORDER

ROLES = ("blind", "ceiling")
RISKS = ("High", "Medium", "Low", "Informational")
SECTIONS = ("reproduced", "open", "claims", "evident", "refuted", "informational")
#: SARIF level -> ZAP risk, the inverse of the report's own mapping.
_LEVEL_RISK = {"error": "High", "warning": "Medium", "note": "Low", "none": "Informational"}
_ZAP = "zap-mirror"
_TOP = 5


def _results(run_dir: str) -> list[dict[str, Any]] | None:
    """A run's SARIF results, or ``None`` if it has no report carrying the worklist."""
    path = Path(run_dir) / "report.sarif.json"
    if not path.is_file():
        return None
    results = json.loads(path.read_text())["runs"][0].get("results", [])
    if not all("worklist_section" in (r.get("properties") or {}) for r in results):
        return None
    return results


def _reports(index: pd.DataFrame) -> list[dict[str, Any]]:
    """One record per base scan execution with a worklist report, in target then run order."""
    if index.empty:
        return []
    valid = default_valid(index, corpus="all")
    scans = valid[valid["role"].isin(ROLES) & (valid["variant"] == "") & (valid["stage"] == "scan")]
    reports = []
    for row in scans.drop_duplicates("run_dir").to_dict("records"):
        results = _results(row["run_dir"])
        if results is not None:
            reports.append({**row, "results": results})
    return sorted(reports, key=lambda r: (_target_order(r["target"]), r["role"], r["run"]))


def _target_order(target: str) -> int:
    return TARGET_ORDER.index(target) if target in TARGET_ORDER else len(TARGET_ORDER)


def _groups(results: list[dict[str, Any]], section: str) -> set[str]:
    return {r["properties"]["worklist_group"] for r in results
            if r["properties"]["worklist_section"] == section}


def _is_high(result: dict[str, Any]) -> bool:
    return result["properties"].get("namespace") == _ZAP and result.get("level") == "error"


def worklist_runs(index: pd.DataFrame) -> pd.DataFrame:
    """Per run: how many results it reports, and how many lines a person reads for them."""
    rows = []
    for rep in _reports(index):
        results = rep["results"]
        count = pd.Series([r["properties"]["worklist_section"] for r in results]).value_counts()
        rows.append({
            "role": rep["role"], "target": rep["target"], "run": rep["run"],
            "results": len(results),
            "requires_triage": sum(r["properties"].get("disposition") == "requires-triage"
                                   for r in results),
            "open_lines": len(_groups(results, "open")),
            "open_claims": int(count.get("claims", 0)),
            "all_lines": len({r["properties"]["worklist_group"] for r in results}),
            "reproduced": int(count.get("reproduced", 0)),
        })
    columns = ["role", "target", "run", "results", "requires_triage", "open_lines",
               "open_claims", "all_lines", "reproduced"]
    return pd.DataFrame(rows, columns=columns)


def read_load(index: pd.DataFrame) -> pd.DataFrame:
    """Per role and target: results against the lines they roll up to, min and max over runs.

    A line is a rule to read, not one fix, so this says what the roll-up removes from a
    reader's list, not what was checked.
    """
    runs = worklist_runs(index)
    measures = ["results", "requires_triage", "open_lines", "open_claims", "all_lines"]
    columns = ["role", "target", "runs",
               *(f"{m}_{end}" for m in measures for end in ("min", "max"))]
    if runs.empty:
        return pd.DataFrame(columns=columns)
    rows = []
    for (role, target), group in runs.groupby(["role", "target"], sort=False):
        row = {"role": role, "target": target, "runs": len(group)}
        for measure in measures:
            row[f"{measure}_min"] = int(group[measure].min())
            row[f"{measure}_max"] = int(group[measure].max())
        rows.append(row)
    return pd.DataFrame(rows, columns=columns)


def risk_disposition(index: pd.DataFrame) -> pd.DataFrame:
    """Per role, target and ZAP risk: mean findings per run in each section. ZAP findings only.

    A refuted row counts what a tool did not reproduce, never that the finding is false.
    """
    columns = ["role", "target", "risk", "runs", "findings", *SECTIONS]
    reports = _reports(index)
    totals: dict[tuple, dict[str, int]] = {}
    runs: dict[tuple, int] = {}
    for rep in reports:
        key = (rep["role"], rep["target"])
        runs[key] = runs.get(key, 0) + 1
        for result in rep["results"]:
            if result["properties"].get("namespace") != _ZAP:
                continue
            risk = _LEVEL_RISK.get(result.get("level"), "Unknown")
            cell = totals.setdefault((*key, risk), {"findings": 0, **dict.fromkeys(SECTIONS, 0)})
            cell["findings"] += 1
            cell[result["properties"]["worklist_section"]] += 1
    rows = []
    for key, n_runs in runs.items():
        for risk in RISKS:
            cell = totals.get((*key, risk))
            if cell:
                rows.append({"role": key[0], "target": key[1], "risk": risk, "runs": n_runs,
                             **{name: round(value / n_runs, 1) for name, value in cell.items()}})
    return pd.DataFrame(rows, columns=columns)


def gate_simulation(index: pd.DataFrame) -> pd.DataFrame:
    """Per role and target: how many runs each CI gate would block, with an ``ALL`` row per role.

    A simulation over stored reports, not a platform test. A quiet gate is not a safe app: it
    says nothing about what the run never detected.
    """
    columns = ["role", "target", "runs", "any_high", "high_not_refuted", "tool_reproduced"]
    per_run = []
    for rep in _reports(index):
        results = rep["results"]
        per_run.append({
            "role": rep["role"], "target": rep["target"],
            "any_high": any(_is_high(r) for r in results),
            "high_not_refuted": any(_is_high(r) and r["properties"].get("disposition") != "refuted"
                                    for r in results),
            "tool_reproduced": any(r["properties"]["worklist_section"] == "reproduced"
                                   for r in results),
        })
    if not per_run:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(per_run)
    rows = []
    for role in ROLES:
        sub = frame[frame["role"] == role]
        if sub.empty:
            continue
        for target, group in [*sub.groupby("target", sort=False), ("ALL", sub)]:
            rows.append({"role": role, "target": target, "runs": len(group),
                         **{gate: int(group[gate].sum()) for gate in columns[3:]}})
    return pd.DataFrame(rows, columns=columns)


def _top_lines(results: list[dict[str, Any]]) -> list[str]:
    """A run's first open rule lines, in the report's order."""
    lines = {r["properties"]["worklist_group"]: r["properties"]["worklist_line"]
             for r in results if r["properties"]["worklist_section"] == "open"}
    return sorted(lines, key=lines.get)[:_TOP]


def _jaccard(left: set, right: set) -> float:
    return len(left & right) / len(left | right) if left | right else 1.0


def _open_ids(results: list[dict[str, Any]]) -> set[str]:
    return {r["properties"]["finding_id"] for r in results
            if r["properties"]["worklist_section"] == "open"}


def _finding_ids(results: list[dict[str, Any]]) -> set[str]:
    return {r["properties"]["finding_id"] for r in results
            if r["properties"].get("namespace") == _ZAP}


def open_stability(index: pd.DataFrame) -> pd.DataFrame:
    """Across blind runs of one configuration: raw alert spread against the open rule list.

    ``*_new_share`` is what a diff against the previous run would call new with nothing
    changed. Rule lines are coarse, so stability here is partly that coarseness: a rule line
    would also hide a new route.
    """
    columns = ["target", "digest", "runs", "alerts_min", "alerts_max", "finding_new_share",
               "open_new_share", "open_rules_new_max", "open_rule_jaccard_mean",
               "open_rule_jaccard_min", "top_jaccard_mean", "top_jaccard_min"]
    by_config: dict[tuple, list[dict[str, Any]]] = {}
    for rep in _reports(index):
        if rep["role"] == "blind":
            by_config.setdefault((rep["target"], rep["digest"]), []).append(rep)
    rows = []
    for (target, digest), reports in by_config.items():
        if len(reports) < 2:
            continue
        results = [rep["results"] for rep in reports]
        finding_new, open_new, rules_new = [], [], []
        for before, after in itertools.pairwise(results):
            finding_new.append(_new_share(_finding_ids(before), _finding_ids(after)))
            open_new.append(_new_share(_open_ids(before), _open_ids(after)))
            rules_new.append(len(_groups(after, "open") - _groups(before, "open")))
        rule_sets = [_groups(res, "open") for res in results]
        tops = [set(_top_lines(res)) for res in results]
        rule_pairs = [_jaccard(a, b) for a, b in itertools.combinations(rule_sets, 2)]
        top_pairs = [_jaccard(a, b) for a, b in itertools.combinations(tops, 2)]
        alerts = [rep.get("results.alerts") for rep in reports]
        known = [a for a in alerts if pd.notna(a)]
        rows.append({
            "target": target, "digest": digest, "runs": len(reports),
            "alerts_min": int(min(known)) if known else None,
            "alerts_max": int(max(known)) if known else None,
            "finding_new_share": round(sum(finding_new) / len(finding_new), 3),
            "open_new_share": round(sum(open_new) / len(open_new), 3),
            "open_rules_new_max": max(rules_new),
            "open_rule_jaccard_mean": round(sum(rule_pairs) / len(rule_pairs), 2),
            "open_rule_jaccard_min": round(min(rule_pairs), 2),
            "top_jaccard_mean": round(sum(top_pairs) / len(top_pairs), 2),
            "top_jaccard_min": round(min(top_pairs), 2),
        })
    return pd.DataFrame(rows, columns=columns)


def _new_share(before: set, after: set) -> float:
    return len(after - before) / len(after) if after else 0.0


def reproduced_first(index: pd.DataFrame) -> pd.DataFrame:
    """Per role and target: whether every reproduced result leads its report.

    True by construction of the sections, so this guards the order against a regression. It
    is not a measurement of how soon a person reaches a true finding.
    """
    columns = ["role", "target", "runs", "runs_with_reproduced", "reproduced_lines_max", "all_first"]
    per_run = []
    for rep in _reports(index):
        lines = sorted({r["properties"]["worklist_line"] for r in rep["results"]
                        if r["properties"]["worklist_section"] == "reproduced"})
        per_run.append({"role": rep["role"], "target": rep["target"], "lines": len(lines),
                        "first": lines == list(range(1, len(lines) + 1))})
    if not per_run:
        return pd.DataFrame(columns=columns)
    rows = []
    for (role, target), group in pd.DataFrame(per_run).groupby(["role", "target"], sort=False):
        rows.append({"role": role, "target": target, "runs": len(group),
                     "runs_with_reproduced": int((group["lines"] > 0).sum()),
                     "reproduced_lines_max": int(group["lines"].max()),
                     "all_first": bool(group["first"].all())})
    return pd.DataFrame(rows, columns=columns)
