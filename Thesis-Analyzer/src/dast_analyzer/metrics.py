"""The RUN-PLAN §9 metric definitions (the authority; implemented, not restated).

Spread, the NFR-02 durations and the NFR-05 scanner memory, and cost-per-finding.
Spread and the durations run off the index; memory and the no-cache cost need the
sub-stage detail the index flattens away (per-container resources, per-sub-stage
token tallies and their distinct models), so those two re-open the raw stage
record from the run dir — located, like the index, by ``run_dir`` + ``suffix``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .prices import computed_cost
from .selection import apply_named, default_valid, group_by

# NFR-02: the whole chain should finish inside 30 minutes; NFR-05 watches the
# scanner container's peak. The chain is scan → triage → verify → report of one
# real end-to-end pass (the minting matrix cells; the model-stage re-runs share a
# stored scan and would double-count it, so the chain is the ``variant=''`` rows).
NFR_02_SECONDS = 30 * 60
NFR_05_SCANNER_CONTAINER = "dast-zap"
CHAIN_STAGES = ("scan", "triage", "verify", "report")

# One "configuration" for Spread: the axes that pin a cell. ``role`` is load-
# bearing — ``variant='rep'`` spans both blind reps and ceiling reps, so a spread
# that dropped ``role`` would merge two configurations (the gitea verify reps are
# the standing example: blind reps confirm 0/0/0/2, ceiling reps 1/2).
CONFIG_KEYS = ["campaign", "target", "auth", "role", "variant_family", "stage"]

# Which config field names the model of each triage/verify sub-stage, for the
# no-cache re-pricing (each sub-stage bills a different model).
_SUBSTAGE_MODEL = {
    "llm_screening": "screening_model",
    "llm_synthesis": "synthesis_model",
    "dispatch": "model",
}


# --------------------------------------------------------------------------- #
# Spread (§9) — "a difference smaller than the spread is not a difference"
# --------------------------------------------------------------------------- #
def spread(
    df: pd.DataFrame, metrics: list[str], by: list[str] | None = None
) -> pd.DataFrame:
    """n / min / max / mean of ``metrics`` per configuration (§9 Spread)."""
    return group_by(df, by or CONFIG_KEYS, metrics)


def within_spread(delta: float, span: float) -> bool:
    """The §9 yardstick: a between-config delta no larger than the within-config
    span (max − min of the reference's repeats) is reported as no effect."""
    return abs(delta) <= abs(span)


def model_stage_spread(index: pd.DataFrame) -> pd.DataFrame:
    """G5 error bars: the model-stage spread on a fixed scan (README cut #4).

    Over the ``rep`` repeats, per (target, auth, role, stage). The deterministic
    quantities (``findings``, ``llm_findings_asked``) are flat by construction;
    the moving one is synthesis ``correlated_findings`` (the ±3–6 band every
    synthesis claim is reported with) and, at verify, the confirmed/refuted/
    inconclusive counts.
    """
    reps = apply_named(index, "reference-model-repeats")
    metrics = [
        "results.findings",
        "results.correlated_findings",
        "results.llm_rescans",
        "results.dispatched",
        "results.confirmed",
        "results.refuted",
        "results.inconclusive",
    ]
    present = [m for m in metrics if m in reps.columns]
    return spread(reps, present, by=["target", "auth", "role", "stage"])


def alert_volume_vs_detection(index: pd.DataFrame) -> pd.DataFrame:
    """README cut #3: alert volume as a range, detection as a point, per target.

    Alerts (and triage findings) over the G3 reference repeats become min/max/
    mean; detection is the blind ladder's per-target figure (0 everywhere), so
    the table carries a range beside a point. Triage ``findings`` is reported too
    because it is far steadier than raw alerts.
    """
    from .markers import blind_vs_ceiling

    scans = apply_named(index, "reference-scans")  # user-blind scan, 3 reps/target
    cell = default_valid(index)
    cell = cell[
        (cell["auth"] == "user")
        & (cell["role"] == "blind")
        & (cell["variant"] == "")
        & (cell["stage"] == "triage")
    ]
    alert_sp = spread(scans, ["results.alerts", "results.active_scanner_alerts"], by=["target"])
    find_sp = spread(cell, ["results.findings"], by=["target"])
    out = alert_sp.merge(find_sp, on="target", how="outer")

    bvc = blind_vs_ceiling(index)
    blind = bvc[bvc["role"] == "blind"].set_index("target")
    out["detected_blind"] = out["target"].map(lambda t: int(blind.loc[t, "detected"]) if t in blind.index else 0)
    out["markers"] = out["target"].map(lambda t: int(blind.loc[t, "n"]) if t in blind.index else 0)
    return out.sort_values("target").reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Duration against NFR-02 (§9)
# --------------------------------------------------------------------------- #
def durations(index: pd.DataFrame) -> pd.DataFrame:
    """Scan-alone and whole-chain seconds per real end-to-end pass (§9/NFR-02).

    One row per (target, auth, role, run, repeat) over the minting matrix cells
    (``variant=''``): the scan's own seconds and the sum across scan→triage→
    verify→report, each flagged against the 30-minute NFR-02 budget.
    """
    v = default_valid(index)
    v = v[(v["variant"] == "") & (v["stage"].isin(CHAIN_STAGES))]
    keys = ["campaign", "target", "auth", "role", "run", "repeat"]
    out = []
    for key, g in v.groupby(keys, dropna=False):
        secs = g.set_index("stage")["total_seconds"]
        scan_s = float(secs.get("scan", float("nan")))
        chain_s = float(g["total_seconds"].sum())
        rec = dict(zip(keys, key))
        rec.update(
            scan_seconds=scan_s,
            chain_seconds=chain_s,
            scan_minutes=scan_s / 60,
            chain_minutes=chain_s / 60,
            scan_over_nfr02=scan_s > NFR_02_SECONDS,
            chain_over_nfr02=chain_s > NFR_02_SECONDS,
            stages_present=int(g["stage"].nunique()),
        )
        out.append(rec)
    df = pd.DataFrame(out)
    return df.sort_values(["target", "auth", "role", "repeat"]).reset_index(drop=True)


def duration_summary(index: pd.DataFrame) -> pd.DataFrame:
    """Per target: worst-case scan-alone and whole-chain minutes vs NFR-02."""
    d = durations(index)
    g = d.groupby("target")
    return pd.DataFrame(
        {
            "n": g.size(),
            "scan_min_max": g["scan_minutes"].max(),
            "scan_min_mean": g["scan_minutes"].mean(),
            "chain_min_max": g["chain_minutes"].max(),
            "chain_min_mean": g["chain_minutes"].mean(),
            "any_chain_over_30min": g["chain_over_nfr02"].any(),
        }
    ).reset_index()


# --------------------------------------------------------------------------- #
# Scanner memory for NFR-05 (§9) — the container peak, from the raw scan record
# --------------------------------------------------------------------------- #
def _stage_record(run_dir: str | Path, stage: str, suffix: str) -> dict | None:
    name = f"{stage}-metrics.json" if not suffix else f"{stage}-metrics-{suffix}.json"
    path = Path(run_dir) / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def scanner_memory(index: pd.DataFrame, container: str = NFR_05_SCANNER_CONTAINER) -> pd.DataFrame:
    """Per scan: the scanner container's peak/mean memory and peak CPU (NFR-05).

    Read from ``scan-metrics.json`` → ``stages.active_scan.resources.<container>``
    (the index keeps only seconds). One row per blind/ceiling/crawl scan.
    """
    v = default_valid(index)
    scans = v[v["stage"] == "scan"]
    out = []
    for r in scans.itertuples(index=False):
        rec = _stage_record(r.run_dir, "scan", getattr(r, "suffix", "") or "")
        if rec is None:
            continue
        res = (((rec.get("stages") or {}).get("active_scan") or {}).get("resources") or {}).get(container, {})
        out.append(
            {
                "target": r.target,
                "auth": r.auth,
                "role": r.role,
                "run": r.run,
                "memory_mb_peak": res.get("memory_mb_peak"),
                "memory_mb_mean": res.get("memory_mb_mean"),
                "cpu_percent_peak": res.get("cpu_percent_peak"),
            }
        )
    return pd.DataFrame(out)


def scanner_memory_summary(index: pd.DataFrame, container: str = NFR_05_SCANNER_CONTAINER) -> pd.DataFrame:
    """Max scanner memory per target plus an ALL row (NFR-05 headline)."""
    mem = scanner_memory(index, container)
    if mem.empty:
        return mem
    rows = []
    for target, g in mem.groupby("target"):
        rows.append({"target": target, "n": len(g), "memory_mb_peak_max": g["memory_mb_peak"].max()})
    rows.append(
        {"target": "ALL", "n": len(mem), "memory_mb_peak_max": mem["memory_mb_peak"].max()}
    )
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Cost per finding (§9) — three denominators, actual and no-cache-computed
# --------------------------------------------------------------------------- #
def _substage_cost(rec: dict, *, cache: bool) -> float | None:
    """Re-price a triage/verify record's sub-stages; None if any model unpriced."""
    config = rec.get("config") or {}
    total = 0.0
    any_priced = False
    for name, sub in (rec.get("stages") or {}).items():
        if not isinstance(sub, dict) or name not in _SUBSTAGE_MODEL:
            continue
        model = config.get(_SUBSTAGE_MODEL[name]) or (sub.get("calls_log") or [{}])[0].get("model_served", "")
        c = computed_cost(
            sub.get("prompt_tokens", 0),
            sub.get("completion_tokens", 0),
            sub.get("cached_prompt_tokens", 0),
            model,
            cache=cache,
        )
        if c is None:
            return None
        any_priced = True
        total += c
    return total if any_priced else None


def cost_per_finding(index: pd.DataFrame) -> pd.DataFrame:
    """Per reference cell: model-stage cost over the three §9 denominators.

    The cost is the triage + verify model spend of one blind reference cell
    (``results.cost_usd``, the billed figure). Denominators: all triage findings,
    findings put to the model (``llm_findings_asked``), findings dispatched to a
    tool at verify. ``*_nocache`` repeats the division with caching re-priced off
    (computed from stored tokens × vendored list prices — labelled computed).
    Costs here are per-run, never the inflated block-3/4 banners (README caveat).
    """
    ref = apply_named(index, "reference-scans")  # user-blind cells, one per repeat
    v = default_valid(index)
    out = []
    for r in ref.itertuples(index=False):
        base = v[(v["run"] == r.run) & (v["variant"] == "")]
        tri = base[base["stage"] == "triage"]
        ver = base[base["stage"] == "verify"]
        if tri.empty:
            continue
        trow = tri.iloc[0]
        findings = trow.get("results.findings")
        asked = trow.get("results.llm_findings_asked")
        dispatched = ver.iloc[0].get("results.dispatched") if not ver.empty else None

        # Sum the actual billed cost and the recomputed costs over the stages that
        # exist for this cell (triage always, verify when present).
        recs = [_stage_record(r.run_dir, "triage", trow.get("suffix") or "")]
        actual = float(trow.get("results.cost_usd") or 0.0)
        if not ver.empty:
            recs.append(_stage_record(r.run_dir, "verify", ver.iloc[0].get("suffix") or ""))
            actual += float(ver.iloc[0].get("results.cost_usd") or 0.0)

        def total_over(cache: bool) -> float:
            return sum(_substage_cost(rec, cache=cache) or 0.0 for rec in recs if rec)

        nocache = total_over(cache=False)
        cached_recompute = total_over(cache=True)

        def per(cost, denom):
            return (cost / denom) if (cost is not None and denom) else None

        out.append(
            {
                "target": r.target,
                "run": r.run,
                "findings": findings,
                "put_to_model": asked,
                "dispatched": dispatched,
                "cost_usd": actual,
                "cost_usd_nocache": nocache,
                "cost_recompute_check": cached_recompute,  # ≈ cost_usd (validates the table)
                "per_finding_all": per(actual, findings),
                "per_finding_asked": per(actual, asked),
                "per_finding_dispatched": per(actual, dispatched),
                "per_finding_all_nocache": per(nocache, findings),
            }
        )
    return pd.DataFrame(out).sort_values(["target", "run"]).reset_index(drop=True)
