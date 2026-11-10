"""Block-6 (§10) spread, timing and catch views over the post-corpus repeats.

Every builder scopes to ``corpus="post"`` (see :func:`selection.default_valid`),
so the §10 spread repeats never share a table with the frozen corpus. The figures
in :mod:`figures` plot these; the thesis reads them as the reproducibility and
cost characterisation that the single-sample frozen corpus could not give.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from .markers import load_detection
from .selection import default_valid

#: Parsers for the report.md funnel header (authoritative, report-computed).
_RE_ALERTS = re.compile(r"alerts.{1,8}findings\s*\|\s*([\d,]+)\D+?([\d,]+)\s+across")
_RE_VERIFIED = re.compile(
    r"verified\s*\|\s*(\d+)\s*confirmed,\s*(\d+)\s*refuted,"
    r"\s*(\d+)\s*inconclusive,\s*(\d+)\s*not"
)
_RE_TRIAGE = re.compile(r"([\d,]+)\s*require triage")

#: Fixed target order for the figure rows (fast to slow scan).
TARGET_ORDER = ["grafana", "cacti", "wordpress", "gitea"]
_TORD = {t: i for i, t in enumerate(TARGET_ORDER)}


def _runs(index: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """One row per post-corpus run with per-stage metrics mapped on, plus the
    full post-corpus stage frame."""
    c6 = default_valid(index, corpus="post").copy()
    # Block-6's gitea is contaminated (persistent target, tree grew 900->5251
    # across repeats), so drop it ALL: the clean --reset-target rescans supersede
    # it — campaign-7-even-scan-variance for BLIND, campaign-8-even-fill for the
    # CEILING (both reset to a snapshot before every scan).
    superseded = (
        (c6["sheet"] == "campaign-6-spread-repeats")
        & (c6["target"] == "gitea")
    )
    c6 = c6[~superseded]
    c6["pol"] = c6["role"].fillna("")

    # gitea blind landed 7 clean --reset-target repeats (campaign-7); keep the
    # first 6 (by run id) so every band shares one n.
    gb_dirs = sorted(
        c6[(c6["target"] == "gitea") & (c6["pol"] == "blind")]["run_dir"].unique()
    )
    if len(gb_dirs) > 6:
        c6 = c6[~c6["run_dir"].isin(set(gb_dirs[6:]))]

    def smap(stage: str, col: str) -> pd.Series:
        s = c6[c6.stage == stage]
        return s.set_index("run_dir")[col] if col in s.columns else pd.Series(dtype=float)

    runs = (
        c6[c6.stage == "scan"][["run_dir", "target", "pol"]]
        .drop_duplicates("run_dir")
        .copy()
    )
    runs["alerts"] = runs.run_dir.map(smap("scan", "results.alerts"))
    runs["claims"] = runs.run_dir.map(smap("triage", "results.correlated_findings"))
    runs["refuted"] = runs.run_dir.map(smap("verify", "results.refuted"))
    runs["confirmed"] = runs.run_dir.map(smap("verify", "results.confirmed"))
    runs["total_min"] = runs.run_dir.map(c6.groupby("run_dir")["total_seconds"].sum()) / 60
    return runs, c6


def _order(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df.assign(_o=df.target.map(_TORD))
        .sort_values(["_o", "pol"])
        .drop(columns="_o")
        .reset_index(drop=True)
    )


#: Sheets whose runs reset the target to a clean snapshot before every scan
#: (--reset-target) vs the persistent repeats that let state accumulate.
_RESET_SHEETS = frozenset({
    "campaign-7-even-scan-variance", "campaign-8-even-fill",
    "campaign-8b-cacti-ceiling", "campaign-8c-cacti-ceiling",
    "campaign-8d-cacti-ceiling",
})
_PERSIST_SHEETS = frozenset({"campaign-6-spread-repeats", "campaign-6-cacti-blind-redo"})


def accumulation(index: pd.DataFrame) -> pd.DataFrame:
    """Spider-tree size (``urls_before_active_scan``) across the variance repeats,
    per target and reset mode, chronological (one row per scan, ``seq`` 1..n).

    The scan surface only accumulates where authenticated scans leave state on it:
    gitea's issues/PRs/repo copies swell its tree ~5x and make it volatile under
    PERSISTENT re-scanning, which ``--reset-target`` flattens to a byte-identical
    clean tree. The other targets are stable across repeats (their pollution —
    wordpress comments, cacti's login log — is off the scan surface).
    """
    scan = default_valid(index, corpus="all")
    scan = scan[scan["stage"] == "scan"].copy()
    scan["tree"] = pd.to_numeric(scan["results.urls_before_active_scan"], errors="coerce")
    scan = scan.dropna(subset=["tree"])

    def series(target: str, sheets: frozenset, mode: str) -> pd.DataFrame:
        d = scan[(scan["target"] == target) & (scan["sheet"].isin(sheets))].sort_values("run_dir")
        return pd.DataFrame({"target": target, "mode": mode,
                             "seq": range(1, len(d) + 1), "tree": d["tree"].to_numpy()})

    frames = [
        series("gitea", _PERSIST_SHEETS, "persistent"),
        series("gitea", _RESET_SHEETS, "reset"),
        series("wordpress", _PERSIST_SHEETS, "persistent"),
        series("grafana", _PERSIST_SHEETS, "persistent"),
        series("cacti", _PERSIST_SHEETS, "persistent"),
    ]
    return pd.concat([f for f in frames if len(f)], ignore_index=True)


def scan_alert_spread(index: pd.DataFrame) -> pd.DataFrame:
    """ZAP alert-volume band (n / min / max / mean) per target x polarity."""
    runs, _ = _runs(index)
    g = (
        runs.dropna(subset=["alerts"])
        .groupby(["target", "pol"])["alerts"]
        .agg(n="size", lo="min", hi="max", mean="mean")
        .reset_index()
    )
    return _order(g)


def stage_count_spread(index: pd.DataFrame) -> pd.DataFrame:
    """Triage-claim and verify refuted/confirmed count bands per target x polarity."""
    runs, _ = _runs(index)
    frames = []
    for metric in ("claims", "refuted", "confirmed"):
        g = (
            runs.dropna(subset=[metric])
            .groupby(["target", "pol"])[metric]
            .agg(lo="min", hi="max", mean="mean", n="size")
            .reset_index()
        )
        g["metric"] = metric
        frames.append(g)
    return _order(pd.concat(frames, ignore_index=True))


def stage_time(index: pd.DataFrame) -> pd.DataFrame:
    """Mean minutes per stage, per target x polarity."""
    _, c6 = _runs(index)
    return (
        c6.groupby(["target", "pol", "stage"])["total_seconds"]
        .mean()
        .div(60)
        .reset_index(name="minutes")
    )


def total_time_spread(index: pd.DataFrame) -> pd.DataFrame:
    """Per-run total wall-clock band (minutes) per target x polarity."""
    runs, _ = _runs(index)
    g = (
        runs.dropna(subset=["total_min"])
        .groupby(["target", "pol"])["total_min"]
        .agg(n="size", lo="min", hi="max", mean="mean")
        .reset_index()
    )
    return _order(g)


def ceiling_catch(index: pd.DataFrame) -> pd.DataFrame:
    """Per target: the fraction of ceiling repeats whose verify confirmed any CVE.

    This is the loose, verify-level signal (a confirmation the ground-truth join
    may not credit to a documented marker); :func:`marker_catch` is the strict one.
    """
    runs, _ = _runs(index)
    cr = runs[runs.pol == "ceiling"].dropna(subset=["confirmed"])
    cat = (
        cr.assign(hit=(cr.confirmed > 0).astype(int))
        .groupby("target")
        .agg(n=("hit", "size"), hits=("hit", "sum"))
        .reset_index()
    )
    cat["rate"] = cat.hits / cat.n
    return cat.sort_values("rate").reset_index(drop=True)


#: The marker lifecycle stages, in pipeline order. Loose unless marked strict;
#: the gap between "confirmed" (loose) and "detected" (strict, at the exact sink)
#: is the rule-class-collision story.
LIFECYCLE_STAGES = [
    ("reached", "reached"),
    ("zap", "ZAP alert"),
    ("triage_det", "triage flag"),
    ("llm", "LLM flag"),
    ("dispatched", "verify dispatch"),
    ("confirmed", "verify confirm"),
    ("detected", "detected (strict)"),
]


def marker_lifecycle(index: pd.DataFrame) -> pd.DataFrame:
    """Per marker, the fraction of ceiling repeats that cleared each pipeline stage.

    Reads each oracle run's ``cve-detection.json``. A marker is reached by the
    oracle, may raise a (loose, rule-class) ZAP alert, be flagged by the
    deterministic or LLM triage arm, be dispatched to verify, be loosely
    ``confirmed`` there, and finally ``detected`` (strict — confirmed at its own
    documented sink). Only ``detected`` is a true positive; the loose steps show
    how far a marker travels before the strict join drops it. Empty when
    ``dast cve`` has not been run over the post corpus.
    """
    _, c6 = _runs(index)
    scans = c6[(c6.stage == "scan") & (c6.pol == "ceiling")]
    rows = []
    for rd in scans.run_dir.unique():
        det = load_detection(Path(rd))
        if not det or not det.get("oracle_guided"):
            continue
        for m in det.get("markers", []):
            if m.get("reach") != "reached":
                continue
            outs = m.get("verification_outcomes", []) or []
            rows.append(
                {
                    "target": det["target"],
                    "marker_id": m.get("marker_id"),
                    "cve": m.get("cve"),
                    "reached": 1,
                    "zap": int(bool(m.get("zap_detected"))),
                    "triage_det": int(bool(m.get("deterministic_flagged"))),
                    "llm": int(bool(m.get("llm_flagged"))),
                    "dispatched": int(any(o != "not-attempted" for o in outs)),
                    "confirmed": int(bool(m.get("verification_confirmed"))),
                    "detected": int(m.get("outcome") == "detected"),
                }
            )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    cols = [s for s, _ in LIFECYCLE_STAGES]
    g = df.groupby(["target", "marker_id", "cve"], dropna=False)
    out = g[cols].mean().reset_index()  # fraction of repeats clearing each stage
    out["n"] = g.size().values
    out["_o"] = out.target.map(_TORD)
    return out.sort_values(["_o", "detected", "confirmed"], ascending=[True, False, False]).drop(columns="_o").reset_index(drop=True)


def marker_catch(index: pd.DataFrame) -> pd.DataFrame:
    """Per marker: ground-truth catch rate over the post-corpus ceiling repeats.

    Reads each oracle run's ``cve-detection.json`` (written by ``dast cve``) and
    pools per marker. ``reached_samples`` (the oracle reached the sink) is the
    denominator; ``detected`` is the strict confirmation at the marker's own sink.
    Returns empty when ``dast cve`` has not been run over the post corpus.
    """
    _, c6 = _runs(index)
    scans = c6[(c6.stage == "scan") & (c6.pol == "ceiling")]
    rows = []
    for rd in scans.run_dir.unique():
        det = load_detection(Path(rd))
        if not det or not det.get("oracle_guided"):
            continue
        for m in det.get("markers", []):
            outcome = m.get("outcome")
            rows.append(
                {
                    "target": det["target"],
                    "marker_id": m.get("marker_id"),
                    "cve": m.get("cve"),
                    "detected": outcome == "detected",
                    "reached": outcome in ("detected", "reached-unconfirmed"),
                }
            )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    g = (
        df.groupby(["target", "marker_id", "cve"], dropna=False)
        .agg(
            oracle_samples=("reached", "size"),
            reached_samples=("reached", "sum"),
            detected=("detected", "sum"),
        )
        .reset_index()
    )
    g["catch_rate"] = [d / r if r else 0.0 for d, r in zip(g.detected, g.reached_samples)]
    return g.sort_values(["catch_rate", "reached_samples"], ascending=False).reset_index(drop=True)


#: The decluttering funnel stages, in order (raw -> what a person reviews).
FUNNEL_STAGES = [
    ("raw_alerts", "raw ZAP alerts"),
    ("findings", "findings (deduplicated)"),
    ("need_a_person", "need a person"),
    ("settled", "tool-settled (confirmed + refuted)"),
]


def declutter_funnel(index: pd.DataFrame) -> pd.DataFrame:
    """Per target, the blind-run noise-control funnel, parsed from report.md.

    The report header carries the authoritative, report-computed counts: raw ZAP
    alerts, deduplicated findings, the verify verdicts, and the "require triage"
    residue ("these need a person"). ``settled`` = confirmed + refuted — the
    findings a tool adjudicated with evidence. The pipeline **declutters** (dedup,
    grounded refutation of high-severity false positives, disposition bucketing);
    it orders by evidence and does not rank by true risk. Empty when no blind
    report.md is present.
    """
    v = default_valid(index, corpus="all")
    v = v[(v.role == "blind") & (v.variant == "") & (v.stage == "scan")]
    rows = []
    for rd, tgt in zip(v.run_dir, v.target):
        p = Path(rd) / "report.md"
        if not p.exists():
            continue
        txt = p.read_text(errors="ignore").replace("*", "")  # drop markdown bold
        af, ver = _RE_ALERTS.search(txt), _RE_VERIFIED.search(txt)
        if not (af and ver):
            continue
        tri = _RE_TRIAGE.search(txt)
        n = lambda s: int(s.replace(",", ""))
        conf, ref = int(ver.group(1)), int(ver.group(2))
        rows.append({
            "target": tgt,
            "raw_alerts": n(af.group(1)),
            "findings": n(af.group(2)),
            "confirmed": conf,
            "refuted": ref,
            "settled": conf + ref,
            "need_a_person": n(tri.group(1)) if tri else float("nan"),
        })
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    g = df.groupby("target").mean(numeric_only=True)
    g["runs"] = df.groupby("target").size()
    order = [t for t in TARGET_ORDER if t in g.index]
    return g.reindex(order).reset_index()
