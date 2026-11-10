"""The remaining result-cuts the results (not just the plan) made load-bearing.

Each is an analyzer-computed join over ``data/`` the README enumerates (#6, #7,
#8, #10, the SCA↔DAST component join, and the G10 OOB record). They read the
triage / verification / scan artifacts straight from the run dir, keyed by the
index — the index carries no per-finding data. finding_ids are stable across
runs (hash of endpoint+rule+evidence, RUN-PLAN §8), which is what lets the
context variants (no verify stage of their own) be read *through* the base cell's
verification, and what lets a synthesis claim's recurrence meet its disposition.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

from .findings import load_triage
from .selection import apply_named, default_valid

# A frontier reasoning model's verify failures are recorded in ``stopped_because``
# (the loop refuses an unparseable verdict rather than trusting it). These two
# substrings are the empty-content and answer-in-reasoning cases; a tool outside
# the allowed enum shows up as a probe command/tool the wrapper rejects.
_UNPARSEABLE_EMPTY = "empty message"
_UNPARSEABLE_REASONING = "reasoning present but no answer"

# ZAP "Vulnerable JS Library" alert; its Other-info names the library + version.
_ZAP_VULN_LIB_RULE = "10003"
_LIB_RE = re.compile(r"library\s+(.+?),\s+version\s+([^\s]+)\s+is vulnerable", re.I)


def _load(path: Path) -> dict | None:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else None


def _verification(run_dir: str | Path, suffix: str = "") -> dict | None:
    name = "verification.json" if not suffix else f"verification-{suffix}.json"
    return _load(Path(run_dir) / name)


def _outcome_by_finding(ver: dict | None, correlated: bool = False) -> dict[str, str]:
    """finding_id → outcome over a verification record's (correlated) verdicts."""
    if ver is None:
        return {}
    key = "correlated_verifications" if correlated else "verifications"
    return {v["finding_id"]: v.get("outcome") for v in ver.get(key, []) if v.get("finding_id")}


# --------------------------------------------------------------------------- #
# #6 Synthesis recurrence (seen_in) vs post-verification disposition
# --------------------------------------------------------------------------- #
def synthesis_recurrence_vs_disposition(index: pd.DataFrame) -> pd.DataFrame:
    """One row per synthesis claim: its seen_in/of recurrence and its disposition.

    ``correlated_findings[].reproducibility`` (how many of the synthesis samples
    raised the claim) joined to the matching ``correlated_verifications`` outcome,
    over the blind reference cells. ``models_agreeing`` is deliberately absent —
    there is no synthesis ensemble (README cut #6).
    """
    blind = apply_named(index, "matrix-blind")
    out = []
    for r in blind[blind["stage"] == "triage"].itertuples(index=False):
        tri = load_triage(r.run_dir, getattr(r, "artifact", None))
        disp = _outcome_by_finding(_verification(r.run_dir), correlated=True)
        for cf in tri.get("correlated_findings", []):
            rep = cf.get("reproducibility") or {}
            out.append(
                {
                    "target": r.target,
                    "auth": r.auth,
                    "run": r.run,
                    "finding_id": cf.get("finding_id"),
                    "pattern": cf.get("pattern"),
                    "severity": cf.get("severity"),
                    "confidence": cf.get("confidence"),
                    "seen_in": rep.get("seen_in"),
                    "of": rep.get("of"),
                    "disposition": disp.get(cf.get("finding_id"), "not-in-verification"),
                }
            )
    return pd.DataFrame(out)


def recurrence_disposition_crosstab(index: pd.DataFrame) -> pd.DataFrame:
    """Recurrence bucket (seen_in/of) × verification disposition, counts.

    The question the join answers: does a claim raised in more synthesis samples
    fare differently at verification? (In this corpus almost every claim is
    out-of-scope / not-attempted — the point the cut must show honestly.)
    """
    claims = synthesis_recurrence_vs_disposition(index)
    if claims.empty:
        return claims
    claims = claims.copy()
    claims["recurrence"] = claims.apply(
        lambda r: f"{int(r.seen_in)}/{int(r['of'])}" if pd.notna(r.seen_in) and pd.notna(r["of"]) else "unknown",
        axis=1,
    )
    return (
        claims.pivot_table(index="recurrence", columns="disposition", values="finding_id", aggfunc="count", fill_value=0)
        .reset_index()
    )


# --------------------------------------------------------------------------- #
# #7 G7 context (codenone / peernone) read THROUGH the base verification
# --------------------------------------------------------------------------- #
def _rescan_candidates(tri: dict) -> set[str]:
    """finding_ids the triage would dispatch (either arm asked for a rescan)."""
    out = set()
    for f in tri.get("findings", []):
        fid = f.get("finding_id")
        det = (f.get("deterministic") or {}).get("needs_rescan")
        llm = (f.get("llm") or {}).get("needs_rescan")
        if fid and (det or llm):
            out.add(fid)
    return out


def context_through_verification(index: pd.DataFrame) -> pd.DataFrame:
    """Per target: base vs codenone vs peernone, dispatch-set joined to base verify.

    The context variants have no verify stage of their own — they were re-triaged
    on the stored reference scan and live in that one run dir — so their effect is
    read through *that* cell's verification (same scan → stable finding_ids): of
    the findings the base verification *refuted* (the false positives), how many
    each variant's triage still flags for dispatch. Code context's measured value
    is this FP-suppression at verify, not the triage claim-count (which sits
    inside the G5 spread — reported beside it as ``correlated_findings``).

    Keyed off the run dir the variant records live in, so the base and its
    variants share one scan and one verification (never a G3 repeat's).
    """
    v = default_valid(index)
    ctx = v[(v["stage"] == "triage") & (v["variant_family"].isin(["codenone", "peernone"]))]
    out = []
    for run_dir, grp in ctx.groupby("run_dir"):
        base_rows = v[(v["run_dir"] == run_dir) & (v["stage"] == "triage") & (v["variant"] == "")]
        if base_rows.empty:
            continue
        br = base_rows.iloc[0]
        base_tri = load_triage(run_dir, br.get("artifact"))
        refuted = {fid for fid, oc in _outcome_by_finding(_verification(run_dir)).items() if oc == "refuted"}

        rows = [("base", "base", base_tri)]
        for vr in grp.itertuples(index=False):
            rows.append((vr.variant_family, getattr(vr, "suffix", "") or vr.variant_family, load_triage(vr.run_dir, getattr(vr, "artifact", None))))
        for vname, label, tri in rows:
            cands = _rescan_candidates(tri)
            out.append(
                {
                    "target": br["target"],
                    "variant": vname,
                    "run_label": label,
                    "correlated_findings": (tri.get("summary") or {}).get("correlated_findings")
                    or len(tri.get("correlated_findings", [])),
                    "dispatch_candidates": len(cands),
                    "base_refuted": len(refuted),
                    "refuted_still_flagged": len(cands & refuted),
                }
            )
    return pd.DataFrame(out).sort_values(["target", "variant", "run_label"]).reset_index(drop=True)


# --------------------------------------------------------------------------- #
# #8 G4 Noir-seeding delta — crawl (Noir off) vs seeded (blind), per target
# --------------------------------------------------------------------------- #
def noir_seeding_delta(index: pd.DataFrame) -> pd.DataFrame:
    """Per target: crawl-only vs Noir-seeded scan tree + alerts, each as a range.

    No ``dast cve`` runs on G4, so this is computed here by joining ``crawl``
    (role=crawl, Noir off) against the seeded ``blind`` reference scans on config.
    Reported as min/max/mean (never one number): the delta is direction-reversing
    — Noir expands sparse apps and tightens link-dense ones (README cut #8).
    """
    v = default_valid(index)
    scans = v[v["stage"] == "scan"]
    out = []
    for target, g in scans.groupby("target"):
        for role, label in (("crawl", "crawl"), ("blind", "seeded")):
            sub = g[(g["role"] == role) & (g["auth"] == "user")]
            if sub.empty:
                continue
            urls = sub["results.urls_before_active_scan"].astype(float)
            alerts = sub["results.alerts"].astype(float)
            out.append(
                {
                    "target": target,
                    "arm": label,
                    "n": len(sub),
                    "urls_min": urls.min(),
                    "urls_max": urls.max(),
                    "urls_mean": urls.mean(),
                    "alerts_min": alerts.min(),
                    "alerts_max": alerts.max(),
                    "alerts_mean": alerts.mean(),
                }
            )
    return pd.DataFrame(out).sort_values(["target", "arm"]).reset_index(drop=True)


# --------------------------------------------------------------------------- #
# #10 G8 frontier — stage read, structured-output failures, cost projection
# --------------------------------------------------------------------------- #
def frontier_unparseable(index: pd.DataFrame) -> pd.DataFrame:
    """Count the Opus verify findings the structured loop could not use.

    A frontier reasoning model intermittently returns a verdict the JSON-schema
    verify loop refuses (empty content / the answer in the reasoning channel / a
    tool outside the enum). The loop marks these not-attempted rather than
    trusting them — an operational *cost* of the model, deterministic and
    independent of token budget (README cut #10). Counted per frontier verify run.
    """
    v = default_valid(index)
    fv = v[(v["stage"] == "verify") & (v["variant_family"] == "frver")]
    out = []
    for r in fv.itertuples(index=False):
        ver = _verification(r.run_dir, getattr(r, "suffix", "") or "")
        if ver is None:
            continue
        reasoning: set[str] = set()
        empty: set[str] = set()
        bad_tool: set[str] = set()
        # Both arms: the single-finding verdicts and the cross-endpoint ones (the
        # hallucinated out-of-enum ``tool: browser`` lands in the correlated arm).
        for x in ver.get("verifications", []) + ver.get("correlated_verifications", []):
            fid = x.get("finding_id")
            sb = (x.get("stopped_because") or "").lower()
            if _UNPARSEABLE_REASONING in sb:
                reasoning.add(fid)
            elif _UNPARSEABLE_EMPTY in sb:
                empty.add(fid)
            tools = [x.get("tool")] + [rnd.get("tool") for rnd in (x.get("rounds") or [])]
            if any(str(t).lower() == "browser" for t in tools if t):
                bad_tool.add(fid)
        out.append(
            {
                "run_label": getattr(r, "suffix", "") or "frver",
                "answer_in_reasoning": len(reasoning),
                "empty_content": len(empty),
                "tool_outside_enum": len(bad_tool),
                "total_unparseable": len(reasoning | empty | bad_tool),  # distinct findings
            }
        )
    return pd.DataFrame(out)


# The gitea Opus probe is the only measured frontier data (SHEET-CATALOG §Sheet 5).
# These name the sub-stage records the per-stage anchor spend is read from.
_FRONTIER_ANCHOR = {
    "screening": ("triage", "frscr", "llm_screening"),
    "synthesis": ("triage", "frsyn", "llm_synthesis"),
    "verify": ("verify", ("frver2", "frver3"), None),  # mean of the two clean reruns
}


def _stage_workload(rec: dict | None, sub: str) -> float:
    """Total (prompt+completion) tokens of a sub-stage — the workload measure."""
    st = ((rec or {}).get("stages") or {}).get(sub) or {}
    return float(st.get("prompt_tokens", 0) or 0) + float(st.get("completion_tokens", 0) or 0)


def frontier_measured(index: pd.DataFrame) -> pd.DataFrame:
    """The measured gitea Opus spend per stage beside the default's (the Nx cost).

    The only frontier data the campaign has: one gitea pass with each stage
    swapped to Opus 5.5 in turn (README cut #10). Opus adds no value at any stage
    (read against ``model_stage_spread``) at this multiple of the default cost.
    """
    from .metrics import _stage_record

    v = default_valid(index)
    ref = v[(v["target"] == "gitea") & (v["role"] == "blind") & (v["auth"] == "user") & (v["variant"] == "")]
    gdir = ref.iloc[0]["run_dir"]
    base_tri = _stage_record(gdir, "triage", "")
    base_ver = _stage_record(gdir, "verify", "")
    default = {
        "screening": (base_tri["stages"]["llm_screening"]["cost_usd"]),
        "synthesis": (base_tri["stages"]["llm_synthesis"]["cost_usd"]),
        "verify": (base_ver["results"]["cost_usd"]),
    }
    out = []
    for stage, opus in _frontier_anchor_costs(gdir).items():
        d = default[stage]
        out.append(
            {
                "stage": stage,
                "default_usd": round(d, 4),
                "opus_usd": round(opus, 4),
                "multiple": round(opus / d, 1) if d else None,
            }
        )
    return pd.DataFrame(out)


def _frontier_anchor_costs(gitea_dir: str | Path) -> dict[str, float]:
    from .metrics import _stage_record

    base = Path(gitea_dir)
    costs = {}
    for stage, (kind, suffix, sub) in _FRONTIER_ANCHOR.items():
        if isinstance(suffix, tuple):  # verify: mean of the clean reruns, whole-stage cost
            vals = [_stage_record(base, kind, f"gitea-user-blind-{s}")["results"]["cost_usd"] for s in suffix]
            costs[stage] = sum(vals) / len(vals)
        else:
            rec = _stage_record(base, kind, f"gitea-user-blind-{suffix}")
            costs[stage] = rec["stages"][sub]["cost_usd"]
    return costs


def frontier_cost_projection(index: pd.DataFrame) -> pd.DataFrame:
    """Full-G8 (all 3 stages, user-blind cell) per target, projected from gitea.

    SHEET-CATALOG's method: anchor on gitea's *measured* per-stage Opus spend, and
    scale every other target by its default-model total-token workload ratio for
    that stage (the ratio cancels the tokenizer/verbosity model-dependence).
    Labelled computed. gitea is the measured anchor (exact); the other rows are a
    projection, matching the published interim table most closely on the dominant
    screening line (cacti's 342-endpoint corpus) and approximately elsewhere.
    """
    from .metrics import _stage_record

    v = default_valid(index)
    ref = v[(v["role"] == "blind") & (v["auth"] == "user") & (v["variant"] == "")]
    gdir = ref[ref["target"] == "gitea"].iloc[0]["run_dir"]
    anchor = _frontier_anchor_costs(gdir)
    g_tri = _stage_record(gdir, "triage", "")
    g_ver = _stage_record(gdir, "verify", "")
    g_wl = {
        "screening": _stage_workload(g_tri, "llm_screening"),
        "synthesis": _stage_workload(g_tri, "llm_synthesis"),
        "verify": _stage_workload(g_ver, "dispatch"),
    }
    sub_of = {"screening": ("triage", "llm_screening"), "synthesis": ("triage", "llm_synthesis"), "verify": ("verify", "dispatch")}
    out = []
    for target, g in ref.groupby("target"):
        row = {"target": target}
        total = 0.0
        for stage, (kind, sub) in sub_of.items():
            s = g[g["stage"] == kind]
            rec = _stage_record(s.iloc[0]["run_dir"], kind, s.iloc[0]["suffix"] or "") if not s.empty else None
            wl = _stage_workload(rec, sub)
            cost = anchor[stage] * (wl / g_wl[stage]) if g_wl[stage] else 0.0
            row[stage] = round(cost, 2)
            total += cost
        row["total"] = round(total, 2)
        out.append(row)
    df = pd.DataFrame(out).sort_values("target").reset_index(drop=True)
    return df


# --------------------------------------------------------------------------- #
# SCA ↔ DAST on component identity (ZAP 10003 ↔ OSV packages)
# --------------------------------------------------------------------------- #
def _zap_vuln_libs(run_dir: Path) -> set[tuple[str, str]]:
    """(library, version) pairs ZAP rule 10003 named in a scan's alerts."""
    za = _load(Path(run_dir) / "scan-zap-alerts.json")
    libs: set[tuple[str, str]] = set()
    if not za:
        return libs
    for a in za.get("alerts", []):
        if str(a.get("pluginId")) != _ZAP_VULN_LIB_RULE:
            continue
        m = _LIB_RE.search(a.get("other", "") or "")
        if m:
            libs.add((m.group(1).strip().lower(), m.group(2).strip()))
    return libs


def _osv_packages(run_dir: Path) -> set[tuple[str, str]]:
    """(package, version) pairs OSV found, from the analysis record top_packages."""
    am = _load(Path(run_dir) / "analysis-metrics.json")
    out: set[tuple[str, str]] = set()
    if not am:
        return out
    for p in (am.get("results", {}).get("osv") or {}).get("top_packages", []):
        pkg = p.get("package", "")
        name, _, ver = pkg.rpartition("@")
        if name:
            out.add((name.lower(), ver))
    return out


def sca_dast_components(index: pd.DataFrame) -> pd.DataFrame:
    """Per target: ZAP's vulnerable-JS-library rule vs OSV, joined on component.

    ZAP 10003 (fires in the blind scans) names a library + version in the HTTP
    response; OSV names packages in the dependency manifests. Matched on component
    name. wordpress SCA no-ops (no scanned manifest, P4), so its OSV side is empty.
    """
    v = default_valid(index)
    scans = v[(v["stage"] == "scan") & (v["role"] == "blind") & (v["auth"] == "user")]
    analyses = v[v["stage"] == "analysis"]
    out = []
    for target in sorted(scans["target"].dropna().unique()):
        zdirs = scans[scans["target"] == target]["run_dir"]
        zlibs: set[tuple[str, str]] = set()
        for d in zdirs:
            zlibs |= _zap_vuln_libs(Path(d))
        adir = analyses[analyses["target"] == target]["run_dir"]
        osv = _osv_packages(Path(adir.iloc[0])) if len(adir) else set()
        znames = {n for n, _ in zlibs}
        onames = {n for n, _ in osv}
        out.append(
            {
                "target": target,
                "zap_10003_libs": len(zlibs),
                "osv_packages": len(osv),
                "component_matches": len(znames & onames),
                "matched_components": ", ".join(sorted(znames & onames)) or "—",
                "zap_only": ", ".join(sorted(znames - onames)) or "—",
            }
        )
    return pd.DataFrame(out)


# --------------------------------------------------------------------------- #
# G10 — the out-of-band confirmation as a standalone record (never a detection)
# --------------------------------------------------------------------------- #
def g10_oob_record(root: str | Path) -> dict | None:
    """Locate and return ``g10-oob-confirmation.json`` (CVE-2022-46169 OOB).

    Surfaced as its own record; it is explicitly OUTSIDE the pipeline detection
    chain and must never be counted as a pipeline detection (README cut #9/#10).
    """
    hits = sorted(Path(root).rglob("g10-oob-confirmation.json"))
    return _load(hits[0]) if hits else None
