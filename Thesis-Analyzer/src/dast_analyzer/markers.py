"""Marker-by-level detection and the per-layer ladder (RUN-PLAN §9).

Each of the 22 markers is assessed once, in the cell whose scan auth matches the
marker's own required level (§G1/G2: 11 at none, 8 at user, 3 at admin). The
per-layer ladder is read from the ``dast cve`` stage's ``cve-detection.json`` (v3)
already written beside every blind and ceiling scan — the four layers are
scanner (zap+noir), the deterministic table, the LLM arm, and verification. The
reported figure is the strict one (§9); the generous one is carried beside it.

Blind detection is 0 at every layer in every cell; the ceiling is the upper
bound, and the two side by side are the detectable-but-missed gap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

# The four cumulative layers and the marker field that marks a catch at each,
# strict (reported) and generous (upper bound).
LAYERS = ("scanner", "det_triage", "llm_triage", "verify")
_LAYER_FIELD = {
    "scanner": ("zap_detected_strict", "zap_detected"),
    "det_triage": ("deterministic_flagged_strict", "deterministic_flagged"),
    "llm_triage": ("llm_flagged_strict", "llm_flagged"),
    "verify": ("verification_confirmed_strict", "verification_confirmed"),
}


def load_detection(run_dir: Path) -> dict | None:
    """Read ``cve-detection.json`` from a scan run dir, or None if absent."""
    path = Path(run_dir) / "cve-detection.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _marker_rows(det: dict, strict: bool) -> list[dict]:
    rows = []
    for m in det.get("markers", []):
        row = {
            "target": det["target"],
            "target_version": det.get("target_version"),
            "oracle_guided": det.get("oracle_guided"),
            "scan_auth": det.get("auth_mode"),
            "run_id": det.get("run_id"),
            "marker_id": m.get("marker_id"),
            "cve": m.get("cve"),
            "cwe": m.get("cwe"),
            "marker_auth": m.get("auth"),
            "reach": m.get("reach"),
            "observe": m.get("observe"),
            "outcome": m.get("outcome"),
            "not_applicable_reason": m.get("not_applicable_reason"),
        }
        for layer, (sf, gf) in _LAYER_FIELD.items():
            row[layer] = bool(m.get(sf if strict else gf, False))
        rows.append(row)
    return rows


def marker_table(scans: pd.DataFrame, strict: bool = True) -> pd.DataFrame:
    """One row per marker assessed at its own level, with per-layer flags.

    ``scans`` is a selection of scan-stage index rows (e.g. matrix-blind scans).
    For each (target, marker) the own-level run (scan_auth == marker_auth) is
    chosen; if repeats exist the latest by run id is taken (the cacti-admin redo
    supersedes its deadlocked first attempt).
    """
    all_rows: list[dict] = []
    for run_dir in scans["run_dir"].unique():
        det = load_detection(Path(run_dir))
        if det is not None:
            all_rows.extend(_marker_rows(det, strict))
    if not all_rows:
        return pd.DataFrame()
    df = pd.DataFrame(all_rows)
    own = df[df["scan_auth"] == df["marker_auth"]].copy()
    own = own.sort_values("run_id").drop_duplicates(["target", "marker_id"], keep="last")
    detected = own["outcome"] == "detected"
    own["detected"] = detected
    return own.sort_values(["target", "marker_auth", "marker_id"]).reset_index(drop=True)


def detection_ladder(markers: pd.DataFrame) -> pd.DataFrame:
    """Per-target and overall: denominator and per-layer / detected counts.

    One row per target plus an ``ALL`` row. ``n`` is the denominator (markers at
    their own level); each layer column counts markers caught at that layer;
    ``detected`` counts ``outcome == detected``.
    """
    if markers.empty:
        return pd.DataFrame()

    def _agg(sub: pd.DataFrame) -> dict:
        out = {"n": len(sub)}
        for layer in LAYERS:
            out[layer] = int(sub[layer].sum())
        out["detected"] = int(sub["detected"].sum())
        out["reached"] = int((sub["reach"] == "reached").sum())
        return out

    rows = []
    for target, sub in markers.groupby("target"):
        rows.append({"target": target, **_agg(sub)})
    rows.append({"target": "ALL", **_agg(markers)})
    return pd.DataFrame(rows)


def blind_vs_ceiling(index: pd.DataFrame) -> pd.DataFrame:
    """The headline table: the per-layer ladder for blind and ceiling side by side."""
    from .selection import apply_named

    frames = []
    for role, sel in (("blind", "matrix-blind"), ("ceiling", "matrix-ceiling")):
        scans = apply_named(index, sel)
        scans = scans[scans["stage"] == "scan"]
        ladder = detection_ladder(marker_table(scans, strict=True))
        ladder.insert(0, "role", role)
        frames.append(ladder)
    return pd.concat(frames, ignore_index=True)


def ceiling_variance(index: pd.DataFrame, include_pilot: bool = True) -> pd.DataFrame:
    """Per marker, pool every oracle-seeded (ceiling) sample — campaign + pilot.

    The single campaign ceiling run reports one confirmable marker (grafana); but
    each marker is assessed once per ceiling cell it is applicable in (none/user/
    admin replicate an unauth marker) *and* in the pilot, which gives a handful of
    oracle samples per marker. These are not designed repeats (RUN-PLAN §10's
    "how many repeats" is still open) — they are the incidental auth-level + pilot
    replication — but enough to separate a reproducible catch from a flickering
    one and to put a crude catch likelihood on each marker:

      - ``reached_samples`` — oracle samples where the sink was actually reached
        (the denominator; reach attrition is isolated from confirmation).
      - ``detected`` / ``catch_rate`` — confirmed among those: grafana
        CVE-2021-43798 is 4/4 (1.00), the wordpress frameid XSS is 1/4 (0.25, the
        pilot sample only), every other marker is 0/N.
    """
    from .selection import default_valid

    scans = default_valid(index, include_pilot=include_pilot, include_incomplete=True)
    scans = scans[scans["stage"] == "scan"]
    rows = []
    for run_dir in scans["run_dir"].unique():
        det = load_detection(Path(run_dir))
        if not det or not det.get("oracle_guided"):
            continue
        source = "pilot" if "canonical-baseline" in str(run_dir) else "campaign"
        for m in det.get("markers", []):
            outcome = m.get("outcome")
            rows.append(
                {
                    "target": det["target"],
                    "marker_id": m.get("marker_id"),
                    "cve": m.get("cve"),
                    "source": source,
                    "scan_auth": det.get("auth_mode"),
                    "outcome": outcome,
                    "detected": outcome == "detected",
                    "reached": outcome in ("detected", "reached-unconfirmed"),
                }
            )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    g = df.groupby(["target", "marker_id", "cve"], dropna=False)
    out = g.agg(
        oracle_samples=("outcome", "size"),
        reached_samples=("reached", "sum"),
        detected=("detected", "sum"),
        pilot_samples=("source", lambda s: int((s == "pilot").sum())),
    ).reset_index()
    out["catch_rate"] = [
        (d / r) if r else 0.0 for d, r in zip(out["detected"], out["reached_samples"])
    ]
    return out.sort_values(["catch_rate", "detected", "reached_samples"], ascending=False).reset_index(drop=True)
