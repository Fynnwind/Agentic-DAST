"""Finding-level joins: the two-arm agreement matrix, tool agreement, overlap.

These read the triage artifact (``triage.json`` or its suffixed variant, located
by the index row's ``artifact``) straight from the run dir — the index does not
carry per-finding data. The two-arm agreement matrix is the thesis's central
claim: the ``llm-only`` cell is ~0, i.e. the model arm never rescues a finding the
deterministic table missed. Joins across runs use ``finding_id`` (a hash of
endpoint, rule and evidence, stable across runs; RUN-PLAN §8).
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

# The per-finding agreement field's vocabulary. ``not-evaluated`` means the LLM
# arm was never asked (the finding was not a triage candidate), so it is carried
# separately and never folded into the four-way matrix.
AGREE_CATS = ("both", "deterministic-only", "llm-only", "neither")
NOT_EVALUATED = "not-evaluated"


def _artifact_name(value: object) -> str:
    """Resolve an index row's ``artifact`` to a filename, tolerant of NaN.

    ``float('nan') or default`` returns the NaN (NaN is truthy), so the fallback
    must be an explicit isna check, not ``value or default``.
    """
    if value is None:
        return "triage.json"
    try:
        if pd.isna(value):
            return "triage.json"
    except (TypeError, ValueError):
        pass
    return str(value) or "triage.json"


def load_triage(run_dir: Path | str, artifact: object = "triage.json") -> dict:
    path = Path(run_dir) / _artifact_name(artifact)
    return json.loads(path.read_text())


def _triage_rows(index: pd.DataFrame) -> pd.DataFrame:
    rows = index[index["stage"] == "triage"].copy()
    if rows.empty:
        raise ValueError("selection contains no triage executions")
    return rows


def agreement_per_run(index: pd.DataFrame) -> pd.DataFrame:
    """One row per triage execution with its two-arm agreement counts."""
    out = []
    for row in _triage_rows(index).itertuples(index=False):
        data = load_triage(row.run_dir, getattr(row, "artifact", None))
        counts = {c: 0 for c in AGREE_CATS}
        counts[NOT_EVALUATED] = 0
        for f in data.get("findings", []):
            a = f.get("agreement")
            if a in counts:
                counts[a] += 1
        evaluated = sum(counts[c] for c in AGREE_CATS)
        out.append(
            {
                "target": row.target,
                "auth": row.auth,
                "role": row.role,
                "variant": row.variant,
                "repeat": row.repeat,
                "sheet": row.sheet,
                "run": row.run,
                "findings": sum(counts.values()),
                "evaluated": evaluated,
                **{c: counts[c] for c in AGREE_CATS},
                NOT_EVALUATED: counts[NOT_EVALUATED],
            }
        )
    return pd.DataFrame(out)


def two_arm_matrix(index: pd.DataFrame) -> pd.DataFrame:
    """The central-claim matrix over the blind reference matrix (one cell per row).

    Columns ``both`` / ``deterministic-only`` / ``llm-only`` / ``neither`` are the
    four arms; ``llm-only`` ~ 0 is the result.
    """
    from .selection import apply_named

    triage = apply_named(index, "matrix-blind")
    per = agreement_per_run(triage)
    return per.sort_values(["target", "auth"]).reset_index(drop=True)


def tool_agreement(index: pd.DataFrame) -> pd.DataFrame:
    """Per triage run: where each arm names a tool, and whether they agree (§9).

    Counted over findings where both arms name a tool; beside it, only-table and
    only-model. ``both_same`` is both naming the *same* tool.
    """
    out = []
    for row in _triage_rows(index).itertuples(index=False):
        data = load_triage(row.run_dir, getattr(row, "artifact", None))
        det_only = llm_only = both = both_same = 0
        for f in data.get("findings", []):
            dtool = (f.get("deterministic") or {}).get("tool")
            ltool = (f.get("llm") or {}).get("suggested_tool")
            if dtool and ltool:
                both += 1
                if dtool == ltool:
                    both_same += 1
            elif dtool:
                det_only += 1
            elif ltool:
                llm_only += 1
        out.append(
            {
                "target": row.target,
                "auth": row.auth,
                "variant": row.variant,
                "repeat": row.repeat,
                "run": row.run,
                "both_name_tool": both,
                "both_same_tool": both_same,
                "table_only_tool": det_only,
                "model_only_tool": llm_only,
            }
        )
    return pd.DataFrame(out)


def _finding_ids(index_row) -> set[str]:
    data = load_triage(index_row.run_dir, getattr(index_row, "artifact", None))
    return {f["finding_id"] for f in data.get("findings", []) if f.get("finding_id")}


def finding_overlap(index_a: pd.DataFrame, index_b: pd.DataFrame) -> dict:
    """Overlap of two triage selections on ``finding_id`` (§8).

    Each selection is reduced to the union of finding ids over its triage runs.
    Returns in-both / only-a / only-b counts; the id sets are returned too so a
    caller can slice by arm or verification outcome.
    """
    a_rows = _triage_rows(index_a)
    b_rows = _triage_rows(index_b)
    a_ids: set[str] = set().union(*(_finding_ids(r) for r in a_rows.itertuples(index=False))) if len(a_rows) else set()
    b_ids: set[str] = set().union(*(_finding_ids(r) for r in b_rows.itertuples(index=False))) if len(b_rows) else set()
    return {
        "in_both": len(a_ids & b_ids),
        "only_a": len(a_ids - b_ids),
        "only_b": len(b_ids - a_ids),
        "a_total": len(a_ids),
        "b_total": len(b_ids),
        "a_ids": a_ids,
        "b_ids": b_ids,
    }
