"""Provenance stamping (RUN-PLAN §8: every output states its selection + run ids).

A table or figure the thesis cites must trace back to the exact executions it was
built from, so every emitted artifact carries a header: the run ids, the config
digests, the targets/stages/campaign in the selection, and when it was generated.
The one value that cannot be read from ``config`` is the *served* synthesis
provider — synthesis is preference-routed, so ``config.synthesis_provider`` is
empty by design (README caveat); it is recorded per call, which this module reads
from the nested ``stages.llm_synthesis.calls_log`` / ``.providers`` of the triage
record (RUN-PLAN §2 input contract).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

import pandas as pd

from .metrics import _stage_record

# The frozen corpus pin (SHEET-CATALOG / NEXT_SESSION §1). The tool does not yet
# stamp the commit into artifacts (P7, deferred), so it is carried as a constant
# the CLI can override rather than read back from a record.
CORPUS_COMMIT = "bc30e8d"


def provenance_header(df: pd.DataFrame, *, corpus_commit: str | None = CORPUS_COMMIT) -> dict:
    """The run ids + digests + axes a selection was computed from (§8)."""

    def uniq(col: str) -> list:
        return sorted(df[col].dropna().unique().tolist()) if col in df.columns else []

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus_commit": corpus_commit,
        "n_executions": int(len(df)),
        "campaigns": uniq("campaign"),
        "targets": uniq("target"),
        "stages": uniq("stage"),
        "harness_ids": uniq("harness_id"),
        "config_digests": uniq("digest"),
        "run_ids": uniq("run"),
    }


def header_lines(header: dict) -> list[str]:
    """Render a provenance header as comment lines (for CSV / Markdown / LaTeX)."""
    lines = [
        f"generated_at: {header['generated_at']}",
        f"corpus_commit: {header['corpus_commit']}",
        f"executions: {header['n_executions']}",
        f"targets: {', '.join(header['targets']) or '-'}",
        f"stages: {', '.join(header['stages']) or '-'}",
        f"config_digests: {', '.join(header['config_digests']) or '-'}",
        f"run_ids ({len(header['run_ids'])}): {', '.join(header['run_ids']) or '-'}",
    ]
    return lines


def served_synthesis_providers(index: pd.DataFrame) -> pd.DataFrame:
    """Per triage run: the provider(s) OpenRouter actually served synthesis from.

    Read from the call log, never from ``config`` (empty by design). The routing
    is a measured fact of the corpus — the originally-pinned provider failed
    ~80% of calls mid-campaign, so routing was opened and the served provider
    recorded per call (SHEET-CATALOG amendment 1).
    """
    triage = index[index["stage"] == "triage"]
    out = []
    for r in triage.itertuples(index=False):
        rec = _stage_record(r.run_dir, "triage", getattr(r, "suffix", "") or "")
        syn = ((rec or {}).get("stages") or {}).get("llm_synthesis") or {}
        providers = syn.get("providers") or {}
        served = Counter()
        for c in syn.get("calls_log", []) or []:
            if c.get("provider"):
                served[c["provider"]] += 1
        served = dict(served) or providers
        out.append(
            {
                "target": r.target,
                "auth": r.auth,
                "variant": r.variant,
                "run": r.run,
                "synthesis_model": (rec or {}).get("config", {}).get("synthesis_model"),
                "synthesis_provider_config": (rec or {}).get("config", {}).get("synthesis_provider") or "(empty — routed)",
                "served_providers": ", ".join(f"{k}×{v}" for k, v in sorted(served.items())) or "-",
            }
        )
    return pd.DataFrame(out)
