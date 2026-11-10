"""Build the one-row-per-stage-execution index (RUN-PLAN §8).

Every selection, group-by and stage-level metric runs off this table. The columns
are those §8 names as its filter keys; ``config.<field>`` and ``results.<field>``
are flattened through so ``--where config.code_context=handler+trace`` and a
group-by on any counter work without special-casing. Finding-level joins do not
live here — they read the triage/verification artifacts straight from ``run_dir``,
located via the ``artifact`` column.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from .naming import TARGETS, parse_row_name
from .records import StageRecord, load_records


def _target_from_run(run: str) -> str | None:
    """Recover the target from a run id (``<ts>-<target>-<digest>``).

    The G9 static/dependency runs carry no ``harness_row``, so their target is
    read from the run id instead of the (absent) row name.
    """
    parts = run.split("-")
    for tok in parts[1:]:
        if tok in TARGETS:
            return tok
    return None


def _launch_flags(run_dir: Path) -> tuple[bool, bool]:
    """(direct_run, launch_complete).

    A direct run lives under ``data/runs/<run>`` (produced by ``dast run``, no
    harness, always canonical). A harness run lives under
    ``data/harness/<launch>/<run>``; its launch is complete only if the launch dir
    wrote a ``results.json`` — the false-start campaign-1 launches did not, so
    their partial records are excluded by default (RUN-PLAN §8 "aborted … excluded").
    """
    parent = run_dir.parent
    if parent.name == "runs":
        return True, True
    return False, (parent / "results.json").exists()


def _sheet_name(harness_id: str) -> str:
    """Strip the launch timestamp prefix: ``20261012T142653Z-campaign-1-…`` -> rest."""
    parts = harness_id.split("-", 1)
    if parts and parts[0] and parts[0][0].isdigit():
        return parts[1] if len(parts) > 1 else harness_id
    return harness_id


def _stage_model_provider(kind: str, config: dict[str, Any]) -> tuple[str, str]:
    """The headline model/provider for a stage (screening slot for triage)."""
    if kind == "triage":
        return (
            config.get("screening_model") or "",
            config.get("screening_provider") or "",
        )
    if kind == "verify":
        return config.get("model") or "", config.get("provider") or ""
    return "", ""


def _flatten(prefix: str, obj: dict[str, Any], out: dict[str, Any]) -> None:
    """Flatten one level of a dict into ``prefix.key``; scalars kept, dicts/lists
    left as objects (finding-level code reads those from the artifact, not here)."""
    for k, v in obj.items():
        out[f"{prefix}.{k}"] = v


def _cross_check(name_auth: str | None, name_role: str | None, config: dict[str, Any]) -> bool:
    """Is the parsed name consistent with the record's own auth_mode / ceiling?"""
    ok = True
    cfg_auth = config.get("auth_mode")
    if name_auth is not None and cfg_auth is not None and cfg_auth != "":
        ok = ok and (name_auth == cfg_auth)
    cfg_ceiling = config.get("ceiling")
    if name_role in ("blind", "ceiling") and isinstance(cfg_ceiling, bool):
        ok = ok and (cfg_ceiling == (name_role == "ceiling"))
    return ok


def record_to_row(rec: StageRecord) -> dict[str, Any]:
    name = parse_row_name(rec.label, rec.harness_row)
    config = rec.data.get("config", {}) or {}
    results = rec.data.get("results", {}) or {}
    host = rec.data.get("host", {}) or {}
    stage_seconds = rec.data.get("stages", {}) or {}
    model, provider = _stage_model_provider(rec.kind, config)
    direct_run, launch_complete = _launch_flags(rec.run_dir)
    target = name.target or _target_from_run(rec.run)

    row: dict[str, Any] = {
        # identity / selection axes (§8)
        "campaign": "pilot" if rec.is_pilot else "campaign",
        "harness_id": rec.harness_id,
        "sheet": _sheet_name(rec.harness_id),
        "row": rec.harness_row,
        "label": rec.label,
        "repeat": name.repeat,  # suffix repeat; minting repeats filled in below
        "target": target,
        "auth": name.auth,
        "role": name.role,
        "variant": name.variant,
        "variant_family": name.variant_family,
        "name_parsed": name.parsed,
        "name_consistent": _cross_check(name.auth, name.role, config),
        "launch_complete": launch_complete,
        "direct_run": direct_run,
        # location
        "run": rec.run,
        "run_dir": str(rec.run_dir),
        "digest": rec.config_digest,
        "suffix": rec.label or "",
        "stage": rec.kind,
        # per-stage model / provider / prompts
        "model": model,
        "provider": provider,
        "screening_prompt_version": config.get("screening_prompt_version"),
        "synthesis_prompt_version": config.get("synthesis_prompt_version"),
        "verify_prompt_version": config.get("verify_prompt_version"),
        # timing / cost / abort
        "started_at": rec.data.get("started_at"),
        "total_seconds": rec.data.get("total_seconds"),
        "cost_usd": results.get("cost_usd"),
        "abort": rec.data.get("abort") or "",
        "aborted": rec.aborted,
        # scanner memory for NFR-05 (host figure; container peak is a known gap)
        "host.memory_gb": host.get("memory_gb"),
        # the stage's primary artifact, for finding-level joins
        "artifact": results.get("artifact"),
    }
    _flatten("config", config, row)
    _flatten("results", results, row)
    for sub, secs in stage_seconds.items():
        row[f"stage.{sub}"] = secs
    return row


_MINTING_KEYS = ["campaign", "target", "auth", "role", "variant", "stage"]


def _assign_minting_repeats(df: pd.DataFrame) -> pd.DataFrame:
    """Number minting repeats run-wise.

    A G3 scan repeat is a distinct run with an empty label, so its ``repeat`` is
    <NA> after parsing. Within each (campaign, target, auth, role, variant, stage)
    group, order the distinct runs by ``started_at`` and assign 1..n so Spread
    (§9) can count them. Suffix repeats already carry their ordinal and are left.
    Rows whose axes did not parse (G9 analysis, pilot) still get an ordinal via a
    string-filled grouping so no run is dropped.
    """
    df = df.copy()
    df["repeat"] = df["repeat"].astype("Int64")
    # Only canonical rows are repeats of a usable configuration: a false-start
    # launch (no results.json) or an aborted run is not repeat-n of the campaign
    # cell, so it must not shift the ordinal of the run that was kept. Its repeat
    # stays <NA> (it is excluded from analysis anyway). Pilot vs campaign are
    # already separated by the ``campaign`` key, so the pilot numbers on its own.
    need = (
        df["repeat"].isna()
        & df["launch_complete"].fillna(False)
        & ~df["aborted"].fillna(False)
    )
    if df.empty or not bool(need.any()):
        return df

    key_cols = _MINTING_KEYS + ["run"]
    sub = df.loc[need, key_cols + ["started_at"]].copy()
    for col in key_cols:
        sub[col] = sub[col].astype("string").fillna("∅")
    firsts = (
        sub.groupby(key_cols, as_index=False)["started_at"].min().sort_values("started_at")
    )
    firsts["ord"] = firsts.groupby(_MINTING_KEYS).cumcount() + 1

    rank = {
        tuple(rec[:-1]): rec[-1]
        for rec in firsts[key_cols + ["ord"]].itertuples(index=False, name=None)
    }
    lookup = df.loc[need, key_cols].copy()
    for col in key_cols:
        lookup[col] = lookup[col].astype("string").fillna("∅")
    vals = [rank.get(t) for t in lookup.itertuples(index=False, name=None)]
    df.loc[need, "repeat"] = pd.array(vals, dtype="Int64")
    return df


def build_index(roots: list[Path] | Path) -> pd.DataFrame:
    """Build the full stage-execution index from one or more data roots."""
    records = load_records(roots)
    rows = [record_to_row(r) for r in records]
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df = df.sort_values(["started_at", "run", "stage"]).reset_index(drop=True)
    df = _assign_minting_repeats(df)
    return df
