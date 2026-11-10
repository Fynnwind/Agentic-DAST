"""Selection surface over the index (RUN-PLAN §8).

``--where key=value[,value]`` on any column (``config.*`` included), repeatable
and AND-combined, values within one key OR-combined. A handful of named
selections bundle the where-clauses a thesis table reuses, loadable/overridable
from a YAML file so the run set is named once. ``group_by`` gives n / min / max /
mean per group. Aborted runs, the pilot, and false-start (incomplete) launches
are dropped unless explicitly asked for.
"""

from __future__ import annotations

from functools import reduce
from operator import or_
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

# The named selections RUN-PLAN §8 requires. Each maps the index columns a thesis
# table pins; a value may be a scalar or a list (OR). They are applied on top of
# the default valid filter.
NAMED_SELECTIONS: dict[str, dict[str, Any]] = {
    "matrix-blind": {"sheet": "campaign-1-blind-matrix", "variant": ""},
    "matrix-ceiling": {
        "sheet": ["campaign-2-ceiling-matrix", "campaign-2-cacti-admin-redo"],
        "variant": "",
    },
    "reference-scans": {"auth": "user", "role": "blind", "variant": "", "stage": "scan"},
    "reference-model-repeats": {"variant_family": "rep"},
    "crawl": {"role": "crawl"},
    "verify-configs": {"variant_family": ["vdet", "vdef", "vllm"]},
    "context": {"variant_family": ["codenone", "peernone"]},
    "frontier-screening": {"variant_family": "frscr"},
    "frontier-synthesis": {"variant_family": "frsyn"},
    "frontier-verification": {"variant_family": "frver"},
}


#: Sheets of the frozen corpus (bc30e8d), the campaign of 12 to 14 October. An
#: allow-list: a sheet run later stays out of the frozen tables and figures unless
#: it is named here, so the rescan (``rerun-*``), smoke runs and one-offs cannot
#: join them unnoticed.
FROZEN_CORPUS_SHEETS = frozenset(
    {
        "campaign-1-blind-matrix",
        "campaign-2-ceiling-matrix",
        "campaign-2-cacti-admin-redo",
        "campaign-3-repeats-and-crawl",
        "campaign-3-resume",
        "campaign-3-resume-2",
        "campaign-4a-triage-parallel",
        "campaign-4b-verify-deferred",
        "campaign-5-g8-gitea-opus",
        "campaign-5-g8-gitea-opus-frver",
        "campaign-5-g8-gitea-opus-frver3",
    }
)


#: The four G9 static analyses of the frozen corpus. They were run directly, so
#: they carry no sheet and are named by run.
FROZEN_DIRECT_RUNS = frozenset(
    {
        "20261013T235954Z-grafana-6395ca",
        "20261014T001119Z-wordpress-5ebe1f",
        "20261014T001146Z-cacti-e17e16",
        "20261014T001257Z-gitea-73f624",
    }
)


#: Sheets produced AFTER the frozen corpus (bc30e8d). Campaign-6 is the §10
#: spread measurement at a later commit; campaign-7 is its follow-up (the clean
#: --reset-target gitea rescan); campaign-8* are the block-8 even-fill (grafana
#: blind +2, and gitea/cacti ceilings with --reset-target) that bring every band
#: to n=6. All are kept out of the frozen-corpus tables and figures by default so
#: the two never share a table (``corpus="post"`` selects them instead).
#: campaign-7-codepaths-retriage is NOT here: it is a variant re-triage written
#: into the frozen canonical-baseline runs, not a post sheet.
POST_CORPUS_SHEETS = frozenset(
    {
        "campaign-6-spread-repeats",
        "campaign-6-cacti-blind-redo",
        "campaign-7-even-scan-variance",
        "campaign-8-even-fill",
        "campaign-8b-cacti-ceiling",
        "campaign-8c-cacti-ceiling",
        "campaign-8d-cacti-ceiling",
    }
)


#: One-off demonstration runs excluded from every default corpus. The OpenAPI
#: spec-seeded scan (2026-10-19, ``…gitea-9fcc38``) proved the ``openapi_import``
#: path on gitea, but its active scan was capped mid-crawl (2808-URL tree, 15-min
#: cap), so it is a demonstration, not a measurement run — it must not sit in the
#: frozen scan count or the detection figures. Excluded by default from every
#: corpus; pass ``include_demo=True`` to see it.
DEMO_RUNS = frozenset({"20261019T211339Z-gitea-9fcc38"})


def default_valid(
    df: pd.DataFrame,
    *,
    include_pilot: bool = False,
    include_aborted: bool = False,
    include_incomplete: bool = False,
    include_demo: bool = False,
    corpus: str = "frozen",
) -> pd.DataFrame:
    """Drop pilot, aborted, false-start (incomplete-launch) and demo rows by default.

    ``corpus`` scopes the result: ``"frozen"`` (the default — the bc30e8d corpus,
    only what ``FROZEN_CORPUS_SHEETS`` and ``FROZEN_DIRECT_RUNS`` name), ``"post"``
    (only the post-corpus §10 sheets), or ``"all"`` (every sheet, the rescan and
    smoke runs included). A frozen table and a post table must never be merged.
    """
    if df.empty:
        return df.copy()
    mask = pd.Series(True, index=df.index)
    if not include_pilot:
        mask &= df["campaign"] != "pilot"
    if not include_aborted:
        mask &= ~df["aborted"].fillna(False).astype(bool)
    if not include_incomplete:
        mask &= df["launch_complete"].fillna(False).astype(bool)
    if not include_demo:
        mask &= ~df["run"].isin(DEMO_RUNS)
    if corpus == "frozen":
        # Pilot and demo rows get this far only when asked for above; those switches
        # decide them, and they sit on no campaign sheet.
        mask &= (
            df["sheet"].isin(FROZEN_CORPUS_SHEETS)
            | df["run"].isin(FROZEN_DIRECT_RUNS)
            | (df["campaign"] == "pilot")
            | df["run"].isin(DEMO_RUNS)
        )
    elif corpus == "post":
        mask &= df["sheet"].isin(POST_CORPUS_SHEETS)
    elif corpus != "all":
        raise ValueError(f"corpus must be 'frozen', 'post', or 'all'; got {corpus!r}")
    return df[mask].copy()


def _col_match(col: pd.Series, value: str) -> pd.Series:
    """One (column == value) mask, tolerant of numeric/bool/empty comparisons."""
    if value == "":
        return col.isna() | (col.astype("string").fillna("") == "")
    if pd.api.types.is_bool_dtype(col):
        return col == (value.strip().lower() in ("true", "1", "yes"))
    if pd.api.types.is_numeric_dtype(col):
        try:
            return col == float(value)
        except ValueError:
            pass
    return col.astype("string") == value


def _filter_one(df: pd.DataFrame, key: str, values: list[str]) -> pd.DataFrame:
    if key not in df.columns:
        raise KeyError(
            f"unknown selection column {key!r}; try one of: "
            + ", ".join(sorted(c for c in df.columns if not c.startswith("stage.")))
        )
    masks = [_col_match(df[key], v) for v in values]
    return df[reduce(or_, masks)]


def apply_where(df: pd.DataFrame, wheres: list[str]) -> pd.DataFrame:
    """Apply ``key=val[,val]`` clauses; AND across clauses, OR within a clause."""
    for clause in wheres:
        key, sep, raw = clause.partition("=")
        if not sep:
            raise ValueError(f"malformed --where {clause!r}; expected key=value")
        values = [v.strip() for v in raw.split(",")]
        df = _filter_one(df, key.strip(), values)
    return df


def load_named_selections(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Built-in named selections, extended/overridden by a YAML file if given."""
    out = {k: dict(v) for k, v in NAMED_SELECTIONS.items()}
    if path is not None:
        extra = yaml.safe_load(Path(path).read_text()) or {}
        for name, constraints in extra.items():
            out[name] = dict(constraints)
    return out


def apply_named(
    df: pd.DataFrame, name: str, selections: dict[str, dict[str, Any]] | None = None
) -> pd.DataFrame:
    """Apply a named selection's constraints on top of the default valid filter."""
    selections = selections or NAMED_SELECTIONS
    if name not in selections:
        raise KeyError(
            f"unknown selection {name!r}; known: {', '.join(sorted(selections))}"
        )
    out = default_valid(df)
    for key, value in selections[name].items():
        values = value if isinstance(value, list) else [value]
        out = _filter_one(out, key, [str(v) for v in values])
    return out


def group_by(
    df: pd.DataFrame, by: list[str], metrics: list[str] | None = None
) -> pd.DataFrame:
    """n / min / max / mean per group (§8). ``metrics`` default to numeric columns."""
    if metrics is None:
        metrics = [
            c
            for c in df.columns
            if pd.api.types.is_numeric_dtype(df[c])
            and not c.startswith("stage.")
            and c != "repeat"
        ]
    grouped = df.groupby(by, dropna=False)
    frames = {"n": grouped.size()}
    for m in metrics:
        if m in df.columns:
            frames[f"{m}.min"] = grouped[m].min()
            frames[f"{m}.max"] = grouped[m].max()
            frames[f"{m}.mean"] = grouped[m].mean()
    return pd.DataFrame(frames).reset_index()
