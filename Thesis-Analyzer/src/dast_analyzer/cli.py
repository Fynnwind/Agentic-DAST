"""``dast-analyze`` — selection → tables (CSV/JSON) + figures + a digest.

The analyzer's one entry point (RUN-PLAN §8). It builds the index once, applies a
selection (``--where`` / ``--named``), and emits either a named analysis table, an
ad-hoc group-by, the figure set, or the full Markdown/LaTeX-ready digest. Every
output carries the provenance header (corpus commit + run ids) so a number in the
thesis traces back to its runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from . import cuts, figures, g9, markers, metrics, priority, provenance
from .findings import agreement_per_run, tool_agreement, two_arm_matrix
from .index import build_index
from .selection import apply_named, apply_where, default_valid, group_by


def _default_data_root() -> Path:
    # <repo>/Thesis-Analyzer/src/dast_analyzer/cli.py -> <repo>/Tool/data
    return Path(__file__).resolve().parents[3] / "Tool" / "data"


# name -> (callable(index)->DataFrame, one-line description). Each named table
# carries its own fixed selection (§8), so --where/--named apply only to `select`.
TABLES: dict[str, tuple] = {
    "two-arm": (two_arm_matrix, "Two-arm triage agreement per blind cell (llm-only=0)"),
    "agreement-per-run": (agreement_per_run, "Agreement counts per triage execution"),
    "tool-agreement": (tool_agreement, "Tool naming agreement between the arms"),
    "detection-ladder": (markers.blind_vs_ceiling, "Per-layer detection, blind vs ceiling"),
    "ceiling-variance": (markers.ceiling_variance, "Per-marker ceiling catch rate (pilot+campaign)"),
    "alert-volume": (metrics.alert_volume_vs_detection, "Alert volume range vs detection point"),
    "duration": (metrics.duration_summary, "Scan/chain minutes vs NFR-02 (30 min)"),
    "memory": (metrics.scanner_memory_summary, "Scanner container peak memory, NFR-05"),
    "cost-per-finding": (metrics.cost_per_finding, "Cost per finding, 3 denominators + no-cache"),
    "model-spread": (metrics.model_stage_spread, "G5 model-stage spread (error bars)"),
    "synthesis-recurrence": (cuts.recurrence_disposition_crosstab, "Synthesis recurrence vs disposition"),
    "context-verify": (cuts.context_through_verification, "G7 context read through verification"),
    "noir-delta": (cuts.noir_seeding_delta, "G4 Noir seeding delta, per target range"),
    "frontier": (cuts.frontier_measured, "G8 Opus vs default per stage (gitea)"),
    "frontier-cost": (cuts.frontier_cost_projection, "G8 full-pass cost projection per target"),
    "frontier-unparseable": (cuts.frontier_unparseable, "G8 structured-output verify failures"),
    "sca-dast": (cuts.sca_dast_components, "SCA (OSV) vs ZAP 10003 on component identity"),
    "g9-populations": (g9.g9_populations, "SAST/SCA populations per target"),
    "g9-cross": (g9.sast_dast_cross, "SAST vs DAST by CWE class"),
    "handler-source": (g9.handler_source_join, "Refuted DAST finding -> handler source -> SAST"),
    "providers": (provenance.served_synthesis_providers, "Served synthesis provider per run (routed)"),
    "read-load": (priority.read_load, "Results against the worklist lines they roll up to"),
    "risk-disposition": (priority.risk_disposition, "ZAP risk against the report's sections, per run"),
    "gate-simulation": (priority.gate_simulation, "Runs each CI gate would block (a simulation)"),
    "open-stability": (priority.open_stability, "Alert spread against the open rule list, repeats"),
    "reproduced-first": (priority.reproduced_first, "Reproduced results lead the report (a guard)"),
}


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def _md_table(df: pd.DataFrame, floatfmt: str = "{:.3g}") -> str:
    def cell(v):
        if isinstance(v, float):
            return floatfmt.format(v)
        return "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)

    cols = list(df.columns)
    head = "| " + " | ".join(cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    rows = ["| " + " | ".join(cell(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join([head, sep, *rows])


def _emit(df: pd.DataFrame, fmt: str, header: dict | None, out) -> None:
    if fmt == "csv":
        if header:
            for line in provenance.header_lines(header):
                out.write(f"# {line}\n")
        out.write(df.to_csv(index=False))
    elif fmt == "json":
        payload = {"provenance": header, "rows": json.loads(df.to_json(orient="records"))}
        out.write(json.dumps(payload, indent=2))
        out.write("\n")
    elif fmt == "latex":
        out.write(df.to_latex(index=False, float_format="%.3g"))
    else:  # md
        if header:
            out.write("<!-- " + "; ".join(provenance.header_lines(header)) + " -->\n\n")
        out.write(_md_table(df))
        out.write("\n")


def _open_out(path: str | None):
    return open(path, "w") if path else sys.stdout


# --------------------------------------------------------------------------- #
# the digest
# --------------------------------------------------------------------------- #
_DIGEST_SECTIONS = [
    ("Two-arm triage agreement (central claim: llm-only = 0)", "two-arm"),
    ("Detection per layer — blind vs ceiling", "detection-ladder"),
    ("Ceiling catch likelihood per marker (pilot + campaign)", "ceiling-variance"),
    ("Alert volume (range) vs detection (point)", "alert-volume"),
    ("Duration vs NFR-02 (30 min)", "duration"),
    ("Scanner memory, NFR-05", "memory"),
    ("Cost per finding", "cost-per-finding"),
    ("Model-stage spread (G5 error bars)", "model-spread"),
    ("Synthesis recurrence vs disposition (#6)", "synthesis-recurrence"),
    ("G7 context through verification (#7)", "context-verify"),
    ("G4 Noir seeding delta (#8)", "noir-delta"),
    ("G8 frontier: value vs cost (#10)", "frontier"),
    ("G8 frontier cost projection (#10)", "frontier-cost"),
    ("G8 structured-output verify failures (#10)", "frontier-unparseable"),
    ("SAST vs DAST by CWE class (G9)", "g9-cross"),
    ("Refuted DAST finding -> handler source -> SAST (G9)", "handler-source"),
    ("SCA vs DAST on component identity", "sca-dast"),
    ("Served synthesis provider (routed, not pinned)", "providers"),
    ("Read load: results against worklist lines", "read-load"),
    ("ZAP's risk against the report's sections", "risk-disposition"),
    ("CI gate simulation (FR-08)", "gate-simulation"),
    ("Alert spread against the open rule list", "open-stability"),
    ("Reproduced results lead the report (guard)", "reproduced-first"),
]


def _digest(index: pd.DataFrame, out, fmt: str = "md") -> None:
    header = provenance.provenance_header(default_valid(index))
    out.write("# Thesis-Analyzer digest\n\n")
    out.write("Machine-generated from the frozen corpus; every table traces to the "
              "runs in the provenance header. See RUN-PLAN §8/§9 for definitions.\n\n")
    out.write("```\n" + "\n".join(provenance.header_lines(header)) + "\n```\n\n")
    for title, name in _DIGEST_SECTIONS:
        func, desc = TABLES[name]
        out.write(f"## {title}\n\n_{desc}_\n\n")
        try:
            df = func(index)
            _emit(df, fmt, None, out)
        except Exception as exc:  # a cut empty under a narrow corpus
            out.write(f"_(no data: {type(exc).__name__}: {exc})_\n")
        out.write("\n")
    # G10 OOB: a standalone record, never a pipeline detection
    g10 = cuts.g10_oob_record(_oob_root(index))
    out.write("## G10 — out-of-band confirmation (standalone, not a pipeline detection)\n\n")
    if g10:
        ev = g10.get("evidence", {})
        out.write(f"- **{g10.get('marker', {}).get('cve')}** — {g10.get('result')} "
                  f"({g10.get('date')}) via {ev.get('tool')} `{ev.get('template_id')}`, "
                  f"digest `{ev.get('nuclei_image_digest', '')[:19]}…`.\n")
    else:
        out.write("_(g10-oob-confirmation.json not found)_\n")
    out.write("\n")


def _oob_root(index: pd.DataFrame) -> Path:
    if not len(index):
        return Path(".")
    # any run_dir -> climb to the data root
    p = Path(index["run_dir"].iloc[0])
    for parent in p.parents:
        if parent.name == "data":
            return parent
    return p.parents[1]


# --------------------------------------------------------------------------- #
# argument plumbing
# --------------------------------------------------------------------------- #
def _common(suppress: bool) -> argparse.ArgumentParser:
    """Shared --data/-o/-f; SUPPRESS on the subparser copy so a value given
    before the subcommand is not clobbered by the subparser's own default."""
    c = argparse.ArgumentParser(add_help=False)
    d = argparse.SUPPRESS if suppress else None
    c.add_argument("--data", action="append", type=Path, default=d, help="data root(s); default <repo>/Tool/data")
    c.add_argument("-o", "--out", default=d, help="output file (default stdout)")
    c.add_argument("-f", "--format", choices=["md", "csv", "json", "latex"], default=d, help="output format")
    return c


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dast-analyze", description=__doc__, parents=[_common(False)])
    sub = p.add_subparsers(dest="cmd", required=True)
    child = [_common(True)]  # options repeated on each subcommand, defaults suppressed

    t = sub.add_parser("table", parents=child, help="emit one named analysis table")
    t.add_argument("name", choices=sorted(TABLES))

    s = sub.add_parser("select", parents=child, help="ad-hoc selection / group-by over the index")
    s.add_argument("--where", action="append", default=[], help="key=val[,val], repeatable")
    s.add_argument("--named", help="a named selection")
    s.add_argument("--group-by", help="comma-separated columns for n/min/max/mean")
    s.add_argument("--metrics", help="comma-separated metric columns for --group-by (default: all numeric)")
    s.add_argument("--include-pilot", action="store_true")

    sub.add_parser("list", parents=child, help="list the named tables")
    sub.add_parser("digest", parents=child, help="the full Markdown/LaTeX digest")

    fg = sub.add_parser("figures", parents=child, help="render the figure set")
    fg.add_argument("--out-dir", default="figures")
    fg.add_argument("--only", help="comma-separated figure names")
    fg.add_argument("--formats", default="pgf,pdf,png")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    roots = args.data or [_default_data_root()]
    index = build_index(roots)
    if index.empty:
        print(f"no records under {', '.join(str(r) for r in roots)}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        for name in sorted(TABLES):
            print(f"{name:22} {TABLES[name][1]}")
        return 0

    if args.cmd == "figures":
        only = args.only.split(",") if args.only else None
        written = figures.render_all(index, args.out_dir, formats=tuple(args.formats.split(",")), only=only)
        print(f"wrote {len(written)} files to {args.out_dir}")
        return 0

    out = _open_out(args.out)
    try:
        if args.cmd == "digest":
            _digest(index, out, fmt="md" if args.format == "latex" else args.format)
        elif args.cmd == "table":
            func, _ = TABLES[args.name]
            df = func(index)
            _emit(df, args.format, provenance.provenance_header(default_valid(index)), out)
        elif args.cmd == "select":
            df = apply_named(index, args.named) if args.named else default_valid(index, include_pilot=args.include_pilot)
            if args.where:
                df = apply_where(df, args.where)
            header = provenance.provenance_header(df)
            if args.group_by:
                metrics_cols = args.metrics.split(",") if args.metrics else None
                df = group_by(df, args.group_by.split(","), metrics_cols)
            _emit(df, args.format, header, out)
    finally:
        if out is not sys.stdout:
            out.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
