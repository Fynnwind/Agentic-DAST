"""Standalone SAST + SCA static-analysis findings (Semgrep + OSV-Scanner): run both over the
target's source tree and write their SARIF unmodified into a run directory.

Standalone or joined by one flag: no ``--run`` mints its own folder, ``--run <id>`` writes
into an existing DAST run's folder (disjoint basenames, its own metrics record, overwrites
nothing) — one-way, the DAST chain never invokes it. A command and not a stage because
these findings are not part of scan→triage→verify→report and must not become so (they
need no target instance, no ZAP, no key, and independence from the system they benchmark).
→ DECISIONS.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from . import StaticAnalysisError, osv_runner, semgrep_runner

REPO_ROOT = Path(__file__).resolve().parents[4]

#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()


def _relative_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


# -- summary ---------------------------------------------------------------


def build_summary_md(record: dict[str, Any]) -> str:
    """Render the run's own numbers as the human-readable half of the artifact.

    Findings-only on purpose: it reports what SAST and SCA found over the target
    source and never opens a DAST report. Cross-referencing the three is the
    thesis's analysis, not this command's, so the summary gives that analysis its
    inputs — notably the CWE histogram, the one vocabulary a Semgrep rule and a
    ZAP alert share — rather than pre-empting it.
    """
    tools = record.get("tools", {})
    results = record.get("results", {})
    semgrep_prov = tools.get("semgrep", {})
    osv_prov = tools.get("osv-scanner", {})
    lines = [
        f"# Static-analysis findings — run `{record.get('run', '?')}`",
        "",
        "Two independent measurements over the target's own source: a SAST scan "
        "and an SCA scan. Neither is part of the DAST pipeline — nothing here is "
        "correlated, verified, or fed to a model, and nothing here directed a "
        "scan.",
        "",
        # Section 1 is the same section, with the same caveat, as report.md's.
        # The two documents describe one run and are read side by side, so they
        # open the same way; a reader should not have to learn two shapes.
        "## 1. How this run was configured",
        "",
        "*Two runs that differ on any of these are not comparable, however "
        "similar their totals look.*",
        "",
        "| setting | value |",
        "|---|---|",
        f"| target | **{results.get('target', '?')}** |",
        f"| source tree | `{results.get('source_dir', '?')}` |",
        f"| tools run | {results.get('tools_requested', '?')} |",
    ]
    if semgrep_prov:
        lines += [
            f"| Semgrep image | `{semgrep_prov.get('image', '?')}` |",
            f"| Semgrep rulesets | {semgrep_prov.get('rulesets', '?')} |",
            f"| Semgrep rules commit | `{(semgrep_prov.get('rules_commit') or '?')[:12]}`"
            + ("" if semgrep_prov.get("rules_pinned")
               else " **⚠ differs from the pin**") + " |",
        ]
    if osv_prov:
        lines.append(f"| OSV-Scanner image | `{osv_prov.get('image', '?')}` |")
        for db in osv_prov.get("database", []):
            lines.append(
                f"| OSV database ({db['ecosystem']}) | "
                f"{db['downloaded_at'][:10]}, `{db['sha256'][:12]}` |"
            )
    lines += [
        "| network | `none` — both tools run offline against pinned inputs |",
        "",
    ]

    semgrep = results.get("semgrep")
    if semgrep:
        prov = semgrep_prov
        pinned = prov.get("rules_pinned")
        drift = "" if pinned else "  **⚠ ruleset differs from the pin**"
        lines += [
            "## 2. SAST — Semgrep",
            "",
            f"- **{semgrep.get('findings', 0)}** findings from "
            f"{semgrep.get('rules_with_findings', 0)} of "
            f"{semgrep.get('rules_loaded', 0)} loaded rules, over "
            f"{semgrep.get('files_scanned', '?')} scanned files "
            f"({semgrep.get('files_with_findings', 0)} files carry one).",
            f"- **{semgrep.get('security_findings', 0)}** carry Semgrep's own "
            "`security` tag — the subset comparable with a DAST scan; the rest "
            "are correctness/best-practice rules, counted but distinct.",
            f"- Severity (SARIF level): {semgrep.get('by_level', {})}.",
            *([f"- {drift.strip()}"] if drift else []),
            "",
            "### Top rules",
            "",
            "| findings | rule |",
            "|---|---|",
        ]
        for row in semgrep.get("top_rules", [])[:10]:
            lines.append(f"| {row['findings']} | `{row['rule_id']}` |")
        by_cwe = semgrep.get("by_cwe") or {}
        if by_cwe:
            lines += [
                "",
                "### CWE histogram (the SAST↔DAST join axis)",
                "",
                "| findings | CWE |",
                "|---|---|",
            ]
            for cwe, n in list(by_cwe.items())[:15]:
                lines.append(f"| {n} | {cwe} |")
        lines.append("")

    osv = results.get("osv")
    if osv:
        prov = osv_prov
        dbs = ", ".join(
            f"{d['ecosystem']} ({d['downloaded_at'][:10]}, "
            f"`{d['sha256'][:12]}`)" for d in prov.get("database", [])
        )
        lines += [
            "## 3. SCA — OSV-Scanner",
            "",
            f"- `{prov.get('image')}` v{prov.get('version')}, offline database "
            f"snapshot: {dbs or 'none recorded'}.",
            f"- **{osv.get('findings', 0)}** findings = "
            f"{osv.get('advisories', 0)} distinct advisories across "
            f"{osv.get('packages', 0)} vulnerable packages.",
            f"- Severity (CVSS band): {osv.get('by_severity', {})}.",
            f"- Manifests: {osv.get('by_manifest', {})}.",
            "",
            "### Most-affected packages",
            "",
            "| advisories | package |",
            "|---|---|",
        ]
        for row in osv.get("top_packages", [])[:10]:
            lines.append(f"| {row['advisories']} | `{row['package']}` |")
        lines.append("")

    return "\n".join(lines)


# -- driver ----------------------------------------------------------------


def run_analysis(
    target: targets.Target,
    source_dir: Path,
    data_dir: Path = DATA_DIR,
    rules_dir: Path | None = None,
    db_dir: Path | None = None,
    rulesets: list[str] | None = None,
    only: "str | None" = None,
    refresh_db: bool = False,
    timestamp: str | None = None,
    run_id: str | None = None,
) -> tuple[run_paths.RunLayout, dict[str, Any], list[str]]:
    """Run the requested tools, write every artifact, return the layout.

    :param run_id: an existing run's directory to write into. Defaults to a new
        ``<timestamp>-<target>-<config>`` id of this run's own.

    A failing tool does not abort the other: SAST and SCA are independent
    measurements, and losing one must not cost the other's number. Failures are
    returned as messages and reflected in the exit status.
    """
    rules_dir = rules_dir or (REPO_ROOT / semgrep_runner.RULES_DIR_NAME)
    db_dir = db_dir or osv_runner.db_dir_default(REPO_ROOT)
    # `None` means "run both" — kept as the string "both" everywhere it is
    # recorded so the artifact and the config digest read the same as before the
    # flag dropped its redundant "both" choice.
    only_label = only or "both"
    # What makes two analysis runs different experiments: which tools ran and
    # which rules they ran. The pinned ruleset commit is the load-bearing one —
    # a number produced by a drifted checkout must not share a name with one
    # produced by the pin.
    run_config = {
        "tools": only_label,
        "rulesets": sorted(rulesets or target.source_analysis.semgrep_rulesets),
        "semgrep_rules_commit": semgrep_runner.rules_commit(rules_dir),
    }
    run_id = run_id or run_paths.make_run_id(
        timestamp or run_paths.now_timestamp(), target.name,
        run_paths.config_digest(run_config),
    )
    layout = run_paths.RunLayout(data_dir, run_id).ensure()

    metrics = run_metrics.RunMetrics(run_id, kind="analysis")
    metrics.record_config(run_config)
    with metrics.guard(data_dir):
        metrics.record_results(
            target=target.name,
            # Relative to the repo root when it sits inside it: an artifact quoted in
            # the writeup should not carry the author's home directory.
            source_dir=_relative_to_repo(source_dir),
            tools_requested=only_label,
        )
        errors: list[str] = []

        if only in (None, "sast"):
            with ui.timed_phase("SAST — Semgrep"), metrics.stage("semgrep") as stage:
                try:
                    chosen = rulesets or list(target.source_analysis.semgrep_rulesets)
                    sarif, run = semgrep_runner.run_semgrep(source_dir, rules_dir, chosen)
                    layout.path(run_paths.SEMGREP_SARIF).write_text(
                        json.dumps(sarif, indent=2)
                    )
                    summary = semgrep_runner.summarise(sarif, run)
                    stage.counters.update(
                        findings=summary["findings"],
                        security_findings=summary["security_findings"],
                        files_scanned=summary["files_scanned"],
                    )
                    metrics.record_results(semgrep=summary)
                    metrics.record_tool(
                        "semgrep",
                        **semgrep_runner.provenance(sarif, run, rules_dir, chosen),
                    )
                    ui.found(f"{summary['findings']} findings, "
                             f"{summary['security_findings']} security-tagged, "
                             f"{summary['files_scanned']} files scanned")
                except StaticAnalysisError as exc:
                    errors.append(f"semgrep: {exc}")
                    print(f"  [semgrep] FAILED: {exc}", file=sys.stderr)

        if only in (None, "sca"):
            refreshed = False
            try:
                if refresh_db or not osv_runner.database_files(db_dir):
                    with metrics.stage("osv_database_download"):
                        print(f"  [osv] downloading advisory database into {db_dir} "
                              "(the one networked step)")
                        download = osv_runner.download_database(source_dir, db_dir)
                        refreshed = True
                    if not osv_runner.database_files(db_dir):
                        raise StaticAnalysisError(
                            "advisory-database download produced no snapshot "
                            f"(exit {download.exit_code}): {download.stderr[-400:]}"
                        )
                with ui.timed_phase("SCA — OSV-Scanner"), metrics.stage("osv") as stage:
                    sarif, run = osv_runner.run_osv(source_dir, db_dir)
                    layout.path(run_paths.OSV_SARIF).write_text(json.dumps(sarif, indent=2))
                    summary = osv_runner.summarise(sarif, run)
                    stage.counters.update(
                        findings=summary["findings"],
                        advisories=summary["advisories"],
                        packages=summary["packages"],
                    )
                    metrics.record_results(osv=summary)
                    metrics.record_tool(
                        "osv-scanner",
                        **osv_runner.provenance(sarif, run, db_dir, refreshed=refreshed),
                    )
                    ui.found(f"{summary['findings']} findings, "
                             f"{summary['advisories']} advisories over "
                             f"{summary['packages']} packages")
            except StaticAnalysisError as exc:
                errors.append(f"osv-scanner: {exc}")
                print(f"  [osv] FAILED: {exc}", file=sys.stderr)

        # `findings` is the column `dast costs` prints for every kind of run, so the
        # the findings are comparable with a scan there without a special case.
        totals = sum(
            (metrics.results.get(name) or {}).get("findings", 0)
            for name in ("semgrep", "osv")
        )
        metrics.record_results(findings=totals, artifact=str(layout.dir.name))

    # The metrics record is already on disk — `guard` wrote it on the way out of
    # the block above (and would have, with an abort object, had the stage
    # crashed). Here on the clean path only: the summary and the Markdown digest.
    metrics.print_summary()
    record = metrics.as_dict()
    layout.path(run_paths.ANALYSIS_MD).write_text(build_summary_md(record))
    return layout, record, errors


def _existing_run(data_dir: Path, ident: str) -> str:
    """Resolve the positional to a run directory that exists.

    Creating the directory is deliberately not an option here: naming a run
    means *join it*, and a typo that silently made a new folder is worse than an
    error. The standalone form is naming the target instead, which is
    unambiguous — a target name and a run id cannot be confused.
    """
    runs = run_paths.RunLayout.runs(data_dir)
    if run_paths.is_latest(ident):
        if not runs:
            raise StaticAnalysisError(
                f"no runs in {data_dir} to join — name the target instead, "
                "which starts a standalone run"
            )
        return runs[-1]
    try:
        resolved = run_paths.RunLayout.resolve(data_dir, ident).run_id
    except ValueError as exc:
        raise StaticAnalysisError(str(exc)) from exc
    if resolved not in runs:
        raise StaticAnalysisError(
            f"{ident!r} is neither a known target nor a run in {data_dir}"
        )
    return resolved

def build_parser() -> argparse.ArgumentParser:
    """This stage's argument parser, built without parsing anything.

    Separate from :func:`main` so ``dast`` can read the flags this stage
    accepts — that is what lets one flag be routed to the right stage of a
    sequence, and an ambiguous one be refused by name rather than silently
    applied to the wrong stage. Defaults still come from the environment, so
    the caller loads the stage's env file first.
    """
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "static-analysis")
    parser = argparse.ArgumentParser(
        description=config.command_description(__doc__), parents=[pre])
    parser.add_argument(
        "target_or_run", metavar="<target-or-run>",
        help="What to analyse. A **target** name (e.g. `gitea`) runs the "
             "analysis standalone, in a new run directory of its own — the "
             "right shape when they run on their own schedule, since a source "
             "analysis is valid for a source-tree version rather than for one "
             "scan. A **run id** (or `latest`) writes into that run's folder "
             "instead, so one complete run of everything is one directory; the "
             "run id already names its target, so nothing else has to.",
    )
    parser.add_argument(
        "--source", type=Path,
        help="Override the source tree analysed. Must match the pinned version "
             "of the running target.\n"
             "Falls back to the target's own tree, relative to the repo root.",
    )
    parser.add_argument(
        "--only", choices=("sast", "sca"), default=os.getenv("STATIC_ANALYSIS_ONLY") or None,
        help="Restrict the run to one pass: SAST (Semgrep) or SCA "
             "(OSV-Scanner).\n"
             "Omit to run both, which is the point of the command.",
    )
    parser.add_argument(
        "--ruleset", action="append", dest="rulesets", default=[], metavar="<dir>",
        help="A Semgrep ruleset to run: a directory of the pinned semgrep-rules "
             "checkout, e.g. --ruleset go.\n"
             "Falls back to the target's own rulesets; the checkout itself is "
             "--rules-dir.",
    )
    parser.add_argument(
        "--rules-dir", type=Path,
        default=REPO_ROOT / semgrep_runner.RULES_DIR_NAME,
        help="Pinned semgrep-rules checkout.",
    )
    parser.add_argument(
        "--db-dir", type=Path, default=osv_runner.db_dir_default(REPO_ROOT),
        help="OSV advisory-database snapshot directory.",
    )
    parser.add_argument(
        "--refresh-db", action="store_true",
        help="Re-download the OSV database before scanning. The only step that "
             "uses the network, and the only thing that changes an SCA result "
             "for an unchanged target — so it is always explicit.",
    )
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument(
        "--dry-run", action="store_true",
        default=config.env_bool("STATIC_ANALYSIS_DRY_RUN"),
        help="Print the exact container invocations and stop.\n"
             "Set it via the env only deliberately — it turns a real run into a "
             "no-op.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Run even though another process holds this stage's lock on the "
             "run directory it is joining. Overrides the refusal; it does not "
             "coordinate the two runs.",
    )
    config.add_targets_dir_flag(parser)
    config.normalize_metavars(parser)
    return parser


@run_lock.guarded
def main(argv: "list[str] | None" = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "static-analysis")
    known, _ = pre.parse_known_args(argv)
    # Loaded before the parser is built, so every ``os.getenv`` default below
    # sees the stage's file and an explicit flag still wins (see config.py).
    env = config.load_stage_env("static-analysis", known.env_file)

    parser = build_parser()
    args = parser.parse_args(argv)
    overridden = config.apply_explicit_overrides(env, args, parser, argv)
    if overridden:
        ui.warn(f"{ui.short_path(known.env_file)} supplies (no flag given): "
                f"{', '.join(sorted(overridden))}")

    # Point discovery and source resolution at the configured dir before the
    # positional is matched against the registry below.
    targets.use_dir(args.targets_dir)

    # One positional, two meanings, told apart by the registry: a target name
    # runs the analysis standalone, anything else names a run to join. A run
    # id already carries its target, so naming it twice was never necessary.
    run_id = None
    if args.target_or_run in targets.REGISTRY:
        target_name = args.target_or_run
    else:
        try:
            run_id = _existing_run(args.data_dir, args.target_or_run)
        except StaticAnalysisError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        target_name = run_paths.split_run_id(run_id).target
        if not target_name:
            print(f"ERROR: run {run_id} predates run ids carrying a target, so "
                  "it cannot say which source tree to analyse. Name the target "
                  "instead, which starts a standalone run: "
                  f"`analyze-run {' | '.join(sorted(targets.REGISTRY))}`.",
                  file=sys.stderr)
            return 2

    try:
        target = targets.get(target_name)
    except KeyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    source_dir = args.source or targets.target_source(target)
    rulesets = args.rulesets or list(target.source_analysis.semgrep_rulesets)

    if args.dry_run:
        try:
            volumes, env, sg_args = semgrep_runner.build_command(
                source_dir, args.rules_dir, rulesets
            )
        except StaticAnalysisError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        osv_volumes, osv_args = osv_runner.build_command(source_dir, args.db_dir)
        print("semgrep:")
        print("  docker run --rm --network none "
              + " ".join(f"-v {v}" for v in volumes) + " "
              + " ".join(f"-e {e}" for e in env)
              + f" -w /src {semgrep_runner.SEMGREP_IMAGE} " + " ".join(sg_args))
        print(f"  ruleset pin: {semgrep_runner.RULES_COMMIT} "
              f"(on disk: {semgrep_runner.rules_commit(args.rules_dir)})")
        print("osv-scanner:")
        print("  docker run --rm --network none "
              + " ".join(f"-v {v}" for v in osv_volumes)
              + f" {osv_runner.OSV_IMAGE} " + " ".join(osv_args))
        for entry in osv_runner.database_provenance(args.db_dir):
            print(f"  database: {entry['ecosystem']} {entry['bytes']}B "
                  f"{entry['sha256'][:12]} {entry['downloaded_at']}")
        return 0

    ui.headline("Static-analysis findings — SAST + SCA",
                f"target {target.name}  →  {source_dir}")
    if run_id:
        ui.item("joining run", run_id)
        # Only when joining: a standalone analysis mints its own directory, so
        # there is nothing for a second one to overwrite. Released by
        # `@run_lock.guarded` however this returns.
        run_lock.claim(run_paths.RunLayout(args.data_dir, run_id).dir,
                       "static-analysis", force=args.force)
    layout, record, errors = run_analysis(
        target,
        source_dir,
        data_dir=args.data_dir,
        rules_dir=args.rules_dir,
        db_dir=args.db_dir,
        rulesets=rulesets,
        only=args.only,
        refresh_db=args.refresh_db,
        run_id=run_id,
    )
    summary_phase = ui.open_phase("Static-analysis summary")
    ui.found(f"{(record.get('results') or {}).get('findings')} findings total")
    # Only what *this* command wrote: a joined run directory also holds the
    # scan's and the triage's artifacts, and claiming those would misreport who
    # produced them.
    summary_phase.close(files=[
        name for name in (run_paths.SEMGREP_SARIF, run_paths.OSV_SARIF,
                          run_paths.ANALYSIS_MD, "run-metrics-analysis.json")
        if layout.has(name)
    ])
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
