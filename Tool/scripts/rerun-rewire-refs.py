#!/usr/bin/env python3
"""Point the deferred rescan sheets (G5/G6/G7/G9) at a fresh G1's admin-blind runs.

G5 (model repeats), G6 (verify configs), G7 (context) and G9 (static) re-process
G1's admin-blind runs through each row's ``run:`` field rather than re-scanning.
After a fresh G1
lands, those run ids change, so this rewrites them from the G1 sheet's
``results.json`` — the one mechanical step between G1 and the deferred sheets,
done once per re-run instead of by hand (and instead of leaving them pointed at a
previous, possibly contaminated, G1).

Usage::

    python scripts/rerun-rewire-refs.py <data/harness/..-rerun-g1-..>   # that G1
    python scripts/rerun-rewire-refs.py <G1 dir> <re-run dir>           # later dir wins per target
    python scripts/rerun-rewire-refs.py                                 # newest G1 matrix
    python scripts/rerun-rewire-refs.py --dry-run                       # show, don't write

It edits ``config/harness/rerun-g{5,6,7,9}-*.yml`` IN PLACE, replacing only the run
id on rows whose name starts ``<target>-admin-blind``; all formatting and
comments are preserved (it is a per-line id swap, not a YAML round-trip). It
prints every change, and exits non-zero if a target a deferred sheet references
has no admin-blind run in the given G1.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]                 # the Tool/ directory
HARNESS = ROOT / "config" / "harness"
DEFERRED = (
    "rerun-g5-model-repeats.yml",
    "rerun-g6-verify-configs.yml",
    "rerun-g7-context.yml",
    "rerun-g9-static.yml",
)
#: One row per line in these sheets, e.g. ``{name: grafana-admin-blind-vdet,
#: run: <id>, ...}`` (G5/G6/G7) or ``{name: grafana-static, run: <id>, ...}`` (G9).
#: Every ``run:`` row in these sheets references a G1 admin-blind scan, so
#: the row's target (its first name segment) is the only key needed.
_NAME_RE = re.compile(r"name:\s*([a-z0-9]+)-")
_RUN_RE = re.compile(r"(run:\s*)([^\s,}]+)")    # the id alone: its "," stays in the row


def latest_g1_dir() -> Path:
    dirs = sorted(glob.glob(str(ROOT / "data" / "harness" / "*-rerun-g1-blind-matrix")))
    if not dirs:
        sys.exit("no rerun-g1-blind-matrix sheet directory under data/harness/; pass one explicitly")
    return Path(dirs[-1])


def admin_blind_ids(g1_dir: Path) -> dict[str, str]:
    """``{target: run_id}`` for every admin-blind execution the G1 sheet recorded."""
    results = json.loads((g1_dir / "results.json").read_text())
    ids: dict[str, str] = {}
    for execution in results.get("executions", []):
        row, run = execution.get("row", ""), execution.get("run")
        if run and row.endswith("admin-blind") and not execution.get("failed_stage"):
            ids[row.split("-", 1)[0]] = run
    if not ids:
        sys.exit(f"no completed admin-blind runs in {g1_dir}/results.json")
    return ids


def rewrite(path: Path, ids: dict[str, str], dry: bool) -> list[tuple[str, str, str]]:
    lines = path.read_text().splitlines(keepends=True)
    changes: list[tuple[str, str, str]] = []
    missing: set[str] = set()
    for i, line in enumerate(lines):
        name = _NAME_RE.search(line)
        run = _RUN_RE.search(line)
        if not (name and run):
            continue
        target = name.group(1)
        if target not in ids:
            missing.add(target)
            continue
        old = run.group(2)
        if old != ids[target]:
            lines[i] = _RUN_RE.sub(rf"\g<1>{ids[target]}", line, count=1)
            changes.append((target, old, ids[target]))
    if missing:
        sys.exit(f"{path.name}: no admin-blind G1 run for {sorted(missing)} "
                 "— did that cell run?")
    if changes and not dry:
        path.write_text("".join(lines))
    return changes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("g1_dirs", nargs="*",
                    help="the fresh G1 sheet dir, then any re-run sheet dirs, whose "
                         "admin-blind runs replace G1's for their target "
                         "(default: newest G1 matrix)")
    ap.add_argument("--dry-run", action="store_true", help="show changes, write nothing")
    args = ap.parse_args(argv)

    g1_dirs = [Path(d) for d in args.g1_dirs] or [latest_g1_dir()]
    ids: dict[str, str] = {}
    for g1_dir in g1_dirs:
        ids.update(admin_blind_ids(g1_dir))
    print(f"G1: {', '.join(d.name for d in g1_dirs)}")
    for target, run in sorted(ids.items()):
        print(f"  {target:10s} -> {run}")

    total = 0
    for sheet in DEFERRED:
        changes = rewrite(HARNESS / sheet, ids, args.dry_run)
        total += len(changes)
        verb = "would rewrite" if args.dry_run else "rewrote"
        print(f"\n{sheet}: {verb} {len(changes)} row(s)")
        for target, old, new in changes:
            print(f"  {target:10s} {old} -> {new}")
    print(f"\n{'(dry-run) ' if args.dry_run else ''}{total} row(s) "
          f"across {len(DEFERRED)} sheets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
