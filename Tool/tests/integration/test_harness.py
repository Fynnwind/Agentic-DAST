"""The configuration harness: sheet validation, env overlays, plans, the table.

No stage is ever executed here — every test either stops at ``--dry-run`` or
replaces the subprocess call, because the point of the harness is what it does
*around* the stages: which run a row acts on, what configuration it archives,
and which rows a broken one takes down with it (none).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import dast_harness as harness
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.stages import table as stages
from dast_orchestrator.foundation.run_paths import RunLayout


@pytest.fixture
def base_env(tmp_path):
    path = tmp_path / "base.env"
    path.write_text(
        "TARGET_NAME=gitea\nAUTH_MODE=none\n"
        "TRIAGE_SCREENING_MODEL=cheap/model\n"
    )
    return path


def _sheet(tmp_path, base_env, body: str):
    path = tmp_path / "sheet.yml"
    path.write_text(f"defaults:\n  base_env: {base_env}\n{body}")
    return path


def _run_with(data_dir, run_id, *basenames):
    layout = RunLayout(data_dir, run_id).ensure()
    for name in basenames:
        layout.path(name).write_text("{}")
    return layout


# -- the stage table -------------------------------------------------------


def test_a_sequence_with_a_gap_is_knowable_before_anything_runs():
    # `scan report` produces no correlation, so nothing can supply report's
    # input. Refusing here is the difference between "this cannot work" and
    # "this stopped working 45 minutes in".
    steps = stages.plan(["scan", "report"])
    assert not steps[1].satisfiable
    problems = stages.unsatisfied(steps)
    assert problems and "triage" in problems[0]


def test_a_sequence_is_satisfied_by_an_earlier_step(tmp_path):
    steps = stages.plan(["scan", "triage", "verify", "report"])
    assert stages.unsatisfied(steps) == []
    assert steps[1].inputs[run_paths.ZAP_ALERTS] == stages.PRODUCED


def test_a_sequence_is_satisfied_by_the_run_directory(tmp_path):
    layout = _run_with(tmp_path, "20260101T000000Z-gitea",
                       run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
    steps = stages.plan(["triage", "verify"], layout.dir)
    assert stages.unsatisfied(steps) == []
    assert steps[0].inputs[run_paths.ZAP_ALERTS] == stages.PRESENT
    assert steps[1].inputs[run_paths.TRIAGE] == stages.PRODUCED


def test_unknown_stage_names_the_ones_that_exist():
    with pytest.raises(stages.StageError, match="triage"):
        stages.resolve(["corelate"])


# -- sheet validation ------------------------------------------------------


def test_sheet_rejects_a_row_that_cannot_complete(tmp_path, base_env):
    path = _sheet(tmp_path, base_env,
                  "rows:\n  - name: a\n    target: gitea\n    stages: [scan, report]\n")
    with pytest.raises(harness.SheetError, match="cannot complete"):
        harness.load_sheet(path)


def test_sheet_rejects_duplicate_row_names(tmp_path, base_env):
    # Row names become artifact suffixes, so a duplicate would have one row
    # silently overwrite another's results.
    path = _sheet(tmp_path, base_env,
                  "rows:\n  - name: a\n    stages: [triage]\n"
                  "  - name: a\n    stages: [verify]\n")
    with pytest.raises(harness.SheetError, match="duplicate row name"):
        harness.load_sheet(path)


def test_sheet_rejects_a_scanning_row_that_also_names_a_run(tmp_path, base_env):
    path = _sheet(tmp_path, base_env,
                  "rows:\n  - name: a\n    stages: [scan]\n    run: latest\n")
    with pytest.raises(harness.SheetError, match="mints its own run"):
        harness.load_sheet(path)


def test_sheet_defaults_to_the_full_chain(tmp_path, base_env):
    path = _sheet(tmp_path, base_env, "  target: gitea\nrows:\n  - name: a\n")
    sheet = harness.load_sheet(path)
    assert sheet.rows[0].stages == stages.FULL_CHAIN


def test_row_env_overlays_the_sheet_default(tmp_path, base_env):
    path = _sheet(
        tmp_path, base_env,
        "  env:\n    SHARED_AUTH_MODE: admin\n"
        "rows:\n  - name: a\n    stages: [triage]\n"
        "    env:\n      TRIAGE_SCREENING_MODEL: big/model\n",
    )
    sheet = harness.load_sheet(path)
    assert sheet.rows[0].env == {"SHARED_AUTH_MODE": "admin",
                                 "TRIAGE_SCREENING_MODEL": "big/model"}


# -- env overlays ----------------------------------------------------------


def test_merged_env_is_complete_not_a_delta(base_env):
    # --env-file names the ONE configuration file a stage reads; the default
    # .env is then not loaded, so an overlay that carried only the differences
    # would silently drop every inherited setting.
    values = harness.merge_env(base_env, {"SHARED_AUTH_MODE": "admin"})
    assert values["TARGET_NAME"] == "gitea"          # inherited
    assert values["SHARED_AUTH_MODE"] == "admin"            # overlaid
    assert values["TRIAGE_SCREENING_MODEL"] == "cheap/model"


def test_no_credential_reaches_an_archived_overlay(tmp_path, monkeypatch):
    # The overlay is archived into a run directory, and the rule that no key
    # reaches a data/ artifact is not relaxed for a file that happens to be
    # configuration. The keys go to the subprocess's environment instead.
    base = tmp_path / "b.env"
    base.write_text("SHARED_OPENROUTER_API_KEY=sk-or-real\nSCAN_ZAP_API_KEY=zap-secret\n"
                    "TARGET_NAME=gitea\n")
    monkeypatch.delenv("SHARED_OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SCAN_ZAP_API_KEY", raising=False)

    values = harness.merge_env(base, {})
    assert "SHARED_OPENROUTER_API_KEY" not in values and "SCAN_ZAP_API_KEY" not in values
    written = harness.write_env_file(tmp_path / "row.env", values, "header")
    assert "sk-or-real" not in written.read_text()
    assert "zap-secret" not in written.read_text()

    # ...but a scan row still gets the ZAP daemon token it cannot run without.
    assert harness.secret_env(base) == {"SHARED_OPENROUTER_API_KEY": "sk-or-real",
                                        "SCAN_ZAP_API_KEY": "zap-secret"}


def test_the_account_credential_is_read_from_the_secrets_env_neighbour(tmp_path, monkeypatch):
    # The real deployment keeps SHARED_OPENROUTER_API_KEY in secrets.env, NOT in
    # the base .env — and a stage the harness spawns is given `--env-file
    # <overlay>`, so its own secrets neighbour is the overlay's directory (no
    # secrets.env there), never config/scanner/secrets.env. If `secret_env` read
    # only the base file the key would never reach the child, and every triage
    # would die with "Missing Authentication header" AFTER a 45-minute scan — the
    # failure observed on 2026-09-23. So the key must come from the neighbour.
    base = tmp_path / ".env"
    base.write_text("SCAN_ZAP_API_KEY=zap-secret\nTARGET_NAME=gitea\n")
    (tmp_path / "secrets.env").write_text("SHARED_OPENROUTER_API_KEY=sk-or-real\n")
    monkeypatch.delenv("SHARED_OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("SCAN_ZAP_API_KEY", raising=False)

    assert harness.secret_env(base) == {"SHARED_OPENROUTER_API_KEY": "sk-or-real",
                                        "SCAN_ZAP_API_KEY": "zap-secret"}


def test_a_real_environment_variable_outranks_the_base_files_secret(tmp_path, monkeypatch):
    base = tmp_path / "b.env"
    base.write_text("SCAN_ZAP_API_KEY=from-file\n")
    monkeypatch.setenv("SCAN_ZAP_API_KEY", "from-shell")
    # Already in the environment, so the child inherits it untouched rather than
    # having the file's value put back over it.
    assert harness.secret_env(base) == {}


# -- running rows ----------------------------------------------------------


def _no_op_stage(monkeypatch, produces: dict[str, tuple[str, ...]] | None = None,
                 fail: str = "", data_dir=None):
    """Replace the row subprocess: record the one ``dast`` argv the harness now
    spawns per row, and fail the whole chain when ``fail`` names a stage in it
    (one subprocess, so a failed stage stops the rest by construction)."""
    calls: list[list[str]] = []

    class _Completed:
        def __init__(self, code):
            self.returncode = code

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        names = [t for t in argv[3:] if t in stages.STAGES]
        return _Completed(1 if fail and fail in names else 0)

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    return calls


def test_a_row_acts_on_the_newest_run_that_has_its_input(tmp_path, base_env, monkeypatch):
    data = tmp_path / "data"
    _run_with(data, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)
    newest = _run_with(data, "20260202T000000Z-gitea", run_paths.ZAP_ALERTS,
                       run_paths.NOIR_AI_CONTEXT)
    calls = _no_op_stage(monkeypatch, data_dir=data)

    row = harness.Row(name="a", stages=("triage",))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    execution = harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)

    assert execution.ok and execution.run_id == newest.run_id
    # One `dast` chain: `... -m dast_orchestrator.cli triage <run-id> ...`.
    assert calls[0][4] == newest.run_id     # positional, after the stage name
    # The configuration is archived next to the artifacts it produced.
    assert (newest.dir / "harness-a.env").is_file()


def test_a_row_with_no_usable_stored_run_is_recorded_not_raised(tmp_path, base_env):
    data = tmp_path / "data"
    data.mkdir()
    row = harness.Row(name="a", stages=("triage",))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    execution = harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)
    assert not execution.ok and "no stored run" in execution.reason


def test_a_failing_row_stops_the_whole_chain_in_one_subprocess(tmp_path, base_env, monkeypatch):
    data = tmp_path / "data"
    _run_with(data, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT, run_paths.TRIAGE)
    calls = _no_op_stage(monkeypatch, fail="triage", data_dir=data)

    row = harness.Row(name="a", stages=("triage", "verify", "report"))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    execution = harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)

    # One `dast` chain runs the whole row, so a failing stage stops the rest by
    # construction — the harness sees one exit code, not which stage broke (that
    # is in the run's own log), and does not misattribute it.
    assert not execution.ok and "exited 1" in execution.reason
    assert execution.failed_stage is None
    assert len(calls) == 1          # one subprocess for the row, not one per stage


def test_a_scanning_row_learns_its_run_id_from_the_directory(tmp_path, base_env, monkeypatch):
    # The run id is minted inside the stage, from its own effective
    # configuration; the harness reads which directory appeared rather than
    # re-deriving a name it would get subtly wrong.
    data = tmp_path / "data"
    data.mkdir()

    class _Completed:
        returncode = 0

    sheet_dir = tmp_path / "sheetdir"

    def fake_run(argv, **_kwargs):
        if "scan" in argv:      # the one `dast` chain includes the scan stage
            _run_with(sheet_dir, "20260303T000000Z-gitea-abc123",
                      run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
        return _Completed()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    row = harness.Row(name="base", stages=("scan", "triage"), target="gitea")
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    execution = harness.run_row(row, 1, sheet, sheet_dir, data)

    assert execution.run_id == "20260303T000000Z-gitea-abc123"
    assert execution.label == ""    # its own directory already distinguishes it


def test_repeats_are_numbered_so_they_do_not_overwrite_each_other():
    row = harness.Row(name="var", stages=("triage",), repeat=3)
    assert [row.label(i) for i in (1, 2, 3)] == ["var-1", "var-2", "var-3"]
    # A single execution needs no number.
    assert harness.Row(name="var", stages=("triage",)).label(1) == "var"


def test_a_dry_run_writes_the_overlays_and_executes_nothing(tmp_path, base_env, monkeypatch):
    data = tmp_path / "data"
    _run_with(data, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)

    def explode(*_a, **_k):
        raise AssertionError("a dry run must not execute a stage")

    monkeypatch.setattr(harness.subprocess, "run", explode)
    row = harness.Row(name="a", stages=("triage",))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    sheet_dir = tmp_path / "sheetdir"
    harness.run_row(row, 1, sheet, sheet_dir, data, dry_run=True)
    assert (sheet_dir / "a.env").is_file()


# -- the comparison table --------------------------------------------------


def _index_row(run, kind, label="", **results):
    return {"run": run, "kind": kind, "label": label, "total_seconds": 60.0,
            "cost_usd": 0.01, "config_digest": "abc123", **results}


def test_index_delta_is_what_this_sheet_appended():
    before = [_index_row("R0", "scan")]
    after = before + [_index_row("R1", "triage")]
    assert harness.index_delta(before, after) == [_index_row("R1", "triage")]


def test_comparison_table_joins_rows_to_what_they_recorded():
    executions = [
        harness.Execution(row="a", repeat=1, label="a", stages=["triage"],
                          run_id="R1"),
        harness.Execution(row="b", repeat=1, label="b", stages=["triage"],
                          run_id="R1"),
    ]
    rows = [_index_row("R1", "triage", "a", findings=900, llm_rescans=16),
            _index_row("R1", "triage", "b", findings=900, llm_rescans=8)]
    table = harness.comparison_table(executions, rows)
    assert "triage" in table and "900" in table and "16" in table and "8" in table


def test_comparison_table_names_the_rows_that_did_not_complete():
    executions = [harness.Execution(row="a", repeat=1, label="a",
                                    stages=["verify"], run_id="R1",
                                    failed_stage="verify", reason="exited 1")]
    table = harness.comparison_table(executions, [])
    assert "did not complete" in table and "verify" in table and "exited 1" in table


def test_variance_reports_spread_only_for_repeated_rows():
    executions = [
        harness.Execution(row="v", repeat=i, label=f"v-{i}",
                          stages=["triage"], run_id="R1")
        for i in (1, 2, 3)
    ] + [harness.Execution(row="once", repeat=1, label="once",
                           stages=["triage"], run_id="R1")]
    rows = [_index_row("R1", "triage", f"v-{i}", llm_rescans=n)
            for i, n in ((1, 11), (2, 16), (3, 14))]
    rows.append(_index_row("R1", "triage", "once", llm_rescans=12))

    spread = harness.variance(executions, rows)
    assert set(spread) == {"v"}          # one sample is not a spread
    assert spread["v"]["llm_rescans"] == {"min": 11.0, "max": 16.0, "mean": 13.667}


def test_run_sheet_writes_its_own_artifacts(tmp_path, base_env, monkeypatch):
    root = tmp_path / "data"
    manual = run_paths.default_runs_dir(root)
    _run_with(manual, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)
    _no_op_stage(monkeypatch, data_dir=manual)

    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",))],
    )
    results = harness.run_sheet(sheet, root)
    sheet_dirs = list((root / harness.HARNESS_DIR_NAME).iterdir())
    assert len(sheet_dirs) == 1
    assert json.loads((sheet_dirs[0] / "results.json").read_text())["executions"]
    assert (sheet_dirs[0] / "comparison.md").is_file()
    # `latest` reached past the sheet into the manual runs, and the re-triage
    # was written beside the scan it triaged rather than under the sheet.
    assert results["executions"][0]["run"] == "20260101T000000Z-gitea"
    assert RunLayout.runs(manual) == ["20260101T000000Z-gitea"]


def test_a_sheets_own_runs_are_nested_under_it(tmp_path, base_env, monkeypatch):
    # The point of the layout: last night's experiments are one directory.
    root = tmp_path / "data"
    minted = "20260303T000000Z-gitea-abc123"

    class _Completed:
        returncode = 0

    def fake_run(argv, **_kwargs):
        if "scan" in argv:      # the one `dast` chain includes the scan stage
            where = Path(argv[argv.index("--data-dir") + 1])
            _run_with(where, minted, run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
        return _Completed()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="base", stages=("scan",), target="gitea")],
    )
    results = harness.run_sheet(sheet, root)
    sheet_dir = next((root / harness.HARNESS_DIR_NAME).iterdir())
    assert results["executions"][0]["run"] == minted
    assert (sheet_dir / minted).is_dir()
    # …and nothing landed among the runs a person started.
    assert RunLayout.runs(run_paths.default_runs_dir(root)) == []


def test_a_scanning_row_must_name_its_target(tmp_path, base_env):
    # TARGET_NAME stopped being a target selector, so the sheet says it — the
    # sheet is the record of what a night's runs were, and "against what" is
    # the first thing that record has to say.
    path = _sheet(tmp_path, base_env, "rows:\n  - name: a\n    stages: [scan]\n")
    with pytest.raises(harness.SheetError, match="names no target"):
        harness.load_sheet(path)


def test_a_scanning_row_passes_its_target_positionally(tmp_path, base_env, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    calls = _no_op_stage(monkeypatch, data_dir=data)
    row = harness.Row(name="base", stages=("scan",), target="gitea")
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)
    assert calls[0][4] == "gitea"   # positional after the stage name


# -- the sheet's own report ------------------------------------------------


def test_the_sheet_report_leads_with_an_overview_and_a_spread():
    executions = [
        harness.Execution(row="v", repeat=i, label=f"v-{i}", stages=["triage"],
                          run_id="R1")
        for i in (1, 2)
    ]
    rows = [_index_row("R1", "triage", f"v-{i}", llm_rescans=n)
            for i, n in ((1, 11), (2, 16))]
    spread = harness.variance(executions, rows)
    report = harness.sheet_report(
        harness.Sheet(path=Path("s.yml"), base_env=Path("b.env"), rows=[]),
        executions, rows, spread, "TABLE", "20260101T000000Z",
    )
    assert report.startswith("# Harness — s")
    assert "## Overview" in report
    assert "Every row completed" in report
    # The spread is the yardstick, so it is a table to compare against rather
    # than JSON to look up.
    assert "| `v` | llm_rescans | 11 | 16 | 13.5 | 5 |" in report
    assert "smaller than the spread" in report


def test_the_sheet_report_names_what_did_not_complete():
    executions = [
        harness.Execution(row="a", repeat=1, label="a", stages=["verify"],
                          run_id="R1", failed_stage="verify", reason="exited 1"),
    ]
    report = harness.sheet_report(
        harness.Sheet(path=Path("s.yml"), base_env=Path("b.env"), rows=[]),
        executions, [], {}, "", "20260101T000000Z",
    )
    assert "did not complete" in report
    assert "`verify`" in report and "exited 1" in report
    # No spread section when nothing repeated — a shorter sheet reads shorter.
    assert "Spread across repeated rows" not in report


# -- timestamps and the end roll-up ----------------------------------------


def test_every_execution_is_stamped_and_timed(tmp_path, base_env, monkeypatch, capsys):
    data = tmp_path / "data"
    _run_with(data, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)
    _no_op_stage(monkeypatch, data_dir=data)
    row = harness.Row(name="a", stages=("triage",))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)

    out = capsys.readouterr().out
    assert "started:" in out                 # when this execution began
    assert "✓ a finished in" in out          # …and how long it took, on its last line


def test_a_failed_execution_closes_with_the_reason(tmp_path, base_env, monkeypatch, capsys):
    data = tmp_path / "data"
    _run_with(data, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT, run_paths.TRIAGE)
    _no_op_stage(monkeypatch, fail="verify", data_dir=data)
    row = harness.Row(name="a", stages=("verify",))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env, rows=[row])
    harness.run_row(row, 1, sheet, tmp_path / "sheetdir", data)

    out = capsys.readouterr().out
    assert "✗ a finished in" in out and "exited 1" in out


def test_the_sheet_closes_with_a_roll_up_and_an_elapsed(tmp_path, base_env,
                                                        monkeypatch, capsys):
    root = tmp_path / "data"
    manual = run_paths.default_runs_dir(root)
    _run_with(manual, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)
    _no_op_stage(monkeypatch, data_dir=manual)
    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",), repeat=2)],
    )
    harness.run_sheet(sheet, root)

    out = capsys.readouterr().out
    # The comparison table is organised by stage kind; this answers the other
    # question — what did the night do, and which part took the time.
    assert "Executions" in out
    assert "1/2" in out and "2/2" in out
    assert "elapsed:" in out and "→" in out          # start → finish, on the banner
    assert "HARNESS RUN COMPLETE" in out


def test_the_report_uses_the_sheets_own_wall_clock():
    # The sum of the stages' own seconds excludes container start-up, ZAP
    # polling and the gaps between rows — the number a reader planning the next
    # night actually needs.
    report = harness.sheet_report(
        harness.Sheet(path=Path("s.yml"), base_env=Path("b.env"), rows=[]),
        [], [{"total_seconds": 60.0, "kind": "triage", "run": "R", "label": ""}],
        {}, "", "20260101T000000Z", elapsed=7200.0, started_at="03:00:00",
    )
    assert "2.0h" in report and "stages 1.0m" in report


def test_a_dry_run_never_claims_anything_completed(tmp_path, base_env, monkeypatch, capsys):
    # "12 of 12 completed" against an empty data directory is exactly the kind
    # of line that gets believed months later.
    root = tmp_path / "data"
    manual = run_paths.default_runs_dir(root)
    _run_with(manual, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)

    def explode(*_a, **_k):
        raise AssertionError("a dry run must not execute a stage")

    monkeypatch.setattr(harness.subprocess, "run", explode)
    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",))],
    )
    harness.run_sheet(sheet, root, dry_run=True)

    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "planned, none executed" in out
    assert "completed" not in out
    assert "✓ a" not in out          # no tick, and no duration, for work not done

    # A dry run lands in the ephemeral scratch namespace, never among the corpora.
    assert not (root / harness.HARNESS_DIR_NAME).exists()
    report = (next((root / run_paths.SCRATCH_DIR_NAME).iterdir()) / "comparison.md").read_text()
    assert "nothing was executed" in report.lower()


def test_a_clean_dry_run_removes_its_scratch(tmp_path, base_env, monkeypatch):
    # A clean dry run is a plan preview; its scratch dir is removed so it never
    # accumulates in data/. (run_sheet writes it in scratch; the caller cleans up.)
    root = tmp_path / "data"
    monkeypatch.setattr(harness.subprocess, "run",
                        lambda *_a, **_k: (_ for _ in ()).throw(
                            AssertionError("dry run must not execute")))
    sheet = harness.Sheet(path=tmp_path / "s.yml", base_env=base_env,
                          rows=[harness.Row(name="a", stages=("triage",))])
    results = harness.run_sheet(sheet, root, dry_run=True)
    scratch_dir = Path(results["sheet_dir"])
    assert scratch_dir.is_dir() and run_paths.SCRATCH_DIR_NAME in scratch_dir.parts
    assert not (root / harness.HARNESS_DIR_NAME).exists()       # never the corpus

    harness._cleanup_scratch(results, ok=True, clean=True)
    assert not scratch_dir.exists()                             # removed when clean

    # …but a NOT-clean dry run (a warning) is kept for inspection.
    results2 = harness.run_sheet(sheet, root, dry_run=True)
    harness._cleanup_scratch(results2, ok=True, clean=False)
    assert Path(results2["sheet_dir"]).is_dir()


# -- cost ceilings ---------------------------------------------------------


def test_a_sheet_ceiling_stops_starting_executions(tmp_path, base_env, monkeypatch):
    # Checked BETWEEN executions: a row is an experiment, and half an experiment
    # is a wasted one rather than a cheaper one.
    root = tmp_path / "data"
    manual = run_paths.default_runs_dir(root)
    _run_with(manual, "20260101T000000Z-gitea", run_paths.ZAP_ALERTS,
              run_paths.NOIR_AI_CONTEXT)
    calls = _no_op_stage(monkeypatch, data_dir=manual)

    # Each poll of the index reports more spend, as real executions would.
    spent = {"n": 0}

    def fake_index(_dir):
        spent["n"] += 1
        return [{"run": "R", "kind": "triage", "label": f"e{i}",
                 "started_at": f"t{i}", "cost_usd": 0.30}
                for i in range(spent["n"] // 2)]

    monkeypatch.setattr(harness.run_metrics, "read_index", fake_index)

    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",), repeat=4)],
        max_cost_usd=0.50,
    )
    results = harness.run_sheet(sheet, root)
    reasons = [e["reason"] for e in results["executions"]]
    assert any("cost ceiling" in r for r in reasons), reasons
    # …and the ones past the ceiling were never spawned.
    assert len(calls) < 4


def test_a_negative_sheet_ceiling_is_no_ceiling():
    assert not harness._over(1_000_000.0, -1.0)
    assert harness._over(0.5, 0.5)
    assert not harness._over(0.4, 0.5)


def test_the_sheet_ceiling_comes_from_defaults(tmp_path, base_env):
    path = _sheet(tmp_path, base_env,
                  "  max_cost_usd: 0.75\nrows:\n  - name: a\n    stages: [triage]\n")
    assert harness.load_sheet(path).max_cost_usd == 0.75
    # Absent means the default ceiling, not unlimited: a sheet is the thing most
    # likely to run unattended for hours, so it is bounded unless it says
    # otherwise.
    plain = _sheet(tmp_path, base_env, "rows:\n  - name: z\n    stages: [triage]\n")
    assert harness.load_sheet(plain).max_cost_usd == harness.DEFAULT_SHEET_MAX_COST_USD
    # …and -1 is still how a sheet opts out.
    unlimited = _sheet(tmp_path, base_env,
                       "  max_cost_usd: -1\nrows:\n  - name: z\n    stages: [triage]\n")
    assert harness.load_sheet(unlimited).max_cost_usd == -1.0


def test_a_row_can_name_a_corpus_an_earlier_sheet_produced(tmp_path, base_env, monkeypatch):
    # The obvious next step after a night of experiments — "re-triage that same
    # corpus with the fix in" — was impossible to express: the run is neither in
    # data/runs nor in this sheet, so it could not be named at all.
    root = tmp_path / "data"
    earlier = root / run_paths.HARNESS_DIR_NAME / "20260101T000000Z-overnight"
    corpus = "20260101T000000Z-gitea-aaaaaa"
    _run_with(earlier, corpus, run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
    run_paths.default_runs_dir(root).mkdir(parents=True, exist_ok=True)
    calls = _no_op_stage(monkeypatch, data_dir=earlier)

    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",), run=corpus)],
    )
    results = harness.run_sheet(sheet, root)
    assert results["executions"][0]["run"] == corpus
    # …and it wrote beside that corpus, not under the new sheet.
    assert calls[0][4] == corpus    # positional after the stage name
    assert str(earlier) in " ".join(calls[0])


def test_latest_never_reaches_into_another_sheet(tmp_path, base_env, monkeypatch):
    # "The newest run anywhere" is not something a sheet should silently
    # resolve to — an earlier sheet's corpus is only reachable by name.
    root = tmp_path / "data"
    earlier = root / run_paths.HARNESS_DIR_NAME / "20260101T000000Z-overnight"
    _run_with(earlier, "20260101T000000Z-gitea-aaaaaa",
              run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
    run_paths.default_runs_dir(root).mkdir(parents=True, exist_ok=True)

    def explode(*_a, **_k):
        raise AssertionError("latest must not reach into another sheet")

    monkeypatch.setattr(harness.subprocess, "run", explode)
    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",))],   # run: latest
    )
    results = harness.run_sheet(sheet, root)
    assert results["executions"][0]["run"] is None
    assert "no stored run" in results["executions"][0]["reason"]


def test_the_table_covers_rows_that_wrote_into_another_sheet(tmp_path, base_env, monkeypatch):
    # The reliability sheet's nine executions all succeeded and its report said
    # "no rows produced a metrics record" with `model spend $0.0000`, because
    # they wrote beside the corpus — which lived in an earlier sheet.
    root = tmp_path / "data"
    earlier = root / run_paths.HARNESS_DIR_NAME / "20260101T000000Z-overnight"
    corpus = "20260101T000000Z-gitea-aaaaaa"
    _run_with(earlier, corpus, run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
    run_paths.default_runs_dir(root).mkdir(parents=True, exist_ok=True)

    class _Completed:
        returncode = 0

    def fake_run(argv, **_kwargs):
        # A stage writes its metrics record beside the run it acted on; the
        # cross-run index is derived from those files on read.
        where = Path(argv[argv.index("--data-dir") + 1])
        layout = run_paths.RunLayout(where, corpus).ensure()
        layout.metrics("triage", "a").write_text(json.dumps({
            "run": corpus, "kind": "triage", "label": "a",
            "started_at": "2026-01-01T00:00:00", "total_seconds": 12.0,
            "results": {"cost_usd": 0.25, "findings": 900},
        }))
        return _Completed()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    sheet = harness.Sheet(
        path=tmp_path / "s.yml", base_env=base_env,
        rows=[harness.Row(name="a", stages=("triage",), run=corpus)],
    )
    results = harness.run_sheet(sheet, root)
    assert len(results["metrics_rows"]) == 1, "the row's metrics must be found"
    report = (next(d for d in (root / harness.HARNESS_DIR_NAME).iterdir()
                   if d != earlier) / "comparison.md").read_text()
    assert "$0.2500" in report and "no rows produced" not in report

def test_a_verify_only_row_reads_the_stored_correlation_not_its_own_label():
    """The bug that made sheet 03 fail every row in three seconds.

    ``--out-suffix`` named the output *and* selected the input, so a row
    verifying one stored correlation under a new configuration looked for
    ``triage-<its own label>.json`` — a file only that same row could have
    written. Verifying one corpus several ways is the comparison the harness
    exists for, and it was unexpressible.
    """
    row = harness.Row(name="residue", stages=("verify",), run="stored-run")

    assert harness.row_in_suffix(row) == ""


def test_a_row_that_correlates_first_keeps_the_stage_default():
    row = harness.Row(name="e2e", stages=("triage", "verify"))

    # None = let verify default to the out-suffix, which here names the
    # triage this same row just wrote.
    assert harness.row_in_suffix(row) is None


def test_a_row_may_name_which_stored_variant_it_verifies():
    row = harness.Row(name="v", stages=("verify",), run="r", correlation="qwen")

    assert harness.row_in_suffix(row) == "qwen"


def test_the_input_suffix_reaches_the_command(tmp_path):
    row = harness.Row(name="residue", stages=("verify",), run="stored-run")
    argv = harness.row_command(
        row.stages, tmp_path / "row.env", "stored-run", "residue-1",
        tmp_path, harness.row_in_suffix(row))

    assert "--out-suffix" in argv and argv[argv.index("--out-suffix") + 1] == "residue-1"
    assert "--in-suffix" in argv and argv[argv.index("--in-suffix") + 1] == ""


def test_a_row_cannot_both_produce_a_correlation_and_name_another(tmp_path):
    (tmp_path / ".env").write_text("SCAN_ZAP_ADDR=http://x:8080\n")
    sheet = tmp_path / "s.yml"
    sheet.write_text(
        "defaults: {target: gitea}\n"
        "rows:\n"
        "  - name: bad\n"
        "    stages: [triage, verify]\n"
        "    correlation: qwen\n"
    )
    with pytest.raises(harness.SheetError, match="two experiments"):
        harness.load_sheet(sheet, tmp_path)

def test_a_sheet_that_may_spend_nothing_may_still_run():
    """`max_cost_usd: 0.0` means "free, and hold me to it" — not "refuse".

    Sheet 14 is scan-only: no row calls a model, so the honest ceiling is zero.
    With a plain `spent >= cap` it was refused before its first row for having
    reached a ceiling of nothing, which is the one sheet that most wants to
    declare itself free.
    """
    from dast_harness import _over

    assert not _over(0.0, 0.0)          # nothing spent, nothing reached
    assert _over(0.01, 0.0)             # …and a cent still stops it

    # Unchanged for a positive ceiling: reaching it stops the next row, because
    # half an experiment is not a cheaper experiment.
    assert _over(5.0, 5.0)
    assert not _over(4.99, 5.0)

    # And the project's no-limit sentinel is no limit.
    assert not _over(1000.0, -1.0)
