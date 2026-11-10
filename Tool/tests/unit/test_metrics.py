"""Unit tests for the run-metrics collector.

The metrics exist to answer "what does this pipeline cost in CI" with measured
numbers, so what is pinned here is mostly the honesty properties: a stage that
raised still reports its time, an unmeasurable value stays null rather than
becoming a zero, and every record names the run it belongs to.
"""

from __future__ import annotations

import json

import jsonschema
import pytest

from pathlib import Path

from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.foundation import run_paths

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "run-metrics.schema.json"
TIMESTAMP = "20260817T155107Z"


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA.read_text())


def test_schema_is_itself_valid(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_record_validates_and_names_its_run(schema, tmp_path):
    metrics = run_metrics.RunMetrics(TIMESTAMP, kind="scan")
    with metrics.stage("noir") as stage:
        stage.counters["endpoints"] = 354
    metrics.record_tool("zap", version="2.17.0")
    metrics.record_results(alerts=6270, artifact="scan-zap-alerts.json")
    metrics.write(tmp_path)

    record = json.loads((tmp_path / TIMESTAMP / "scan-metrics.json").read_text())
    jsonschema.validate(record, schema)
    # The join key back to the run's other artifacts.
    assert record["run"] == TIMESTAMP
    assert record["results"]["artifact"] == "scan-zap-alerts.json"
    assert record["stages"]["noir"]["endpoints"] == 354


def test_a_clean_stage_records_an_empty_limits_list(schema, tmp_path):
    # Always present, [] on a clean finish — so "ran clean" and "predates limit
    # tracking" never look alike, the same reason `abort` is always present.
    metrics = run_metrics.RunMetrics(TIMESTAMP, kind="scan")
    with metrics.stage("active_scan") as stage:
        stage.counters.update(truncated_by_cap=False, cap_minutes=45,
                              urls_in_tree=932)
    metrics.record_results(active_scanner_alerts=7)
    record = metrics.as_dict()
    jsonschema.validate(record, schema)
    assert record["limits"] == []


def test_a_capped_active_scan_is_flagged_as_a_limit():
    limits = run_metrics.derive_limits(
        "scan",
        {"active_scan": {"seconds": 2703, "truncated_by_cap": True,
                         "cap_minutes": 45, "urls_in_tree": 5251}},
        {"active_scanner_alerts": 0},
    )
    names = {limit["limit"] for limit in limits}
    # Cut off AND it fired nothing: both the cap and the zero-alert guard.
    assert names == {"active_scan_cap_minutes", "active_scanner_zero_alerts"}


def test_a_completed_zero_alert_scan_is_not_a_limit():
    # Grafana blind completes with no active-scanner alert every run — a real
    # measurement, not a ceiling. The zero-alert flag is gated on the cap firing,
    # so a completed scan never raises it.
    limits = run_metrics.derive_limits(
        "scan",
        {"active_scan": {"seconds": 920, "truncated_by_cap": False,
                         "urls_in_tree": 214},
         "spider": {"poll_outcome": "complete"}},
        {"active_scanner_alerts": 0},
    )
    assert limits == []


def test_a_stalled_client_spider_is_flagged():
    limits = run_metrics.derive_limits(
        "scan", {"spider": {"poll_outcome": "client-stalled"}}, {})
    assert [limit["limit"] for limit in limits] == ["spider_client_stall"]


def test_triage_empty_code_context_is_flagged():
    # WordPress resolves no handler source for any endpoint, yet screening is
    # configured to use it — the silent weakening this flag makes loud.
    limits = run_metrics.derive_limits(
        "triage", {},
        {"code_context_endpoints_with_source": 0,
         "code_context_endpoints_without_source": 16},
    )
    assert [limit["limit"] for limit in limits] == ["code_context_no_source"]


def test_triage_unanswered_findings_are_flagged():
    limits = run_metrics.derive_limits(
        "triage", {}, {"llm_findings_asked": 23, "llm_findings_unanswered": 23})
    assert [limit["limit"] for limit in limits] == ["screening_findings_unanswered"]


def test_verify_budget_exhaustion_is_flagged():
    # The valid-looking artifact with everything not-attempted: derivable as a
    # limit from the metrics record, not only the per-finding prose.
    limits = run_metrics.derive_limits(
        "verify", {}, {"not_attempted_by_reason": {"budget": 21, "no-probe-url": 1}})
    assert [limit["limit"] for limit in limits] == ["verify_dispatch_budget"]


def test_a_budget_ceiling_abort_is_a_limit_but_an_error_is_not():
    ceiling = run_metrics.derive_limits(
        "triage", {}, {}, {"type": "budget-ceiling", "reason": "LlmError: budget"})
    assert [limit["limit"] for limit in ceiling] == ["cost_ceiling"]
    # An error/cancel abort is the failure it was and stays in `abort` alone.
    crash = run_metrics.derive_limits(
        "scan", {}, {}, {"type": "error", "reason": "RuntimeError: ZAP died"})
    assert crash == []


def test_record_limits_recomputes_for_a_record_without_the_field():
    # A report built over a corpus written before `limits` existed still names
    # every ceiling those runs hit.
    old_record = {
        "kind": "scan",
        "stages": {"active_scan": {"seconds": 2703, "truncated_by_cap": True,
                                   "cap_minutes": 45, "urls_in_tree": 5251}},
        "results": {"active_scanner_alerts": 0},
    }
    names = {limit["limit"] for limit in run_metrics.record_limits(old_record)}
    assert names == {"active_scan_cap_minutes", "active_scanner_zero_alerts"}


def test_a_failed_stage_still_reports_the_time_it_burned():
    # A scan that dies 40 minutes into the active scan must not report nothing:
    # the wasted time is exactly the number a CI budget cares about.
    metrics = run_metrics.RunMetrics(TIMESTAMP)
    with pytest.raises(RuntimeError):
        with metrics.stage("active_scan"):
            raise RuntimeError("ZAP died")
    assert metrics.stages["active_scan"].seconds is not None


def test_unmeasurable_values_stay_null_rather_than_zero():
    # A missing measurement and a measured zero must never look alike.
    timing = run_metrics.StageTiming("spider")
    assert timing.as_dict()["seconds"] is None


def test_scan_and_triage_are_separate_records(tmp_path):
    # Triage re-runs many times against one scan; merging them would make the
    # scan's runtime unrecoverable.
    run_metrics.RunMetrics(TIMESTAMP, kind="scan").write(tmp_path)
    run_metrics.RunMetrics(TIMESTAMP, kind="triage").write(tmp_path)
    assert (tmp_path / TIMESTAMP / "scan-metrics.json").is_file()
    assert (tmp_path / TIMESTAMP / "triage-metrics.json").is_file()
    assert len(run_metrics.read_index(tmp_path)) == 2


def test_standalone_verify_under_a_sheet_recovers_its_harness_id(monkeypatch, tmp_path):
    # A standalone `dast verify` of a harness run has HARNESS_ID/ROW unset (they
    # live only in the harness subprocess env), so the record used to orphan from
    # its sheet and the analyzer dropped it. The sheet is a fact of the path, so
    # it is recovered from there; the row falls back to the artifact label.
    monkeypatch.delenv(run_metrics.HARNESS_ID_VAR, raising=False)
    monkeypatch.delenv(run_metrics.HARNESS_ROW_VAR, raising=False)
    sheet = tmp_path / run_paths.HARNESS_DIR_NAME / "20261015T000000Z-campaign-9-demo"
    m = run_metrics.RunMetrics(TIMESTAMP, kind="verify", label="vdet")
    m.write(sheet)
    record = json.loads((sheet / TIMESTAMP / "verify-metrics-vdet.json").read_text())
    assert record["harness_id"] == "20261015T000000Z-campaign-9-demo"
    assert record["harness_row"] == "vdet"


def test_a_manual_run_gets_no_harness_id(monkeypatch, tmp_path):
    # The inference fires only under data/harness/<sheet>/; a run under data/runs/
    # is a person's run and must stay unattributed to any sheet.
    monkeypatch.delenv(run_metrics.HARNESS_ID_VAR, raising=False)
    runs = run_paths.default_runs_dir(tmp_path)
    run_metrics.RunMetrics(TIMESTAMP, kind="verify").write(runs)
    record = json.loads((runs / TIMESTAMP / "verify-metrics.json").read_text())
    assert record["harness_id"] == ""


def test_index_covers_every_recorded_run(tmp_path):
    # Derived on read from the per-run metrics files — every run that wrote one
    # appears, oldest first.
    for ts in ("20260817T100000Z-gitea-aaaaaa", "20260817T110000Z-gitea-bbbbbb"):
        metrics = run_metrics.RunMetrics(ts, kind="triage")
        metrics.record_results(cost_usd=0.02, findings=1247)
        metrics.write(tmp_path)
    rows = run_metrics.read_index(tmp_path)
    assert [r["run"] for r in rows] == ["20260817T100000Z-gitea-aaaaaa",
                                        "20260817T110000Z-gitea-bbbbbb"]
    assert all(r["cost_usd"] == 0.02 for r in rows)


def test_a_corrupt_metrics_file_is_skipped_not_fatal(tmp_path):
    # A truncated or garbled record must not blank the whole table — the reader
    # skips it and keeps the runs it can parse.
    run_id = "20260817T100000Z-gitea-aaaaaa"
    run_metrics.RunMetrics(run_id, kind="scan").write(tmp_path)
    (tmp_path / run_id / "triage-metrics.json").write_text("{not json")
    assert len(run_metrics.read_index(tmp_path)) == 1


def test_no_credentials_reach_a_record(monkeypatch, tmp_path):
    monkeypatch.setenv("SHARED_OPENROUTER_API_KEY", "sk-or-v1-secret")
    metrics = run_metrics.RunMetrics(TIMESTAMP, kind="triage")
    metrics.record_tool("openrouter", model="deepseek/deepseek-v4-flash-0731")
    metrics.record_results(cost_usd=0.038)
    blob = json.dumps(metrics.as_dict())
    assert "sk-or-v1" not in blob


def test_record_tool_drops_unknown_facts_instead_of_storing_null():
    metrics = run_metrics.RunMetrics(TIMESTAMP)
    metrics.record_tool("noir", image="ghcr.io/owasp-noir/noir:1.2.1", digest=None)
    assert metrics.tools["noir"] == {"image": "ghcr.io/owasp-noir/noir:1.2.1"}


def test_format_index_reports_totals(tmp_path):
    metrics = run_metrics.RunMetrics(TIMESTAMP, kind="triage")
    metrics.record_results(cost_usd=0.0376, findings=1247)
    metrics.write(tmp_path)
    table = run_metrics.format_index(run_metrics.read_index(tmp_path))
    assert "$0.0376" in table
    assert "1 runs" in table


def test_format_index_on_an_empty_index_explains_itself():
    assert "No runs recorded" in run_metrics.format_index([])


# -- resource sampling -----------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        # Longest suffix must win: a bare "B" also matches the tail of "GiB",
        # which silently produced None for every reading until it was ordered.
        ("1.2GiB / 7.6GiB", 1228.8),
        ("512MiB / 2GiB", 512.0),
        ("3.4GB / 8GB", 3481.6),
        ("nonsense", None),
        (None, None),
    ],
)
def test_parse_memory(value, expected):
    assert run_metrics._parse_memory_mb(value) == expected


@pytest.mark.parametrize("value, expected", [("12.34%", 12.34), ("", None), (None, None)])
def test_parse_percent(value, expected):
    assert run_metrics._parse_percent(value) == expected


def test_sampler_reports_peak_and_mean():
    sampler = run_metrics.ResourceSampler([], interval=0.01)
    sampler.samples = {"dast-zap": [(10.0, 100.0), (50.0, 900.0), (30.0, 500.0)]}
    summary = sampler.summary()["dast-zap"]
    # Peak is the number a CI capacity question actually asks about.
    assert summary["cpu_percent_peak"] == 50.0
    assert summary["memory_mb_peak"] == 900.0
    assert summary["memory_mb_mean"] == 500.0
    assert summary["samples"] == 3


def test_sampler_without_docker_is_silent_and_empty():
    # A missing docker binary must never take down an otherwise fine scan; an
    # empty summary then correctly reports that nothing was measured.
    with run_metrics.ResourceSampler([], interval=0.01) as sampler:
        pass
    assert sampler.summary() == {}


def test_a_comparison_run_does_not_overwrite_the_baselines_metrics(tmp_path):
    # This happened for real: --out-suffix protected the correlation artifact
    # but not the metrics file, so the qwen run silently replaced deepseek's
    # per-call log while its result artifact survived.
    base = run_metrics.RunMetrics(TIMESTAMP, kind="triage")
    base.record_tool("openrouter", model="deepseek/deepseek-v4-flash-0731")
    base.record_results(cost_usd=0.0426)
    base_path = base.write(tmp_path)

    other = run_metrics.RunMetrics(TIMESTAMP, kind="triage", label="qwen235b")
    other.record_tool("openrouter", model="qwen/qwen3-235b-a22b-2507")
    other.record_results(cost_usd=0.0975)
    other_path = other.write(tmp_path)

    assert base_path != other_path
    assert base_path.is_file() and other_path.is_file()
    kept = json.loads(base_path.read_text())
    assert kept["tools"]["openrouter"]["model"] == "deepseek/deepseek-v4-flash-0731"


def test_index_rows_name_the_model_so_runs_are_distinguishable(tmp_path):
    for label, model, cost in [
        ("", "deepseek/deepseek-v4-flash-0731", 0.0426),
        ("qwen235b", "qwen/qwen3-235b-a22b-2507", 0.0975),
    ]:
        m = run_metrics.RunMetrics(TIMESTAMP, kind="triage", label=label)
        m.record_tool("openrouter", model=model)
        m.record_results(cost_usd=cost, findings=1247)
        m.write(tmp_path)
    rows = run_metrics.read_index(tmp_path)
    assert [r["model"] for r in rows] == [
        "deepseek/deepseek-v4-flash-0731",
        "qwen/qwen3-235b-a22b-2507",
    ]
    assert "qwen/qwen3-235b" in run_metrics.format_index(rows)


def test_stdout_summary_omits_nested_structures(capsys):
    # The per-call log is ~77 entries; dumping it to a terminal is noise.
    m = run_metrics.RunMetrics(TIMESTAMP, kind="triage")
    with m.stage("llm_screening") as stage:
        stage.counters["calls"] = 77
        stage.counters["calls_log"] = [{"latency_ms": 1} for _ in range(77)]
        stage.counters["providers"] = {"deepinfra": 77}
    m.print_summary()
    out = capsys.readouterr().out
    assert "calls=77" in out
    assert "latency_ms" not in out
    assert "deepinfra" not in out


def test_a_control_arm_run_records_no_model(tmp_path):
    # "Measured, never estimated": a --no-llm run never called a model, so
    # naming one in its metrics would be a fabricated fact.
    m = run_metrics.RunMetrics(TIMESTAMP, kind="triage")
    m.record_results(findings=1247)
    m.write(tmp_path)
    assert run_metrics.read_index(tmp_path)[0]["model"] is None


# -- the index survives being written the wrong way ------------------------


def test_index_row_lists_the_runs_files(tmp_path):
    # `artifact` named whatever one command wrote last; a run directory
    # accumulates, and "what does this run consist of" is the question the index
    # is read to answer.
    metrics = run_metrics.RunMetrics("20260101T000000Z-gitea", kind="scan")
    layout = run_paths.RunLayout(tmp_path, "20260101T000000Z-gitea").ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text("{}")
    layout.path(run_paths.TRIAGE).write_text("{}")
    metrics.write(tmp_path)

    row = run_metrics.read_index(tmp_path)[0]
    assert run_paths.ZAP_ALERTS in row["artifacts"]
    assert run_paths.TRIAGE in row["artifacts"]
    assert "scan-metrics.json" in row["artifacts"]


# -- console shape ---------------------------------------------------------


def test_a_phase_always_ends_with_its_duration(capsys):
    from dast_orchestrator.foundation import ui

    with ui.timed_phase("Active scan"):
        ui.step("[ascan]   5%")
        ui.found("5273 alerts")
        ui.wrote("data/x/scan-zap-alerts.json")
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert "Active scan" in lines[0] and lines[0].startswith("--")
    # Order is fixed so the eye learns one shape: progress, findings, files, time.
    assert "[ascan]" in lines[1] and "5273 alerts" in lines[2]
    assert lines[3].startswith("  → ")
    assert lines[-1].startswith("  ✓ ")


def test_a_failing_phase_still_reports_the_time_it_burned(capsys):
    # The duration of a *failed* stage is exactly the number missing when a run
    # has to be re-planned.
    from dast_orchestrator.foundation import ui

    with pytest.raises(RuntimeError):
        with ui.timed_phase("Active scan"):
            raise RuntimeError("zap died")
    assert capsys.readouterr().out.strip().splitlines()[-1].startswith("  ✓ ")


def test_long_durations_are_shown_in_minutes(capsys):
    from dast_orchestrator.foundation import ui

    ui.done(1643.2)
    ui.done(12.5)
    out = capsys.readouterr().out
    assert "27.4 min" in out and "12.5s" in out


def test_files_are_second_to_last_and_time_is_last(capsys):
    # Both are scanned for rather than read, so they sit at a fixed offset from
    # the end of every phase, whatever else it printed.
    from dast_orchestrator.foundation import ui

    with ui.timed_phase("Noir static extraction") as state:
        ui.step("running")
        ui.found("354 endpoints")
        state["files"] = ["scan-noir-endpoints.json", "scan-noir-ai-context.json"]
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert lines[-1].startswith("  ✓ ")
    assert lines[-2].startswith("  → ") and lines[-3].startswith("  → ")


def test_an_open_phase_closes_with_the_same_shape(capsys):
    # Setup interleaves configuration with the checks that report it, so it
    # cannot be a single block — but it must still end like every other phase.
    from dast_orchestrator.foundation import ui

    phase = ui.open_phase("ZAP setup")
    ui.found("ZAP 2.17.0 ready")
    phase.close(files=["scan-zap-alerts.json"])
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert "ZAP setup" in lines[0] and lines[0].startswith("--")
    assert lines[-2].startswith("  → scan-zap-alerts.json")
    assert lines[-1].startswith("  ✓ ")


def test_every_command_closes_the_same_way(capsys, tmp_path):
    # Stage timings, then the files written, then the total — so the two things
    # a reader scans for sit at a fixed offset from the end of every command,
    # exactly as they do at the end of every phase.
    metrics = run_metrics.RunMetrics("20260101T000000Z-gitea", kind="triage")
    with metrics.stage("join") as stage:
        stage.counters["findings"] = 990
    metrics.print_summary(files=["triage.json", "triage-metrics.json"])
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert "Run metrics" in lines[0]
    assert lines[1].startswith("  join:")
    assert lines[-4].startswith("  → triage.json")
    assert lines[-3].startswith("  → triage-metrics.json")
    assert lines[-2].startswith("  ✓ ") and lines[-2].endswith("total")
    # A log pasted into a notebook carries its own span.
    assert lines[-1].startswith("  finished ")


# -- one table for one run's stages ----------------------------------------


def _record(tmp_path, run_id, kind, seconds, **results):
    layout = run_paths.RunLayout(tmp_path, run_id).ensure()
    layout.metrics(kind).write_text(json.dumps({
        "schema_version": 1, "run": run_id, "kind": kind, "label": "",
        "started_at": f"2026-08-26T0{seconds}:00:00+00:00",
        "total_seconds": seconds, "results": results,
    }))


def test_run_summary_totals_the_stages_of_one_run(tmp_path):
    run = "20260101T000000Z-gitea"
    _record(tmp_path, run, "scan", 120, alerts=3442, auth_mode="none")
    _record(tmp_path, run, "triage", 60, findings=990, cost_usd=0.018)
    table = run_metrics.run_summary(tmp_path, run)
    assert "scan" in table and "triage" in table
    assert "alerts=3442" in table and "findings=990" in table
    # Four separate per-stage blocks answer "what did this stage cost" four
    # times and "what did this run cost" not at all.
    assert "total" in table and "3.0m" in table and "$0.0180" in table


def test_run_summary_keeps_one_line_per_stage(tmp_path):
    run = "20260101T000000Z-gitea"
    _record(tmp_path, run, "triage", 10,
            **{c: 1 for c in run_metrics.TABLE_COLUMNS["triage"]})
    lines = [l for l in run_metrics.run_summary(tmp_path, run).splitlines()
             if l.startswith("triage")]
    assert len(lines) == 1
    # Only the leading columns; the order in TABLE_COLUMNS is most-important-first.
    assert "findings=1" in lines[0]
    assert "self_comparisons" not in lines[0]


def test_run_summary_is_empty_when_the_run_recorded_nothing(tmp_path):
    assert run_metrics.run_summary(tmp_path, "20260101T000000Z-gitea") == ""


def test_the_run_cost_ceiling_counts_one_experiment_not_the_whole_corpus(tmp_path):
    """The bug that refused verification pass 2 its first ever run.

    A run directory is not the unit of spending it looks like: the harness
    re-triages one stored corpus dozens of times and every row writes its
    metrics beside that corpus. Summed across the directory, the most-used run
    in the project hits the ceiling and all future model work on it is blocked.
    """
    run_id = "20260101T000000Z-gitea-abc123"
    directory = run_paths.RunLayout(tmp_path, run_id).dir
    directory.mkdir(parents=True)

    def record(kind, label, cost):
        (directory / f"run-metrics-{kind}{'-' + label if label else ''}.json").write_text(
            json.dumps({"run": run_id, "kind": kind, "label": label,
                        "started_at": f"2026-01-01T00:00:0{cost:.0f}Z",
                        "results": {"cost_usd": cost}}))

    # Twenty earlier experiments against this corpus, plus this one's own scan.
    for i in range(20):
        record("triage", f"experiment-{i}", 0.05)
    record("scan", "", 0.0)

    # This experiment has spent nothing yet, whatever the corpus has cost.
    assert run_metrics.run_cost_so_far(tmp_path, run_id, "residue-default-1") == 0.0
    # A plain sequence (empty label) is likewise unaffected by the labelled rows.
    assert run_metrics.run_cost_so_far(tmp_path, run_id, "") == 0.0
    # ...but the stages of ONE experiment still add up, which is the point.
    record("verify", "residue-default-1", 0.02)
    record("triage", "residue-default-1", 0.03)
    assert run_metrics.run_cost_so_far(tmp_path, run_id, "residue-default-1") == 0.05


# -- the index reader and harness membership -------------------------------


def test_run_index_reads_the_directories_the_writer_actually_writes_to(tmp_path,
                                                                      monkeypatch):
    """`dast costs` printed "No runs recorded yet" over ~100 rows.

    The writer puts a manual run under `data/runs/<run>/` and each sheet's runs
    under `data/harness/<sheet>/<run>/`; the reader must derive across both. It
    once looked in `data/` — the parent — and found nothing.
    """
    from dast_orchestrator.foundation import metrics as run_metrics

    r1 = "20260101T000000Z-gitea-aaaaaa"
    run_metrics.RunMetrics(r1, kind="scan").write(tmp_path / "runs")

    sheet = "20260101T000000Z-overnight"
    monkeypatch.setenv(run_metrics.HARNESS_ID_VAR, sheet)
    r2 = "20260102T000000Z-gitea-bbbbbb"
    run_metrics.RunMetrics(r2, kind="triage").write(
        tmp_path / "harness" / sheet)
    monkeypatch.delenv(run_metrics.HARNESS_ID_VAR)

    rows = run_metrics.read_all_indexes(tmp_path)
    assert [r["run"] for r in rows] == [r1, r2]          # oldest first, one history
    # Harness membership is a field on the record, so the question "was this part
    # of an experiment" is answerable from the row, not the directory path.
    assert rows[0].get("harness_id", "") == ""
    assert rows[1]["harness_id"] == sheet

    assert r1 in run_metrics.format_index(rows)
    # The sheet column is width-capped and truncates a long id visibly, so the
    # membership shows as its prefix in the table (the full id is on the row).
    assert sheet[:20] in run_metrics.format_index(rows)


def test_a_harness_run_stamps_its_membership_onto_every_record(monkeypatch, tmp_path):
    """Provenance as a field, not as a directory path.

    A sheet spawns each stage as its own subprocess, so the id travels in the
    environment; what matters here is that it reaches the record and the index
    row, since those are what a comparison table is built from at writing time.
    """
    from dast_orchestrator.foundation import metrics as run_metrics

    monkeypatch.setenv(run_metrics.HARNESS_ID_VAR, "20260101T000000Z-overnight")
    monkeypatch.setenv(run_metrics.HARNESS_ROW_VAR, "hybrid")
    metrics = run_metrics.RunMetrics("20260101T000000Z-gitea", kind="verify")
    record = metrics.as_dict()
    assert record["harness_id"] == "20260101T000000Z-overnight"
    assert record["harness_row"] == "hybrid"
    assert run_metrics.index_row(record)["harness_row"] == "hybrid"


def test_a_manual_run_is_not_claimed_by_any_sheet(monkeypatch):
    from dast_orchestrator.foundation import metrics as run_metrics

    monkeypatch.delenv(run_metrics.HARNESS_ID_VAR, raising=False)
    monkeypatch.delenv(run_metrics.HARNESS_ROW_VAR, raising=False)
    record = run_metrics.RunMetrics("20260101T000000Z-gitea").as_dict()
    assert record["harness_id"] == "" and record["harness_row"] == ""


def test_cached_prompt_tokens_are_read_across_provider_shapes():
    """Prompt caching has to be measurable, or the A/B that tests it cannot run.

    Both multi-turn callers re-send a stable prefix every turn and mark it
    cacheable. Without this number the only visible effect is a total cost that
    may have moved for any reason, so "does caching close the pull-vs-push gap"
    — the question the retrieval A/B exists to answer — would have no evidence
    behind it either way.
    """
    from dast_orchestrator.analysis.screening import cached_tokens

    class U:
        pass

    nested = U(); nested.prompt_tokens_details = {"cached_tokens": 512}
    assert cached_tokens(nested) == 512

    flat = U(); flat.cached_tokens = 77
    assert cached_tokens(flat) == 77

    anthropic = U(); anthropic.cache_read_input_tokens = 9
    assert cached_tokens(anthropic) == 9

    # A provider that reports nothing is indistinguishable from a miss, and the
    # docstring says so rather than letting a zero be read as "caching failed".
    assert cached_tokens(U()) == 0
    assert cached_tokens(None) == 0


def test_prompt_caching_can_be_turned_off_for_the_cost_comparison():
    """Caching changes no output, so its value can only be shown by pricing it.

    Two runs of one corpus differing ONLY in this switch are directly
    comparable, and that difference is the saving. Without a switch the number
    would have to be asserted rather than measured.
    """
    import os
    from dast_orchestrator.analysis import screening as lc

    convo = [{"role": "system", "content": "stable"},
             {"role": "user", "content": "task"},
             {"role": "user", "content": "new turn"}]
    prior = os.environ.get("SHARED_PROMPT_CACHE")
    try:
        os.environ["SHARED_PROMPT_CACHE"] = "1"
        assert lc.caching_enabled()
        assert isinstance(lc._mark_cache_prefix(convo, 2)[1]["content"], list)

        for off in ("0", "false", "no", "off"):
            os.environ["SHARED_PROMPT_CACHE"] = off
            assert not lc.caching_enabled(), off
            # ...and the conversation goes out byte-identical to the uncached one.
            assert lc._mark_cache_prefix(convo, 2) == convo
    finally:
        if prior is None:
            os.environ.pop("SHARED_PROMPT_CACHE", None)
        else:
            os.environ["SHARED_PROMPT_CACHE"] = prior


def test_each_caching_site_is_switchable_on_its_own():
    """Aggregate pricing would hide which site carries the saving.

    The three differ by an order of magnitude — 7.2% on triage, 63% on the
    verification loop, unmeasured on retrieval — so a single switch could only
    answer "caching helps", never "caching helps HERE", which is the claim the
    writeup actually makes.
    """
    import os
    from dast_orchestrator.analysis import screening as lc

    keys = ["SHARED_PROMPT_CACHE", *lc.CACHE_SITE_VARS.values()]
    prior = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        assert all(lc.caching_enabled(s) for s in lc.CACHE_SITES)

        # One site off leaves the others alone.
        os.environ["TRIAGE_PROMPT_CACHE"] = "off"
        assert not lc.caching_enabled("screening")
        assert lc.caching_enabled("verify") and lc.caching_enabled("retrieval")

        # The global switch still turns everything off...
        os.environ["SHARED_PROMPT_CACHE"] = "0"
        assert not any(lc.caching_enabled(s) for s in lc.CACHE_SITES)
        # ...and an explicit per-site value still wins over it, so one site can
        # be priced in isolation from either direction.
        os.environ["VERIFY_PROMPT_CACHE"] = "on"
        assert lc.caching_enabled("verify")
        assert not lc.caching_enabled("retrieval")
    finally:
        for k, v in prior.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_synthesis_has_no_switch_because_it_marks_no_breakpoint():
    """Its 99.8% is the provider caching identical prefixes on its own.

    A flag would claim this code controls something it does not.
    """
    from dast_orchestrator.analysis import screening as lc

    assert "synthesis" not in lc.CACHE_SITES


def test_both_llm_stages_expose_the_switch():
    from dast_orchestrator.foundation import config

    for stage in ("triage", "verify"):
        assert config.STAGE_FLAGS[stage]["prompt_cache"] == "SHARED_PROMPT_CACHE"


# -- costs columns: provider, suffix-aware stages, abort type -----------------


def test_index_row_names_the_served_providers_from_the_call_log():
    from dast_orchestrator.foundation import metrics
    record = {
        "run": "r", "kind": "triage", "started_at": "20260101T000000Z",
        "total_seconds": 1.0, "tools": {"openrouter": {"model": "m"}},
        "stages": {"llm_screening": {"seconds": 1.0, "calls_log": [
            {"provider": "Wafer"}, {"provider": "Baidu"}, {"provider": "Wafer"}]}},
    }
    row = metrics.index_row(record)
    assert row["provider"] == "Wafer,Baidu"      # distinct, first-seen order
    assert row["abort"] == ""                     # a clean finish carries no abort


def test_a_verify_record_surfaces_its_provider_from_the_dispatch_stage(schema, tmp_path):
    from dast_orchestrator.foundation import metrics
    # The verify driver now writes the LLM usage — the per-call log included —
    # into its `dispatch` stage, exactly as triage does for its arms, so the
    # `dast costs` provider column and the §T3 per-call cuts cover verify too
    # (they were blank before: verify recorded only aggregate cost). The read
    # path iterates every stage, so `dispatch` is treated like any LLM stage.
    m = run_metrics.RunMetrics(TIMESTAMP, kind="verify")
    with m.stage("dispatch") as stage:
        stage.counters["dispatched"] = 2
        stage.counters.update({  # the shape LlmUsage.as_dict() hands the driver
            "calls": 2, "cost_usd": 0.01, "providers": {"Wafer": 2},
            "calls_log": [{"provider": "Wafer"}, {"provider": "Wafer"}],
        })
    path = m.write(tmp_path)
    record = json.loads(path.read_text())
    jsonschema.validate(record, schema)      # a stage's per-call log is schema-valid
    assert record["stages"]["dispatch"]["calls_log"][0]["provider"] == "Wafer"
    row = metrics.index_row(record)
    assert row["provider"] == "Wafer"
    assert row["abort"] == ""      # a clean finish carries no abort


def test_costs_table_sorts_by_run_then_stage_order():
    from dast_orchestrator.foundation import metrics
    # Newest run at the bottom (ascending run id); within one run the stages read
    # in pipeline order (scan → triage → verify → report), whatever order the
    # records were discovered in.
    def row(run, kind, at):
        return {"run": run, "kind": kind, "started_at": at, "total_seconds": 1.0}
    rows = [
        row("20260102T000000Z-gitea", "scan", "b1"),
        row("20260101T000000Z-gitea", "verify", "a3"),
        row("20260101T000000Z-gitea", "scan", "a1"),
        row("20260101T000000Z-gitea", "triage", "a2"),
    ]
    table = metrics.format_index(rows)
    order = [ln.split()[0:2] for ln in table.splitlines()
             if ln.startswith("20260")]
    assert order == [
        ["20260101T000000Z-gitea", "scan"],
        ["20260101T000000Z-gitea", "triage"],
        ["20260101T000000Z-gitea", "verify"],
        ["20260102T000000Z-gitea", "scan"],   # newest run last
    ]
    assert "stages" not in table.splitlines()[0]   # the trailing column is gone


def test_abort_type_reads_the_explicit_object_then_falls_back_to_open_timings():
    from dast_orchestrator.foundation import metrics
    # The explicit abort object a crashing stage now persists names the type...
    assert metrics._abort_type({"abort": {"type": "budget-ceiling"}, "stages": {}}) \
        == "budget-ceiling"
    assert metrics._abort_type({"abort": {"type": "error"}, "stages": {}}) == "error"
    # ...a clean finish carries none...
    assert metrics._abort_type({"abort": None, "stages": {"scan": {"seconds": 3.0}}}) == ""
    # ...and a record with no abort field but a stage timing that never closed
    # (predates abort tracking, or truncated on disk) still reads as an error.
    assert metrics._abort_type({"stages": {"scan": {"seconds": None}}}) == "error"
    assert metrics._abort_type({"stages": {"scan": {"seconds": 3.0}}}) == ""


def test_every_stage_kind_validates_against_the_schema(schema, tmp_path):
    # A record of each kind a driver writes must satisfy the schema — the `kind`
    # enum silently dropped "report" once, so report-metrics.json never validated.
    for kind in ("scan", "triage", "verify", "report", "analysis"):
        m = run_metrics.RunMetrics(TIMESTAMP, kind=kind)
        with m.stage("s"):
            pass
        record = json.loads(m.write(tmp_path).read_text())
        jsonschema.validate(record, schema)
        assert record["abort"] is None      # a clean write carries a null abort


def test_record_abort_classifies_the_exception():
    m = run_metrics.RunMetrics(TIMESTAMP, kind="verify")
    m.record_abort(RuntimeError("zap gone"))
    assert m.abort == {"type": "error", "reason": "RuntimeError: zap gone"}
    m.record_abort(KeyboardInterrupt())
    assert m.abort["type"] == "cancelled"
    # An LlmError whose kind names a controlled stop is recorded as that stop.
    from dast_orchestrator.analysis.screening import LlmError
    m.record_abort(LlmError("ceiling reached", "budget"))
    assert m.abort["type"] == "budget-ceiling"


def test_guard_writes_a_record_even_when_the_stage_crashes(tmp_path):
    # The whole point: a stage that dies mid-run still leaves a metrics file, with
    # the abort object saying why — and the exception still propagates.
    import pytest
    from dast_orchestrator.foundation import metrics
    m = run_metrics.RunMetrics(TIMESTAMP, kind="scan")
    with pytest.raises(RuntimeError):
        with m.guard(tmp_path):
            with m.stage("active_scan"):
                raise RuntimeError("zap gone")
    record = json.loads((tmp_path / TIMESTAMP / "scan-metrics.json").read_text())
    assert record["abort"] == {"type": "error", "reason": "RuntimeError: zap gone"}
    assert metrics.index_row(record)["abort"] == "error"
