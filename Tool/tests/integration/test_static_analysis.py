"""Unit tests for the standalone SAST/SCA static-analysis findings.

No live containers and no network: :func:`docker_run` is monkeypatched, and the
two SARIF fixtures are verbatim excerpts of real runs over the pinned Gitea
v1.16.0 source (``semgrep-gitea-sample.sarif.json``,
``osv-gitea-sample.sarif.json``) — the same one-artifact-two-jobs rule the Noir
fixture follows, so the recorded output shape cannot rot unnoticed.

What these tests are actually protecting is the *reproducibility contract*: the
invocations must stay offline, read-only and pinned, and the derived numbers
must come out of the stored SARIF rather than out of a parallel count.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import pytest

from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.stages.static_analysis import (
    StaticAnalysisError,
    ToolRun,
    analyze,
    cwe_ids,
    osv_runner,
    parse_sarif_stdout,
    semgrep_runner,
)

FIXTURES = FIXTURES_DIR
SEMGREP_SARIF = json.loads((FIXTURES / "semgrep-gitea-sample.sarif.json").read_text())
OSV_SARIF = json.loads((FIXTURES / "osv-gitea-sample.sarif.json").read_text())
SARIF_SCHEMA = FIXTURES / "sarif-2.1.0-schema.json"


def _run(stdout: str = "", exit_code: int = 0, stderr: str = "", timed_out=False):
    return ToolRun(["docker", "run", "stub"], exit_code, stdout, stderr, 1.0, timed_out)


# -- the invocations -------------------------------------------------------


def test_semgrep_command_is_pinned_offline_and_read_only():
    volumes, env, args = semgrep_runner.build_command(
        Path("/repo/targets/gitea/src"), Path("/repo/semgrep-rules"), ["go", "javascript"]
    )
    assert all(v.endswith(":ro") for v in volumes), "an analyser must not mutate its input"
    # The rules come from the pinned checkout, never from the registry: a
    # `p/...` config would be an unpinned network fetch on every run.
    assert "--config" in args and "/rules/go" in args and "/rules/javascript" in args
    assert not any(a.startswith("p/") for a in args)
    assert "--metrics=off" in args and "--disable-version-check" in args
    # Relative SARIF URIs: scan "." from inside the mounted source root.
    assert args[-1] == "."
    assert env == ["HOME=/tmp"]


def test_semgrep_rejects_registry_packs_and_empty_rulesets():
    with pytest.raises(StaticAnalysisError, match="registry pack"):
        semgrep_runner.config_args(["p/golang"])
    with pytest.raises(StaticAnalysisError, match="semgrep_rulesets"):
        semgrep_runner.config_args([])


def test_osv_command_is_offline_and_disables_call_analysis():
    volumes, args = osv_runner.build_command(Path("/repo/targets/gitea/src"), Path("/repo/osv-db"))
    assert volumes[0].endswith(":ro")
    # The database mount stays writable: it is a cache the scanner reads.
    assert volumes[1].endswith(osv_runner.DB_MOUNTPOINT)
    assert "--offline-vulnerabilities" in args
    # govulncheck needs the Go toolchain and the module proxy at run time.
    assert args[args.index("--no-call-analysis") + 1] == "all"
    assert "--download-offline-databases" not in args


def test_osv_download_command_is_the_only_networked_one():
    _, args = osv_runner.build_command(Path("/src"), Path("/db"), download=True)
    assert "--download-offline-databases" in args


def test_docker_run_defaults_to_no_network(monkeypatch):
    seen: dict = {}

    class _Proc:
        returncode = 0
        stdout = b"{}"
        stderr = b""

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
    def record(argv, **kwargs):
        seen["argv"] = argv
        return _Proc()

    monkeypatch.setattr("subprocess.run", record)
    from dast_orchestrator.stages.static_analysis import docker_run

    docker_run("img:1", ["x"], timeout=5)
    assert seen["argv"][:5] == ["docker", "run", "--rm", "--network", "none"]


# -- missing inputs say exactly how to fix them ----------------------------


def test_missing_ruleset_checkout_quotes_the_fetch_commands(tmp_path):
    with pytest.raises(StaticAnalysisError) as exc:
        semgrep_runner.run_semgrep(tmp_path, tmp_path / "absent", ["go"])
    message = str(exc.value)
    assert semgrep_runner.RULES_COMMIT in message
    assert "git fetch --depth 1" in message


def test_missing_database_points_at_the_refresh_flag(tmp_path):
    with pytest.raises(StaticAnalysisError, match="--refresh-db"):
        osv_runner.run_osv(tmp_path, tmp_path / "osv-db")


# -- exit codes ------------------------------------------------------------


def test_semgrep_exit_1_means_findings_not_failure(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()
    monkeypatch.setattr(
        semgrep_runner, "docker_run",
        lambda *a, **k: _run(json.dumps(SEMGREP_SARIF), exit_code=1),
    )
    sarif, _ = semgrep_runner.run_semgrep(tmp_path, tmp_path / "rules", ["go"])
    assert len(sarif["runs"][0]["results"]) == 7


def test_semgrep_other_exit_codes_raise(monkeypatch, tmp_path):
    (tmp_path / "rules").mkdir()
    monkeypatch.setattr(
        semgrep_runner, "docker_run", lambda *a, **k: _run("", exit_code=2, stderr="boom")
    )
    with pytest.raises(StaticAnalysisError, match="exited 2"):
        semgrep_runner.run_semgrep(tmp_path, tmp_path / "rules", ["go"])


def test_osv_exit_1_means_vulnerabilities_found(monkeypatch, tmp_path):
    db = tmp_path / "osv-db" / "osv-scanner" / "Go"
    db.mkdir(parents=True)
    (db / "all.zip").write_bytes(b"snapshot")
    monkeypatch.setattr(
        osv_runner, "docker_run", lambda *a, **k: _run(json.dumps(OSV_SARIF), exit_code=1)
    )
    sarif, _ = osv_runner.run_osv(tmp_path, tmp_path / "osv-db")
    assert len(sarif["runs"][0]["results"]) == 5


def _osv_db(tmp_path):
    db = tmp_path / "osv-db" / "osv-scanner" / "Go"
    db.mkdir(parents=True)
    (db / "all.zip").write_bytes(b"snapshot")


def test_osv_no_package_sources_is_an_empty_success(monkeypatch, tmp_path):
    # A manifest-free tree (WordPress + the WPDM plugin is pure PHP) makes
    # osv-scanner exit 128 "No package sources found" and write no SARIF: no SCA
    # surface, not a failure. run_osv returns a valid, result-free SARIF so the
    # corpus reads 4/4 uniformly, and the 128 is still recorded in provenance.
    _osv_db(tmp_path)
    monkeypatch.setattr(
        osv_runner, "docker_run",
        lambda *a, **k: _run("", exit_code=128, stderr="No package sources found in /src\n"),
    )
    sarif, run = osv_runner.run_osv(tmp_path, tmp_path / "osv-db")
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "osv-scanner"
    assert osv_runner.summarise(sarif)["findings"] == 0
    assert run.exit_code == 128
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(sarif, json.loads(SARIF_SCHEMA.read_text()))


def test_osv_other_128_still_raises(monkeypatch, tmp_path):
    # The empty-success path is gated on the exact message: any other 128 is a
    # real failure and must still surface, not be swallowed as "nothing found".
    _osv_db(tmp_path)
    monkeypatch.setattr(
        osv_runner, "docker_run",
        lambda *a, **k: _run("", exit_code=128, stderr="fatal: could not open database"),
    )
    with pytest.raises(StaticAnalysisError, match="exited 128"):
        osv_runner.run_osv(tmp_path, tmp_path / "osv-db")


def test_non_sarif_stdout_surfaces_the_tools_stderr():
    with pytest.raises(StaticAnalysisError, match="config file not found"):
        parse_sarif_stdout(_run("not json", 2, stderr="config file not found"), "semgrep")


def test_timeout_is_reported_as_such():
    with pytest.raises(StaticAnalysisError, match="timed out"):
        parse_sarif_stdout(_run("", None, timed_out=True), "osv-scanner")


# -- derived numbers come out of the stored SARIF --------------------------


def test_semgrep_summary_splits_the_security_subset():
    summary = semgrep_runner.summarise(SEMGREP_SARIF)
    assert summary["findings"] == 7
    # The whole language ruleset runs; the DAST-comparable subset is recovered
    # from Semgrep's own tag rather than by running a second, narrower config.
    assert 0 < summary["security_findings"] < summary["findings"]
    assert summary["rules_with_findings"] == 6  # one rule fired twice


def test_semgrep_severity_falls_back_to_the_rule_default():
    # Semgrep omits `level` on results and puts it on the rule; reading only the
    # result would report every finding as unrated.
    summary = semgrep_runner.summarise(SEMGREP_SARIF)
    assert sum(summary["by_level"].values()) == summary["findings"]
    assert "none" not in summary["by_level"]


def test_cwe_histogram_is_the_join_axis_with_zap():
    summary = semgrep_runner.summarise(SEMGREP_SARIF)
    assert summary["by_cwe"], "CWE ids are how a SAST rule and a ZAP alert compare"
    assert all(key.startswith("CWE-") for key in summary["by_cwe"])


def test_cwe_ids_ignores_non_cwe_tags():
    rule = {"properties": {"tags": ["security", "OWASP-A03:2021 - Injection",
                                    "CWE-89: SQL Injection"]}}
    assert cwe_ids(rule) == ["CWE-89"]


def test_files_scanned_is_null_when_semgrep_did_not_report_it():
    # Measured, never estimated: the count lives only on stderr, so a run whose
    # stderr is absent records null rather than a stand-in.
    assert semgrep_runner.summarise(SEMGREP_SARIF)["files_scanned"] is None
    with_stderr = semgrep_runner.summarise(
        SEMGREP_SARIF, _run(stderr="Ran 262 rules on 3632 files: 346 findings.")
    )
    assert with_stderr["files_scanned"] == 3632
    assert with_stderr["rules_run"] == 262


def test_osv_summary_separates_advisories_from_packages():
    summary = osv_runner.summarise(OSV_SARIF)
    assert summary["findings"] == 5
    assert summary["advisories"] == 5 and summary["packages"] == 5
    assert sum(summary["by_severity"].values()) == summary["findings"]
    assert summary["by_manifest"]


@pytest.mark.parametrize(
    "score, band",
    [(9.8, "critical"), (7.5, "high"), (5.0, "medium"), (2.1, "low"),
     (None, "unknown"), ("", "unknown"), ("n/a", "unknown")],
)
def test_cvss_bands_are_the_standard_ones(score, band):
    assert osv_runner.severity_band(score) == band


# -- provenance ------------------------------------------------------------


def test_database_provenance_hashes_every_ecosystem_snapshot(tmp_path):
    for eco in ("Go", "npm"):
        d = tmp_path / "osv-scanner" / eco
        d.mkdir(parents=True)
        (d / "all.zip").write_bytes(b"advisories-" + eco.encode())
    entries = osv_runner.database_provenance(tmp_path)
    assert [e["ecosystem"] for e in entries] == ["Go", "npm"]
    assert len({e["sha256"] for e in entries}) == 2
    assert all(e["downloaded_at"].endswith("+00:00") for e in entries)


def test_ruleset_drift_is_recorded_not_corrected(monkeypatch, tmp_path):
    monkeypatch.setattr(semgrep_runner, "rules_commit", lambda _: "deadbeef")
    monkeypatch.setattr(
        "dast_orchestrator.foundation.metrics.docker_image_digest", lambda _: "sha256:abc"
    )
    prov = semgrep_runner.provenance(SEMGREP_SARIF, _run(), tmp_path, ["go"])
    assert prov["rules_commit"] == "deadbeef"
    assert prov["rules_commit_pinned"] == semgrep_runner.RULES_COMMIT
    assert prov["rules_pinned"] is False
    assert prov["version"] == "1.140.0"
    assert prov["network"] == "none"


# -- the fixtures are valid SARIF 2.1.0, like the DAST report --------------


def test_both_tools_emit_schema_valid_sarif():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SARIF_SCHEMA.read_text())
    for sarif in (SEMGREP_SARIF, OSV_SARIF):
        jsonschema.validate(sarif, schema)


# -- the driver ------------------------------------------------------------


@pytest.fixture
def stub_tools(monkeypatch):
    """Both containers replaced by canned SARIF; nothing is executed."""
    monkeypatch.setattr(
        semgrep_runner, "run_semgrep",
        lambda *a, **k: (SEMGREP_SARIF, _run(stderr="Ran 2 rules on 9 files: 7 findings.")),
    )
    monkeypatch.setattr(osv_runner, "run_osv", lambda *a, **k: (OSV_SARIF, _run()))
    monkeypatch.setattr(osv_runner, "database_files", lambda _: [Path("all.zip")])
    monkeypatch.setattr(osv_runner, "database_provenance", lambda _: [])
    monkeypatch.setattr(semgrep_runner, "rules_commit", lambda _: semgrep_runner.RULES_COMMIT)
    monkeypatch.setattr("dast_orchestrator.foundation.metrics.docker_image_digest", lambda _: None)


def test_run_writes_both_sarifs_a_summary_and_metrics(stub_tools, tmp_path):
    layout, record, errors = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data",
        timestamp="20260824T120000Z",
    )
    assert not errors
    # One uniform run id everywhere: timestamp first (so `data/` sorts
    # chronologically), then the target, then a digest of the configuration —
    # here the ruleset pin, which is what makes a drifted checkout's numbers
    # visibly a different experiment.
    assert layout.dir.name.startswith("20260824T120000Z-gitea-")
    assert layout.dir.name == run_paths.make_run_id(
        "20260824T120000Z", "gitea", run_paths.config_digest(record["config"])
    )
    for name in (run_paths.SEMGREP_SARIF, run_paths.OSV_SARIF, run_paths.ANALYSIS_MD):
        assert layout.has(name), name
    assert layout.metrics("analysis").is_file()
    # Raw tool output, stored unmodified.
    assert json.loads(layout.path(run_paths.OSV_SARIF).read_text()) == OSV_SARIF
    # `findings` is the column `dast costs` prints for every kind of run.
    assert record["results"]["findings"] == 12
    assert record["results"]["target"] == "gitea"


def test_one_failing_tool_does_not_cost_the_other(monkeypatch, stub_tools, tmp_path):
    def boom(*a, **k):
        raise StaticAnalysisError("no ruleset checkout")

    monkeypatch.setattr(semgrep_runner, "run_semgrep", boom)
    layout, record, errors = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data",
    )
    assert errors and "no ruleset checkout" in errors[0]
    assert not layout.has(run_paths.SEMGREP_SARIF)
    assert layout.has(run_paths.OSV_SARIF)          # SCA still measured
    assert record["results"]["findings"] == 5


def test_metrics_record_matches_the_published_contract(stub_tools, tmp_path):
    # The analysis run carries a `<ts>-<target>` id and a fourth `kind`;
    # both are part of the run-metrics contract, so drift is caught here rather
    # than by a reader of `dast costs` months later.
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas" / "run-metrics.schema.json")
        .read_text()
    )
    layout, _, _ = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data",
    )
    record = json.loads(layout.metrics("analysis").read_text())
    jsonschema.validate(record, schema)
    assert record["kind"] == "analysis"


def test_only_sast_skips_the_sca_pass(stub_tools, tmp_path):
    layout, record, _ = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data", only="sast",
    )
    assert layout.has(run_paths.SEMGREP_SARIF)
    assert not layout.has(run_paths.OSV_SARIF)
    assert "osv" not in record["results"]


def test_summary_reports_both_populations_without_touching_dast(stub_tools, tmp_path):
    layout, record, _ = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data",
    )
    text = layout.path(run_paths.ANALYSIS_MD).read_text()
    assert "SAST — Semgrep" in text and "SCA — OSV-Scanner" in text
    assert "CWE-" in text
    # The static-analysis pass never reads a DAST artifact: the comparison is the writeup's.
    assert "triage.json" not in text and "report.sarif.json" not in text


# -- standalone vs joined to a DAST run ------------------------------------


def test_analysis_joins_an_existing_run_without_overwriting_it(stub_tools, tmp_path):
    # The "one complete run, one folder" shape: --run writes the findings into
    # a DAST run's directory. Basenames are disjoint, so joining adds files.
    data = tmp_path / "data"
    dast = run_paths.RunLayout(data, "20260824T120000Z-gitea").ensure()
    dast.path(run_paths.ZAP_ALERTS).write_text('{"alerts": []}')
    dast.path(run_paths.TRIAGE).write_text("{}")

    layout, _, errors = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=data,
        run_id="20260824T120000Z-gitea",
    )
    assert not errors
    assert layout.dir == dast.dir
    assert layout.has(run_paths.ZAP_ALERTS) and layout.has(run_paths.TRIAGE)
    assert layout.has(run_paths.SEMGREP_SARIF) and layout.has(run_paths.OSV_SARIF)
    # Its own metrics record, beside the DAST stages' rather than replacing one.
    assert layout.metrics("analysis").is_file()
    assert json.loads(dast.path(run_paths.TRIAGE).read_text()) == {}


def test_the_joined_run_names_its_own_target(tmp_path):
    # A run id carries its target, so joining one needs nothing else — and
    # attaching an analysis of the wrong target became impossible rather than
    # merely refused.
    run_paths.RunLayout(tmp_path, "20260824T120000Z-wordpress").ensure()
    resolved = analyze._existing_run(tmp_path, "20260824T120000Z-wordpress")
    assert run_paths.split_run_id(resolved).target == "wordpress"


def test_joining_refuses_something_that_is_neither_target_nor_run(tmp_path):
    # Naming a run means *join it*; a typo must not quietly mint a new folder.
    with pytest.raises(StaticAnalysisError, match="neither a known target nor a run"):
        analyze._existing_run(tmp_path, "20260824T120000Z-gitea")


def test_join_latest_picks_the_newest_run(tmp_path):
    for name in ("20260101T000000Z-gitea", "20260202T000000Z-gitea"):
        run_paths.RunLayout(tmp_path, name).ensure()
    assert analyze._existing_run(tmp_path, "latest") == "20260202T000000Z-gitea"


def test_standalone_run_mints_its_own_id(stub_tools, tmp_path):
    layout, record, _ = analyze.run_analysis(
        targets.get("gitea"), tmp_path / "src", data_dir=tmp_path / "data",
    )
    assert layout.target == "gitea"
    assert layout.run_id == record["run"]


def test_target_declares_its_rulesets_as_data():
    # The seam the "does it generalise?" claim rests on: a new target is one
    # more YAML file, including for the SAST pass.
    assert targets.get("gitea").source_analysis.semgrep_rulesets == ("go", "javascript")
