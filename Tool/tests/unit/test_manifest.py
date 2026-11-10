"""A run's manifest.json: a self-description scanned from the directory, so a
reader learns what a run contains from one file instead of probing well-known
names. → foundation.manifest.
"""

from __future__ import annotations

import json

from dast_orchestrator.foundation import manifest, run_paths


def _run(tmp_path):
    layout = run_paths.RunLayout(tmp_path, "20260101T000000Z-wp-abcdef").ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text(
        json.dumps({"schema_version": 3, "alerts": []}))
    layout.path(run_paths.TRIAGE).write_text(json.dumps({"schema_version": 1}))
    layout.metrics("scan").write_text(json.dumps({"kind": "scan"}))
    layout.path(run_paths.REPORT_MD).write_text("# report")   # no schema
    return layout


def test_manifest_lists_artifacts_with_schema_and_version(tmp_path):
    m = manifest.build_manifest(_run(tmp_path))
    assert m["run"] == "20260101T000000Z-wp-abcdef"
    by_file = {a["file"]: a for a in m["artifacts"]}

    assert by_file["scan-zap-alerts.json"]["schema"] == "zap-alerts.schema.json"
    assert by_file["scan-zap-alerts.json"]["schema_version"] == 3
    assert by_file["scan-metrics.json"]["schema"] == "run-metrics.schema.json"
    # an artifact with no registered schema is listed with schema=None
    assert by_file["report.md"]["schema"] is None
    assert "schema_version" not in by_file["report.md"]


def test_write_manifest_excludes_itself_and_is_reread(tmp_path):
    layout = _run(tmp_path)
    path = manifest.write_manifest(layout)
    assert path.name == "manifest.json"
    doc = json.loads(path.read_text())
    files = {a["file"] for a in doc["artifacts"]}
    assert "manifest.json" not in files          # never lists itself
    assert "scan-zap-alerts.json" in files
    # a second write is idempotent in shape (a full rescan, not an append)
    again = json.loads(manifest.write_manifest(layout).read_text())
    assert {a["file"] for a in again["artifacts"]} == files


def test_metrics_write_refreshes_the_manifest(tmp_path):
    # Every stage records metrics, so metrics.write is the chokepoint that keeps
    # the manifest current.
    from dast_orchestrator.foundation import metrics as run_metrics
    m = run_metrics.RunMetrics("20260101T000000Z-wp-abcdef", kind="scan")
    m.write(tmp_path)
    manifest_path = tmp_path / "20260101T000000Z-wp-abcdef" / "manifest.json"
    assert manifest_path.is_file()
    files = {a["file"] for a in json.loads(manifest_path.read_text())["artifacts"]}
    assert "scan-metrics.json" in files
