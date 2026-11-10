"""scripts/rerun-rewire-refs.py: deferred sheets point at G1's admin-blind runs.

Runs against a temporary harness and data tree, so no committed sheet is touched.
"""

import importlib.util
import json
from pathlib import Path

TOOL = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("rerun_rewire_refs",
                                               TOOL / "scripts" / "rerun-rewire-refs.py")
rewire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rewire)


def _sheet_dir(root: Path, name: str, runs: dict[str, str]) -> Path:
    d = root / "data" / "harness" / name
    d.mkdir(parents=True)
    executions = [{"row": f"{t}-admin-blind", "run": r} for t, r in runs.items()]
    (d / "results.json").write_text(json.dumps({"executions": executions}))
    return d


def _setup(tmp_path, monkeypatch):
    harness = tmp_path / "config" / "harness"
    harness.mkdir(parents=True)
    (harness / "g5.yml").write_text(
        "rows:\n"
        "  - {name: grafana-admin-blind-rep, run: old-g, stages: [triage]}\n"
        "  - {name: cacti-admin-blind-rep, run: old-c, stages: [triage]}\n")
    monkeypatch.setattr(rewire, "ROOT", tmp_path)
    monkeypatch.setattr(rewire, "HARNESS", harness)
    monkeypatch.setattr(rewire, "DEFERRED", ("g5.yml",))
    return harness / "g5.yml"


def test_a_later_sheet_replaces_g1s_run_for_its_target_only(tmp_path, monkeypatch):
    sheet = _setup(tmp_path, monkeypatch)
    g1 = _sheet_dir(tmp_path, "20261104T011344Z-rerun-g1-blind-matrix",
                    {"grafana": "g1-g", "cacti": "g1-c"})
    again = _sheet_dir(tmp_path, "20261104T150000Z-rerun-g1-cacti-signed-in", {"cacti": "re-c"})
    assert rewire.main([str(g1), str(again)]) == 0
    text = sheet.read_text()
    assert "run: g1-g," in text and "run: re-c," in text and "g1-c" not in text


def test_the_default_is_the_newest_g1_matrix_not_a_re_run_sheet(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    g1 = _sheet_dir(tmp_path, "20261104T011344Z-rerun-g1-blind-matrix", {"grafana": "g", "cacti": "c"})
    _sheet_dir(tmp_path, "20261104T150000Z-rerun-g1-cacti-signed-in", {"cacti": "re-c"})
    assert rewire.latest_g1_dir() == g1
