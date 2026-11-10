"""The worklist tables, over synthetic reports: the figures here reach the thesis, so the
arithmetic is pinned without the corpus. The corpus only has to not break them."""

from __future__ import annotations

import json

import pandas as pd
import pytest

from dast_analyzer import priority


def _result(fid, section, group=None, line=1, level="warning", namespace="zap-mirror",
            disposition=None):
    default = {"reproduced": "confirmed", "evident": "confirmed", "open": "requires-triage",
               "claims": "requires-triage", "refuted": "refuted",
               "informational": "informational"}
    return {"level": level, "properties": {
        "finding_id": fid, "namespace": namespace, "worklist_section": section,
        "worklist_group": group or f"{section}:{fid}", "worklist_line": line,
        "disposition": disposition or default[section]}}


@pytest.fixture
def make_index(tmp_path, monkeypatch):
    monkeypatch.setattr(priority, "default_valid", lambda frame, **_: frame)

    def build(*runs):
        rows = []
        for number, (target, role, digest, results, alerts) in enumerate(runs):
            run_dir = tmp_path / f"run{number}"
            run_dir.mkdir()
            if results is not None:
                (run_dir / "report.sarif.json").write_text(
                    json.dumps({"runs": [{"results": results}]}))
            rows.append({"run": f"2026{number:02}-{target}-{digest}", "run_dir": str(run_dir),
                         "target": target, "role": role, "digest": digest, "variant": "",
                         "stage": "scan", "results.alerts": alerts})
        return pd.DataFrame(rows)

    return build


def test_a_report_without_the_worklist_is_skipped_not_guessed(make_index):
    old = [{"level": "error", "properties": {"finding_id": "f-1", "disposition": "refuted"}}]
    index = make_index(("cacti", "blind", "a", old, 10), ("gitea", "blind", "b", None, 10))
    assert priority.worklist_runs(index).empty
    assert priority.read_load(index).empty
    assert priority.gate_simulation(index).empty
    assert priority.risk_disposition(index).empty
    assert priority.open_stability(index).empty
    assert priority.reproduced_first(index).empty


def test_read_load_counts_lines_not_findings(make_index):
    results = [
        _result("f-1", "open", "open:1", 1), _result("f-2", "open", "open:1", 1),
        _result("f-3", "open", "open:2", 2),
        _result("c-1", "claims", "claims:c-1", 3, namespace="dast-synthesis"),
        _result("f-4", "evident", "evident:9", 4), _result("f-5", "evident", "evident:9", 4),
    ]
    row = priority.read_load(make_index(("cacti", "blind", "a", results, 10))).iloc[0]
    assert (row["results_max"], row["requires_triage_max"]) == (6, 4)
    assert (row["open_lines_max"], row["open_claims_max"], row["all_lines_max"]) == (2, 1, 4)


def test_read_load_keeps_blind_and_ceiling_apart(make_index):
    results = [_result("f-1", "open", "open:1")]
    table = priority.read_load(make_index(("cacti", "blind", "a", results, 1),
                                          ("cacti", "ceiling", "b", results, 1)))
    assert sorted(table["role"]) == ["blind", "ceiling"]


def test_risk_disposition_means_per_run_and_counts_zap_findings_only(make_index):
    first = [_result("f-1", "refuted", level="error"), _result("f-2", "open", level="error"),
             _result("c-1", "claims", level="error", namespace="dast-synthesis")]
    second = [_result("f-1", "refuted", level="error"), _result("f-9", "evident", level="note")]
    table = priority.risk_disposition(make_index(("gitea", "blind", "a", first, 1),
                                                 ("gitea", "blind", "a", second, 1)))
    high = table[table["risk"] == "High"].iloc[0]
    assert (high["runs"], high["findings"], high["refuted"], high["open"], high["claims"]) \
        == (2, 1.5, 1.0, 0.5, 0.0)
    assert table[table["risk"] == "Low"].iloc[0]["evident"] == 0.5


def test_the_gates_read_as_the_thesis_states_them(make_index):
    settled_high = [_result("f-1", "refuted", level="error")]
    open_high = [_result("f-1", "open", level="error")]
    reproduced = [_result("f-1", "reproduced", level="error")]
    no_high = [_result("f-1", "open", level="warning")]
    index = make_index(("cacti", "blind", "a", settled_high, 1), ("cacti", "blind", "a", open_high, 1),
                       ("gitea", "blind", "b", reproduced, 1), ("gitea", "blind", "b", no_high, 1))
    table = priority.gate_simulation(index).set_index("target")
    assert table.loc["cacti", ["any_high", "high_not_refuted", "tool_reproduced"]].tolist() == [2, 1, 0]
    assert table.loc["gitea", ["any_high", "high_not_refuted", "tool_reproduced"]].tolist() == [1, 1, 1]
    assert table.loc["ALL", ["runs", "any_high", "high_not_refuted", "tool_reproduced"]].tolist() \
        == [4, 3, 2, 1]


def test_a_claim_at_error_level_is_not_a_zap_high(make_index):
    claim = [_result("c-1", "claims", level="error", namespace="dast-synthesis")]
    row = priority.gate_simulation(make_index(("cacti", "blind", "a", claim, 1))).iloc[0]
    assert row["any_high"] == 0


def test_stability_separates_finding_churn_from_the_rule_list(make_index):
    before = [_result("f-1", "open", "open:1", 1), _result("f-2", "open", "open:2", 2)]
    after = [_result("f-1", "open", "open:1", 1), _result("f-3", "open", "open:2", 2)]
    row = priority.open_stability(make_index(("gitea", "blind", "a", before, 1341),
                                             ("gitea", "blind", "a", after, 2115))).iloc[0]
    assert (row["alerts_min"], row["alerts_max"]) == (1341, 2115)
    assert row["open_new_share"] == 0.5      # f-3 is new among 2 open findings
    assert row["open_rules_new_max"] == 0    # …and no rule line is
    assert row["open_rule_jaccard_mean"] == 1.0


def test_stability_groups_by_configuration_and_ignores_ceilings_and_singletons(make_index):
    results = [_result("f-1", "open", "open:1")]
    index = make_index(("gitea", "blind", "a", results, 1), ("gitea", "blind", "b", results, 1),
                       ("cacti", "ceiling", "c", results, 1), ("cacti", "ceiling", "c", results, 1))
    assert priority.open_stability(index).empty


def test_the_top_lines_follow_the_report_s_order_not_the_alphabet(make_index):
    results = [_result(f"f-{n}", "open", f"open:{name}", line)
               for n, (name, line) in enumerate([("z", 1), ("a", 7)])]
    assert priority._top_lines(results) == ["open:z", "open:a"]


def test_reproduced_first_flags_a_report_that_buries_one(make_index):
    good = [_result("f-1", "reproduced", line=1), _result("f-2", "open", "open:2", 2)]
    bad = [_result("f-2", "open", "open:2", 1), _result("f-1", "reproduced", line=2)]
    table = priority.reproduced_first(make_index(("grafana", "ceiling", "a", good, 1),
                                                 ("cacti", "ceiling", "b", bad, 1))).set_index("target")
    assert bool(table.loc["grafana", "all_first"]) is True
    assert bool(table.loc["cacti", "all_first"]) is False
    assert table.loc["grafana", "runs_with_reproduced"] == 1


def test_the_tables_survive_the_real_corpus(index):
    # Reports from before the worklist are skipped, so these may be empty until regenerated.
    for table in (priority.read_load, priority.risk_disposition, priority.gate_simulation,
                  priority.open_stability, priority.reproduced_first):
        assert isinstance(table(index), pd.DataFrame)
