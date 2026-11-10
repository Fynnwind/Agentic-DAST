"""§9 metric definitions against the frozen corpus (SHEET-CATALOG §Sheet 3/5)."""

from dast_analyzer import metrics as M


def test_alert_volume_range_matches_catalog(index):
    av = M.alert_volume_vs_detection(index).set_index("target")
    # wordpress ~34% swing, gitea ~27% (SHEET-CATALOG §Sheet 3)
    assert int(av.loc["wordpress", "results.alerts.min"]) == 1166
    assert int(av.loc["wordpress", "results.alerts.max"]) == 1563
    assert int(av.loc["gitea", "results.alerts.min"]) == 1545
    assert int(av.loc["gitea", "results.alerts.max"]) == 2122
    # grafana/cacti stable
    assert int(av.loc["grafana", "results.alerts.max"]) - int(av.loc["grafana", "results.alerts.min"]) <= 2
    # detection is a point at 0 everywhere (blind); denominators are the 22 markers
    assert (av["detected_blind"] == 0).all()
    assert dict(av["markers"]) == {"grafana": 5, "wordpress": 10, "cacti": 2, "gitea": 5}


def test_duration_chain_exceeds_nfr02_for_large_targets(index):
    d = M.duration_summary(index).set_index("target")
    assert bool(d.loc["wordpress", "any_chain_over_30min"])  # whole chain > 30 min
    assert bool(d.loc["gitea", "any_chain_over_30min"])
    # grafana's whole chain stays well under the budget
    assert d.loc["grafana", "chain_min_max"] < 40


def test_scanner_memory_is_captured_not_a_gap(index):
    mem = M.scanner_memory_summary(index)
    allrow = mem[mem.target == "ALL"].iloc[0]
    # dast-zap peaks in the multi-GB range — NFR-05 is measurable (not a gap)
    assert allrow["memory_mb_peak_max"] > 10_000
    assert int(allrow["n"]) == 40  # every blind/ceiling/crawl/repeat scan


def test_cost_per_finding_three_denominators_and_nocache(index):
    c = M.cost_per_finding(index)
    assert {"per_finding_all", "per_finding_asked", "per_finding_dispatched", "per_finding_all_nocache"} <= set(c.columns)
    # actual billed cost is positive and the cache-aware recompute tracks it
    assert (c["cost_usd"] > 0).all()
    gitea = c[c.target == "gitea"].iloc[0]
    assert abs(gitea["cost_recompute_check"] - gitea["cost_usd"]) / gitea["cost_usd"] < 0.20
    # no-cache is never cheaper than the cached recompute
    assert (c["cost_usd_nocache"] >= c["cost_recompute_check"] - 1e-9).all()


def test_model_stage_spread_keeps_blind_and_ceiling_separate(index):
    """variant='rep' spans blind + ceiling reps; the spread must not merge them."""
    s = M.model_stage_spread(index)
    gverify = s[(s.target == "gitea") & (s.stage == "verify")]
    roles = set(gverify["role"])
    assert {"blind", "ceiling"} <= roles  # both configurations present, not merged
    blind = gverify[gverify.role == "blind"].iloc[0]
    # the cautionary cell: confirmed 0 in three reps, 2 in the fourth -> spread 0..2
    assert blind["results.confirmed.min"] == 0
    assert blind["results.confirmed.max"] == 2
    # synthesis claim-count band (the ±3–6 reproducibility) on the blind triage reps
    gtri = s[(s.target == "gitea") & (s.role == "blind") & (s.stage == "triage")].iloc[0]
    assert gtri["results.correlated_findings.min"] >= 10
    assert gtri["results.correlated_findings.max"] <= 17


def test_within_spread_yardstick():
    assert M.within_spread(2, 5) is True
    assert M.within_spread(6, 5) is False
