"""Detection-ladder invariants against the frozen corpus (SHEET-CATALOG §Sheet 1-2)."""

from dast_analyzer.markers import blind_vs_ceiling, ceiling_variance, detection_ladder, marker_table
from dast_analyzer.selection import apply_named


def _scans(index, sel):
    s = apply_named(index, sel)
    return s[s.stage == "scan"]


def test_denominator_is_22_markers(index):
    mt = marker_table(_scans(index, "matrix-blind"), strict=True)
    assert len(mt) == 22
    by_target = dict(mt.groupby("target").size())
    assert by_target == {"grafana": 5, "wordpress": 10, "cacti": 2, "gitea": 5}


def test_blind_detection_zero_everywhere(index):
    ladder = detection_ladder(marker_table(_scans(index, "matrix-blind"), strict=True))
    allrow = ladder[ladder.target == "ALL"].iloc[0]
    for layer in ("scanner", "det_triage", "llm_triage", "verify", "detected"):
        assert int(allrow[layer]) == 0, f"blind {layer} not zero"


def test_ceiling_two_detected_markers_grafana_and_cacti(index):
    mt = marker_table(_scans(index, "matrix-ceiling"), strict=True)
    detected = mt[mt.detected].set_index("target")
    assert set(detected.index) == {"grafana", "cacti"}
    # grafana traversal: scanner + deterministic table (ffuf confirms it), never
    # the LLM arm.
    graf = detected.loc["grafana"]
    assert graf.cve == "CVE-2021-43798"
    assert bool(graf.scanner) and bool(graf.det_triage) and not bool(graf.llm_triage)
    # cacti RCE: detected strict by ZAP's time-based rule 90037 on the remote_agent
    # poller_id sink, flagged by both triage arms, and verify-confirmed out of band.
    # The three ceiling cells were re-verified on 2026-10-25, after cd167d6 closed the
    # OOB gap (RESULTS-campaign.md, "as re-run"); their first verify did not confirm it,
    # refuted at none, timed out at user and admin.
    cacti = detected.loc["cacti"]
    assert cacti.cve == "CVE-2022-46169"
    assert bool(cacti.scanner) and bool(cacti.det_triage) and bool(cacti.llm_triage) and bool(cacti.verify)


def test_llm_layer_never_flags_what_the_table_misses(index):
    # The central claim: the LLM arm's value is not discovery. In neither polarity
    # does it strict-flag a marker the deterministic table did not also flag. On
    # the ceiling it flags exactly one marker — cacti's command injection, which
    # the table flags too — and blind it flags none.
    for sel in ("matrix-blind", "matrix-ceiling"):
        mt = marker_table(_scans(index, sel), strict=True)
        assert (mt["llm_triage"] <= mt["det_triage"]).all()
    assert int(marker_table(_scans(index, "matrix-blind"), strict=True)["llm_triage"].sum()) == 0


def test_ceiling_variance_catch_likelihood(index):
    """Pooling pilot + campaign oracle samples gives a crude per-marker catch rate:
    grafana is reproducible (4/4), cacti's RCE is now caught most ceilings (3/4,
    via ZAP's time-based rule 90037 at its sink), the wordpress frameid XSS
    flickers (1/4), the rest are 0 — the honest answer to 'how likely is a catch'."""
    cv = ceiling_variance(index).set_index("marker_id")
    assert len(cv) == 22  # every marker, pooled

    graf = cv.loc["grafana-plugin-path-traversal"]
    assert int(graf["detected"]) == int(graf["reached_samples"]) == 4
    assert graf["catch_rate"] == 1.0

    cacti = cv.loc["cacti-remote-agent-cmd-injection"]
    assert int(cacti["detected"]) == 3 and int(cacti["reached_samples"]) == 4
    assert cacti["catch_rate"] == 0.75

    xss = cv.loc["wpdm-frameid-reflected-xss"]
    assert int(xss["detected"]) == 1 and int(xss["reached_samples"]) == 4
    assert xss["catch_rate"] == 0.25
    assert int(xss["pilot_samples"]) == 1  # the one catch is the pilot sample

    # three markers now detect under the oracle across all samples
    assert int((cv["detected"] > 0).sum()) == 3


def test_blind_vs_ceiling_shape(index):
    bvc = blind_vs_ceiling(index)
    assert set(bvc["role"]) == {"blind", "ceiling"}
    assert set(bvc[bvc.role == "blind"]["target"]) == {
        "cacti",
        "gitea",
        "grafana",
        "wordpress",
        "ALL",
    }
