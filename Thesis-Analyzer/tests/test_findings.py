"""Two-arm agreement / overlap invariants (SHEET-CATALOG §Sheet 1)."""

from dast_analyzer.findings import finding_overlap, two_arm_matrix
from dast_analyzer.selection import apply_named, default_valid


def test_llm_only_is_zero_in_every_blind_cell(index):
    m = two_arm_matrix(index)
    assert len(m) == 12
    assert int(m["llm-only"].sum()) == 0  # the central claim
    assert (m["llm-only"] == 0).all()


def test_gitea_user_agreement_matches_catalog(index):
    m = two_arm_matrix(index)
    row = m[(m.target == "gitea") & (m.auth == "user")].iloc[0]
    assert int(row["both"]) == 14
    assert int(row["deterministic-only"]) == 12
    assert int(row["neither"]) == 262
    assert int(row["not-evaluated"]) == 649


def test_overlap_of_a_scan_with_itself_is_total(index):
    blind = apply_named(index, "matrix-blind")
    gt = blind[(blind.target == "gitea") & (blind.auth == "user") & (blind.stage == "triage")]
    ov = finding_overlap(gt, gt)
    assert ov["only_a"] == 0 and ov["only_b"] == 0
    assert ov["in_both"] == ov["a_total"] == ov["b_total"]


def test_rescan_repeat_overlaps_base_almost_perfectly(index):
    v = default_valid(index)
    blind = apply_named(index, "matrix-blind")
    base = blind[(blind.target == "gitea") & (blind.auth == "user") & (blind.stage == "triage")]
    rep = v[(v.variant == "rep") & (v.target == "gitea") & (v.stage == "triage") & (v.repeat == 1)]
    ov = finding_overlap(base, rep)
    # same scan, re-triaged: finding-id sets differ by at most a handful
    assert ov["in_both"] >= 930
    assert ov["only_a"] + ov["only_b"] <= 5
