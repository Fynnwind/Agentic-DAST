"""The remaining result-cuts against the frozen corpus (README #6–#10, SCA, G10)."""

from pathlib import Path

from dast_analyzer import cuts as C


def test_synthesis_recurrence_crosstab_mostly_out_of_scope(index):
    ct = C.recurrence_disposition_crosstab(index).set_index("recurrence")
    # every synthesis sample-count bucket exists (1/5 .. 5/5)
    assert {"1/5", "2/5", "3/5", "4/5", "5/5"} <= set(ct.index)
    # not-attempted (out-of-scope) dominates at every recurrence level — the honest
    # finding: recurrence does not buy a synthesis claim a verification verdict
    assert "not-attempted" in ct.columns
    assert ct["not-attempted"].sum() > ct.drop(columns=["not-attempted"]).to_numpy().sum()


def test_context_removal_does_not_move_dispatch_of_refuted(index):
    ctx = C.context_through_verification(index)
    g = ctx[ctx.target == "gitea"]
    base = g[g.variant == "base"].iloc[0]
    # every codenone/peernone variant still flags exactly the base-refuted set:
    # at the dispatch-candidate level, context removal is not a measurable change
    assert (g["refuted_still_flagged"] == base["base_refuted"]).all()
    assert base["base_refuted"] > 0


def test_noir_seeding_delta_is_direction_reversing(index):
    nd = C.noir_seeding_delta(index).set_index(["target", "arm"])
    # gitea: the raw spider EXPLODES; Noir seeding yields a tighter, smaller tree
    assert nd.loc[("gitea", "crawl"), "alerts_mean"] > nd.loc[("gitea", "seeded"), "alerts_mean"]
    # grafana/cacti: Noir EXPANDS the sparse tree (opposite direction)
    assert nd.loc[("grafana", "seeded"), "urls_mean"] > nd.loc[("grafana", "crawl"), "urls_mean"]
    assert nd.loc[("cacti", "seeded"), "alerts_mean"] > nd.loc[("cacti", "crawl"), "alerts_mean"]


def test_frontier_unparseable_structured_output_failures(index):
    fu = C.frontier_unparseable(index).set_index("run_label")
    # the credit-void first run has no findings
    assert int(fu.loc["gitea-user-blind-frver", "total_unparseable"]) == 0
    # the two clean reruns both show the empty-content / reasoning-channel failures
    for run in ("gitea-user-blind-frver2", "gitea-user-blind-frver3"):
        assert int(fu.loc[run, "empty_content"]) >= 3
        assert int(fu.loc[run, "total_unparseable"]) >= 5
        assert int(fu.loc[run, "tool_outside_enum"]) >= 1  # the hallucinated tool:browser


def test_frontier_measured_adds_no_value_at_large_multiple(index):
    fm = C.frontier_measured(index).set_index("stage")
    # Opus costs 16–37x the default at every stage (SHEET-CATALOG §Sheet 5)
    assert (fm["multiple"] >= 15).all()
    assert fm.loc["verify", "multiple"] >= 30


def test_frontier_cost_projection_anchors_gitea(index):
    proj = C.frontier_cost_projection(index).set_index("target")
    # gitea is the measured anchor -> reproduced (≈ $7.4 full-pass)
    assert abs(proj.loc["gitea", "total"] - 7.42) < 0.2
    # cacti's 342-endpoint screening is the largest single line
    assert proj.loc["cacti", "screening"] == proj["screening"].max()


def test_sca_dast_wordpress_noops(index):
    sca = C.sca_dast_components(index).set_index("target")
    assert int(sca.loc["wordpress", "osv_packages"]) == 0  # no scanned manifest (P4)
    # ZAP's vulnerable-JS-library rule fires where there is client-side JS
    assert int(sca.loc["grafana", "zap_10003_libs"]) >= 1


def test_g10_oob_is_confirmed_and_standalone(data_root):
    rec = C.g10_oob_record(data_root)
    assert rec is not None
    assert rec["result"] == "CONFIRMED"
    assert rec["marker"]["cve"] == "CVE-2022-46169"
    assert "OUTSIDE" in rec["axis"]  # never a pipeline detection
