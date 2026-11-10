"""Index-build invariants, asserted against the frozen corpus (commit bc30e8d)."""

from dast_analyzer.selection import apply_named, default_valid


def test_total_and_stage_breakdown(valid):
    # 234 canonical campaign stage executions across the five blocks.
    assert len(valid) == 234
    stages = dict(valid["stage"].value_counts())
    assert stages == {"verify": 88, "triage": 82, "scan": 40, "report": 20, "analysis": 4}


def test_false_starts_and_pilot_excluded(index):
    v = default_valid(index)
    assert (v["campaign"] == "pilot").sum() == 0
    assert v["launch_complete"].all()
    assert not v["aborted"].any()
    # the four abandoned campaign-1 launches contribute no valid rows
    assert (v["sheet"] == "campaign-1-blind-matrix").sum() == 48  # 12 cells x 4 stages


def test_blind_matrix_is_twelve_cells(index):
    mb = apply_named(index, "matrix-blind")
    cells = mb.groupby(["target", "auth"]).ngroups
    assert cells == 12
    # each cell ran scan, triage, verify, report exactly once
    per = mb.groupby(["target", "auth"])["stage"].apply(lambda s: sorted(set(s)))
    assert all(p == ["report", "scan", "triage", "verify"] for p in per)


def test_ceiling_matrix_twelve_cells_STV(index):
    mc = apply_named(index, "matrix-ceiling")
    assert mc.groupby(["target", "auth"]).ngroups == 12
    assert set(mc["stage"]) == {"scan", "triage", "verify"}  # no report at ceiling


def test_reference_cell_has_three_scan_repeats(index):
    ref = apply_named(index, "reference-scans")
    for t in ("gitea", "wordpress", "grafana", "cacti"):
        reps = sorted(ref[ref.target == t]["repeat"].dropna().tolist())
        assert reps == [1, 2, 3], f"{t}: {reps}"


def test_crawl_has_two_repeats_per_target(index):
    crawl = apply_named(index, "crawl")
    scans = crawl[crawl.stage == "scan"]
    for t in ("gitea", "wordpress", "grafana", "cacti"):
        assert sorted(scans[scans.target == t]["repeat"].dropna()) == [1, 2]


def test_minting_repeats_never_exceed_three(valid):
    minting = valid[valid["variant"] == ""]
    assert int(minting["repeat"].max()) == 3


def test_g9_analysis_targets_backfilled(valid):
    a = valid[valid.stage == "analysis"]
    assert len(a) == 4
    assert set(a["target"]) == {"gitea", "wordpress", "grafana", "cacti"}
    assert a["direct_run"].all()


def test_names_consistent_with_config(valid):
    parsed = valid[valid["name_parsed"]]
    assert parsed["name_consistent"].all()


def test_frontier_selections(index):
    assert set(apply_named(index, "frontier-verification")["variant"]) == {
        "frver",
        "frver2",
        "frver3",
    }
    assert len(apply_named(index, "frontier-screening")) == 1


def test_corpus_split_keeps_campaign6_out_of_the_frozen_corpus(index):
    """campaign-6 (§10 spread, later commit) must not leak into frozen tables."""
    from dast_analyzer.selection import FROZEN_CORPUS_SHEETS, POST_CORPUS_SHEETS

    frozen = default_valid(index)  # default scope
    post = default_valid(index, corpus="post")
    both = default_valid(index, corpus="all")
    assert not frozen["sheet"].isin(POST_CORPUS_SHEETS).any()
    assert post["sheet"].isin(POST_CORPUS_SHEETS).all()
    assert frozen.index.intersection(post.index).empty
    # "all" holds both scopes; what is in neither sits on a sheet neither list names
    rest = both.drop(frozen.index.union(post.index))
    assert not rest["sheet"].isin(FROZEN_CORPUS_SHEETS | POST_CORPUS_SHEETS).any()
    # the designed §10 repeats exist and exceed the frozen 3-rep reference cell
    reps = post[post.stage == "scan"].groupby(["target", "role"]).size()
    assert int(reps.max()) >= 6


def test_frozen_scope_admits_only_what_it_names(index):
    """The rescan and later one-offs share the data tree, not the frozen tables."""
    from dast_analyzer.selection import FROZEN_DIRECT_RUNS

    frozen = default_valid(index)
    sheets = frozen["sheet"].fillna("")
    assert not sheets.str.startswith("rerun-").any()
    assert not sheets.isin({"smoke", "wp-admin-ceiling-oneoff"}).any()
    assert set(frozen.loc[sheets == "", "run"]) == FROZEN_DIRECT_RUNS
    # a sheet nobody registered stays out by default and still shows under "all"
    later = index.assign(sheet="some-later-sheet")
    assert set(default_valid(later)["run"]) == FROZEN_DIRECT_RUNS
    assert len(default_valid(later, corpus="all")) == len(default_valid(index, corpus="all"))
