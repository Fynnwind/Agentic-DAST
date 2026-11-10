"""Block-6 (§10) post-corpus spread/timing/catch views.

The §10 run data is USB-backed, not committed (it is 1.2 GB), so these tests
SKIP when the post corpus is absent (a fresh checkout) and run where it is
present. See [[no-committing-large-run-data]] / docs for the policy.
"""

import matplotlib.pyplot as plt
import pytest

from dast_analyzer import figures, spread
from dast_analyzer.selection import default_valid


@pytest.fixture
def post_index(index):
    if default_valid(index, corpus="post").empty:
        pytest.skip("§10 post-corpus not present (run data is USB-backed, not in git)")
    return index


def test_scan_alert_spread_bands(post_index):
    av = spread.scan_alert_spread(post_index).set_index(["target", "pol"])
    assert len(av) == 8
    g = av.loc[("grafana", "blind")]  # near-deterministic scanner
    assert int(g.lo) == 95 and int(g.hi) == 101
    # gitea ceiling is now --reset-target (campaign-8): the snapshot reset tames
    # the spider-coverage nondeterminism that made PERSISTENT gitea swing >5x, so
    # its band is tight like the others (the reset's headline effect, not a bug).
    gc = av.loc[("gitea", "ceiling")]
    assert gc.hi / gc.lo < 3


def test_accumulation_only_gitea_swells(post_index):
    acc = spread.accumulation(post_index)
    gp = acc[(acc.target == "gitea") & (acc["mode"] == "persistent")]["tree"]
    gr = acc[(acc.target == "gitea") & (acc["mode"] == "reset")]["tree"]
    assert len(gp) and len(gr)
    # persistent gitea balloons vs its --reset-target tree ...
    assert gp.max() > 3 * gr.max()
    # ... and the reset tree is flat (byte-identical snapshot each scan).
    assert gr.max() / gr.min() < 1.3
    # the other targets never swell on the scan surface (stay well under gitea's).
    others = acc[acc.target.isin(["wordpress", "grafana"])]["tree"]
    assert others.max() < gp.max()


def test_ceiling_catch_per_target(post_index):
    cat = spread.ceiling_catch(post_index).set_index("target")
    assert cat.loc["grafana", "rate"] == 1.0 and int(cat.loc["grafana", "n"]) == 6
    assert int(cat.loc["wordpress", "hits"]) == 1 and int(cat.loc["wordpress", "n"]) == 6
    # cacti's RCE is verify-confirmed out of band every ceiling run: the nuclei
    # OOB probe lands the interactsh callback (the session cookie is dropped for
    # this UNAUTHENTICATED sink and the DAST fuzz is scoped to its cmdi class, so
    # it confirms inside the tool timeout instead of self-saturating the target).
    assert cat.loc["cacti", "rate"] == 1.0 and int(cat.loc["cacti", "hits"]) == 6


def test_marker_catch_grafana_and_cacti_reproducible(post_index):
    mc = spread.marker_catch(post_index)
    if mc.empty:
        pytest.skip("run `dast cve` over the §10 runs to populate cve-detection.json")
    graf = mc[mc.cve == "CVE-2021-43798"].iloc[0]
    assert int(graf.detected) == int(graf.reached_samples) == 6
    assert graf.catch_rate == 1.0
    # cacti's unauth RCE is strictly detected every ceiling run: ZAP's time-based
    # OS-command-injection rule (90037) fires on remote_agent.php's poller_id sink
    # (injects `;sleep 15;`, confirms via response timing). It is ALSO confirmed
    # out of band — the nuclei OOB probe lands the interactsh callback — so cacti
    # is caught on both channels (ceiling_catch 6/6).
    cacti = mc[mc.cve == "CVE-2022-46169"].iloc[0]
    assert int(cacti.detected) == int(cacti.reached_samples) == 6
    assert cacti.catch_rate == 1.0
    # the wordpress stats SQLi is REACHED but NOT detected at its marker sink,
    # even though a SQLi finding was verify-confirmed once (ceiling_catch 1/6).
    sqli = mc[mc.cve == "CVE-2021-25069"].iloc[0]
    assert int(sqli.reached_samples) == 6 and int(sqli.detected) == 0
    # exactly two markers are reproducibly detected under the oracle: grafana's
    # traversal and cacti's RCE (both detected at their sink and tool-confirmed).
    assert int((mc.catch_rate > 0).sum()) == 2


def test_stage_time_scan_dominates(post_index):
    piv = spread.stage_time(post_index).pivot_table(
        index="target", columns="stage", values="minutes", aggfunc="mean"
    )
    for t in ("grafana", "cacti", "wordpress", "gitea"):
        assert piv.loc[t, "scan"] > piv.loc[t, "triage"]
        assert piv.loc[t, "scan"] > piv.loc[t, "verify"]
    assert piv.loc["grafana", "scan"] < piv.loc["wordpress", "scan"]


def test_total_time_spread_shape(post_index):
    tt = spread.total_time_spread(post_index).set_index(["target", "pol"])
    assert len(tt) == 8
    assert tt.loc[("grafana", "blind"), "mean"] < tt.loc[("wordpress", "blind"), "mean"]


def test_marker_lifecycle_reach_to_strict(post_index):
    lc = spread.marker_lifecycle(post_index)
    if lc.empty:
        pytest.skip("run `dast cve` over the §10 runs to populate cve-detection.json")
    byc = lc.set_index("cve")
    assert (lc["reached"] == 1.0).all()  # the oracle reaches every marker
    assert byc.loc["CVE-2021-43798", "detected"] == 1.0  # grafana strict 6/6
    # cacti's RCE is strictly detected (ZAP time-based rule 90037 on the
    # remote_agent sink) AND tool-confirmed out of band — the nuclei OOB probe
    # lands the interactsh callback — so detected=1.0 and confirmed=1.0.
    cacti = byc.loc["CVE-2022-46169"]
    assert cacti["detected"] == 1.0 and cacti["confirmed"] == 1.0 and cacti["dispatched"] == 1.0
    assert lc["detected"].sum() == 2.0  # grafana + cacti both strictly detected
    # the wordpress SQLi travels to a LOOSE confirm (a rule-class collision) but
    # never a strict detection at its own sink
    sqli = byc.loc["CVE-2021-25069"]
    assert sqli["dispatched"] == 1.0 and 0 < sqli["confirmed"] < 1.0 and sqli["detected"] == 0.0
    # the LLM arm never flags a marker the deterministic table missed (central claim)
    assert (lc["llm"] <= lc["triage_det"]).all()


def test_declutter_funnel(index):
    f = spread.declutter_funnel(index)
    if f.empty:
        pytest.skip("no blind report.md present (full-chain reports needed)")
    assert (f["raw_alerts"] >= f["findings"]).all()  # dedup only reduces the count
    assert "declutter-funnel" in figures.FIGURES
    figures.configure()
    fig = figures.fig_declutter_funnel(index)
    assert fig is not None
    plt.close(fig)


def test_report_ordering_figure_builds(index):
    # data-independent (drawn from report.py's sort logic), so no post-corpus skip
    assert "report-ordering" in figures.FIGURES
    figures.configure()
    fig = figures.fig_report_ordering(index)
    assert fig is not None
    plt.close(fig)


def test_block6_figures_registered_and_build(post_index):
    names = [n for n in figures.FIGURES if n.startswith("campaign6-")]
    assert len(names) == 8
    figures.configure()
    for n in names:
        fig = figures.FIGURES[n](post_index)
        assert fig is not None
        plt.close(fig)
