"""CVE ground truth: marker loading (FACTS + auth), the MEASURED single-run
assessment (reach/observe → outcome), and the two-run blind-vs-oracle ladder.

The load-bearing shift (docs/DETECTABILITY.md): detectability is measured, never
asserted. A marker carries facts only — its one detection-adjacent field is
``auth`` (the session the CVE requires), because a run below it is
``not-applicable (auth)``, not a miss. The strict/generous ZAP join is kept as the
observe signal and the per-layer breakdown.
"""

from __future__ import annotations

import json

import pytest

from dast_orchestrator.foundation import run_paths
from dast_orchestrator.stages import ground_truth as gt


def _marker(**kw):
    base = dict(
        id="m", name="m", cve="", fixed_in="", description="", cwe="",
        zap_rules=(), probe_method="GET", probe_path="/", expect_status=(),
        signal="", auth="none",
    )
    base.update(kw)
    return gt.Marker(**base)


# -- marker loading: facts + the auth fact ----------------------------------


def test_every_target_loads_with_an_auth_fact():
    expected_counts = {"gitea": 5, "wordpress": 10, "grafana": 5, "cacti": 2}
    for name, n in expected_counts.items():
        ms = gt.MarkerSet.load(name)
        assert len(ms.markers) == n
        for m in ms.markers:
            assert m.auth in gt.AUTH_RANK, f"{name}/{m.id} bad auth {m.auth!r}"


def test_the_auth_facts_match_the_cve_requirements():
    gitea = {m.id: m.auth for m in gt.MarkerSet.load("gitea").markers}
    assert gitea["storage-path-traversal"] == "none"
    assert gitea["open-redirect-login"] == "user"
    wp = {m.id: m.auth for m in gt.MarkerSet.load("wordpress").markers}
    assert wp["wpdm-frameid-reflected-xss"] == "none"
    assert wp["wpdm-stats-user-package-ids-sqli"] == "admin"
    cacti = {m.id: m.auth for m in gt.MarkerSet.load("cacti").markers}
    assert cacti["cacti-remote-agent-cmd-injection"] == "none"
    assert cacti["cacti-snmp-options-cmd-injection"] == "admin"


def test_an_unknown_auth_value_is_rejected(tmp_path, monkeypatch):
    bad = tmp_path / "bad" / "cve-markers.yml"
    bad.parent.mkdir(parents=True)
    bad.write_text(
        'target: bad\nversion: "1"\nmarkers:\n  - id: m\n    cve: X\n'
        '    auth: superuser\n    zap_rules: []\n    probe:\n      path: /\n')
    monkeypatch.setattr(gt, "markers_path", lambda _n: bad)
    with pytest.raises(ValueError, match="auth"):
        gt.MarkerSet.load("bad")


def test_the_seed_must_land_at_the_markers_sink(tmp_path, monkeypatch):
    bad = tmp_path / "bad" / "cve-markers.yml"
    bad.parent.mkdir(parents=True)
    bad.write_text(
        'target: bad\nversion: "1"\nmarkers:\n  - id: m\n    cve: X\n'
        '    zap_rules: []\n    seed: ["/somewhere-else"]\n'
        '    probe:\n      path: /the/sink\n')
    monkeypatch.setattr(gt, "markers_path", lambda _n: bad)
    with pytest.raises(ValueError, match="not at this"):
        gt.MarkerSet.load("bad")


def test_oracle_seeds_are_every_markers_seed_deduped():
    seeds = gt.MarkerSet.load("grafana").oracle_seeds()
    assert "/public/plugins/prometheus/plugin.json" in seeds
    assert len(seeds) == len(set(seeds))


# -- the measured links: reach × observe → outcome --------------------------


def test_detected_is_reached_and_observed():
    m = _marker(zap_rules=("40018",), probe_path="/x")
    r = gt.assess_marker(m, [{"pluginId": "40018", "url": "http://t/x"}], {}, {})
    assert r["reach"] == gt.REACH_REACHED
    assert r["observe"] == gt.OBSERVE_IN_BAND
    assert r["outcome"] == gt.OUTCOME_DETECTED


def test_reached_but_unobserved_is_reached_unconfirmed():
    m = _marker(zap_rules=(), probe_path="/x")   # no rule can fire → no observe
    r = gt.assess_marker(m, [], {}, {},
                         reach_paths=frozenset({"http://t/x"}))
    assert r["reach"] == gt.REACH_REACHED
    assert r["observe"] == gt.OBSERVE_NONE
    assert r["outcome"] == gt.OUTCOME_REACHED_UNCONFIRMED


def test_unreached_when_the_sink_is_in_no_tree():
    m = _marker(zap_rules=("40018",), probe_path="/x")
    r = gt.assess_marker(m, [], {}, {}, reach_paths=frozenset({"http://t/other"}))
    assert r["reach"] == gt.REACH_NONE
    assert r["outcome"] == gt.OUTCOME_UNREACHED


def test_auth_above_the_run_is_not_applicable_never_unreached():
    m = _marker(auth="admin", zap_rules=("40018",), probe_path="/x")
    # Even reached+observed, a run below the marker's auth is not-applicable.
    r = gt.assess_marker(m, [{"pluginId": "40018", "url": "http://t/x"}], {}, {},
                         run_auth_mode="user")
    assert r["outcome"] == gt.OUTCOME_NOT_APPLICABLE
    assert r["not_applicable_reason"] == "auth"
    # ...and it is applicable once the run provides the auth.
    ok = gt.assess_marker(m, [{"pluginId": "40018", "url": "http://t/x"}], {}, {},
                          run_auth_mode="admin")
    assert ok["outcome"] == gt.OUTCOME_DETECTED


def test_an_out_of_band_confirmation_is_observe_oob():
    m = _marker(zap_rules=("90020",), probe_path="/remote_agent.php")
    verification = {"verifications": [
        {"plugin_id": "90020", "outcome": "confirmed",
         "target": "http://t/remote_agent.php", "tool": "nuclei",
         "detail": "interactsh callback landed"},
    ]}
    r = gt.assess_marker(m, [], {}, verification)
    assert r["observe"] == gt.OBSERVE_OOB
    assert r["outcome"] == gt.OUTCOME_DETECTED


# -- the strict / generous ZAP join (the observe signal, kept) --------------


def test_the_generous_join_is_an_upper_bound_and_strict_catches_collisions():
    m = _marker(zap_rules=("10031",), probe_path="/downloads/?skw=x")
    alerts = [{"pluginId": "10031", "url": "http://t/downloads/?order=asc",
               "param": "order"}]
    r = gt.assess_marker(m, alerts, {}, {})
    assert r["zap_detected"] is True            # generous: class fired
    assert r["zap_detected_strict"] is False    # but on the wrong parameter
    # A collision is not an observation: no strict hit → not detected.
    assert r["observe"] == gt.OBSERVE_NONE


def test_a_traversal_marker_is_strict_detected_under_its_seed_base():
    m = _marker(
        zap_rules=("6",),
        probe_path="/public/plugins/prometheus/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    alerts = [{"pluginId": "6",
               "url": "http://t/public/plugins/prometheus/../../etc/passwd",
               "param": ""}]
    r = gt.assess_marker(m, alerts, {}, {})
    assert r["zap_detected"] and r["zap_detected_strict"]
    assert r["outcome"] == gt.OUTCOME_DETECTED


def test_a_trailing_slash_is_not_a_different_route():
    m = _marker(zap_rules=("6",), probe_path="/downloads/")
    alerts = [{"pluginId": "6", "url": "http://t/downloads", "param": ""}]
    assert gt.assess_marker(m, alerts, {}, {})["zap_detected_strict"] is True


def test_every_layer_carries_both_bounds():
    m = _marker(zap_rules=("40018",), probe_path="/sign-in/?x=1")
    correlation = {"findings": [
        {"alert": {"plugin_id": "40018", "param": "permalink",
                   "example_urls": ["http://t/sign-in/?permalink=1"]},
         "deterministic": {"needs_rescan": True}, "llm": {"needs_rescan": True}},
    ]}
    verification = {"verifications": [
        {"plugin_id": "40018", "outcome": "confirmed",
         "target": "http://t/sign-in/?permalink=1", "param": "permalink"},
    ]}
    r = gt.assess_marker(m, [], correlation, verification)
    assert r["deterministic_flagged"] and not r["deterministic_flagged_strict"]
    assert r["llm_flagged"] and not r["llm_flagged_strict"]
    assert r["verification_confirmed"] and not r["verification_confirmed_strict"]


# -- the single-run table ---------------------------------------------------


def test_single_run_table_groups_by_outcome():
    assessments = [
        {"marker_id": "d", "outcome": gt.OUTCOME_DETECTED, "observe": "in-band",
         "reach": "reached"},
        {"marker_id": "r", "outcome": gt.OUTCOME_REACHED_UNCONFIRMED,
         "observe": "none", "reach": "reached"},
        {"marker_id": "u", "outcome": gt.OUTCOME_UNREACHED, "observe": "none",
         "reach": "none"},
        {"marker_id": "n", "outcome": gt.OUTCOME_NOT_APPLICABLE, "observe": "none",
         "reach": "none"},
    ]
    t = gt.single_run_table(assessments)
    assert t["markers_total"] == 4
    assert t["by_outcome"] == {"detected": 1, "reached-unconfirmed": 1,
                               "unreached": 1, "not-applicable": 1}
    assert t["outcomes"]["detected"] == ["d"]
    assert t["reached"] == 2


# -- the two-run comparison -------------------------------------------------


def _assessment(oracle, markers):
    return {"target": "t", "run_id": ("o" if oracle else "b"),
            "oracle_guided": oracle, "auth_mode": "none", "markers": markers}


def _m(mid, outcome, reach="reached"):
    return {"marker_id": mid, "outcome": outcome, "reach": reach}


def test_compare_splits_blind_from_seeded():
    blind = _assessment(False, [
        _m("a", gt.OUTCOME_DETECTED),
        _m("b", gt.OUTCOME_UNREACHED, reach="none"),
        _m("c", gt.OUTCOME_REACHED_UNCONFIRMED),
        _m("d", gt.OUTCOME_UNREACHED, reach="none"),
    ])
    oracle = _assessment(True, [
        _m("a", gt.OUTCOME_DETECTED),
        _m("b", gt.OUTCOME_DETECTED),        # found only when seeded
        _m("c", gt.OUTCOME_REACHED_UNCONFIRMED),
        _m("d", gt.OUTCOME_UNREACHED, reach="none"),
    ])
    ladder = gt.compare_runs(blind, oracle)["ladder"]
    assert ladder[gt.LADDER_DETECTED_BLIND] == ["a"]
    assert ladder[gt.LADDER_DETECTED_SEEDED] == ["b"]
    assert ladder[gt.LADDER_REACHED_UNCONFIRMED] == ["c"]
    assert ladder[gt.LADDER_UNREACHED] == ["d"]


def test_compare_rates_and_not_applicable():
    blind = _assessment(False, [
        _m("a", gt.OUTCOME_DETECTED),
        _m("b", gt.OUTCOME_NOT_APPLICABLE, reach="none"),
    ])
    oracle = _assessment(True, [
        _m("a", gt.OUTCOME_DETECTED),
        _m("b", gt.OUTCOME_NOT_APPLICABLE, reach="none"),
    ])
    result = gt.compare_runs(blind, oracle)
    assert result["blind_rate"] == 0.5
    assert result["ceiling_rate"] == 0.5
    assert result["not_applicable"] == ["b"]


# -- assess_run: the written single-run artifact ----------------------------


def test_assess_run_writes_the_single_run_shape(tmp_path):
    rid = "20260101T000000Z-gitea-aaaaaa"
    layout = run_paths.RunLayout(tmp_path, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text(
        '{"alerts": [], "auth_mode": "user"}')
    layout.path(run_paths.TRIAGE).write_text('{"findings": [], "oracle_guided": false}')
    layout.path(run_paths.VERIFICATION).write_text('{"verifications": []}')
    result = gt.assess_run(gt.MarkerSet.load("gitea"), layout)
    assert result["schema_version"] == 3
    assert result["oracle_guided"] is False
    assert result["auth_mode"] == "user"
    assert set(result["summary"]["by_outcome"]) == set(gt.OUTCOMES)
    # gitea's admin/user markers vs a user run: nothing above user, so none
    # not-applicable; the two user markers are applicable.
    nas = result["summary"]["outcomes"]["not-applicable"]
    assert nas == []


def test_assess_run_marks_admin_markers_not_applicable_on_an_anon_run(tmp_path):
    rid = "20260101T000000Z-cacti-aaaaaa"
    layout = run_paths.RunLayout(tmp_path, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text(
        '{"alerts": [], "auth_mode": "none"}')
    layout.path(run_paths.TRIAGE).write_text('{"findings": []}')
    layout.path(run_paths.VERIFICATION).write_text('{"verifications": []}')
    result = gt.assess_run(gt.MarkerSet.load("cacti"), layout)
    outcomes = {m["marker_id"]: m["outcome"] for m in result["markers"]}
    assert outcomes["cacti-snmp-options-cmd-injection"] == gt.OUTCOME_NOT_APPLICABLE


def test_a_missing_triage_or_verification_artifact_warns(tmp_path, capsys):
    rid = "20260101T000000Z-wordpress-aaaaaa"
    layout = run_paths.RunLayout(tmp_path, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text(
        '{"alerts": [], "auth_mode": "user"}')
    gt.assess_run(gt.MarkerSet.load("wordpress"), layout)
    err = " ".join(capsys.readouterr().err.split())
    assert "triage" in err and "verification" in err and "NOT MEASURED" in err


# -- ground truth is OPTIONAL -----------------------------------------------


def test_has_markers_reports_presence():
    assert gt.has_markers("gitea")
    assert not gt.has_markers("no-such-target")


def test_assess_no_ops_on_a_markerless_target(tmp_path, monkeypatch):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    runs = run_paths.default_runs_dir(tmp_path)
    rid = "20260101T000000Z-nomarkers-aaaaaa"
    layout = run_paths.RunLayout(runs, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text('{"alerts": []}')
    rc = gt.main([rid])
    assert rc == 0
    assert not layout.path(run_paths.CVE_DETECTION).is_file()


# -- resolving run ids across the data layout -------------------------------


def _write_run(data_dir, rid, oracle=False, auth="none"):
    layout = run_paths.RunLayout(data_dir, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text(
        json.dumps({"alerts": [], "auth_mode": auth}))
    layout.path(run_paths.TRIAGE).write_text(
        json.dumps({"findings": [], "oracle_guided": oracle}))
    layout.path(run_paths.VERIFICATION).write_text('{"verifications": []}')
    return layout


def test_resolve_run_anywhere_searches_runs_and_harness(tmp_path, monkeypatch):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    _write_run(run_paths.default_runs_dir(tmp_path), "20260101T000000Z-gitea-aaaaaa")
    sheet = tmp_path / run_paths.HARNESS_DIR_NAME / "20260101T000000Z-sheet"
    _write_run(sheet, "20260102T000000Z-gitea-bbbbbb")
    assert gt.resolve_run_anywhere("20260101T000000Z-gitea-aaaaaa") is not None
    assert gt.resolve_run_anywhere("20260102T000000Z-gitea-bbbbbb") is not None
    assert gt.resolve_run_anywhere("nope") is None


def test_a_target_name_is_rejected_as_a_run_id(capsys):
    assert gt.main(["gitea"]) == 1
    assert "target name" in capsys.readouterr().err


# -- the two-run command path -----------------------------------------------


def test_two_same_polarity_runs_are_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    runs = run_paths.default_runs_dir(tmp_path)
    _write_run(runs, "20260101T000000Z-gitea-aaaaaa", oracle=False)
    _write_run(runs, "20260102T000000Z-gitea-bbbbbb", oracle=False)
    rc = gt.main(["20260101T000000Z-gitea-aaaaaa", "20260102T000000Z-gitea-bbbbbb"])
    assert rc == 1
    assert "both runs are blind" in capsys.readouterr().err


def test_a_blind_oracle_pair_prints_the_ladder(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    runs = run_paths.default_runs_dir(tmp_path)
    blind = _write_run(runs, "20260101T000000Z-gitea-aaaaaa", oracle=False)
    orc = _write_run(runs, "20260102T000000Z-gitea-bbbbbb", oracle=True)
    rc = gt.main([blind.run_id, orc.run_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ladder" in out.lower()
    # both wrote their single-run artifact
    assert blind.path(run_paths.CVE_DETECTION).is_file()
    assert orc.path(run_paths.CVE_DETECTION).is_file()


# -- the flipped-counterpart reconstruction ---------------------------------


def test_flip_argv_reproduces_scan_config_and_toggles_oracle(tmp_path, monkeypatch):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    runs = run_paths.default_runs_dir(tmp_path)
    rid = "20260101T000000Z-gitea-aaaaaa"
    layout = run_paths.RunLayout(runs, rid).ensure()
    layout.path(run_paths.metrics_basename("scan")).write_text(json.dumps({
        "config": {"auth_mode": "user", "use_noir": True,
                   "max_scan_minutes": 45, "spiders": "traditional,client",
                   "injectable_targets": 19, "disabled_rules": ["10104"]}}))
    # A blind run flips ON.
    argv = gt._flip_argv(layout, oracle_guided=False)
    assert argv[:4] == ["scan", "triage", "verify", "gitea"]
    assert "--oracle" in argv
    assert "--auth" in argv and "user" in argv
    assert "--use-noir" in argv
    assert "--disable-rule" in argv and "10104" in argv
    # An oracle run flips OFF.
    assert "--oracle" not in gt._flip_argv(layout, oracle_guided=True)


def test_one_run_auto_runs_the_flipped_counterpart(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_paths, "DATA_ROOT", tmp_path)
    runs = run_paths.default_runs_dir(tmp_path)
    source = _write_run(runs, "20260101T000000Z-gitea-aaaaaa", oracle=False)
    source.path(run_paths.metrics_basename("scan")).write_text(
        json.dumps({"config": {"auth_mode": "none"}}))

    # The flip is live; stub cli.main to mint the --oracle counterpart instead.
    import dast_orchestrator.cli as cli

    def fake_chain(argv):
        assert "--oracle" in argv            # a blind source flips on
        _write_run(runs, "20260102T000000Z-gitea-bbbbbb", oracle=True)
        return 0

    monkeypatch.setattr(cli, "main", fake_chain)
    rc = gt.main([source.run_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ladder" in out.lower()
    assert source.path(run_paths.CVE_DETECTION).is_file()


@pytest.mark.parametrize("target", ["gitea", "wordpress", "grafana", "cacti"])
def test_every_oracle_seed_reaches_zap_as_a_url_it_accepts(target):
    # A seed ZAP refuses is skipped with a warning and its sink never enters the
    # tree: WordPress's package_ids[] seed was, in every ceiling until 2026-11-02.
    import re

    from dast_orchestrator.adapters.noir_runner import SeedRequest

    for path in gt.MarkerSet.load(target).oracle_seeds():
        url = SeedRequest("GET", "http://target" + path, "oracle").url
        assert not re.search(r"[\[\]{}|\\^`<>\" ]|%(?![0-9A-Fa-f]{2})", url), url
