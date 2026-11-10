"""scripts/rerun-chain.py: the rescan's sheets back to back, and when it stops.

Every command goes through an injected runner, so nothing here touches Docker,
a target or the harness. → the script's docstring for the policy under test.
"""

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("rerun_chain", TOOL / "scripts" / "rerun-chain.py")
chain = importlib.util.module_from_spec(_spec)
sys.modules["rerun_chain"] = chain          # dataclasses resolve annotations through it
_spec.loader.exec_module(chain)

T0 = datetime(2026, 11, 3, 8, 0, 0, tzinfo=timezone.utc)


def _names(steps):
    return [step.name for step in steps]


def _sheets(step):
    return [action.sheet for action in step.actions if action.sheet]


# -- the plan ------------------------------------------------------------------

def test_the_plan_runs_the_documented_order():
    assert _names(chain.plan()) == [
        "g1", "g2", "g2-cacti", "repeats", "repeats-cacti", "g4",
        "rewire", "g5", "g6", "g7", "g9"]


def test_every_sheet_the_plan_names_exists():
    for step in chain.plan():
        for sheet in _sheets(step):
            assert (TOOL / chain.HARNESS_DIR / sheet).is_file(), sheet


def test_the_cacti_ceilings_run_one_per_invocation_then_restart():
    steps = {step.name: step for step in chain.plan()}
    g2, band = steps["g2-cacti"], steps["repeats-cacti"]
    assert _sheets(g2) == ["rerun-cacti-ceiling-none.yml", "rerun-cacti-ceiling-user.yml",
                           "rerun-cacti-ceiling.yml"]
    # 3 in the band + G2's admin ceiling = the band's n of 4.
    assert _sheets(band) == ["rerun-cacti-ceiling.yml"] * 3
    for step in (g2, band):
        ceilings = [a for a in step.actions if a.sheet]
        assert all(a.argv[:3] == ["bash", chain.DRIVER, "1"] for a in ceilings)
        assert step.actions[-1] is chain.CACTI_RESTART


def test_every_scanning_step_reclaims_first_and_g5_g6_reset_every_target():
    steps = {step.name: step for step in chain.plan()}
    for name in ("g2", "g2-cacti", "repeats", "repeats-cacti", "g4", "g5"):
        assert steps[name].actions[0].reclaim, name
    for name, sheet in (("g5", "rerun-g5-model-repeats.yml"),
                        ("g6", "rerun-g6-verify-configs.yml")):
        resets = [a.argv[1] for a in steps[name].actions if a.label.startswith("reset ")]
        assert [Path(p).parts[-3] for p in resets] == list(chain.TARGETS), name
        assert steps[name].actions[-1].sheet == sheet
    assert not any(a.reclaim for a in steps["g6"].actions + steps["g7"].actions
                   + steps["g9"].actions)


def test_the_driver_can_restart_cacti_without_running_a_sheet():
    driver = (TOOL / chain.DRIVER).read_text()
    assert '"${1:-}" == "--restart-only"' in driver


def test_from_and_to_select_an_inclusive_slice():
    steps = chain.plan()
    assert _names(chain.select(steps, None, "g1")) == ["g1"]
    assert _names(chain.select(steps, "g6", None)) == ["g6", "g7", "g9"]
    with pytest.raises(SystemExit):
        chain.select(steps, "g9", "g1")
    with pytest.raises(SystemExit):
        chain.select(steps, "g3", None)


# -- running: a fake runner and the results.json the harness would leave ---------

class _Fake:
    """Records commands; a sheet command writes the results it is told to."""

    def __init__(self, data_dir, results=None, codes=None, free_kb=100 * 1024 ** 2):
        self.data_dir, self.results, self.codes = data_dir, results or {}, codes or {}
        self.free_kb, self.ran, self.clock = free_kb, [], T0

    def now(self):
        self.clock += timedelta(minutes=1)
        return self.clock

    def run(self, argv):
        self.ran.append(argv)
        key = next((k for k in self.codes if k in " ".join(argv)), None)
        sheet = next((Path(a).name for a in argv if a.endswith(".yml")), None)
        if sheet in self.results and "--dry-run" not in argv:
            rows = self.results[sheet]
            out = self.data_dir / f"{self.now():%Y%m%dT%H%M%SZ}-{Path(sheet).stem}"
            out.mkdir(parents=True)
            (out / "results.json").write_text(json.dumps({"executions": [
                {"row": f"r{i}", "repeat": 1, "failed_stage": stage, "reason": reason}
                for i, (stage, reason) in enumerate(rows)]}))
            failed = any(stage or reason for stage, reason in rows)
            return self.codes.get(key, 1 if failed else 0)
        return self.codes.get(key, 0)

    def capture(self, argv):
        if argv[:2] == ["docker", "inspect"]:
            return 0, f"/var/lib/docker/containers/{argv[2]}/x-json.log\n"
        return 0, ("Filesystem 1024-blocks Used Available Capacity Mounted\n"
                   f"/dev/vda1 131000000 12000000 {self.free_kb} 10% /\n")


OK_ROW, FAIL_ROW = (None, ""), ("scan", "exited 1")


def _chain(tmp_path, **fake):
    fake = _Fake(tmp_path, **fake)
    lines = []
    return chain.Chain(data_dir=tmp_path, run=fake.run, capture=fake.capture,
                       say=lines.append, now=fake.now), fake, lines


def _steps(*names):
    return [s for s in chain.plan() if s.name in names]


def test_a_clean_chain_runs_every_step_in_order(tmp_path):
    sheets = {s: [OK_ROW] for step in chain.plan() for s in _sheets(step)}
    runner, fake, _lines = _chain(tmp_path, results=sheets)
    assert runner.execute(chain.plan()) == 0
    harness = [a[-1] for a in fake.ran if a[:4] == ["uv", "run", "dast", "harness"]]
    assert [Path(p).name for p in harness] == [
        "rerun-g1-blind-matrix.yml", "rerun-g2-ceiling-matrix.yml",
        "rerun-repeats.yml", "rerun-g4-crawl.yml", "rerun-g5-model-repeats.yml",
        "rerun-g6-verify-configs.yml", "rerun-g7-context.yml", "rerun-g9-static.yml"]
    assert sum(1 for a in fake.ran if a[:3] == ["bash", chain.DRIVER, "1"]) == 6
    assert fake.ran.index(next(a for a in fake.ran if "rerun-rewire-refs.py" in a[-1])) \
        < fake.ran.index(next(a for a in fake.ran if a[-1].endswith("g5-model-repeats.yml")))


def test_one_failed_row_is_recorded_for_a_top_up_and_the_chain_goes_on(tmp_path):
    runner, fake, lines = _chain(tmp_path, results={
        "rerun-g1-blind-matrix.yml": [OK_ROW, FAIL_ROW, OK_ROW],
        "rerun-g2-ceiling-matrix.yml": [OK_ROW]})
    assert runner.execute(_steps("g1", "g2")) == 1
    assert any(a[-1].endswith("rerun-g2-ceiling-matrix.yml") for a in fake.ran)
    assert any("rows to top up" in line for line in lines)


def test_a_step_whose_every_row_failed_stops_the_chain(tmp_path):
    # The 2026-10-30 full-disk launch: 35 of 35 rows failed at scan.
    runner, fake, lines = _chain(tmp_path, results={
        "rerun-g1-blind-matrix.yml": [FAIL_ROW] * 3,
        "rerun-g2-ceiling-matrix.yml": [OK_ROW]})
    assert runner.execute(_steps("g1", "g2")) == 2
    assert not any(a[-1].endswith("rerun-g2-ceiling-matrix.yml") for a in fake.ran)
    assert any("resume with --from g1" in line for line in lines)


def test_one_failed_cacti_ceiling_in_a_group_goes_on_but_all_three_stop(tmp_path):
    flaky = {"rerun-cacti-ceiling-none.yml": [FAIL_ROW],
             "rerun-cacti-ceiling-user.yml": [OK_ROW], "rerun-cacti-ceiling.yml": [OK_ROW]}
    runner, _fake, _lines = _chain(tmp_path, results=flaky)
    assert runner.execute(_steps("g2-cacti")) == 1

    dead = {sheet: [FAIL_ROW] for sheet in flaky}
    runner, fake, _lines = _chain(tmp_path / "dead", results=dead)
    assert runner.execute(_steps("g2-cacti", "repeats")) == 2
    assert not any(a[-1].endswith("rerun-repeats.yml") for a in fake.ran)


def test_a_cacti_restart_that_never_reaches_its_sheet_stops_and_says_what_is_left(tmp_path):
    # The driver exits 1 before the harness runs: no results.json since it began.
    runner, fake, lines = _chain(tmp_path, results={
        "rerun-cacti-ceiling-none.yml": [OK_ROW]},
        codes={"rerun-cacti-ceiling-user.yml": 1})
    assert runner.execute(_steps("g2-cacti")) == 2
    assert not any("rerun-cacti-ceiling.yml" in " ".join(a) for a in fake.ran)
    tail = "\n".join(lines[lines.index(next(l for l in lines if "finish this step" in l)):])
    assert "rerun-cacti-ceiling-user.yml" in tail and "--restart-only" in tail


def test_a_sheet_that_reached_its_cost_ceiling_stops(tmp_path):
    runner, _fake, _lines = _chain(tmp_path, results={
        "rerun-g1-blind-matrix.yml": [OK_ROW, (None, "sheet cost ceiling ($8.0000)")]})
    assert runner.execute(_steps("g1", "g2")) == 2


def test_a_sheet_that_does_not_load_stops(tmp_path):
    runner, _fake, _lines = _chain(tmp_path, codes={"rerun-g1-blind-matrix.yml": 2})
    assert runner.execute(_steps("g1")) == 2


def test_a_failing_step_between_sheets_stops(tmp_path):
    runner, fake, _lines = _chain(tmp_path, codes={"rerun-rewire-refs.py": 1},
                                  results={"rerun-g6-verify-configs.yml": [OK_ROW]})
    assert runner.execute(_steps("rewire", "g6")) == 2
    assert not any("reset.sh" in " ".join(a) for a in fake.ran)


def test_the_reclaim_truncates_every_target_log_and_recreates_zap(tmp_path):
    runner, fake, _lines = _chain(tmp_path, results={"rerun-g4-crawl.yml": [OK_ROW]})
    assert runner.execute(_steps("g4")) == 0
    truncated = [a[-1] for a in fake.ran if "truncate" in a]
    assert [Path(p).parts[-2] for p in truncated] == list(chain.TARGET_CONTAINERS)
    assert chain.ZAP_RECREATE in fake.ran
    assert fake.ran.index(chain.ZAP_RECREATE) < len(fake.ran) - 1   # before the sheet


def test_too_little_free_disk_after_the_reclaim_stops_before_the_sheet(tmp_path):
    runner, fake, lines = _chain(tmp_path, free_kb=10 * 1024 ** 2,
                                 results={"rerun-g4-crawl.yml": [OK_ROW]})
    assert runner.execute(_steps("g4")) == 2
    assert not any(a[-1].endswith("rerun-g4-crawl.yml") for a in fake.ran)
    assert any("10.0 GB free" in line for line in lines)


def test_a_dry_run_runs_each_sheets_own_dry_run_and_touches_no_container(tmp_path):
    runner, fake, _lines = _chain(tmp_path)
    assert runner.execute(chain.plan(), dry_run=True) == 0
    assert all(a[-1] == "--dry-run" for a in fake.ran)
    assert not any(a[0] in ("docker", "bash") for a in fake.ran)
    sheets = {Path(a[-2]).name for a in fake.ran}
    assert sheets == {s for step in chain.plan() for s in _sheets(step)}
