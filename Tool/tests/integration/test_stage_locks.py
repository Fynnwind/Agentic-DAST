"""Every stage claims a lock, and a busy run directory stops it at the door.

The failure this protects against was observed on 2026-09-02: four
``dast verify <run> --out-suffix hybrid`` processes running at once against one
run directory, racing to write ``verification-hybrid.json``, dispatching
containers at the same target and spending the same key, with no warning.

The refusal itself is driven **from the stages table** — the lock a stage takes
is :meth:`stages.Stage.lock_name`, so a stage added later without a lock fails
here rather than in a night's runs. The mechanics of the lock file are
``tests/unit/test_run_lock.py``.
"""

from __future__ import annotations

import json
import os
import socket

import pytest

from dast_orchestrator import cli
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.stages import scan
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.stages import table as stage_table

RUN_ID = "20260826T212340Z-gitea-60c7a0"

#: What each stage needs in the run directory to get as far as the lock, and the
#: argv that takes it there. The artifacts are minimal but **schema-valid**: a
#: stage reads and validates its inputs (§R5) before it claims the lock, so a
#: placeholder that failed validation would refuse for the wrong reason.
TS = "20260826T212340Z"
_VALID_STUBS = {
    run_paths.ZAP_ALERTS: {"alerts": []},
    run_paths.NOIR_AI_CONTEXT: {"schema_version": 1, "generated_at": TS,
                                "noir_image": "", "source_dir": "", "endpoints": []},
    run_paths.TRIAGE: {
        "schema_version": 1, "run_id": RUN_ID, "generated_at": TS,
        "source": {"target": "", "zap_alerts": "", "ai_context": "", "seed_map": ""},
        "join": {"tiers": [], "seed_map_available": False, "absent_reasons": {}},
        "rescan_table": {"version": 1, "rules": []},
        "summary": {"bundles": 0, "raw_alerts": 0, "findings": 0,
                    "alerts_by_join_tier": {}, "alerts_by_zap_source": {},
                    "deterministic_rescans": 0, "llm_findings_asked": 0,
                    "llm_evaluated_findings": 0, "llm_findings_unanswered": 0,
                    "llm_rescans": 0, "agreement": {}},
        "findings": [], "correlated_findings": [],
    },
}
AT_THE_DOOR = {
    "triage": ((run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT),
                  ["--out-suffix", "hybrid"], "hybrid"),
    "verify": ((run_paths.TRIAGE,), ["--out-suffix", "hybrid"], "hybrid"),
    "report": ((run_paths.TRIAGE,), ["--out-suffix", "hybrid"], "hybrid"),
    "static-analysis": ((), [], ""),
}


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path / "runs"


def _run_dir(data_dir, *basenames):
    layout = run_paths.RunLayout(data_dir, RUN_ID).ensure()
    for name in basenames:
        for suffix in ("", "hybrid"):
            layout.path(name, suffix).write_text(
                json.dumps(_VALID_STUBS.get(name, {})))
    return layout


def _hold(layout, stage: str, suffix: str = "", pid: "int | None" = None):
    """Write a lock as if another process held it — a live pid by default."""
    path = layout.dir / stage_table.STAGES[stage].lock_name(suffix)
    path.write_text(json.dumps({
        "stage": stage, "suffix": suffix,
        "pid": os.getpid() if pid is None else pid,
        "host": socket.gethostname(),
        "started": "2026-09-02T18:04:11+00:00",
        "command": f"dast {stage} {RUN_ID} --out-suffix {suffix}".rstrip(),
    }))
    return path


@pytest.mark.parametrize("name", sorted(AT_THE_DOOR))
def test_a_busy_run_directory_refuses_every_stage(name, data_dir, capsys):
    required, flags, suffix = AT_THE_DOOR[name]
    layout = _run_dir(data_dir, *required)
    _hold(layout, name, suffix)

    stage = stage_table.STAGES[name]
    code = stage.load().main([RUN_ID, "--data-dir", str(data_dir), *flags])

    assert code == run_lock.BUSY_EXIT
    error = capsys.readouterr().err
    assert f"{name} is already running" in error
    assert f"pid {os.getpid()}" in error          # names who, not just "something"
    assert "--force" in error                     # and how to override it


def test_a_lock_left_by_a_dead_process_does_not_block(data_dir, capsys):
    # A run killed with SIGKILL leaves its lock behind; a guard nobody can clear
    # is a wall, and deleting it by hand is what anyone would do anyway. Driven
    # through `verify --dry-run` because it is the one stage that runs to
    # completion without a container, a key or a live target.
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    _hold(layout, "verify", "hybrid", pid=2 ** 22 - 1)  # above every pid_max in use

    code = stage_table.STAGES["verify"].load().main(
        [RUN_ID, "--data-dir", str(data_dir), "--out-suffix", "hybrid", "--dry-run"]
    )

    assert code == 0
    error = capsys.readouterr().err
    assert "stale lock" in error
    assert "verify is already running" not in error


def test_verify_after_triage_may_spend_what_the_run_has_left(data_dir, capsys):
    # The ceiling smoke of 2026-11-02: triage spent $1.27 of a $2.00 run ceiling
    # and verify was left nothing, its earlier spend counted twice.
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    (layout.dir / "run-metrics-triage.json").write_text(json.dumps(
        {"run": RUN_ID, "kind": "triage", "label": "",
         "started_at": "2026-08-26T21:30:00Z", "results": {"cost_usd": 1.27}}))

    code = stage_table.STAGES["verify"].load().main(
        [RUN_ID, "--data-dir", str(data_dir), "--invocation", "llm",
         "--run-max-cost", "2.0", "--stage-max-cost", "-1", "--dry-run"]
    )

    assert code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "cost ceiling: $0.7300 ($1.2700 already spent by this run)" in out


def test_two_suffixes_of_one_stage_are_not_each_others_business(data_dir, capsys):
    # `--out-suffix` exists so a model comparison lives inside one run directory
    # instead of paying for a second scan; locking the directory as a whole would
    # forbid exactly that.
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    _hold(layout, "verify", "qwen")

    code = stage_table.STAGES["verify"].load().main(
        [RUN_ID, "--data-dir", str(data_dir), "--out-suffix", "hybrid", "--dry-run"]
    )

    assert code == 0
    assert "already running" not in capsys.readouterr().err


def test_force_overrides_the_refusal(data_dir, capsys):
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    _hold(layout, "verify", "hybrid")

    code = stage_table.STAGES["verify"].load().main(
        [RUN_ID, "--data-dir", str(data_dir), "--out-suffix", "hybrid",
         "--dry-run", "--force"]
    )

    assert code == 0
    assert "--force: taking over" in capsys.readouterr().err


def test_the_lock_is_gone_once_the_stage_returns(data_dir):
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    lock = layout.dir / stage_table.STAGES["verify"].lock_name("hybrid")

    assert stage_table.STAGES["verify"].load().main(
        [RUN_ID, "--data-dir", str(data_dir), "--out-suffix", "hybrid", "--dry-run"]
    ) == 0

    assert not lock.exists()


def test_scan_claims_before_it_spawns_anything(tmp_path, monkeypatch):
    # `scan` mints its own directory, so it claims the moment the run id exists —
    # which is before Noir, before ZAP, before the first container. If the claim
    # came later this would fail with a connection error to the unreachable
    # daemon instead of the refusal.
    claimed: list[tuple] = []

    def refuse(run_dir, stage, suffix="", force=False):
        claimed.append((stage, suffix, force))
        raise run_lock.Busy("held by someone else")

    monkeypatch.setattr(run_lock, "claim", refuse)
    with pytest.raises(run_lock.Busy):
        scan.run_scan("http://127.0.0.1:1", "key", "http://target-gitea:3000",
                      1, 1, use_noir=False, target_name="gitea", data_dir=tmp_path)

    assert claimed == [("scan", "", False)]


def test_a_held_lock_is_not_recorded_as_an_artifact_of_the_run(data_dir):
    # `RunMetrics.artifacts` answers "what does this run consist of", and it is
    # taken while the stage still holds its lock. Bookkeeping is not an artifact.
    layout = _run_dir(data_dir, run_paths.TRIAGE)
    lock = _hold(layout, "verify", "hybrid")

    names = run_metrics.RunMetrics(RUN_ID, kind="verify").files(data_dir)

    assert lock.name not in names
    assert run_paths.TRIAGE in names


# -- uniformity ------------------------------------------------------------


def test_every_stage_takes_force_and_dast_broadcasts_it():
    # One `dest`, so `dast` reads the five flags as one setting and sends it to
    # every stage of a sequence — see cli.route_flags.
    per_stage = cli.route_flags(["--force"], stage_table.resolve(stage_table.STAGES))
    assert all(fragment == ["--force"] for fragment in per_stage.values())
    assert set(per_stage) == set(stage_table.STAGES)


def test_only_the_stages_with_a_suffix_flag_lock_per_suffix():
    for stage in stage_table.STAGES.values():
        expected = (f".lock-{stage.name}-hybrid" if stage.suffix_flag
                    else f".lock-{stage.name}")
        assert stage.lock_name("hybrid") == expected
