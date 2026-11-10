"""The Automation Framework driving mode: finding a plan, hashing it, delivering it.

`rest` stays the default and the proven path. This mode exists because a YAML
plan is how ZAP is normally driven in CI, and because a plan written in ZAP's
own GUI can be handed to someone who knows nothing about this codebase.
"""

from __future__ import annotations

import hashlib

import pytest

from dast_orchestrator.adapters import zap_plan


def _target(tmp_path, name="demo", body="jobs: []\n"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / zap_plan.PLAN_BASENAME).write_text(body)
    return d


def test_a_target_can_ship_its_own_plan(tmp_path):
    """A plan beside the target's other data is used without being named."""
    _target(tmp_path)
    found = zap_plan.plan_for_target("demo", tmp_path)
    assert found is not None and found.name == zap_plan.PLAN_BASENAME
    assert zap_plan.plan_for_target("nosuch", tmp_path) is None


def test_an_explicitly_named_plan_wins_over_the_target_s(tmp_path):
    _target(tmp_path, body="jobs: [{type: spider}]\n")
    other = tmp_path / "other.yml"
    other.write_text("jobs: [{type: activeScan}]\n")
    assert zap_plan.resolve_plan(other, "demo", tmp_path) == other


def test_naming_a_plan_that_does_not_exist_is_an_error(tmp_path):
    """Not a fall-through to the target's.

    Naming a plan is a statement about how this run should be driven, so
    quietly running a different one would be the worst available answer.
    """
    _target(tmp_path)
    with pytest.raises(zap_plan.PlanError, match="no automation plan at"):
        zap_plan.resolve_plan(tmp_path / "absent.yml", "demo", tmp_path)


def test_the_plan_is_hashed_by_its_bytes(tmp_path):
    """Plans are not versioned, so the hash is what ties a result to a file.

    Bytes rather than parsed YAML: the question is "is this the same file that
    produced that run", and a reformat that changes nothing semantically still
    changes the file a reader is holding.
    """
    d = _target(tmp_path, body="jobs: []\n")
    path = d / zap_plan.PLAN_BASENAME
    assert zap_plan.plan_digest(path) == hashlib.sha256(b"jobs: []\n").hexdigest()

    path.write_text("jobs:  []\n")          # semantically identical, different bytes
    assert zap_plan.plan_digest(path) != hashlib.sha256(b"jobs: []\n").hexdigest()


def test_a_failed_delivery_says_which_container(tmp_path, monkeypatch):
    """A plan that never reached the daemon must not look like one that ran."""
    import subprocess

    class _Failed:
        returncode = 1
        stdout = ""
        stderr = "No such container: dast-zap"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Failed())
    with pytest.raises(zap_plan.PlanError, match="dast-zap"):
        zap_plan.deliver(tmp_path / "plan.yml", "dast-zap")
