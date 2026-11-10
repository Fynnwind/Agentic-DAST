"""The Noir-source guardrail: a foreign source tree is surfaced, not silent.

Measured 2026-09-09: a `dast wordpress` run with a stale `SCAN_NOIR_SOURCE_DIR=gitea-src`
in the shell resolved Noir's source to the gitea tree — a real env var outranks
the target's own `source_dir` by design — and nothing warned. Had the path
existed, a wordpress run id would have carried gitea's static analysis. These
pin the check that ends that silence.
"""

from __future__ import annotations

from pathlib import Path

from dast_orchestrator.stages import scan
from dast_orchestrator.adapters import targets


def test_the_targets_own_tree_is_not_foreign():
    assert scan.source_is_foreign(targets.TARGETS_DIR / "wordpress" / "src",
                                  "wordpress") is False


def test_another_targets_tree_is_foreign():
    # The gitea tree under a wordpress run — the exact cross-target mismatch.
    assert scan.source_is_foreign(targets.TARGETS_DIR / "gitea" / "src",
                                  "wordpress") is True


def test_a_bare_relative_override_is_foreign(monkeypatch, tmp_path):
    # `SCAN_NOIR_SOURCE_DIR=gitea-src` resolves against the cwd, nowhere near the
    # target's directory — the literal value from the reported incident.
    monkeypatch.chdir(tmp_path)
    assert scan.source_is_foreign("gitea-src", "wordpress") is True


def test_a_nonexistent_path_is_still_judged_by_location():
    # The check is about WHERE the tree is, not whether it exists — the missing
    # path is noir_runner's error to raise, this is the earlier warning.
    assert scan.source_is_foreign(targets.TARGETS_DIR / "gitea" / "src-missing",
                                  "wordpress") is True
