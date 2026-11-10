"""The triage gate: code context that locates no endpoint's handler refuses the run.

A run with code context on but no handler located would record a level it never
had, so it is refused before anything is sent; a partial count is recorded,
never gated.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.context import code_context as cc
from dast_orchestrator.context import evidence
from dast_orchestrator.stages.triage.arms import (
    CodeContextUngrounded, require_located_handlers,
)


class _Bundle:
    def __init__(self, identifier, callees=(), code_paths=(), technology=""):
        self.identifier = identifier
        self.static_context = {
            "technology": technology,
            "ai_context": {"callees": [{"name": n} for n in callees]},
            "code_paths": [{"path": p, "line": line} for p, line in code_paths],
        }


@pytest.fixture
def assembler(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "issue.go").write_text("func Issues() {\n}\n")
    (tmp_path / "Admin").mkdir()
    (tmp_path / "Admin" / "X.php").write_text("function register() {\n}\n")
    index = cc.SymbolIndex([
        cc.Symbol("Issues", "repo", "repo/issue.go", 1, 2, kind="func"),
        cc.Symbol("register", "", "Admin/X.php", 1, 2, kind="function"),
    ])
    return evidence.Assembler(code_level="handler+trace", index=index,
                              source_dir=tmp_path)


FILE_ONLY = _Bundle("GET /x.php", code_paths=[("/src/Admin/X.php", 0)],
                    technology="php_pure")
UNRESOLVED = _Bundle("GET /nowhere", callees=["http.Error"])
LOCATED = _Bundle("GET /issues", callees=["repo.Issues"])


def test_refuses_when_no_candidate_has_its_handler_located(assembler):
    """File-level source is not a located handler."""
    with pytest.raises(CodeContextUngrounded) as raised:
        require_located_handlers(assembler, [FILE_ONLY, UNRESOLVED])
    message = str(raised.value)
    assert "none of the 2 endpoint(s)" in message
    assert "callees 0, registration 0, code_paths 1, none 1" in message
    assert "--code-context none" in message


def test_one_located_handler_is_enough(assembler):
    """A partial count is recorded, never gated."""
    require_located_handlers(assembler, [FILE_ONLY, UNRESOLVED, LOCATED])
    assert assembler.grounding()["handler_located"] == 1


def test_no_candidates_means_nothing_to_ground(assembler):
    require_located_handlers(assembler, [])


def test_code_context_off_is_never_gated():
    require_located_handlers(evidence.Assembler(), [FILE_ONLY])
    require_located_handlers(None, [FILE_ONLY])


def test_the_gate_judges_only_the_candidates_it_is_given(assembler):
    """A located handler outside the candidate set must not rescue it."""
    assembler.prepare([LOCATED])
    with pytest.raises(CodeContextUngrounded):
        require_located_handlers(assembler, [FILE_ONLY])
