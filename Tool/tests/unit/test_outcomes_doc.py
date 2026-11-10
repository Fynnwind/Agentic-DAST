"""`docs/OUTCOMES.md` is pinned to the code, because a stale one teaches the bug.

That document is the single page saying what every status means and what it
resolves to. Its whole value is that a reader can trust it instead of reading
four modules — so a vocabulary that grows without it is worse than no document,
and this project has already shipped one prose claim (`docker/ephemeral.yml` on
ZAP memory) that the logs falsified.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dast_orchestrator.domain import verification

DOC = Path(__file__).resolve().parents[2] / "docs" / "OUTCOMES.md"


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.is_file(), f"{DOC} is missing"
    return DOC.read_text()


@pytest.mark.parametrize("vocabulary", [
    "OUTCOMES", "NA_REASONS", "SIBLING_OUTCOMES", "DISPOSITIONS", "SECTIONS",
])
def test_every_value_of_every_vocabulary_appears_in_the_document(
        text, vocabulary):
    for value in getattr(verification, vocabulary):
        assert f"`{value}`" in text, (
            f"{vocabulary}.{value} is not in docs/OUTCOMES.md — a status the "
            f"reference page does not list is one a reader will meet in an "
            f"artifact with nothing to explain it")


def test_the_pass_one_verdicts_are_the_ones_the_schema_actually_allows(text):
    """These are a JSON-schema enum, so a model can only ever return these."""
    import re

    from dast_orchestrator.analysis import screening

    source = Path(screening.__file__).read_text()
    match = re.search(r'"verdict":\s*\{\s*"type":\s*"string",\s*"enum":\s*\['
                      r'([^\]]*)\]', source)
    assert match, "could not find the pass-1 verdict enum in screening"
    verdicts = re.findall(r'"([a-z-]+)"', match.group(1))
    assert len(verdicts) >= 3, f"enum parsed as {verdicts!r}"

    for verdict in verdicts:
        assert f"`{verdict}`" in text, (
            f"pass-1 verdict {verdict!r} is not in docs/OUTCOMES.md")


def test_the_four_end_statuses_are_still_four(text):
    """The document's own headline claim, asserted rather than trusted."""
    assert len(verification.OUTCOMES) == 4
    assert "never become three" in text
