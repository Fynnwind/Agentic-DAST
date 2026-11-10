"""``docs/api/`` is generated from the package docstrings; this keeps it in sync.

Like :mod:`tests.unit.test_command_docs` for ``COMMANDS.md``: if a docstring
changes and the reference is not regenerated, the diff fails here — run
``uv run dast docs``.
"""
from pathlib import Path

import pytest

from dast_orchestrator.cli import api_docs

API_DIR = Path(__file__).resolve().parents[2] / "docs" / "api"
REGEN = "docs/api/ is out of date — run `uv run dast docs`"


def test_rest_to_md_converts_roles_and_literals():
    assert api_docs.rst_to_md(":func:`~a.b.c`") == "`c`"
    assert api_docs.rst_to_md(":data:`STAGE_FLAGS`") == "`STAGE_FLAGS`"
    assert api_docs.rst_to_md("a ``literal`` here") == "a `literal` here"


def test_index_in_sync():
    assert (API_DIR / "README.md").read_text() == api_docs.render_index(), REGEN


@pytest.mark.parametrize("layer", list(api_docs.LAYERS))
def test_layer_in_sync(layer):
    assert (API_DIR / f"{layer}.md").read_text() == api_docs.render_layer(layer), REGEN
