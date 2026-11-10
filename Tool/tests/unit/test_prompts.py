"""Prompts as versioned files: the filename is the version, and it is selectable.

The point of the directory is that a prompt change stops being a code change —
it becomes a run parameter a sheet row can pin, so two prompt versions can be
compared over one stored scan.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.foundation import prompts
from dast_orchestrator.analysis import verify_loop


def _write(tmp_path, name, version, text="hello"):
    path = tmp_path / f"{name}.v{version}.md"
    path.write_text(text)
    return path


# -- the convention --------------------------------------------------------


def test_every_pass_has_a_prompt_on_disk():
    for name in prompts.PASSES:
        assert prompts.available(name), f"no {name}.v*.md in {prompts.PROMPTS_DIR}"


def test_the_modules_load_their_prompts_from_disk():
    # Not a triple-quoted string in the module that sends it: that made a prompt
    # edit invisible in a diff of configuration and impossible to select per run.
    assert screening.SYSTEM_PROMPT == prompts.load("screening").text
    assert synthesize.SYNTHESIS_SYSTEM_PROMPT == prompts.load("synthesis").text
    # The verification loop resolves its prompt per run rather than into a
    # module constant — it is selectable with --verify-prompt — so what is
    # asserted here is that the default resolves to a file on disk at all.
    assert verify_loop.build_messages({})[0]["content"] == prompts.load("verify").text


def test_the_version_constants_come_from_the_filenames():
    # A constant a human has to remember to bump is a convention; the filename
    # is a mechanism, and it cannot drift from the text beside it.
    assert screening.PROMPT_VERSION == prompts.load("screening").version
    assert synthesize.SYNTHESIS_PROMPT_VERSION == prompts.load("synthesis").version


def test_filenames_follow_the_convention():
    # Searched recursively — prompts are grouped into subdirs (screening/, oracle/…).
    for path in prompts.PROMPTS_DIR.rglob("*.md"):
        if path.name == "README.md":
            continue
        match = prompts.FILENAME_RE.match(path.name)
        if match:
            # A versioned pass prompt: <pass>.v<N>.md, name in PASSES.
            assert match.group("name") in prompts.PASSES, path.name
        else:
            # An unversioned oracle block: <name>.md, name in ORACLE_BLOCKS.
            assert path.stem in prompts.ORACLE_BLOCKS, path.name


def test_every_oracle_block_is_present_and_unversioned():
    # The oracle blocks are generic scaffolding, not an A/B axis, so they carry
    # no vN — loaded by bare filename with `load_oracle`, version 0.
    for name in prompts.ORACLE_BLOCKS:
        block = prompts.load_oracle(name)
        assert block.text and block.version == 0
        assert block.path.name == f"{name}.md"


# -- selecting a version ---------------------------------------------------


def test_the_newest_version_is_the_default(tmp_path):
    _write(tmp_path, "screening", 1, "old")
    _write(tmp_path, "screening", 2, "new")
    assert prompts.load("screening", prompts_dir=tmp_path).text == "new"
    assert prompts.load("screening", prompts_dir=tmp_path).version == 2


def test_an_older_version_can_be_pinned(tmp_path):
    # What makes a comparison stay valid when a newer prompt lands.
    _write(tmp_path, "screening", 1, "old")
    _write(tmp_path, "screening", 2, "new")
    assert prompts.load("screening", 1, prompts_dir=tmp_path).text == "old"
    assert prompts.load("screening", "v1", prompts_dir=tmp_path).text == "old"
    # An empty value is "unset", not "version zero" — env files yield "".
    assert prompts.load("screening", "", prompts_dir=tmp_path).version == 2


def test_versions_beyond_nine_sort_numerically(tmp_path):
    # `v10` must beat `v9`; string ordering would pick the wrong prompt for
    # every run after the ninth revision.
    for version in (2, 9, 10):
        _write(tmp_path, "screening", version, f"v{version}")
    assert prompts.load("screening", prompts_dir=tmp_path).version == 10
    assert prompts.available("screening", tmp_path) == [2, 9, 10]


def test_a_missing_version_names_the_ones_that_exist(tmp_path):
    _write(tmp_path, "screening", 3)
    with pytest.raises(prompts.PromptError, match="available: v3"):
        prompts.load("screening", 4, prompts_dir=tmp_path)


def test_an_unknown_pass_names_the_ones_that_exist(tmp_path):
    with pytest.raises(prompts.PromptError, match="synthesis"):
        prompts.load("triaje", prompts_dir=tmp_path)


def test_a_non_numeric_version_is_refused(tmp_path):
    _write(tmp_path, "screening", 1)
    with pytest.raises(prompts.PromptError, match="not a number"):
        prompts.load("screening", "latest", prompts_dir=tmp_path)


# -- what the artifact records --------------------------------------------


def test_metadata_carries_the_text_not_just_a_reference(tmp_path):
    # A run has to stay readable after the file is edited or deleted: "prompt
    # v3" means nothing to a reader without this checkout.
    path = _write(tmp_path, "screening", 3, "the actual words")
    meta = prompts.load("screening", 3, prompts_dir=tmp_path).as_metadata()
    assert meta["system_prompt"] == "the actual words"
    assert meta["prompt_version"] == 3
    assert meta["prompt_file"] == path.name
    assert meta["prompt_name"] == "screening"
