"""The run-directory layout: stable basenames, suffix splicing, discovery."""

from __future__ import annotations

from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation.run_paths import RunLayout


def test_paths_land_in_the_run_folder(tmp_path):
    layout = RunLayout(tmp_path, "20260101T000000Z")
    p = layout.path(run_paths.TRIAGE)
    assert p == tmp_path / "20260101T000000Z" / "triage.json"


def test_suffix_splices_before_extension():
    assert run_paths._splice_suffix("triage.json", "qwen") == "triage-qwen.json"
    # multi-part extension survives
    assert run_paths._splice_suffix("report.sarif.json", "qwen") == "report-qwen.sarif.json"
    assert run_paths._splice_suffix("triage.json", "") == "triage.json"


def test_metrics_basename_carries_kind_and_suffix(tmp_path):
    layout = RunLayout(tmp_path, "R")
    assert layout.metrics("verify").name == "verify-metrics.json"
    assert layout.metrics("verify", "qwen").name == "verify-metrics-qwen.json"


def test_latest_with_picks_newest_run_that_has_the_artifact(tmp_path):
    for run_id in ("20260101T000000Z", "20260202T000000Z"):
        RunLayout(tmp_path, run_id).ensure().path(run_paths.ZAP_ALERTS).write_text("{}")
    # only the older run has a correlation
    RunLayout(tmp_path, "20260101T000000Z").path(run_paths.TRIAGE).write_text("{}")

    assert RunLayout.latest_with(tmp_path, run_paths.ZAP_ALERTS).run_id == "20260202T000000Z"
    assert RunLayout.latest_with(tmp_path, run_paths.TRIAGE).run_id == "20260101T000000Z"
    assert RunLayout.latest_with(tmp_path, run_paths.VERIFICATION) is None


def test_runs_lists_only_directories_whose_name_is_a_run_id(tmp_path):
    RunLayout(tmp_path, "20260101T000000Z-gitea").ensure()
    (tmp_path / "notes.txt").write_text("")   # a top-level file, not a run
    # The harness keeps its sheets and tables here too. A directory sorting
    # after every timestamp would otherwise be returned as "the newest run".
    (tmp_path / "harness").mkdir()
    assert RunLayout.runs(tmp_path) == ["20260101T000000Z-gitea"]


# -- run ids: <timestamp>-<target>-<config> --------------------------------


def test_run_id_is_timestamp_then_target_then_config():
    assert run_paths.make_run_id("20260824T103111Z", "gitea") == "20260824T103111Z-gitea"
    assert run_paths.make_run_id("20260824T103111Z", "gitea", "a3f19c") == (
        "20260824T103111Z-gitea-a3f19c"
    )
    assert run_paths.split_run_id("20260824T103111Z-gitea-a3f19c") == (
        "20260824T103111Z", "gitea", "a3f19c"
    )
    # Both trailing fields are optional: ids predating each still parse.
    assert run_paths.split_run_id("20260824T103111Z-gitea") == (
        "20260824T103111Z", "gitea", ""
    )
    assert run_paths.split_run_id("20260817T155107Z") == ("20260817T155107Z", "", "")


def test_a_target_may_not_contain_the_field_separator():
    # The three fields are parsed by position, so `wordpress-6.4` would make
    # `…-wordpress-6.4` and `…-wordpress-a3f19c` the same shape. Refused where
    # the id is built, not discovered when the second target is added.
    import pytest

    with pytest.raises(ValueError, match="separates the fields"):
        run_paths.make_run_id("20260824T103111Z", "wordpress-6.4")
    assert run_paths.make_run_id("20260824T103111Z", "wordpress_6.4") == (
        "20260824T103111Z-wordpress_6.4"
    )


def test_config_digest_is_stable_and_ignores_defaults_left_unset():
    same = run_paths.config_digest({"model": "m", "auth": "none"})
    # Key order is invisible; a knob left unset must not change the digest, or
    # every existing id moves the day a stage grows a flag.
    assert same == run_paths.config_digest({"auth": "none", "model": "m"})
    assert same == run_paths.config_digest(
        {"model": "m", "auth": "none", "oob": None, "suffix": ""}
    )
    assert same != run_paths.config_digest({"model": "m", "auth": "admin"})
    assert len(same) == run_paths.CONFIG_DIGEST_LEN
    # A digest of nothing claims nothing, and makes a two-field id.
    assert run_paths.config_digest({}) == ""
    assert run_paths.make_run_id("20260824T103111Z", "gitea", "") == "20260824T103111Z-gitea"


def test_a_config_digest_distinguishes_two_runs_of_one_target_in_one_second(tmp_path):
    # The collision the field exists to prevent: same instant, same target, two
    # configurations. Without the digest these are one directory.
    ts = "20260824T103111Z"
    first = run_paths.make_run_id(ts, "gitea", run_paths.config_digest({"auth": "none"}))
    second = run_paths.make_run_id(ts, "gitea", run_paths.config_digest({"auth": "admin"}))
    assert first != second
    for run_id in (first, second):
        RunLayout(tmp_path, run_id).ensure().path(run_paths.ZAP_ALERTS).write_text("{}")
    assert len(RunLayout.runs(tmp_path)) == 2


def test_run_ids_sort_chronologically_not_by_target(tmp_path):
    # The reason the timestamp leads: `latest_with` is a reverse-sorted scan, so
    # a target-first id would return the newest run of the last target by name.
    for run_id in ("20260101T000000Z-zzz", "20260202T000000Z-aaa"):
        RunLayout(tmp_path, run_id).ensure().path(run_paths.ZAP_ALERTS).write_text("{}")
    assert RunLayout.latest_with(tmp_path, run_paths.ZAP_ALERTS).run_id == "20260202T000000Z-aaa"


def test_layout_exposes_the_three_fields_of_its_id(tmp_path):
    layout = RunLayout(tmp_path, "20260824T103111Z-gitea-a3f19c")
    assert layout.timestamp == "20260824T103111Z"
    assert layout.target == "gitea"
    assert layout.config == "a3f19c"
    # An id predating the field reports it absent rather than guessing one.
    assert RunLayout(tmp_path, "20260824T103111Z-gitea").config == ""


def test_bare_timestamp_still_resolves_to_the_run(tmp_path):
    # `--timestamp 20260824T103111Z` has to keep working now the folder is
    # `20260824T103111Z-gitea`.
    RunLayout(tmp_path, "20260824T103111Z-gitea").ensure()
    assert RunLayout.resolve(tmp_path, "20260824T103111Z").run_id == "20260824T103111Z-gitea"
    assert RunLayout.resolve(tmp_path, "20260824T103111Z-gitea").run_id == "20260824T103111Z-gitea"


def test_ambiguous_timestamp_raises_rather_than_guessing(tmp_path):
    # Same instant, two targets: picking one would silently report the wrong
    # system's run, which no reader of a summary would catch.
    for name in ("20260824T103111Z-gitea", "20260824T103111Z-wordpress"):
        RunLayout(tmp_path, name).ensure()
    import pytest

    with pytest.raises(ValueError, match="ambiguous"):
        RunLayout.resolve(tmp_path, "20260824T103111Z")


def test_unknown_run_is_returned_as_named(tmp_path):
    # So the caller reports the artifact it was actually looking for.
    assert RunLayout.resolve(tmp_path, "nope").run_id == "nope"


def test_reserved_out_suffixes_are_refused(tmp_path):
    # `metrics`/`prompts` would make a variant artifact indistinguishable from a
    # metrics record or the prompt dump (flat filename namespace), so they are
    # refused at the one chokepoint every suffixed path goes through.
    import pytest

    layout = RunLayout(tmp_path, "20260101T000000Z-wp-abcdef")
    for bad in ("metrics", "prompts"):
        with pytest.raises(run_paths.SuffixError):
            layout.path(run_paths.TRIAGE, bad)
    # a normal suffix still works
    assert layout.path(run_paths.TRIAGE, "qwen").name == "triage-qwen.json"
    # and the metrics record's own row suffix is fine (it is never "metrics")
    assert layout.metrics("triage", "wordpress-baseline").name == \
        "triage-metrics-wordpress-baseline.json"
