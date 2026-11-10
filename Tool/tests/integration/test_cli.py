"""``dast``: how a command line is split, routed, resolved and refused.

No stage is ever really executed — every test either stops before running or
replaces the stage's ``main`` — because what is under test is the routing:
which stage gets which flag, what the trailing argument means, and which
sequences are refused before anything starts.
"""

from __future__ import annotations

import argparse

import pytest

from dast_orchestrator import cli
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.stages import table as stage_table
from dast_orchestrator.foundation.run_paths import RunLayout


def _stages(*names):
    return stage_table.resolve(names)


def _run_with(data_dir, run_id, *basenames):
    layout = RunLayout(data_dir, run_id).ensure()
    for name in basenames:
        layout.path(name).write_text("{}")
    return layout


# -- splitting the command line --------------------------------------------


def test_leading_tokens_are_stages_until_one_is_not():
    names, positional, flags = cli.split_argv(
        ["scan", "triage", "gitea", "--auth", "user"]
    )
    assert names == ["scan", "triage"]
    assert positional == "gitea"
    assert flags == ["--auth", "user"]


def test_a_bare_positional_is_the_whole_chain():
    names, positional, flags = cli.split_argv(["gitea"])
    assert names == [] and positional == "gitea" and flags == []
    # An empty stage list means the full chain, resolved by main().
    assert [s.name for s in stage_table.resolve(stage_table.FULL_CHAIN)] == [
        "scan", "triage", "verify", "report"
    ]


def test_a_missing_positional_is_a_usage_error():
    with pytest.raises(cli.CliError, match="no target or run id"):
        cli.split_argv(["scan", "triage"])


def test_a_flag_before_the_positional_is_refused_not_reordered():
    # `dast scan --auth user gitea` and `dast scan --auth gitea` would otherwise
    # differ by a typo nobody would see.
    with pytest.raises(cli.CliError, match="expected a target or run id"):
        cli.split_argv(["scan", "--auth", "user", "gitea"])


# -- routing flags to stages -----------------------------------------------


def test_a_flag_goes_to_the_one_stage_that_accepts_it():
    per_stage = cli.route_flags(
        ["--peer-context", "none"], _stages("triage", "report")
    )
    assert per_stage["triage"] == ["--peer-context", "none"]
    assert per_stage["report"] == []


def test_one_setting_several_stages_hold_is_broadcast():
    # correlate/verify/report all resolve --out-suffix to the same dest, so they
    # mean one thing by it — exactly as one line in the env file would configure
    # all three. Refusing it would block the obvious comparison workflow.
    per_stage = cli.route_flags(
        ["--out-suffix", "qwen"], _stages("triage", "verify", "report")
    )
    assert all(per_stage[name] == ["--out-suffix", "qwen"]
               for name in ("triage", "verify", "report"))


def test_a_shared_setting_routes_to_every_stage_not_a_collision():
    # SHARED_AUTH_MODE is one setting shared by scan and verify (same env var, same
    # flag), so routing it to both is correct, not an ambiguous collision.
    per_stage = cli.route_flags(["--auth", "admin"], _stages("scan", "verify"))
    assert per_stage["scan"] == ["--auth", "admin"]
    assert per_stage["verify"] == ["--auth", "admin"]


def test_stages_that_disagree_about_a_flag_make_it_ambiguous(monkeypatch):
    # Nothing in the codebase is ambiguous today; this is the guard for a flag
    # added later that is not so careful. Two stages, one flag string, two dests.
    def left():
        p = argparse.ArgumentParser()
        p.add_argument("--mode", dest="scan_mode")
        return p

    def right():
        p = argparse.ArgumentParser()
        p.add_argument("--mode", dest="verify_mode")
        return p

    monkeypatch.setattr(stage_table.Stage, "parser",
                        lambda self: left() if self.name == "scan" else right())
    with pytest.raises(cli.CliError, match="ambiguous"):
        cli.route_flags(["--mode", "x"], _stages("scan", "verify"))


def test_an_unknown_flag_names_what_the_stages_do_accept():
    with pytest.raises(cli.CliError, match="no stage in `report` accepts"):
        cli.route_flags(["--nonsense"], _stages("report"))


def test_a_retired_flag_is_answered_with_the_reason():
    # These no longer exist on any stage — what to act on is the positional —
    # so a stale command line gets the reason rather than "unknown flag".
    for flag in ("--run", "--timestamp", "--target-name"):
        with pytest.raises(cli.CliError, match="no longer exists"):
            cli.route_flags([flag, "x"], _stages("triage"))


def test_store_true_flags_consume_no_value():
    per_stage = cli.route_flags(
        ["--no-llm", "--peer-context", "none"], _stages("triage")
    )
    assert per_stage["triage"] == ["--no-llm", "--peer-context", "none"]


def test_inline_values_are_accepted():
    per_stage = cli.route_flags(["--peer-context=none"], _stages("triage"))
    assert per_stage["triage"] == ["--peer-context", "none"]


def test_a_valued_flag_with_nothing_after_it_is_an_error():
    with pytest.raises(cli.CliError, match="expects a value"):
        cli.route_flags(["--peer-context"], _stages("triage"))


def test_there_is_no_separate_class_of_global_flag():
    # --env-file/--env-dir/--data-dir are a single dest shared by all five
    # stages, so the one routing rule already sends them everywhere. A declared
    # "global" list would have been a second mechanism giving the same answer.
    per_stage = cli.route_flags(
        ["--data-dir", "/tmp/x", "--no-llm"], _stages("triage", "report")
    )
    assert per_stage["triage"] == ["--data-dir", "/tmp/x", "--no-llm"]
    assert per_stage["report"] == ["--data-dir", "/tmp/x"]


def test_a_flag_no_invoked_stage_accepts_is_an_error_not_a_silent_drop():
    # `static-analysis` writes no suffixed artifact. Saying so beats dropping the flag.
    with pytest.raises(cli.CliError, match="no stage in `static-analysis` accepts"):
        cli.route_flags(["--out-suffix", "x"], _stages("static-analysis"))


def test_the_data_dir_is_read_before_routing(tmp_path):
    # It has to be known before the positional can be resolved against it.
    assert cli.data_dir_from(["--data-dir", str(tmp_path)]) == tmp_path
    assert cli.data_dir_from([f"--data-dir={tmp_path}"]) == tmp_path
    assert cli.data_dir_from(["--no-llm"]) == cli.DATA_DIR


# -- what the positional means ---------------------------------------------


def test_a_scanning_sequence_takes_a_target(tmp_path):
    assert cli.resolve_positional(_stages("scan", "triage"), "gitea", tmp_path) == (
        "target", "gitea"
    )


def test_an_unknown_target_names_the_known_ones(tmp_path):
    with pytest.raises(cli.CliError, match="unknown target"):
        cli.resolve_positional(_stages("scan"), "nosuchtarget", tmp_path)


def test_every_other_sequence_takes_a_run_id(tmp_path):
    _run_with(tmp_path, "20260101T000000Z-gitea", run_paths.TRIAGE)
    assert cli.resolve_positional(_stages("verify"), "20260101T000000Z", tmp_path) == (
        "run", "20260101T000000Z-gitea"
    )


def test_latest_is_resolved_once_against_the_first_stages_needs(tmp_path):
    # `dast verify report latest` acting on two different runs because one of
    # them wrote a file in between is exactly what resolving once prevents.
    _run_with(tmp_path, "20260101T000000Z-gitea", run_paths.TRIAGE)
    _run_with(tmp_path, "20260202T000000Z-gitea", run_paths.ZAP_ALERTS)
    kind, value = cli.resolve_positional(_stages("verify", "report"), "latest", tmp_path)
    assert (kind, value) == ("run", "20260101T000000Z-gitea")


def test_latest_with_no_usable_run_says_what_was_needed(tmp_path):
    with pytest.raises(cli.CliError, match="triage.json"):
        cli.resolve_positional(_stages("verify"), "latest", tmp_path)


def test_analyze_alone_accepts_a_target(tmp_path):
    # The baselines are not a stage of the chain and need no run at all, so
    # `dast static-analysis gitea` is the natural way to ask for one.
    assert cli.resolve_positional(_stages("static-analysis"), "gitea", tmp_path) == (
        "target", "gitea"
    )


def test_analyze_in_a_sequence_still_joins_the_run(tmp_path):
    _run_with(tmp_path, "20260101T000000Z-gitea", run_paths.TRIAGE)
    assert cli.resolve_positional(
        _stages("report", "static-analysis"), "20260101T000000Z-gitea", tmp_path
    ) == ("run", "20260101T000000Z-gitea")


# -- running a sequence ----------------------------------------------------


class _Stub:
    """Stands in for a stage module: records the argv, returns an exit code."""

    def __init__(self, code=0, creates=None, data_dir=None):
        self.code, self.creates, self.data_dir = code, creates, data_dir
        self.calls = []

    def build_parser(self):
        # Only the invocation flags matter here; the routing of stage-specific
        # ones is covered above, against the real parsers.
        parser = argparse.ArgumentParser()
        parser.add_argument("--data-dir")
        parser.add_argument("--run")
        parser.add_argument("--target-name")
        return parser

    def main(self, argv):
        self.calls.append(argv)
        if self.creates:
            _run_with(self.data_dir, self.creates, run_paths.ZAP_ALERTS,
                      run_paths.NOIR_AI_CONTEXT)
        return self.code


def _install(monkeypatch, stubs: dict):
    monkeypatch.setattr(stage_table.Stage, "load",
                        lambda self: stubs[self.name])


def test_an_unsatisfiable_sequence_runs_nothing(monkeypatch, tmp_path, capsys):
    stubs = {"scan": _Stub(), "report": _Stub()}
    _install(monkeypatch, stubs)
    code = cli.run(_stages("scan", "report"), "target", "gitea", {}, tmp_path)
    assert code == 2
    assert stubs["scan"].calls == [] and stubs["report"].calls == []
    assert "cannot complete" in capsys.readouterr().err


def test_a_failing_stage_aborts_and_names_what_was_skipped(monkeypatch, tmp_path, capsys):
    _run_with(tmp_path, "20260101T000000Z-gitea", run_paths.TRIAGE)
    stubs = {"verify": _Stub(code=1), "report": _Stub()}
    _install(monkeypatch, stubs)
    code = cli.run(_stages("verify", "report"), "run", "20260101T000000Z-gitea",
                   {}, tmp_path)
    assert code == 1
    assert stubs["report"].calls == []          # never started
    err = capsys.readouterr().err
    assert "verify` failed" in err and "skipped: report" in err


def test_the_sequence_inherits_the_run_id_the_scan_minted(monkeypatch, tmp_path):
    # The stages are stubbed, so the keys are never spent — but the chain's
    # secrets pre-flight resolves every stage's arm up front, so a scan+triage
    # sequence has to see them present to get past it to the mechanics under test.
    monkeypatch.setenv("SCAN_ZAP_API_KEY", "test")
    monkeypatch.setenv("SHARED_OPENROUTER_API_KEY", "test")
    minted = "20260303T000000Z-gitea-abc123"
    stubs = {"scan": _Stub(creates=minted, data_dir=tmp_path),
             "triage": _Stub()}
    _install(monkeypatch, stubs)
    assert cli.run(_stages("scan", "triage"), "target", "gitea", {}, tmp_path) == 0
    # scan was told the target; correlate the concrete run scan produced. Both
    # positionally — every stage takes what it acts on as its first argument.
    assert stubs["scan"].calls[0][0] == "gitea"
    assert stubs["triage"].calls[0][0] == minted


def test_a_scan_that_creates_no_run_directory_is_a_failure(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SCAN_ZAP_API_KEY", "test")
    monkeypatch.setenv("SHARED_OPENROUTER_API_KEY", "test")
    stubs = {"scan": _Stub(), "triage": _Stub()}
    _install(monkeypatch, stubs)
    code = cli.run(_stages("scan", "triage"), "target", "gitea", {}, tmp_path)
    assert code != 0
    assert stubs["triage"].calls == []
    assert "created no run directory" in capsys.readouterr().err


# -- the cross-stage secrets pre-flight ------------------------------------


def _empty_env(tmp_path):
    """An env file with no keys, and no secrets.env beside it — so the pre-flight
    sees only what the test sets in the environment, never the repo's real config.
    """
    path = tmp_path / "empty.env"
    path.write_text("# nothing\n")
    return path


def test_a_chain_is_refused_when_a_later_stages_key_is_missing(monkeypatch, tmp_path, capsys):
    # scan runs 45 minutes; a triage/verify whose key is absent must be caught
    # here, before it, not when the later stage finally reaches the key.
    for var in ("SCAN_ZAP_API_KEY", "SHARED_OPENROUTER_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    envf = _empty_env(tmp_path)
    stages = _stages("scan", "triage", "verify")
    per_stage = {s.name: ["--env-file", str(envf)] for s in stages}
    code = cli.run(stages, "target", "gitea", per_stage, tmp_path)
    assert code == 2
    err = capsys.readouterr().err
    assert "SCAN_ZAP_API_KEY" in err and "SHARED_OPENROUTER_API_KEY" in err
    assert "nothing was run" in err


def test_missing_secrets_names_every_absent_key_for_the_active_arms(monkeypatch, tmp_path):
    for var in ("SCAN_ZAP_API_KEY", "SHARED_OPENROUTER_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    envf = _empty_env(tmp_path)
    stages = _stages("scan", "triage", "verify")
    per_stage = {s.name: ["--env-file", str(envf)] for s in stages}
    result = dict(cli.missing_secrets(stages, per_stage, "gitea"))
    assert set(result) == {"SCAN_ZAP_API_KEY", "SHARED_OPENROUTER_API_KEY"}
    # One key is named against both stages that would spend it.
    assert set(result["SHARED_OPENROUTER_API_KEY"]) == {"triage", "verify"}
    assert result["SCAN_ZAP_API_KEY"] == ["scan"]


def test_the_control_arm_chain_demands_no_llm_key(monkeypatch, tmp_path):
    # A --no-llm triage and a deterministic verify spend nothing, so the
    # OpenRouter key is not required — only scan's ZAP key, which is present.
    monkeypatch.setenv("SCAN_ZAP_API_KEY", "test")
    monkeypatch.delenv("SHARED_OPENROUTER_API_KEY", raising=False)
    envf = _empty_env(tmp_path)
    stages = _stages("scan", "triage", "verify")
    per_stage = {
        "scan": ["--env-file", str(envf)],
        "triage": ["--env-file", str(envf), "--no-llm"],
        "verify": ["--env-file", str(envf), "--invocation", "deterministic"],
    }
    assert cli.missing_secrets(stages, per_stage, "gitea") == []


def test_targets_dir_from_prefers_flag_then_env_file_then_env(monkeypatch, tmp_path):
    envf = tmp_path / "row.env"
    envf.write_text("SHARED_TARGETS_DIR=/from/file\n")
    monkeypatch.setenv("SHARED_TARGETS_DIR", "/from/env")
    # An explicit flag wins over everything.
    assert cli.targets_dir_from(
        ["--env-file", str(envf), "--targets-dir", "/from/flag"]) == "/from/flag"
    # No flag: the named env file's value beats the real environment.
    assert cli.targets_dir_from(["--env-file", str(envf)]) == "/from/file"
    # No flag, no file value: the real environment.
    monkeypatch.setattr(cli.config, "DEFAULT_ENV_DIR", tmp_path / "empty")
    assert cli.targets_dir_from([]) == "/from/env"


def test_a_dry_run_triage_demands_no_key(monkeypatch, tmp_path):
    # --dry-run writes the prompts and stops, spending nothing.
    monkeypatch.delenv("SHARED_OPENROUTER_API_KEY", raising=False)
    envf = _empty_env(tmp_path)
    stages = _stages("triage")
    per_stage = {"triage": ["--env-file", str(envf), "--dry-run"]}
    assert cli.missing_secrets(stages, per_stage, "latest") == []


# -- the entry point -------------------------------------------------------


def test_no_arguments_prints_usage_and_fails():
    assert cli.main([]) == 2


def test_help_for_one_stage_shows_that_stages_flags(capsys):
    assert cli.main(["triage", "--help"]) == 0
    assert "--peer-context" in capsys.readouterr().out


def test_help_without_a_stage_shows_the_grammar(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    # The `stages:` line is the pipeline chain only; static-analysis is a
    # standalone command, listed among the commands, not a stage.
    assert "usage: dast" in out and "stages:   scan, triage, verify, report" in out
    assert "scan, triage, verify, report, static-analysis" not in out
    assert "dast static-analysis <target>" in out


def test_a_bad_stage_name_is_reported_before_anything_runs(capsys):
    # `corelate` is not a stage, so it is read as the positional — and then it
    # is not a run either. Either way nothing runs and usage is printed.
    assert cli.main(["corelate", "--no-llm"]) == 2


def test_cve_is_folded_under_dast_and_delegated_whole(monkeypatch):
    # `cve` is not a stage, so it must never reach the stage router:
    # it is handed to ground_truth.main verbatim, minus its own verb.
    import dast_orchestrator.stages.ground_truth as ground_truth

    seen = {}

    def fake(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(ground_truth, "main", fake)
    assert cli.main(["cve", "latest"]) == 0
    assert seen["argv"] == ["latest"]


def test_run_index_is_folded_under_dast_and_delegated_whole(monkeypatch):
    import dast_orchestrator.foundation.metrics as metrics

    seen = {}

    def fake(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(metrics, "main", fake)
    assert cli.main(["costs"]) == 0
    assert seen["argv"] == []


def test_the_grammar_lists_the_two_folded_verbs(capsys):
    cli.main(["--help"])
    out = capsys.readouterr().out
    assert "cve" in out and "costs" in out


def test_stage_help_names_the_full_command(capsys):
    # `dast scan --help` should echo the command you typed, not a bare `dast`.
    assert cli.main(["scan", "--help"]) == 0
    assert "usage: dast scan" in capsys.readouterr().out


def test_folded_verb_help_names_the_full_command(capsys):
    # cve delegates to its own argparse (which exits on --help), and it
    # too should read `dast cve`, not `dast`.
    with pytest.raises(SystemExit):
        cli.main(["cve", "--help"])
    assert "usage: dast cve" in capsys.readouterr().out


def test_suffix_availability_matrix():
    """The suffix flags machine-check the run-directory-identity rule (§R1).

    A scan *is* the run directory, so it takes no suffix; every downstream
    variant shares that directory and is named by ``--out-suffix`` (the variant a
    writer produces) and reads its upstream variant with ``--in-suffix``. The
    matrix: ``--out-suffix`` on triage/verify/report, ``--in-suffix`` on
    verify/report, ``scan`` takes NEITHER — and a suffix flag on it is a hard
    argparse error rather than a silent no-op.
    """
    opts = {name: stage.option_strings()
            for name, stage in stage_table.STAGES.items()}

    assert "--out-suffix" not in opts["scan"]
    assert "--in-suffix" not in opts["scan"]
    for stage in ("triage", "verify", "report"):
        assert "--out-suffix" in opts[stage], stage
    assert "--in-suffix" not in opts["triage"]
    for stage in ("verify", "report"):
        assert "--in-suffix" in opts[stage], stage

    with pytest.raises(SystemExit):
        stage_table.STAGES["scan"].parser().parse_args(["gitea", "--out-suffix", "x"])
