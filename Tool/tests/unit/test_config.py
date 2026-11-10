"""Per-stage configuration: every env var is a flag, and nothing drifts.

The single `.env` drifted from the code silently — five variables the code reads
were missing from it by 2026-08-25, and nothing noticed because nothing compared
the two. These tests are that comparison.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from dast_orchestrator.foundation import config

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMANDS = {
    "scan": "dast scan",
    "triage": "dast triage",
    "verify": "dast verify",
    "static-analysis": "dast static-analysis",
    "report": "dast report",
}


def _env_vars_read_by_the_code() -> set[str]:
    """Every ``os.getenv("X")`` in the package and the wrappers."""
    found: set[str] = set()
    for directory in ("src/dast_orchestrator", "mcp"):
        for path in (REPO_ROOT / directory).rglob("*.py"):
            found |= set(re.findall(r'os\.getenv\(\s*"([A-Z0-9_]+)"', path.read_text()))
    return found


def test_every_variable_the_code_reads_belongs_to_a_stage():
    declared = {var for flags in config.STAGE_FLAGS.values() for var in flags.values()}
    declared |= config.WRAPPER_ONLY
    declared |= config.ENVIRONMENT_ONLY
    # Secrets are the one exception to "every variable is a flag": a key on a
    # command line lands in shell history and in `ps`.
    declared |= config.SECRET_VARS
    unassigned = _env_vars_read_by_the_code() - declared
    assert not unassigned, (
        f"{sorted(unassigned)} are read from the environment but belong to no "
        "stage in config.STAGE_FLAGS — add them (with a flag) or to WRAPPER_ONLY"
    )


def test_every_declared_variable_is_documented_in_an_example_file():
    documented = set()
    for path in [REPO_ROOT / "config/scanner" / "default.env",
                 *(REPO_ROOT / "config/scanner").glob("*.env.example")]:
        documented |= set(re.findall(r"^#?([A-Z0-9_]+)=", path.read_text(), re.M))
    for stage, flags in config.STAGE_FLAGS.items():
        for var in flags.values():
            assert var in documented, f"{var} ({stage}) is in no default.env"


@pytest.mark.parametrize("stage,command", sorted(COMMANDS.items()))
def test_every_stage_variable_has_a_flag_on_its_command(stage, command):
    help_text = subprocess.run(
        [sys.executable, "-m", "dast_orchestrator.stages." + {
            "scan": "scan", "triage": "triage", "verify": "verify",
            "report": "report", "static-analysis": "static_analysis.analyze"}[stage], "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT / "src")},
    ).stdout
    if not help_text:
        pytest.skip("could not render --help in this environment")
    for dest in config.STAGE_FLAGS[stage]:
        flag = "--" + dest.replace("_", "-")
        assert flag in help_text, f"{flag} missing from `{command} --help`"


# -- loading and precedence -------------------------------------------------


def test_secrets_outrank_the_config_file(tmp_path, monkeypatch):
    # One config file plus secrets: the split that matters is secrets from the
    # rest, so a key in secrets.env wins over the same name in .env.
    (tmp_path / ".env").write_text("TARGET_NAME=gitea\nSHARED=config\n")
    (tmp_path / "secrets.env").write_text("SHARED=secret\n")
    for var in ("TARGET_NAME", "SHARED"):
        monkeypatch.delenv(var, raising=False)

    env = config.load_stage_env("scan", env_dir=tmp_path)
    assert env.values["SHARED"] == "secret"
    assert env.values["TARGET_NAME"] == "gitea"


def test_a_real_environment_variable_outranks_every_file(tmp_path, monkeypatch):
    # A one-off export on the command line has to be possible.
    (tmp_path / ".env").write_text("SCAN_ZAP_ADDR=http://from-file:8080\n")
    monkeypatch.setenv("SCAN_ZAP_ADDR", "http://from-shell:9090")
    config.load_stage_env("scan", env_dir=tmp_path)
    import os

    assert os.environ["SCAN_ZAP_ADDR"] == "http://from-shell:9090"


def test_a_named_env_file_fills_flags_you_did_not_pass(tmp_path):
    named = tmp_path / "ci.env"
    named.write_text("SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES=90\nSCAN_ZAP_ADDR=http://ci-zap:8080\n")
    env = config.load_stage_env("scan", env_file=named, env_dir=tmp_path)

    class Args:
        max_active_scan_minutes = 5
        zap_addr = "http://localhost:8080"

    args = Args()
    # No argv passed, so nothing counts as explicitly typed: the named file
    # fills every mapped flag, exactly as before the flip.
    changed = config.apply_explicit_overrides(env, args)
    assert args.max_active_scan_minutes == 90 and isinstance(args.max_active_scan_minutes, int)
    assert args.zap_addr == "http://ci-zap:8080"
    assert sorted(changed) == ["max_active_scan_minutes", "zap_addr"]


def test_an_explicit_flag_beats_a_named_env_file(tmp_path):
    # The flip (2026-09-09): typing a flag is the most specific instruction, so
    # it wins even over a file the user named — while a flag left unset is still
    # filled from that file.
    import argparse

    named = tmp_path / "ci.env"
    named.write_text("SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES=90\nSCAN_ZAP_ADDR=http://ci-zap:8080\n")
    env = config.load_stage_env("scan", env_file=named, env_dir=tmp_path)

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-active-scan-minutes", type=int)
    parser.add_argument("--zap-addr")
    argv = ["--max-active-scan-minutes", "5"]            # typed; --zap-addr left to the file
    args = parser.parse_args(argv)

    changed = config.apply_explicit_overrides(env, args, parser, argv)
    assert args.max_active_scan_minutes == 5             # the typed flag wins
    assert args.zap_addr == "http://ci-zap:8080"  # the unset one is filled
    assert changed == ["zap_addr"]


def test_typed_dests_reads_both_flag_forms():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-active-scan-minutes", type=int)
    parser.add_argument("--zap-addr")
    assert config._typed_dests(parser, ["--max-active-scan-minutes", "5"]) == {"max_active_scan_minutes"}
    assert config._typed_dests(parser, ["--zap-addr=http://x"]) == {"zap_addr"}
    assert config._typed_dests(parser, []) == set()
    assert config._typed_dests(None, ["--anything"]) == set()


def test_a_default_env_file_does_not_override_flags(tmp_path):
    (tmp_path / ".env").write_text("SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES=90\n")
    env = config.load_stage_env("scan", env_dir=tmp_path)

    class Args:
        max_active_scan_minutes = 5

    args = Args()
    assert config.apply_explicit_overrides(env, args) == []
    assert args.max_active_scan_minutes == 5


def test_secrets_are_never_rendered():
    rendered = config.redact({"SHARED_OPENROUTER_API_KEY": "sk-or-realkey",
                              "SCAN_ZAP_API_KEY": "", "SCAN_ZAP_ADDR": "http://z:8080"})
    assert rendered["SHARED_OPENROUTER_API_KEY"] == "<set>"
    assert rendered["SCAN_ZAP_API_KEY"] == "<empty>"
    assert rendered["SCAN_ZAP_ADDR"] == "http://z:8080"
    assert "sk-or-realkey" not in str(rendered)


# -- the multi-layer resolvers: flag > env > target.yml > built-in ----------
#
# These pin the deliberately-ordered precedence of the two `None`-defaulted
# resolvers, whose corners the four-layer file tests above do not reach — a
# characterisation net for any future config-precedence unification.

def test_resolve_rule_minutes_prefers_flag_then_env_then_target_then_builtin(monkeypatch):
    import types
    from dast_orchestrator.stages import scan

    target = types.SimpleNamespace(max_rule_minutes=10)

    # A typed flag is the most specific statement of intent and wins over all.
    monkeypatch.setenv("SCAN_ZAP_MAX_RULE_MINUTES", "8")
    assert scan.resolve_rule_minutes(7, target) == 7

    # No flag: the env var (how a sheet holds the number fixed across rows)
    # OUTRANKS the target — the load-bearing "target is not the most specific".
    assert scan.resolve_rule_minutes(None, target) == 8

    # No flag, no env: the target's own value.
    monkeypatch.delenv("SCAN_ZAP_MAX_RULE_MINUTES", raising=False)
    assert scan.resolve_rule_minutes(None, target) == 10

    # No flag, no env, target silent: the built-in default.
    assert scan.resolve_rule_minutes(
        None, types.SimpleNamespace(max_rule_minutes=None)
    ) == scan.DEFAULT_MAX_RULE_MINUTES


def test_dispatch_budget_override_merges_rule_caps_and_keeps_none():
    from dast_orchestrator.domain.verification import DispatchBudget

    base = DispatchBudget(rule_caps=(("40018", 3),), max_minutes=20)
    # A CLI cap on one rule must not silently drop the ones an env file set:
    # rule_caps MERGE rather than replace.
    merged = base.override(rule_caps=(("10031", 5),), max_minutes=None)
    assert dict(merged.rule_caps) == {"40018": 3, "10031": 5}
    # None keeps the current ceiling (an unset flag is not "set to nothing").
    assert merged.max_minutes == 20
    # A named cap on the same rule replaces that one, leaving the others.
    reraised = base.override(rule_caps=(("40018", 99),))
    assert dict(reraised.rule_caps) == {"40018": 99}


def test_an_env_override_uses_the_flags_declared_type(tmp_path):
    # The bug the smoke sheet found: a flag whose default is None has no type to
    # copy, so its env value stayed a string and reached the dispatch loop as
    # one — `TypeError: '>' not supported between 'float' and 'str'`, minutes
    # into a run, from a sheet row that merely set VERIFY_MAX_MINUTES.
    import argparse

    named = tmp_path / "row.env"
    named.write_text("VERIFY_MAX_MINUTES=3\nVERIFY_MAX_DISPATCH_ALL_RULES=2\n")
    env = config.load_stage_env("verify", env_file=named, env_dir=tmp_path)

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-minutes", type=int)        # default None
    parser.add_argument("--max-dispatch-all-rules", type=int)
    args = parser.parse_args([])
    assert args.max_minutes is None                       # nothing to infer from

    changed = config.apply_explicit_overrides(env, args, parser)
    assert sorted(changed) == ["max_dispatch_all_rules", "max_minutes"]
    assert args.max_minutes == 3 and isinstance(args.max_minutes, int)
    assert args.max_dispatch_all_rules == 2
    assert isinstance(args.max_dispatch_all_rules, int)


def test_a_boolean_flag_is_read_from_the_word_not_from_bool(tmp_path):
    # `bool("false")` is True, which would turn the control arm back on.
    named = tmp_path / "row.env"
    named.write_text("TRIAGE_LLM_ENABLED=false\n")
    env = config.load_stage_env("triage", env_file=named, env_dir=tmp_path)

    class Args:
        use_llm = True

    args = Args()
    assert config.apply_explicit_overrides(env, args) == ["use_llm"]
    assert args.use_llm is False


def test_the_verification_invocation_axis_is_expressible_as_configuration(tmp_path):
    """A sheet row must be able to set the verification invocation axis.

    This is what makes the N-configuration comparison runnable unattended: the
    fully-deterministic control and the default hybrid are two rows of one sheet
    over one corpus, not two source edits. (Tool choice is no longer an axis —
    it is always the deterministic lookup.)
    """
    assert config.STAGE_FLAGS["verify"]["invocation"] == "VERIFY_INVOCATION"
    assert config.STAGE_FLAGS["verify"]["max_rounds"] == "VERIFY_MAX_ROUNDS"
    assert "tool_choice" not in config.STAGE_FLAGS["verify"]


def test_the_verification_axes_survive_the_env_round_trip(tmp_path):
    from dast_orchestrator.stages import verify

    named = tmp_path / "row.env"
    named.write_text("VERIFY_INVOCATION=deterministic\nVERIFY_MAX_ROUNDS=5\n")
    env = config.load_stage_env("verify", env_file=named, env_dir=tmp_path)

    parser = verify.build_parser()
    args = parser.parse_args(["latest"])

    config.apply_explicit_overrides(env, args, parser)
    assert args.invocation == "deterministic"
    # Coerced through the flag's declared type. A sheet row that set a budget
    # reached the dispatch loop as a *string* once, and failed minutes into a
    # run — so what this asserts is the type, not just the value.
    assert args.max_rounds == 5

    # And an explicit flag still beats a file found by default.
    assert parser.parse_args(
        ["latest", "--invocation", "llm"]).invocation == "llm"


def test_one_no_limit_sentinel_across_the_whole_tool():
    """`-1` everywhere, never `0`, and the ZAP translation lives in one place.

    It used to be `0` on the scan caps and `-1` on the verification caps: two
    conventions for one idea, so every new flag was a coin flip for a reader.
    `-1` wins because `0` has to keep its arithmetic meaning — a per-rule cap of
    0 means *never dispatch that rule*, and a `--max-active-scan-minutes 0` silently
    meaning "unlimited" is the misreading that costs 45 minutes.
    """
    from dast_orchestrator.stages import scan
    from dast_orchestrator.domain import verification
    from dast_orchestrator.adapters import zap_client

    assert config.NO_LIMIT == -1
    assert verification.NO_CAP == config.NO_LIMIT, (
        "the verification caps must use the project sentinel, not their own")
    assert scan.DEFAULT_MAX_ALERTS_PER_RULE == config.NO_LIMIT

    # ZAP's own API says 0 for the same idea. That translation is allowed to
    # exist exactly once, at the adapter boundary.
    assert zap_client.zap_unlimited(config.NO_LIMIT) == 0
    assert zap_client.zap_unlimited(0) == 0        # a real 0 still means 0
    assert zap_client.zap_unlimited(45) == 45


def test_no_flag_help_still_advertises_zero_as_unlimited():
    """The docs are the interface here, and a stale one re-teaches the old rule.

    Scanned across the drivers rather than asserted per flag, so a flag added
    later with the old wording fails too.
    """
    import inspect

    from dast_orchestrator.stages import scan
    from dast_orchestrator.stages import verify

    for module in (scan, verify):
        source = inspect.getsource(module)
        for phrase in ("0 = unlimited", "0 disables it", "0 means unlimited"):
            assert phrase not in source, (
                f"{module.__name__} still documents {phrase!r}; the project "
                f"sentinel is {config.NO_LIMIT}")


def test_a_stage_running_without_a_ceiling_says_so():
    """Legitimate, sometimes necessary, and never allowed to be quiet.

    "What would the 83 findings the budget dropped have said?" is a real
    question and the reason the sentinel exists. But a run whose numbers came
    from an unbounded stage is not comparable with one that was bounded, and the
    reader of the artifact is usually not the person who typed the command.
    """
    import types

    one_off = types.SimpleNamespace(max_active_scan_minutes=config.NO_LIMIT,
                                    max_rule_minutes=5)
    assert config.unbounded(one_off) == ["the active scan has no time ceiling"]

    # Resolved values outrank the parsed flags: what matters is the number the
    # stage will actually run with, not the one the flag happened to hold.
    assert config.unbounded(one_off, {"max_rule_minutes": config.NO_LIMIT}) == [
        "the active scan has no time ceiling",
        "no active-scan rule has a time ceiling",
    ]

    bounded = types.SimpleNamespace(max_active_scan_minutes=45, max_rule_minutes=5,
                                    max_dispatches_total=40)
    assert config.unbounded(bounded) == []


def test_the_shipped_default_configuration_trips_no_ceiling_warning():
    """A default run must be a bounded run, or the warning becomes noise.

    Read out of `config/scanner/.env` rather than asserted against constants,
    because the file is what an ordinary invocation actually loads — and it is
    the file that would drift.
    """
    import types

    env_file = Path(__file__).resolve().parents[2] / "config" / "scanner" / ".env"
    values = {}
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()

    resolved = {}
    for dest, var in {**STAGE_FLAG_VARS}.items():
        if var in values and values[var].lstrip("-").isdigit():
            resolved[dest] = int(values[var])
    assert resolved, "no numeric ceilings found in .env — the check is vacuous"

    assert config.unbounded(types.SimpleNamespace(), resolved) == [], (
        "the shipped default configuration runs a stage without a ceiling")


#: The env var behind each ceiling the warning covers, so the default-config
#: check reads the same file an ordinary run does.
STAGE_FLAG_VARS = {
    "max_active_scan_minutes": "SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES",
    "max_rule_minutes": "SCAN_ZAP_MAX_RULE_MINUTES",
    "max_dispatch_all_rules": "VERIFY_MAX_DISPATCH_ALL_RULES",
    "max_dispatches_total": "VERIFY_MAX_DISPATCHES_TOTAL",
    "max_minutes": "VERIFY_MAX_MINUTES",
    "tool_timeout": "VERIFY_TOOL_TIMEOUT_SECONDS",
    "max_rounds": "VERIFY_MAX_ROUNDS",
    "screening_max_minutes": "TRIAGE_SCREENING_MAX_MINUTES",
}


def test_every_ceiling_the_warning_covers_has_an_env_var_in_the_check():
    """Otherwise a new ceiling is added and the default-config check ignores it."""
    assert set(config.UNBOUNDED_WARNINGS) == set(STAGE_FLAG_VARS), (
        "UNBOUNDED_WARNINGS and STAGE_FLAG_VARS have drifted apart, so the "
        "default-configuration check no longer covers every ceiling")


# -- defaults are single-sourced from default.env (§T #1, 2026-09-29) --------
#
# A default used to live in up to four disagreeing places (default.env, the
# runtime .env, the os.getenv literal fallback, a Python constant), and they
# drifted — SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES read 45 in the file and 5 in the
# parser. default.env is now the always-loaded base and the single source of
# truth; these tests keep it that way.

#: Flag vars whose default is genuinely "unset / a per-invocation toggle", so they
#: are intentionally NOT active lines in default.env (they resolve to None / False
#: in code). Everything else must have a committed default in default.env.
_OPTIONAL_OR_TOGGLE = frozenset({
    "SCAN_TARGET_URL", "SCAN_NOIR_SOURCE_DIR", "SHARED_TARGETS_DIR",
    "SCAN_ZAP_PASSIVE_ONLY", "TRIAGE_DRY_RUN", "VERIFY_DRY_RUN",
    "STATIC_ANALYSIS_DRY_RUN", "STATIC_ANALYSIS_ONLY",
})

_STAGE_MODULES = {
    "scan": "dast_orchestrator.stages.scan",
    "triage": "dast_orchestrator.stages.triage",
    "verify": "dast_orchestrator.stages.verify",
    "static-analysis": "dast_orchestrator.stages.static_analysis.analyze",
    "report": "dast_orchestrator.stages.report",
}


def test_default_for_reads_default_env_and_raises_on_an_unknown_var(monkeypatch):
    # Falls back to the committed default.env even with nothing in the environment…
    monkeypatch.delenv("SCAN_ZAP_MODE", raising=False)
    assert config.default_for("SCAN_ZAP_MODE") == "rest"
    # …the live environment wins when set…
    monkeypatch.setenv("SCAN_ZAP_MODE", "af")
    assert config.default_for("SCAN_ZAP_MODE") == "af"
    # …and a var with no default anywhere fails loudly rather than inventing one.
    with pytest.raises(KeyError):
        config.default_for("NOT_A_REAL_VARIABLE")


def test_every_non_optional_flag_var_has_an_active_default_env_line():
    base = config._base_defaults()
    for stage, flags in config.STAGE_FLAGS.items():
        for dest, var in flags.items():
            if var in config.SECRET_VARS or var in _OPTIONAL_OR_TOGGLE:
                continue
            assert var in base, (
                f"{var} ({stage}.{dest}) has no active line in config/scanner/"
                "default.env — the single source of truth. default_for would raise "
                "at runtime; add the default there, not as a literal in the parser.")


def test_every_flag_default_resolves_from_default_env(monkeypatch):
    """No parser default may diverge from default.env.

    With default.env loaded, each stage's parser default must equal the committed
    value (coerced to the flag's type). Catches a stray `default=<literal>` or an
    env_bool default that disagrees — the drift class this refactor removed.
    """
    import importlib

    base = config._base_defaults()
    for var, value in base.items():
        monkeypatch.setenv(var, value)
    for stage, module in _STAGE_MODULES.items():
        parser = importlib.import_module(module).build_parser()
        for dest, var in config.STAGE_FLAGS[stage].items():
            if var in config.SECRET_VARS or var not in base:
                continue
            # The resolved default for the dest; get_default settles --flag/--no-flag
            # pairs that share one dest, and needs no positional args.
            actual = parser.get_default(dest)
            if actual is None:
                continue
            if var in config.NONE_IS_UNSET and base[var].strip().lower() == "none":
                expected = type(actual)()   # sentinel → the empty of the flag's type
                                            # ("" for a string, [] for the list flag)
            elif isinstance(actual, bool):
                expected = base[var].strip().lower() in ("1", "true", "yes", "on")
            else:
                expected = type(actual)(base[var])
            assert actual == expected, (
                f"{stage}.{dest} ({var}): parser default {actual!r} != "
                f"default.env {base[var]!r}")


def test_library_default_constants_agree_with_default_env():
    """The function-signature default constants (kept in code, used by programmatic
    callers) must equal the default.env value, so the CLI and a direct call share
    one default."""
    from dast_orchestrator.adapters import noir_runner
    from dast_orchestrator.adapters import retrieval
    from dast_orchestrator.analysis import screening, verify_loop
    from dast_orchestrator.context import code_context, evidence
    from dast_orchestrator.stages.scan import common as scan_common
    from dast_orchestrator.stages.triage import common as triage_common
    from dast_orchestrator.stages.verify import probes

    base = config._base_defaults()
    mapping = {
        "SCAN_NOIR_IMAGE": noir_runner.NOIR_IMAGE,
        "SCAN_ZAP_MODE": scan_common.ZAP_MODE_REST,
        "SCAN_ZAP_CONTAINER": scan_common.DEFAULT_ZAP_CONTAINER,
        "SCAN_ZAP_INJECTABLE_TARGETS": scan_common.DEFAULT_INJECTABLE_TARGETS,
        "TRIAGE_PEER_CONTEXT": screening.DEFAULT_PASS1_CONTEXT,
        "TRIAGE_HTTP_CONTEXT": evidence.DEFAULT_POLICY,
        "TRIAGE_CODE_CONTEXT": code_context.DEFAULT_CODE_CONTEXT,
        "TRIAGE_RETRIEVAL": retrieval.DEFAULT_RETRIEVAL,
        "VERIFY_RETRIEVAL": retrieval.DEFAULT_RETRIEVAL,
        "TRIAGE_CONCURRENCY": triage_common.DEFAULT_CONCURRENCY,
        "VERIFY_MAX_SIBLINGS": probes.DEFAULT_MAX_SIBLINGS,
        "VERIFY_MODEL": verify_loop.VERIFY_MODEL,
        "SHARED_STAGE_MAX_COST_USD": screening.UNLIMITED,
    }
    for var, const in mapping.items():
        assert var in base, f"{var} missing from default.env"
        expected = type(const)(base[var])   # int/float/str, per the constant's type
        assert expected == const, (
            f"{var}: default.env {base[var]!r} disagrees with the code constant "
            f"{const!r} — the two default sources have drifted.")


def test_the_none_sentinel_resolves_identically_to_empty(monkeypatch):
    """Config hygiene (§T #2, option A): the optional vars ship as `none`
    instead of a blank RHS, and `none` (case-insensitive) resolves to "" for them —
    identical to the old empty default — while staying a real value elsewhere.

    Two of them — the synthesis and verify prompt versions — are now PINNED to a
    concrete corpus version (5 / 2) rather than left to float to the newest on
    disk. They stay in :data:`NONE_IS_UNSET` so `none` remains an explicit
    "use the newest" escape hatch, but they ship a real default, not the sentinel.
    """
    pinned = {"TRIAGE_SYNTHESIS_PROMPT_VERSION", "VERIFY_PROMPT_VERSION"}
    base = config._base_defaults()
    for var in config.NONE_IS_UNSET:
        shipped = base.get(var)
        assert shipped, f"{var} missing from default.env"
        if var in pinned:
            assert shipped not in ("none", ""), (
                f"{var} is pinned to a concrete version, not the `none` sentinel")
        else:
            assert shipped == "none", f"{var} should ship as the `none` sentinel"
        monkeypatch.setenv(var, "none")
        assert config.default_for(var) == "", f"{var}=none must resolve to ''"
        monkeypatch.setenv(var, "NONE")            # case-insensitive
        assert config.default_for(var) == ""
        monkeypatch.setenv(var, "fireworks")       # a real value passes through
        assert config.default_for(var) == "fireworks"
        monkeypatch.delenv(var, raising=False)

    # …and `none` is NOT normalised for a var where it is a real value.
    monkeypatch.setenv("SHARED_AUTH_MODE", "none")
    assert config.default_for("SHARED_AUTH_MODE") == "none"


def test_loading_the_env_turns_the_none_sentinel_into_unset(monkeypatch, tmp_path):
    """A direct ``os.getenv`` reader sees the sentinel as unset too.

    Loaded raw, ``VERIFY_MAX_DISPATCH_RULE=none`` (the ``default.env`` value) reached
    :meth:`DispatchBudget.from_env` as a rule cap and raised, on any checkout whose
    ``.env`` kept the template value.
    """
    import os

    from dast_orchestrator.domain.verification import DispatchBudget

    env = {k: v for k, v in os.environ.items() if k not in config.NONE_IS_UNSET}
    monkeypatch.setattr(os, "environ", env)
    (tmp_path / ".env").write_text("VERIFY_MAX_DISPATCH_RULE=none\nSHARED_AUTH_MODE=none\n")
    config.load_stage_env("verify", env_file=tmp_path / ".env")
    assert os.environ["VERIFY_MAX_DISPATCH_RULE"] == ""
    assert DispatchBudget.from_env().rule_caps == ()
    assert os.environ["SHARED_AUTH_MODE"] == "none"     # a real value elsewhere
