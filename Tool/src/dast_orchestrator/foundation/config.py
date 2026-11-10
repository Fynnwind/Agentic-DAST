"""Per-stage configuration: one env file per command, and every value is also a flag.

``config/scanner/{.env,secrets.env}`` splits secrets from the rest, so the agent can read
config to keep variables/flags/docs in sync without seeing a key; :data:`STAGE_FLAGS` is
the single value↔flag table, drift-tested both ways. Precedence, most specific first: an
explicit flag > a named ``--env-file`` > a default file > the built-in default (values load
into the environment before argparse computes defaults). → DECISIONS.md.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any, NamedTuple

from dast_orchestrator.foundation import ui

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The default config directory, used when no `--env-file` points elsewhere.
DEFAULT_ENV_DIR = REPO_ROOT / "config" / "scanner"

SECRETS_FILE = "secrets.env"

#: Every stage reads the same file; the stage still selects which *flags* the
#: values may override (see :data:`STAGE_FLAGS`).
CONFIG_FILE = ".env"

#: The committed template AND the single source of truth for every flag's default.
#: It is loaded as the always-present BASE beneath ``.env`` (see
#: :func:`load_stage_env`), so a parser's default resolves from here even with no
#: ``.env`` — which is why parsers carry no literal fallbacks (:func:`default_for`).
DEFAULT_ENV_FILE = "default.env"

#: An env file holds strings, so a boolean is a *word*. One reader for all of
#: them, so ``on``/``off`` mean what they say everywhere and are not, like a bare
#: ``bool("false")``, silently true. ``true``/``false``/``1``/``0``/``yes``/``no``
#: are accepted too; anything else falls back to the flag's default.
_TRUE_WORDS = frozenset({"1", "true", "yes", "on"})
_FALSE_WORDS = frozenset({"0", "false", "no", "off", ""})


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean env var by word (``on``/``off``/…), not by truthiness."""
    raw = os.getenv(name)
    if raw is None:
        return default
    word = raw.strip().lower()
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    return default

#: ``stage -> {argparse dest: env var}``. The single source of truth for "every
#: env var is a flag": :mod:`tests.test_config` walks it against the variables
#: the code actually reads and against each command's parser.
STAGE_FLAGS: dict[str, dict[str, str]] = {
    "scan": {
        "api_key": "SCAN_ZAP_API_KEY",
        "zap_addr": "SCAN_ZAP_ADDR",
        "target": "SCAN_TARGET_URL",
        "auth": "SHARED_AUTH_MODE",
        "targets_dir": "SHARED_TARGETS_DIR",
        "max_active_scan_minutes": "SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES",
        "max_rule_minutes": "SCAN_ZAP_MAX_RULE_MINUTES",
        "injectable_targets": "SCAN_ZAP_INJECTABLE_TARGETS",
        "add_query_param": "SCAN_ZAP_ADD_QUERY_PARAM",
        "passive_only": "SCAN_ZAP_PASSIVE_ONLY",
        "reset_target": "SCAN_RESET_TARGET",
        "use_noir": "SCAN_NOIR_ENABLED",
        "max_alerts_per_rule": "SCAN_ZAP_MAX_ALERTS_PER_RULE",
        "noir_image": "SCAN_NOIR_IMAGE",
        "noir_source": "SCAN_NOIR_SOURCE_DIR",
        "zap_mode": "SCAN_ZAP_MODE",
        "keep_session": "SCAN_ZAP_KEEP_SESSION",
        "zap_plan": "SCAN_ZAP_PLAN",
        "zap_container": "SCAN_ZAP_CONTAINER",
        "spiders": "SCAN_ZAP_SPIDERS",
        "browser_spider_minutes": "SCAN_ZAP_BROWSER_SPIDER_MINUTES",
    },
    "triage": {
        "prompt_cache": "SHARED_PROMPT_CACHE",
        "prompt_cache_triage": "TRIAGE_PROMPT_CACHE",
        "prompt_cache_retrieval": "TRIAGE_PROMPT_CACHE_RETRIEVAL",
        "screening_model": "TRIAGE_SCREENING_MODEL",
        "synthesis_model": "TRIAGE_SYNTHESIS_MODEL",
        # One provider setting per model setting above (no bare "sets both"
        # flag): each pass sets its own model and provider explicitly.
        "screening_provider": "TRIAGE_SCREENING_PROVIDER",
        "synthesis_provider": "TRIAGE_SYNTHESIS_PROVIDER",
        "synthesis_providers": "TRIAGE_SYNTHESIS_PROVIDERS",
        "synthesis_repeats": "TRIAGE_SYNTHESIS_REPEATS",
        "synthesis_timeout_seconds": "TRIAGE_SYNTHESIS_TIMEOUT_SECONDS",
        "synthesis_max_prompt_tokens": "TRIAGE_SYNTHESIS_MAX_PROMPT_TOKENS",
        "synthesis_models": "TRIAGE_SYNTHESIS_MODELS",
        "concurrency": "TRIAGE_CONCURRENCY",
        "peer_context": "TRIAGE_PEER_CONTEXT",
        "http_context": "TRIAGE_HTTP_CONTEXT",
        "code_context": "TRIAGE_CODE_CONTEXT",
        "code_context_hops": "TRIAGE_CODE_CONTEXT_MAX_HOPS",
        "code_context_lines": "TRIAGE_CODE_CONTEXT_MAX_LINES",
        "retrieval": "TRIAGE_RETRIEVAL",
        "retrieval_max_calls": "TRIAGE_RETRIEVAL_MAX_CALLS",
        "max_alerts_per_call": "TRIAGE_MAX_ALERTS_PER_CALL",
        "use_llm": "TRIAGE_LLM_ENABLED",
        "screening_prompt": "TRIAGE_PROMPT_VERSION",
        "synthesis_prompt": "TRIAGE_SYNTHESIS_PROMPT_VERSION",
        # Oracle-guided mode. Shared with `verify` deliberately: one switch
        # turns the ceiling on for the whole chain, because a run where triage
        # knew the answer and verification did not is neither a ceiling nor a
        # blind run. See `dast_orchestrator.analysis.oracle`.
        "oracle": "SHARED_ORACLE",
        "stage_max_cost": "SHARED_STAGE_MAX_COST_USD",
        "run_max_cost": "SHARED_RUN_MAX_COST_USD",
        "use_synthesis": "TRIAGE_SYNTHESIS_ENABLED",
        "max_endpoints": "TRIAGE_MAX_ENDPOINTS",
        "max_unmatched_findings": "TRIAGE_MAX_UNMATCHED_FINDINGS",
        "screening_max_minutes": "TRIAGE_SCREENING_MAX_MINUTES",
        "prune_noninteractive_php": "TRIAGE_PRUNE_NONINTERACTIVE_PHP",
        "dry_run": "TRIAGE_DRY_RUN",
    },
    # Four knobs where there were nine. The old set — a residue model, a probe
    # model, a routing preference, and three booleans deciding which of three
    # arms ran — described a stage assembled from pieces; these describe one
    # loop with one axis (invocation). See `verify.py`'s module docstring.
    "verify": {
        "prompt_cache": "SHARED_PROMPT_CACHE",
        "prompt_cache_verify": "VERIFY_PROMPT_CACHE",
        "model": "VERIFY_MODEL",
        "provider": "VERIFY_PROVIDER",
        "invocation": "VERIFY_INVOCATION",
        "retrieval": "VERIFY_RETRIEVAL",
        "retrieval_max_calls": "VERIFY_RETRIEVAL_MAX_CALLS",
        "max_rounds": "VERIFY_MAX_ROUNDS",
        "verify_prompt": "VERIFY_PROMPT_VERSION",
        "auth": "SHARED_AUTH_MODE",
        "targets_dir": "SHARED_TARGETS_DIR",
        "tool_timeout": "VERIFY_TOOL_TIMEOUT_SECONDS",
        "max_dispatch_all_rules": "VERIFY_MAX_DISPATCH_ALL_RULES",
        "max_dispatch_rule": "VERIFY_MAX_DISPATCH_RULE",
        "max_dispatches_total": "VERIFY_MAX_DISPATCHES_TOTAL",
        "max_minutes": "VERIFY_MAX_MINUTES",
        "max_siblings": "VERIFY_MAX_SIBLINGS",
        "oracle": "SHARED_ORACLE",
        "oracle_seed_dispatch": "VERIFY_ORACLE_SEED_DISPATCH",
        "oob": "VERIFY_OOB",
        "stage_max_cost": "SHARED_STAGE_MAX_COST_USD",
        "run_max_cost": "SHARED_RUN_MAX_COST_USD",
        "interactsh_server": "VERIFY_INTERACTSH_SERVER",
        "nuclei_templates_volume": "VERIFY_NUCLEI_TEMPLATES_VOLUME",
        "dry_run": "VERIFY_DRY_RUN",
    },
    "static-analysis": {
        "only": "STATIC_ANALYSIS_ONLY",
        "targets_dir": "SHARED_TARGETS_DIR",
        "dry_run": "STATIC_ANALYSIS_DRY_RUN",
    },
    "report": {},
}

#: Read by an MCP server rather than by a driver, so they have no flag of their
#: own on any command; listed so the drift test knows they are accounted for.
#:
#: The ``DAST_CONTEXT_*`` four configure the read-only context server
#: (``mcp/context_server.py``), which is spawned per retrieval session and told
#: which run it is serving. They are **not** run configuration in the sense the
#: rest of this table is: three of them are paths the correlator derives from
#: the run it is already working on, so a flag for them would be a way to point
#: one run's retrieval at another run's artifacts.
WRAPPER_ONLY = frozenset({
    "VERIFY_INTERACTSH_COOLDOWN_SECONDS",
    "VERIFY_INTERACTSH_DNS",
    "TRIAGE_CONTEXT_MESSAGES",
    "TRIAGE_CONTEXT_SOURCE",
    "TRIAGE_CONTEXT_INDEX",
    "TRIAGE_CONTEXT_MAX_CHARS",
})

#: Facts about *where the process is running*, not about how a stage is
#: configured — so they are deliberately not flags. ``CI`` is set by every major
#: CI system and makes :class:`ui.Progress` emit stepped lines even when a pty
#: was allocated; a ``--ci`` flag would be a thing to remember to pass in the one
#: situation where nobody is watching.
#: ``HARNESS_ID`` / ``HARNESS_ROW`` are set by the harness on each
#: stage subprocess it spawns, so a metrics record can state which sheet
#: execution produced it. Facts about the caller, not settings a person chooses,
#: so a flag for them would be a way to claim membership of a sheet that never
#: ran.
ENVIRONMENT_ONLY = frozenset({"CI", "HARNESS_ID", "HARNESS_ROW"})

#: Never printed, never logged, never written to an artifact.
#:
#: These deliberately have **no flag of their own** — the one exception to
#: "every variable is a flag". A key passed on a command line is recorded in
#: shell history and visible in ``ps`` to every process on the machine, so it
#: comes from a file or the environment, never from an argument.
#: (``SCAN_ZAP_API_KEY`` keeps its long-standing ``--api-key`` flag for local use,
#: and is listed here so it is redacted wherever configuration is displayed.)
#: **The one value that means "no limit", on every flag in this project that has
#: such a value.** ``-1``, never ``0``.
#:
#: It was ``0`` on the scan caps and ``-1`` on the verification caps, which is
#: two conventions for one idea and a coin flip every time a reader meets a new
#: flag. ``-1`` wins because ``0`` has to keep its arithmetic meaning:
#: ``--max-dispatch-rule 10031=0`` reads as *never dispatch that rule*, and a
#: ``--max-active-scan-minutes 0`` that silently meant *unlimited* is the reading most
#: likely to be got wrong in the direction that costs 45 minutes.
#:
#: ZAP's own API uses ``0`` for unlimited on the options it exposes. That
#: translation belongs at the adapter boundary and nowhere else — see
#: :func:`dast_orchestrator.adapters.zap_client.zap_unlimited`.
NO_LIMIT = -1

#: Every ceiling a stage may run without, as ``dest -> what it bounds``. The
#: keys are flag dests, so a stage's parsed arguments can be checked directly.
#:
#: A run with one of these at :data:`NO_LIMIT` is legitimate and sometimes
#: necessary — "what would the 83 findings the budget dropped have said?" is a
#: real question, and it is the reason the sentinel exists. What it must never
#: be is *quiet*: a run whose numbers came from an unbounded stage is not
#: comparable with one that was bounded, and the reader of the artifact is
#: usually not the person who typed the command.
#:
#: **``max_alerts_per_rule`` is deliberately not here**, though it takes the same
#: sentinel and ships unbounded. It caps how many alerts one *passive* rule may
#: report — output volume, not work — so switching it off cannot make a stage
#: fail to terminate or cost more. Capping it is what would be dangerous: rule
#: ``10031`` supplies most of the deterministic arm's flags, and ZAP's own
#: default of 10 leaves the LLM arm and the verification stage with almost
#: nothing to judge. Warning about the shipped default would also make the
#: warning noise, which is how a warning stops being read.
UNBOUNDED_WARNINGS = {
    "max_active_scan_minutes": "the active scan has no time ceiling",
    "max_rule_minutes": "no active-scan rule has a time ceiling",
    "max_dispatch_all_rules": "no ZAP rule has a dispatch ceiling",
    "max_dispatches_total": "the run has no total dispatch ceiling",
    "max_minutes": "the dispatch stage has no time ceiling",
    "screening_max_minutes": "pass 1 has no time ceiling",
    "tool_timeout": "no single tool invocation has a timeout",
    "max_rounds": "a verification loop has no round ceiling",
}


def unbounded(args: Any, extra: "dict[str, Any] | None" = None) -> list[str]:
    """Which ceilings this invocation switched off, in readable form.

    :param extra: values resolved outside the parser — a target's own
        ``max_rule_minutes``, a budget assembled from flag + env + defaults —
        keyed by the same dests. Checked *after* the parser's, because what
        matters is the number the stage will actually run with, not the one the
        flag happened to hold.
    """
    values = {dest: getattr(args, dest, None) for dest in UNBOUNDED_WARNINGS}
    values.update({k: v for k, v in (extra or {}).items()
                   if k in UNBOUNDED_WARNINGS})
    return [UNBOUNDED_WARNINGS[dest] for dest, value in sorted(values.items())
            if value == NO_LIMIT]


def warn_if_unbounded(args: Any, extra: "dict[str, Any] | None" = None) -> None:
    """Say so, once, before the stage runs. Never refuses.

    Escalated when more than one is off, because that is the case a reader is
    most likely to mistake for an ordinary run: a single raised ceiling is
    usually a deliberate probe of one thing, while several at once means the
    stage was effectively unbounded and its numbers describe a different
    experiment from every stored one.
    """
    off = unbounded(args, extra)
    if not off:
        return
    if len(off) == 1:
        ui.warn(f"NO CEILING: {off[0]}. Deliberate settings, but this run's "
                "numbers are not comparable with a bounded one — say so "
                "wherever they are quoted.")
        return
    ui.warn(f"{len(off)} CEILINGS ARE OFF — " + "; ".join(off) + ". This stage "
            "is effectively unbounded: it may not terminate in any useful time, "
            "and its numbers describe a different experiment from every stored "
            "run. Intended only for a deliberate exhaustive measurement.")


SECRET_VARS = frozenset({"SHARED_OPENROUTER_API_KEY", "SCAN_ZAP_API_KEY"})

#: The secret each stage cannot run its key-consuming path without, as
#: ``stage -> env var`` — the single source both the runtime checks and the
#: ``⚐`` doc marker (:data:`command_docs.REQUIRED_ENV`) read from, so a new
#: required secret is declared in one place.
#:
#: The requirement is **conditional**: a stage needs its secret only on the path
#: that spends it (``triage`` with the LLM arm on, ``verify`` in an ``llm``
#: invocation; a ``--no-llm`` triage or a ``deterministic`` verify needs none).
#: Each stage keeps its own check, for standalone use and as the authority. The
#: **chain-wide pre-flight** that lists every missing secret for a whole ``dast
#: scan triage verify`` invocation at once — before the 45-minute scan runs into
#: a later stage's absent key — lives in the front end
#: (:func:`dast_orchestrator.cli.missing_secrets`), which resolves each stage's
#: arm the way the stage itself does before any stage runs.
REQUIRED_SECRETS: dict[str, str] = {
    "scan": "SCAN_ZAP_API_KEY",
    "triage": "SHARED_OPENROUTER_API_KEY",
    "verify": "SHARED_OPENROUTER_API_KEY",
}

#: The flat "must be set" set, derived from :data:`REQUIRED_SECRETS`, for the
#: env-column ``⚐`` marker in the generated command reference.
REQUIRED_ENV = frozenset(REQUIRED_SECRETS.values())


class LoadedEnv(NamedTuple):
    """What a stage's configuration load did, so a command can report it."""

    stage: str
    files: list[Path]
    values: dict[str, str]
    #: True when the user named a file with ``--env-file``; see the precedence
    #: note in the module docstring.
    explicit: bool

    def describe(self) -> str:
        if not self.files:
            return "no env file"
        names = ", ".join(p.name for p in self.files)
        return f"{names}{' (named; fills unset flags)' if self.explicit else ''}"


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse ``KEY=value`` lines. Comments, blanks and ``export`` are ignored."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


#: The sentinel that means "unset" in ``default.env`` — so an optional value ships
#: with an explicit word instead of a blank ``VAR=`` right-hand side.
SENTINEL_NONE = "none"

#: The flag vars for which ``none`` (case-insensitive) is normalised to ``""``
#: (:func:`default_for`, :func:`apply_explicit_overrides`, :func:`load_stage_env`), so their consumers —
#: which already treat empty as "unset / use the built-in behaviour" — need no
#: change. SCOPED on purpose: ``none`` is a *real* value elsewhere
#: (``SHARED_AUTH_MODE``, ``TRIAGE_CODE_CONTEXT``, ``TRIAGE_PEER_CONTEXT``), so a
#: blanket normalisation would corrupt those. Every entry is one of the nine
#: previously-blank lines in ``default.env``.
NONE_IS_UNSET = frozenset({
    "SCAN_ZAP_PLAN",
    "TRIAGE_SCREENING_PROVIDER",
    "TRIAGE_SYNTHESIS_PROVIDER",
    "TRIAGE_SYNTHESIS_MODELS",
    "TRIAGE_SYNTHESIS_PROVIDERS",
    "TRIAGE_SYNTHESIS_PROMPT_VERSION",
    "VERIFY_MAX_DISPATCH_RULE",
    "VERIFY_PROVIDER",
    "VERIFY_PROMPT_VERSION",
})


def _unset_sentinel(var: str, value: str) -> str:
    """Map the ``none`` sentinel to ``""`` for the scoped vars, else pass through."""
    if var in NONE_IS_UNSET and value.strip().lower() == SENTINEL_NONE:
        return ""
    return value


def _base_defaults() -> dict[str, str]:
    """The committed defaults from ``default.env`` — the SSOT, minus the secret
    placeholders (``change-me``/``your-key``), which are never real values.

    Not cached: the file is small, and a cache would go stale for the doc
    generator, which parses a chosen ``default.env`` per call.
    """
    parsed = parse_env_file(DEFAULT_ENV_DIR / DEFAULT_ENV_FILE)
    return {k: v for k, v in parsed.items() if k not in SECRET_VARS}


def default_for(var: str) -> str:
    """The default a flag resolves to — the single source of truth.

    Reads the live environment first, which :func:`load_stage_env` populates from
    ``default.env`` (the base), then ``.env`` / a named ``--env-file``, then the
    process environment — so this reflects the full precedence. It falls back to
    the committed ``default.env`` directly for callers that build a parser without
    loading env first (a unit test, ``--help`` before the load), and **raises** if
    the variable has no default anywhere.

    A ``STAGE_FLAGS`` variable missing from ``default.env`` is a bug, not a reason
    to invent a literal fallback in the parser: the literal is a second source of
    truth that drifts (``SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES`` once read 45 in the
    file and 5 in the parser). One place, or it fails loudly.
    """
    value = os.getenv(var)
    if value is None:
        base = _base_defaults()
        if var not in base:
            raise KeyError(
                f"{var}: no default in config/scanner/{DEFAULT_ENV_FILE}. Every "
                "flag variable's default lives there (the single source of truth) "
                "— add it there rather than a literal fallback in the parser.")
        value = base[var]
    # `none` is the "unset" sentinel for the scoped optional vars, resolved to ""
    # so their consumers (which already handle empty) are unchanged.
    return _unset_sentinel(var, value)


def config_and_secrets(
    env_file: "str | Path | None" = None,
    env_dir: "str | Path | None" = None,
) -> "tuple[Path, Path]":
    """The ``(config file, its secrets.env neighbour)`` a stage loads, in ONE place.

    With no ``--env-file`` the pair is the default ``config/scanner/{.env,
    secrets.env}``; with ``--env-file path/x.env`` the secrets are ITS neighbour,
    ``path/secrets.env``. This rule is easy to reimplement wrong — the harness
    once read only the base file and dropped the OpenRouter key — so both
    :func:`load_stage_env` and the harness's ``secret_env`` resolve it here
    rather than each pairing a file with a secrets neighbour of its own.
    """
    if env_file is not None:
        named = Path(env_file)
        return named, named.parent / SECRETS_FILE
    directory = Path(env_dir) if env_dir else DEFAULT_ENV_DIR
    return directory / CONFIG_FILE, directory / SECRETS_FILE


def load_stage_env(
    stage: str,
    env_file: "str | Path | None" = None,
    env_dir: "str | Path | None" = None,
) -> LoadedEnv:
    """Load one stage's configuration into ``os.environ`` and report what it did.

    Loading into the environment *before* argparse builds its defaults is what
    lets every existing ``os.getenv`` default keep working, and it is why an
    explicit flag still beats a file found by default.

    **Where ``secrets.env`` comes from.** With no ``--env-file`` the pair is the
    default one — ``config/scanner/{.env,secrets.env}``. With ``--env-file
    path/to/x.env`` the secrets are its *neighbour*, ``path/to/secrets.env`` — so
    pointing at a config file brings its keys along, and there is no separate
    directory flag to keep in step. The
    harness needs no ``secrets.env`` beside its overlay: it hands each stage
    subprocess the keys through the environment instead.

    A variable already set in the real environment is never overwritten: an
    export on the command line has to outrank a file on disk, or a one-off
    override becomes impossible to make.
    """
    explicit = env_file is not None
    config_file, secrets_file = config_and_secrets(env_file, env_dir)

    # `default.env` is the always-loaded committed BASE (the SSOT), then the config
    # file (`.env` or a named `--env-file`) overrides it, then `secrets.env`. Later
    # files win in the accumulator; the process environment then wins over all via
    # setdefault. The base's secret placeholders are dropped (`_base_defaults`), so
    # a real key from secrets.env / the environment is never masked.
    base = DEFAULT_ENV_DIR / DEFAULT_ENV_FILE
    loaded: list[Path] = []
    values: dict[str, str] = dict(_base_defaults())
    if base.is_file():
        loaded.append(base)
    for path in (config_file, secrets_file):
        parsed = parse_env_file(path)
        if not parsed and not path.is_file():
            continue
        loaded.append(path)
        values.update(parsed)

    # The `none` sentinel lands as "", so a direct `os.getenv` reader sees "unset" too.
    for key, value in values.items():
        os.environ.setdefault(key, _unset_sentinel(key, value))
    return LoadedEnv(stage, loaded, values, explicit)


def _typed_dests(parser: Any, argv: "list[str] | None") -> set[str]:
    """Which flag *dests* appeared on the command line.

    Scans the tokens for known option strings (``--flag`` and ``--flag=value``
    alike) and maps each to its ``dest``. Prefix abbreviations are deliberately
    not resolved: a user who abbreviates a flag simply falls back to the file for
    it, which is the safe direction. With no parser or no argv, nothing is
    considered explicit.
    """
    if parser is None:
        return set()
    by_option: dict[str, str] = {}
    for action in getattr(parser, "_actions", []) or []:
        for opt in getattr(action, "option_strings", []) or []:
            by_option[opt] = action.dest
    seen: set[str] = set()
    for token in argv or []:
        if not isinstance(token, str) or not token.startswith("-"):
            continue
        name = token.split("=", 1)[0]
        if name in by_option:
            seen.add(by_option[name])
    return seen


def apply_explicit_overrides(env: LoadedEnv, args: Any, parser: Any = None,
                             argv: "list[str] | None" = None) -> list[str]:
    """Apply a *named* env file to the flags the user did NOT type. Returns the
    dests it changed.

    Precedence, most specific first: **an explicit flag > a named ``--env-file``
    > a default file > the built-in default.** A flag you type on the command
    line is the most deliberate statement of intent there is, so it wins even
    over a file you named — the file is the base a stray flag *does not* silently
    override, but an intended one does. (A named file used to outrank even an
    explicit flag, which surprised anyone who typed ``--auth user`` beside
    ``--env-file`` and got ``none``.)

    A file discovered by default never reaches here — there the flag's own
    ``os.getenv`` default already carried the file's value, and an explicit flag
    beats its own default for free.

    :param argv: the tokens as typed, so a flag the user set can be left alone.
        Without it every mapped flag is treated as unset (the file fills all of
        them), which is the old behaviour and is what the two-argument test
        calls still exercise.
    :param parser: the stage's parser, so a value is converted with the **flag's
        own declared type** and so ``argv`` can be mapped to dests. Without it
        the type is guessed from whatever the flag currently holds, and that
        guess fails exactly where it matters: a flag whose default is ``None``
        (``--max-minutes``, every ``verify`` budget) has no type to copy, so its
        env value stayed a string and reached the code as one — a
        ``TypeError: '>' not supported between 'float' and 'str'`` minutes into a
        run. Always pass the parser.
    """
    if not env.explicit:
        return []
    typed = _typed_dests(parser, argv)
    types = {}
    for action in getattr(parser, "_actions", []) or []:
        if action.type is not None:
            types[action.dest] = action.type

    changed: list[str] = []
    for dest, var in STAGE_FLAGS.get(env.stage, {}).items():
        if var not in env.values or not hasattr(args, dest):
            continue
        if dest in typed:
            # The user typed this flag; it outranks even a named file.
            continue
        current = getattr(args, dest)
        coerced = _coerce(_unset_sentinel(var, env.values[var]), current,
                          types.get(dest))
        if coerced != current:
            setattr(args, dest, coerced)
            changed.append(dest)
    return changed


def _coerce(value: str, like: Any, declared: Any = None) -> Any:
    """Turn an env string into the type the flag expects.

    The flag's declared ``type`` wins when there is one; otherwise the type is
    inferred from the value the flag currently holds. Booleans are read from
    words rather than passed to ``bool()``, for which ``"false"`` is true.
    """
    if isinstance(like, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if declared is not None:
        try:
            return declared(value)
        except (TypeError, ValueError):
            return like
    if isinstance(like, int):
        try:
            return int(value)
        except ValueError:
            return like
    if isinstance(like, Path):
        return Path(value)
    return value


def add_env_flags(parser: Any, stage: str) -> None:
    """Add the two configuration flags every command shares."""
    parser.add_argument(
        "--env-file",
        help="Configuration file for this stage. It fills any setting not passed "
             "as a flag; an explicit flag always wins over it.\n"
             f"Falls back to config/scanner/{CONFIG_FILE}; keys come from a "
             f"{SECRETS_FILE} beside the file named here.",
    )


def add_targets_dir_flag(parser: Any) -> None:
    """The shared ``--targets-dir`` flag, for the four stages that read a target's
    source (scan/triage/verify/static-analysis).

    Points target discovery *and* source resolution at a directory outside the
    tool — the §R1 repo split, where the example-targets become a sibling repo.
    Applied early via :func:`dast_orchestrator.adapters.targets.use_dir` so the
    registry the stage resolves against is the configured one. Default: the tool's
    own ``targets/`` (``None`` here, resolved by ``use_dir``); ``SHARED_TARGETS_DIR``
    fills it from the environment or an env file, an explicit flag wins.
    """
    parser.add_argument(
        "--targets-dir", dest="targets_dir",
        default=os.getenv("SHARED_TARGETS_DIR"),
        help="Directory holding the <name>/target.yml definitions and the source "
             "trees they point at. Default: the tool's own targets/. Set it to "
             "reach an example-targets checkout outside the tool (the §R1 split).\n"
             "Shared by scan/triage/verify/static-analysis; a target's source_dir "
             "is resolved under this directory's parent.",
    )


def arg_type(action: argparse.Action) -> str:
    """The value-type of a flag's argument — ``int`` / ``float`` / ``url`` /
    ``path`` / ``string``.

    One source shared by the ``--help`` metavars (:func:`normalize_metavars`)
    and the Markdown value column (:mod:`command_docs`), so a flag reads the
    same in both.
    """
    if action.type is int:
        return "int"
    if action.type is float:
        return "float"
    if action.type is Path or isinstance(action.default, Path):
        return "path"
    default = action.default
    if action.dest in ("zap_addr", "target", "interactsh_server", "base_url") \
            or action.dest.endswith("_url") or (
            isinstance(default, str) and default.startswith("http")):
        return "url"
    if action.dest in ("env_file", "zap_plan", "noir_source", "source",
                       "rules_dir", "db_dir") or action.dest.endswith(
                           ("_file", "_dir", "_source")):
        return "path"
    return "string"


def normalize_metavars(parser: argparse.ArgumentParser) -> None:
    """Give every scalar value flag a consistent ``<type>`` metavar in ``--help``.

    Left to itself argparse names a flag's value by its upper-cased dest
    (``--zap-addr ZAP_ADDR``), which both echoes the env-var name — redundant on
    a help page, where the flag and the variable are bound — and reads
    inconsistently beside the flags that set an ad-hoc metavar (``N``, ``USD``,
    ``PATH``). Replace those with one vocabulary (:func:`arg_type`).

    Left untouched: a flag with ``choices`` (argparse's ``{a,b,c}`` *is* the list
    of values), a switch (takes no value), and a repeatable list flag (its
    metavar shows the ``<name>=<value>`` syntax the type name cannot).
    """
    for action in parser._actions:
        if not action.option_strings:            # positional
            continue
        if action.nargs == 0:                     # store_true/false, help — no value
            continue
        if action.choices:                        # {a,b,c} already shows the values
            continue
        if isinstance(action, argparse._AppendAction):  # list: keep its syntax metavar
            continue
        action.metavar = f"<{arg_type(action)}>"


#: reStructuredText that reads as noise on a plain ``--help`` page: a ``:role:``
#: cross-reference (kept as its last dotted component), an inline ````literal````
#: or ``` `literal` ``` span (unwrapped), and the trailing ``→ DECISIONS.md``-style
#: pointers the module-docstring convention adds for code readers.
_RST_ROLE = re.compile(r":[a-zA-Z:]+:`~?([^`]+)`")
_RST_LITERAL = re.compile(r"``?([^`]+?)``?")
_DOC_POINTER = re.compile(r"\s*→.*$", re.S)


def command_description(doc: "str | None") -> str:
    """A command's ``--help`` description, from its module docstring.

    The SAME source ``dast commands`` renders into COMMANDS.md, so the reference
    and the help page cannot drift — but rendered for a terminal: reStructuredText
    markup and the ``→ DECISIONS.md`` code-reader pointers are stripped, and the
    first paragraph (the user-facing summary) is kept. Whitespace is collapsed so
    argparse can reflow it.
    """
    para = (doc or "").strip().split("\n\n")[0]
    para = _DOC_POINTER.sub("", para)
    para = _RST_ROLE.sub(lambda m: m.group(1).rsplit(".", 1)[-1], para)
    para = _RST_LITERAL.sub(r"\1", para)
    return " ".join(para.split())


def redact(values: dict[str, str]) -> dict[str, str]:
    """Configuration with every secret replaced — safe to print or record."""
    return {
        k: ("<set>" if v else "<empty>") if k in SECRET_VARS else v
        for k, v in values.items()
    }
