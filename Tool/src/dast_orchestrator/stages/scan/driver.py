"""``dast scan`` — argparse plus orchestration for the scan stage.

Builds the parser, resolves the target and config, and calls
:func:`~dast_orchestrator.stages.scan.pipeline.run_scan`. The thin CLI entry;
the work lives in ``pipeline`` / ``common``.
"""
from __future__ import annotations
import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any
import httpx
from dast_orchestrator.foundation import config
from dast_orchestrator.adapters import zap_plan
from dast_orchestrator.adapters import auth
from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters.noir_runner import NoirError
from dast_orchestrator.adapters.zap_client import ZapError
from .common import *
from .pipeline import *

#: A scan failure a target with a `recovery` block can retry through: the target
#: dropped the connection mid-scan (Cacti's /JSON/core/action seed storm →
#: httpx.RemoteProtocolError) or ZAP could not reach it. NOT NoirError — a Noir
#: failure is static, so restarting the target cannot help it.
RECOVERABLE_SCAN_ERRORS = (httpx.TransportError, ZapError)
#: Total scan attempts for a recovery-capable target: one restart-and-retry.
SCAN_RETRY_ATTEMPTS = 2


def build_parser() -> argparse.ArgumentParser:
    """This stage's argument parser, built without parsing anything.

    Separate from :func:`main` so ``dast`` can read the flags this stage
    accepts — that is what lets one flag be routed to the right stage of a
    sequence, and an ambiguous one be refused by name rather than silently
    applied to the wrong stage. Defaults still come from the environment, so
    the caller loads the stage's env file first.
    """
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "scan")
    # The user-facing package docstring, not this driver's developer docstring —
    # the SAME source `dast commands` renders, so --help and COMMANDS.md agree.
    from dast_orchestrator.stages import scan as _pkg
    parser = argparse.ArgumentParser(
        description=config.command_description(_pkg.__doc__), parents=[pre])
    parser.add_argument(
        "target_name", metavar="<target>",
        help="Which target to scan — a directory under targets/, e.g. `gitea`. "
             "It supplies the base URL, the source tree and the path-var "
             "defaults.",
    )
    parser.add_argument(
        "--data-dir", type=Path, default=DATA_DIR,
        help="Where this run's directory is created.",
    )
    parser.add_argument(
        "--zap-addr", default=config.default_for("SCAN_ZAP_ADDR"),
        help="Where the ZAP daemon's REST API is reached. The host-published "
             "address, not the container name — ZAP is driven from the host, "
             "only the scan traffic goes over dast-net.",
    )
    parser.add_argument(
        "--api-key", default=os.getenv("SCAN_ZAP_API_KEY", ""),
        help="The API key the ZAP daemon requires on every REST call. Any "
             "non-empty string; it must match the daemon's configured key.\n"
             "Supply it through the env/secrets file — a key on a command line "
             "is visible in ps and shell history to every process on the host.",
    )
    parser.add_argument(
        "--target", default=os.getenv("SCAN_TARGET_URL"),
        help="Override the base URL the scan is pointed at.\n"
             "Falls back to the target's own base URL.",
    )
    parser.add_argument(
        "--max-active-scan-minutes", type=int,
        default=int(config.default_for("SCAN_ZAP_MAX_ACTIVE_SCAN_MINUTES")),
        help="Cap total active-scan wall time; -1 removes the cap.\n"
             "Bounds the active scanner only — the spider has its own caps "
             "(--browser-spider-minutes, --max-rule-minutes bounds each rule).",
    )
    parser.add_argument(
        "--max-rule-minutes", type=int, default=None,
        help="Cap per-rule active-scan wall time; -1 removes the cap. ZAP "
             "applies ONE number to every rule — there is no per-rule timer in "
             "its API.\n"
             "Falls back to the target's own `zap_scan.max_rule_minutes`, then "
             "the built-in; this flag and the env var outrank the target.",
    )
    parser.add_argument(
        "--no-noir", dest="use_noir", action="store_false",
        default=config.env_bool("SCAN_NOIR_ENABLED", True),
        help="Skip Noir static extraction and seeding; scan only what the "
             "spider crawls unaided.\n"
             "Pairs with --use-noir (the on switch); measures the coverage "
             "delta Noir seeding provides (Phase 1 behaviour).",
    )
    parser.add_argument(
        "--use-noir", dest="use_noir", action="store_true",
        help="Run Noir static extraction and seeding.\n"
             "The explicit on form of --no-noir, so an env file or a sheet row "
             "can set it either way without a flag.",
    )
    parser.add_argument(
        "--passive-only", action="store_true",
        default=config.env_bool("SCAN_ZAP_PASSIVE_ONLY"),
        help="Run everything up to and including the passive scan — Noir, "
             "seeding, the spider, the passive queue — but SKIP the active "
             "scan. A legitimate passive baseline: only passive-scanner alerts, "
             "no active probing touches the target.\n"
             "A different experiment from a full scan, so it carries its own "
             "configuration digest.",
    )
    parser.add_argument(
        "--reset-target", action="store_true",
        default=config.env_bool("SCAN_RESET_TARGET"),
        help="Reset the target to its clean, freshly-seeded state before "
             "scanning (the target stays persistent afterwards), via the "
             "target's own env/reset.sh. OFF by default: a persistent target "
             "models a permanent CI/CD staging environment, and the state "
             "prior authenticated scans accumulate in it (content, settings and "
             "the scanner's own footprint) is itself a finding. ON gives each "
             "scan a clean starting instance, so scan-volume variance is the "
             "scanner's rather than accumulation's.\n"
             "A structural parameter: a reset run carries its own "
             "configuration digest.",
    )
    parser.add_argument(
        "--noir-source", type=Path,
        default=Path(os.getenv("SCAN_NOIR_SOURCE_DIR")) if os.getenv("SCAN_NOIR_SOURCE_DIR") else None,
        help="Override the source tree Noir analyses.\n"
             "Falls back to the target's own tree, relative to the repo root.",
    )
    parser.add_argument(
        "--noir-image",
        default=config.default_for("SCAN_NOIR_IMAGE"),
        help="Pinned Noir image.",
    )
    parser.add_argument(
        "--zap-mode", dest="zap_mode", choices=ZAP_MODES,
        default=config.default_for("SCAN_ZAP_MODE"),
        help="How ZAP is driven. `rest` sequences the scan over the REST API — "
             "every option is set in one visible place and the run records what "
             "it did. `af` hands crawling and scanning to an Automation "
             "Framework plan instead (how ZAP is normally driven in CI, more "
             "portable), moving those decisions into a YAML this code does not "
             "read.\n"
             "`af` takes its plan from --zap-plan. The two modes are NOT "
             "comparable runs; the mode is part of the configuration digest.",
    )
    parser.add_argument(
        "--zap-plan", dest="zap_plan", default=config.default_for("SCAN_ZAP_PLAN"),
        help="The Automation Framework plan for --zap-mode af. A plan named "
             "here that does not exist is an error, not a fall-through — naming "
             "one is a statement about how the run is driven. The file's SHA-256 "
             "is recorded so a result matches the YAML that produced it.\n"
             "Used only with --zap-mode af; falls back to the target's own "
             "targets/<name>/zap.yml when it has one.",
    )
    parser.add_argument(
        "--keep-zap-session", "--keep-session", dest="keep_session",
        action="store_true",
        default=config.env_bool("SCAN_ZAP_KEEP_SESSION"),
        help="Leave the run's ZAP session file in the daemon instead of "
             "removing it. It holds every request and response of the scan, so "
             "a run can be reopened in ZAP Desktop — a debugging affordance, "
             "not an artifact (gigabytes per run; the message sidecar already "
             "carries the exchanges the pipeline reads).\n"
             "Kept sessions accumulate until removed by hand.",
    )
    parser.add_argument(
        "--zap-container", dest="zap_container", default=config.default_for("SCAN_ZAP_CONTAINER"),
        help="The daemon's container name. Used only to deliver an automation "
             "plan into it with `docker cp` — runPlan takes a path inside the "
             "container and the daemon has no bind mount.\n"
             "Relevant only with --zap-mode af.",
    )
    parser.add_argument(
        # Both spellings: `--spider` is what you type, `--spiders` is what the
        # dest and SCAN_ZAP_SPIDERS are called, and the flag-vs-variable drift test
        # checks the latter.
        "--spider", "--spiders", dest="spiders", default=config.default_for("SCAN_ZAP_SPIDERS"),
        help="Which crawlers to run, comma-separated and in order: "
             "traditional, ajax, client. Order matters — each adds to the tree "
             "the previous built, so the cheap HTML pass first means the "
             "browser crawlers start from a populated tree.\n"
             "KEEP `traditional` in any list: every recorded coverage number "
             "came from it alone, so dropping it moves the baseline. `client` "
             "needs a browser (present on the pinned image); its cap is "
             "--browser-spider-minutes.\n"
             "Empty falls back to the target's own `spiders:` list, then to "
             "`traditional`.",
    )
    parser.add_argument(
        "--browser-spider-minutes", "--ajax-spider-minutes",
        type=int, default=int(config.default_for("SCAN_ZAP_BROWSER_SPIDER_MINUTES")),
        help="Wall-clock cap for EITHER browser-driven crawler (the AJAX and "
             "client spiders). Neither reports completion usefully — the AJAX "
             "spider has no duration option and the client spider's status is "
             "not monotonic (seen climbing to 93 then dropping to 72), so "
             "waiting for 100 hangs.\n"
             "The client spider also stops once the tree stops growing; this "
             "cap is the backstop. Selected by --spider.",
    )
    parser.add_argument(
        "--injectable-targets", type=int,
        default=int(config.default_for("SCAN_ZAP_INJECTABLE_TARGETS")),
        help="ZAP injectable-target bitmask, summed: query-string 1, post-data "
             "2, cookie 4, http-headers 8, url-path 16.\n"
             "ZAP's own default omits url-path, which leaves Noir-seeded "
             "endpoints uninjectable — this pipeline includes it.",
    )
    parser.add_argument(
        "--add-query-param", action="store_true",
        default=config.env_bool("SCAN_ZAP_ADD_QUERY_PARAM"),
        help="Let ZAP append a synthetic query parameter to URLs that declare "
             "none, reaching inputs no endpoint declares. A finding on it "
             "concerns a guessed parameter — report it as a separate scan mode.",
    )
    parser.add_argument(
        "--path-var", action="append", default=[], metavar="<name>=<value>",
        help="Override one route-placeholder substitution, e.g. --path-var "
             "username=thesis.\n"
             "Falls back to the target's own path-var defaults.",
    )
    parser.add_argument(
        "--disable-rule", action="append", dest="disabled_rules", default=[],
        metavar="<rule-id>",
        help="An active-scan rule to switch off, by ZAP rule id.\n"
             "With none given, a built-in noisy-rule set is disabled "
             "(DEFAULT_DISABLED_RULES); --keep-all-rules runs every rule "
             "instead.",
    )
    parser.add_argument(
        "--keep-all-rules", action="store_true",
        help="Run every active rule, including the noisy ones. Reproduces the "
             "older behaviour before the noisy rules were disabled; expect rule "
             "10104 to dominate the alerts and heavy ZAP memory use.\n"
             "Overrides --disable-rule's built-in set.",
    )
    parser.add_argument(
        "--max-alerts-per-rule", type=int,
        default=int(config.default_for("SCAN_ZAP_MAX_ALERTS_PER_RULE")),
        help="Cap alerts from any single passive rule; -1 removes the cap.\n"
             "ZAP's own baseline uses 10; on this target the cap value did not "
             "change the maximum alerts per rule, so whatever it counts is not "
             "alerts-per-rule-per-run here.",
    )
    parser.add_argument(
        "--auth", choices=("none", "user", "admin"),
        default=config.default_for("SHARED_AUTH_MODE"),
        help="Scan authenticated as the target's seeded 'user' or 'admin' "
             "account, or 'none' for anonymous. Most of the CVE cluster sits "
             "behind login, so this is the biggest lever on detection rate.\n"
             "Runs at each mode are separate and not comparable across modes.",
    )
    config.add_targets_dir_flag(parser)
    parser.add_argument(
        "--oracle", dest="oracle", action="store_true",
        default=config.env_bool("SHARED_ORACLE"),
        help="Oracle-guided (ceiling) mode: additionally seed the benign sinks of "
             "this target's documented CVE markers (cve-markers.yml `seed:`) — "
             "surfaces no static extractor names and no crawler discovers. "
             "Measures what the pipeline could detect GIVEN we point the scanner "
             "at the known sinks; the gap from a blind run is what discovery "
             "costs.\n"
             "Changes the scan's configuration digest, so an oracle run and a "
             "blind run never share a corpus. The LLM stages take the same flag "
             "to be TOLD the vulnerabilities — this is its scan-stage half.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Run even though another process holds this stage's lock on the "
             "run directory. Overrides the refusal; it does not coordinate the "
             "two runs.",
    )
    config.normalize_metavars(parser)
    return parser


@run_lock.guarded
def main(argv: "list[str] | None" = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "scan")
    known, _ = pre.parse_known_args(argv)
    # Loaded before the parser is built, so every ``os.getenv`` default below
    # sees the stage's file and an explicit flag still wins (see config.py).
    env = config.load_stage_env("scan", known.env_file)

    parser = build_parser()
    args = parser.parse_args(argv)
    overridden = config.apply_explicit_overrides(env, args, parser, argv)
    if overridden:
        ui.warn(f"{ui.short_path(known.env_file)} supplies (no flag given): "
                f"{', '.join(sorted(overridden))}")

    if not args.api_key:
        ui.error(f"{config.REQUIRED_SECRETS['scan']} is not set "
                 "(export it or pass --api-key).")
        return 2

    # Point discovery and source resolution at the configured targets dir before
    # any target is looked up — flag > env-file > env > the tool's own targets/.
    targets.use_dir(args.targets_dir)

    try:
        target = targets.get(args.target_name)
        # Flag beats the target's own list beats `traditional`. Resolved here so
        # the run records what it actually crawled with, never a default that
        # might move under a later edit.
        try:
            spiders = (parse_spiders(args.spiders) if args.spiders
                       else parse_spiders(target.spiders) if target.spiders
                       else DEFAULT_SPIDERS)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        # Flag beats the target's own zap.yml. Resolved before anything runs so
        # a missing plan fails in a second rather than after the seeding.
        try:
            plan_path = zap_plan.resolve_plan(
                args.zap_plan, target.name, targets.TARGETS_DIR)
        except zap_plan.PlanError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        if args.zap_mode == ZAP_MODE_AF and plan_path is None:
            print(f"ERROR: --zap-mode af needs a plan: pass --zap-plan, or put "
                  f"a {zap_plan.PLAN_BASENAME} in targets/{target.name}/",
                  file=sys.stderr)
            return 2
    except KeyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # The target supplies the defaults; env/flags override. Path-var flags layer
    # on top of the target's set rather than replacing it.
    target_url = args.target or target.base_url
    source_dir = args.noir_source or targets.target_source(target)
    path_vars = {**target.path_vars, **noir_runner.parse_path_vars(args.path_var)}

    # A source override that is not the target's own tree is almost always a
    # stale ``SCAN_NOIR_SOURCE_DIR`` left in the shell — a real env var outranks the
    # target's ``source_dir`` by design, so it silently analyses one target's
    # code under another target's run id (measured: a wordpress run pointed at
    # `gitea-src`). Surface it; the run still proceeds, because a deliberate
    # ``--noir-source`` override is legitimate.
    if args.noir_source and source_is_foreign(source_dir, target.name):
        ui.warn(
            f"Noir source {source_dir} is not under targets/{target.name}/ — "
            f"analysing it against a {target.name} scan. If that is unintended "
            f"it is probably a stale SCAN_NOIR_SOURCE_DIR in your shell; "
            f"`unset SCAN_NOIR_SOURCE_DIR`."
        )

    # Oracle (ceiling) mode: the documented CVE sinks to seed, read from this
    # target's markers. Empty unless --oracle, so a blind run seeds none of them.
    # A missing/malformed markers file is not fatal here — a blind scan needs no
    # markers, and `ground-truth assess` is where a broken markers file fails
    # loudly — so an oracle run with no markers seeds nothing and says so.
    oracle_seeds: tuple[str, ...] = ()
    if args.oracle:
        try:
            from dast_orchestrator.stages import ground_truth
            oracle_seeds = tuple(ground_truth.MarkerSet.load(target.name).oracle_seeds())
        except (FileNotFoundError, ValueError) as exc:
            ui.warn(f"--oracle: could not read CVE marker seeds for "
                    f"{target.name}: {exc}")
        if not oracle_seeds:
            ui.warn(f"--oracle set, but {target.name} has no marker `seed:` "
                    "entries — nothing extra is seeded, so this is a blind scan "
                    "under an oracle name.")

    def _scan_once(auth_session):
        rule_minutes = resolve_rule_minutes(args.max_rule_minutes, target)
        # Before anything is spawned, and with the numbers the stage will
        # actually run with rather than the ones the flags happened to hold.
        config.warn_if_unbounded(args, {"max_rule_minutes": rule_minutes})
        run_scan(
            args.zap_addr, args.api_key, target_url,
            args.max_active_scan_minutes, rule_minutes,
            use_noir=args.use_noir,
            source_dir=source_dir,
            noir_image=args.noir_image,
            path_vars=path_vars,
            injectable_targets=args.injectable_targets,
            add_query_param=args.add_query_param,
            auth_session=auth_session,
            target_name=target.name,
            disabled_rules=(
                () if args.keep_all_rules
                else tuple(args.disabled_rules or DEFAULT_DISABLED_RULES)
            ),
            max_alerts_per_rule=args.max_alerts_per_rule,
            data_dir=args.data_dir,
            noir_ignore_technologies=target.noir_ignore_technologies,
            # Oracle (ceiling) seeds only when --oracle: the documented CVE
            # sinks, read from the target's markers. Empty in a blind run, so its
            # tree is what discovery alone produced.
            oracle_seeds=oracle_seeds,
            openapi_specs=target.openapi_specs,
            target_dir=targets.TARGETS_DIR / target.name,
            spiders=spiders,
            browser_spider_minutes=args.browser_spider_minutes,
            zap_mode=args.zap_mode,
            plan_path=plan_path,
            zap_container=args.zap_container,
            # A property of how the target routes, so it comes from the target
            # definition and has no flag: turning it off for one run would
            # produce a differently-shaped corpus under a name that says
            # nothing about it, and the honest way to compare is two targets or
            # two deliberate baselines.
            structural_parameters=target.structural_parameters,
            # Same reasoning: a header-gated sink is a property of the
            # application, so the header the scanner must carry comes from the
            # target definition and has no flag.
            scan_headers=target.scan_headers,
            # Same reasoning: which active rules this target weakens or turns
            # off is a property of what the application IS, so it comes from
            # the target definition and has no flag.
            scan_rules=target.scan_rules,
            keep_session=args.keep_session,
            passive_only=args.passive_only,
            reset_target=args.reset_target,
            force=args.force,
        )

    # A target that declares how to recover (only Cacti — it deadlocks under
    # sustained scanning and its seed flakes) gets a restart-and-retry when the
    # scan drops the connection; every other target runs exactly once, as before.
    attempts = SCAN_RETRY_ATTEMPTS if target.recovery is not None else 1
    for attempt in range(1, attempts + 1):
        auth_session = None
        if args.auth != "none":
            if target.auth is None:
                print(f"ERROR: target {target.name!r} defines no login flow; "
                      "cannot run --auth.", file=sys.stderr)
                return 2
            if args.reset_target:
                # run_scan logs in after its reset: a login before it would hold a
                # session the reset removes, and fails on a target an earlier scan
                # left broken, which the reset is about to repair.
                auth_session = PendingLogin(args.auth)
            else:
                try:
                    auth_session = auth.login(target_url, target.auth, args.auth)
                except auth.AuthError as exc:
                    print(f"ERROR: authentication failed: {exc}", file=sys.stderr)
                    return 1
        try:
            _scan_once(auth_session)
            return 0
        except auth.AuthError as exc:
            print(f"ERROR: authentication failed: {exc}", file=sys.stderr)
            return 1
        except RECOVERABLE_SCAN_ERRORS as exc:
            if attempt >= attempts:
                # Recovery exhausted, or this target has none: keep the prior
                # contract — a ZapError is a clean exit 1, anything else (a raw
                # transport error) propagates as it always did.
                if isinstance(exc, ZapError):
                    print(f"ERROR: {exc}", file=sys.stderr)
                    return 1
                raise
            ui.warn(f"scan of {target.name} failed ({type(exc).__name__}: {exc}); "
                    f"restarting the target and retrying "
                    f"(attempt {attempt + 1} of {attempts})")
            if not recover_target(target.name):
                print(f"ERROR: {target.name} did not return to a loginable state; "
                      "not retrying.", file=sys.stderr)
                return 1
        except NoirError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    return 1


__all__ = [
    'build_parser',
    'main',
]
