"""The interactive front end (console script ``dast``): split ``[stage …] <target-or-run>
[flags]``, route each flag to the stage(s) that mean one setting by it, echo the plan, and
refuse an unsatisfiable sequence — adding no behaviour of its own.

The trailing argument is positional and required (a target for ``scan``, a run id
otherwise; ``latest`` is legal, never a flag, never defaulted); staged runs execute in
order sharing one resolved run id; the bare form is the full chain. Prerequisites are
checked before any work (:func:`plan`) so a gap is refused before a 45-minute scan, and a
flag is broadcast to every invoked stage sharing its argparse ``dest``
(:data:`config.STAGE_FLAGS`). → docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.stages import table as stage_table
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui

REPO_ROOT = Path(__file__).resolve().parents[3]
#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()

#: Spellings that used to name what to act on. **No stage accepts them any
#: more** — every stage takes a required positional instead — so these exist
#: only to answer a stale command line with the reason rather than with
#: "unknown flag". Removed along with ``TARGET_NAME`` as a target
#: selector: naming what to act on is not an option a command can do without,
#: so it is the argument.
RETIRED_FLAGS = ("--run", "--timestamp", "--target-name")

USAGE = """\
usage: dast [stage ...] <target-or-run-id> [options]

Commands are literal keywords; an argument one takes is shown in <angle
brackets> (a target name, a run id or `latest`, or a sheet):

  dast <target>                       the whole chain against a target
  dast scan <target>                  one stage; scan takes a target
  dast triage <run-id>                a later stage takes a run id
  dast verify report <run-id>         a sequence, run in the order written
  dast scan triage verify <target>    a sequence that creates the run, then reuses it
  dast static-analysis <target>       SAST + SCA over a target's source (standalone)
  dast harness <sheet>                a sheet of runs, unattended (--smoke to test)
  dast cve <run-id>                   measure CVE detection; auto-runs the --oracle counterpart
  dast cve <blind> <oracle>           compare a blind run against its --oracle run
  dast costs                          runtime + cost across every recorded run
  dast commands                       regenerate the command reference (COMMANDS.md)
  dast docs                           regenerate the API reference (docs/api/)

stages:   {stages}
targets:  {targets}

The trailing argument is required. `latest` is a legal run id and means the
newest run that holds what the first stage needs.

`static-analysis`, `cve`, `costs`, `commands` and `docs` are NOT stages — they
run standalone SAST/SCA, measure the pipeline, read across runs, or regenerate
docs — but they share the one `dast` entry point. Each keeps its own grammar:
`dast static-analysis --help`, `dast cve --help`, `dast costs --help`,
`dast commands --help`, `dast docs --help`.

options:  an option reaches every stage that means the same setting by it; a
          stage's own options are on `dast <stage> --help`.
  --env-file <path>    configuration file for the run; an option overrides it
  --data-dir <path>    where the run directory is created
  --out-suffix <string> name the OUTPUT variant (triage / verify / report)
  --in-suffix <string>  pick the INPUT variant (verify / report)
  --force              run despite another process's stage lock
"""


class CliError(ValueError):
    """A usage error: bad stage, missing positional, ambiguous or unknown flag."""


# -- argument routing ------------------------------------------------------


def split_argv(argv: list[str]) -> tuple[list[str], str, list[str]]:
    """``["scan", "triage", "gitea", "--auth", "user"]`` -> its three parts.

    Leading tokens are read as stage names until one is not a stage; that token
    is the positional, and everything after it is flags. A flag appearing before
    the positional is a usage error rather than a silent reordering — the
    grammar puts the subject before its modifiers, and accepting both orders
    would make ``dast scan --auth user gitea`` and ``dast scan --auth gitea``
    differ by a typo nobody would see.

    :returns: ``(stage names, positional, flag tokens)``.
    :raises CliError: if no positional is present.
    """
    names: list[str] = []
    index = 0
    while index < len(argv) and argv[index] in stage_table.STAGES:
        names.append(argv[index])
        index += 1
    if index >= len(argv):
        raise CliError(
            "no target or run id given. "
            + (f"`dast {' '.join(names)}` names stage(s) but nothing to act on."
               if names else "")
        )
    if argv[index].startswith("-"):
        raise CliError(
            f"expected a target or run id, found the option {argv[index]!r}. "
            "The positional comes before the options: "
            f"`dast {' '.join(names) or '<stage>'} <target-or-run-id> [options]`."
        )
    return names, argv[index], list(argv[index + 1:])


def owners_of(flag: str,
              stages: list[stage_table.Stage]) -> tuple[list[str], set[str], Any]:
    """Which of ``stages`` accept ``flag``, what each calls it, and its action.

    The ``dest`` set is what decides whether a flag with several owners is one
    setting or two different ones — see :func:`route_flags`.
    """
    owners: list[str] = []
    dests: set[str] = set()
    action = None
    for stage in stages:
        for candidate in stage.parser()._actions:
            if flag in candidate.option_strings:
                owners.append(stage.name)
                dests.add(candidate.dest)
                action = action or candidate
    return owners, dests, action


def route_flags(tokens: list[str],
                stages: list[stage_table.Stage]) -> dict[str, list[str]]:
    """Assign each flag to the stage — or stages — it belongs to.

    :returns: ``{stage name: argv fragment}``.
    :raises CliError: on an unknown flag, on one that names what to act on, or
        on one whose owners disagree about what it means.

    **When several stages accept a flag, the question is whether they mean the
    same setting by it — and the codebase already answers that: the argparse
    ``dest``.** ``dest`` is the join key :data:`config.STAGE_FLAGS` uses to map a
    stage's flag onto its environment variable, so two stages naming a flag the
    same ``dest`` are two views of one setting, exactly as one line in the env
    file configures both. Such a flag is **broadcast** to every owner, which is
    what the env file would have done anyway. Two stages using one flag string
    for *different* ``dest``s genuinely disagree, and that is refused by name.

    This is a correction to the plan in ``NEXT_SESSION.md``, which listed
    ``--model``, ``--auth`` and ``--out-suffix`` as real collisions
    to be rejected. They are not: every stage accepting them resolves them to one
    ``dest`` — and for ``--model`` and ``--auth``, to one env variable
    (``OPENROUTER_MODEL``, ``SHARED_AUTH_MODE``). Rejecting them would have blocked the
    obvious workflows (``dast triage verify report latest --out-suffix qwen``)
    to protect against a confusion the naming already rules out. **Nothing is
    ambiguous today**; the check is the guard for a flag added later that is not
    so careful.

    **There is no separate class of "global" flag**, and that is deliberate.
    ``--env-file`` and ``--data-dir`` were briefly a declared
    list; they turned out to be nothing special — each is a single ``dest``
    shared by all five stages, so the rule above already sends them everywhere.
    Keeping the list would have been a second mechanism producing the same
    answer, and a hand-kept one at that. ``--out-suffix`` reaches
    ``triage``/``verify``/``report`` by the same rule and for the same reason:
    it names the variant the whole invocation operates on, and a sequence whose
    stages disagreed about it would have ``verify`` reading the baseline
    correlation while ``triage`` wrote the suffixed one.

    A consequence worth keeping: a flag *no* invoked stage accepts is an error
    even when other stages would have taken it. ``dast static-analysis latest
    --out-suffix x`` says so rather than silently dropping it, which a
    filter-on-the-way-out design could not.

    Flag *arity* is read from the owning stage's own action, so a store-true flag
    consumes no value and a valued one consumes exactly its own. The parser is
    the authority on both, and nothing here re-declares either.
    """
    per_stage: dict[str, list[str]] = {stage.name: [] for stage in stages}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            raise CliError(
                f"unexpected argument {token!r}. Only one target or run id is "
                "taken, and it comes before the flags."
            )
        flag, _, inline = token.partition("=")
        owners, dests, action = owners_of(flag, stages)

        if flag in RETIRED_FLAGS:
            raise CliError(
                f"{flag!r} no longer exists — what to act on is the positional:\n"
                f"    dast {' '.join(s.name for s in stages)} <target-or-run-id>"
            )
        if not owners:
            known = sorted({
                option for stage in stages for option in stage.option_strings()
            } - set(RETIRED_FLAGS) - {"-h", "--help"})
            raise CliError(
                f"no stage in `{' '.join(s.name for s in stages)}` accepts "
                f"{flag!r}.\n  Flags these stages accept: {', '.join(known)}"
            )
        elif len(dests) > 1:
            raise CliError(
                f"{flag!r} is ambiguous here — {' and '.join(owners)} accept it "
                "but mean different settings by it "
                f"({', '.join(sorted(dests))}).\n  Run those stages separately "
                "so the flag can only mean one thing:\n"
                + "\n".join(f"    dast {name} <run-id> {flag} …" for name in owners)
            )
        else:
            # One setting, however many stages hold a view of it — the same thing
            # one line in the env file would configure.
            destinations = [per_stage[name] for name in owners]

        value: list[str] = []
        takes_value = not (action is not None and action.nargs == 0)
        if inline:
            value = [inline]
        elif takes_value:
            if index + 1 >= len(tokens):
                raise CliError(f"{flag!r} expects a value.")
            value = [tokens[index + 1]]
            index += 1
        for destination in destinations:
            destination.append(flag)
            destination.extend(value)
        index += 1
    return per_stage


# -- resolving what the sequence acts on -----------------------------------


def resolve_positional(stages: list[stage_table.Stage], positional: str,
                       data_dir: Path) -> tuple[str, str]:
    """Decide whether the positional names a target or a run, and resolve it.

    A sequence that begins by scanning takes a **target**; every other sequence
    takes a **run id**, resolved here — once — so every stage of it acts on the
    same directory.

    ``analyze`` alone is the one exception, and it earns it: the SAST/SCA
    static-analysis findings are not a stage of the chain, they need no run at all, and
    ``dast static-analysis gitea`` is the natural way to ask for a static-analysis pass over a
    target's source. So a lone ``analyze`` accepts either, deciding by whether
    the name is a registered target.

    :returns: ``("target"|"run", resolved value)``.
    """
    if stages and stages[0].mints_run:
        if positional not in targets.REGISTRY:
            raise CliError(
                f"unknown target {positional!r}; known: "
                f"{', '.join(sorted(targets.REGISTRY))}"
            )
        return "target", positional

    if [s.name for s in stages] == ["static-analysis"] and positional in targets.REGISTRY:
        return "target", positional

    if run_paths.is_latest(positional):
        required = stages[0].requires if stages else ()
        layout = run_paths.RunLayout.latest_with(data_dir, *required)
        if layout is None:
            need = ", ".join(required) or "anything"
            raise CliError(
                f"`latest` found no run in {data_dir} holding {need}, which "
                f"`{stages[0].name}` needs."
            )
        return "run", layout.run_id
    try:
        layout = run_paths.RunLayout.resolve(data_dir, positional)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    if not layout.dir.is_dir():
        raise CliError(f"no run {positional!r} in {data_dir}")
    return "run", layout.run_id


def stage_argv(stage: stage_table.Stage, kind: str, value: str,
               own_flags: list[str]) -> list[str]:
    """The argv one stage is called with — its own flags plus what it acts on."""
    # The positional leads, matching `dast`'s own grammar: every stage now takes
    # what it acts on as a required positional rather than a defaulted flag.
    return [value, *own_flags]


# -- the cross-stage secrets pre-flight ------------------------------------


def _stage_needs_secret(stage: stage_table.Stage, own_flags: list[str],
                        positional: str) -> bool:
    """Whether this stage will run the path that spends its key, resolved the way
    the stage itself resolves it.

    Replicates the stage's own preamble — read ``--env-file``, load that stage's
    env, then parse its flags — so the arm this reads is the arm the stage will
    run, env file and all. The key-spending path is conditional: ``scan`` always
    talks to the ZAP daemon; ``triage`` spends only with the LLM arm on and not a
    dry run; ``verify`` only in an ``llm`` invocation and not a dry run. A stage
    with no required secret never reaches here.
    """
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, stage.name)
    known, _ = pre.parse_known_args(own_flags)
    config.load_stage_env(stage.name, known.env_file)
    args, _ = stage.parser().parse_known_args([positional, *own_flags])

    if stage.name == "triage":
        return bool(getattr(args, "use_llm", True)) and not getattr(args, "dry_run", False)
    if stage.name == "verify":
        cfg = stage.load().loop_config(args.invocation, args.max_rounds)
        return cfg["invocation"] == "llm" and not getattr(args, "dry_run", False)
    # scan (and any future secret-consuming stage): the key is unconditional.
    return True


def missing_secrets(stages: list[stage_table.Stage],
                    per_stage: dict[str, list[str]],
                    positional: str) -> list[tuple[str, list[str]]]:
    """Every required secret absent for the arms this whole chain will run, as
    ``(env var, [stages that need it])``.

    Answered once, before the first stage, rather than discovered when a later
    stage reaches its key — the same reason :func:`stage_table.unsatisfied`
    refuses a gap before the 45-minute scan runs into it. Each stage's own check
    stays as the authority (and for standalone use); this is the chain-wide
    pre-flight that a ``scan triage verify`` sequence needs and no single stage
    can give. Presence is read from the environment only — the value is never
    touched, printed or logged.
    """
    needed: dict[str, list[str]] = {}
    for stage in stages:
        var = config.REQUIRED_SECRETS.get(stage.name)
        if not var:
            continue
        try:
            needs = _stage_needs_secret(stage, per_stage.get(stage.name, []), positional)
        except Exception:
            # Best-effort: this is an *early* warning, never the authority. A
            # stage whose arm cannot be resolved here (a partial environment, a
            # test stub) is left to its own key check rather than blocked by a
            # pre-flight that could not read it.
            continue
        if needs and not (os.getenv(var) or "").strip():
            needed.setdefault(var, []).append(stage.name)
    return list(needed.items())


#: How to satisfy each missing secret, keyed by the env var — the actionable half
#: of the pre-flight's error, so a chain refused for a missing key also says the
#: two ways out (set it, or run the key-less arm).
_SECRET_REMEDY = {
    "SCAN_ZAP_API_KEY": "export it or pass --api-key",
    "SHARED_OPENROUTER_API_KEY":
        "the LLM arm needs it — export it, or run the key-less control arm "
        "(triage --no-llm / verify --invocation deterministic)",
}


# -- running ---------------------------------------------------------------


def data_dir_from(tokens: list[str]) -> Path:
    """Where artifacts live for this invocation, per ``--data-dir``.

    Read from the raw tokens rather than from a routed fragment: the directory
    has to be known *before* the positional can be resolved against it, which is
    before routing has decided anything.
    """
    for index, token in enumerate(tokens):
        flag, _, inline = token.partition("=")
        if flag != "--data-dir":
            continue
        if inline:
            return Path(inline)
        if index + 1 < len(tokens):
            return Path(tokens[index + 1])
    return DATA_DIR


def env_file_from(tokens: list[str]) -> Path:
    """The env file the stages will read, per ``--env-file`` or the default pair.

    Resolved the same way :func:`config.load_stage_env` resolves it, so the plan
    can name the file that actually configures the run rather than guessing.
    """
    for index, token in enumerate(tokens):
        flag, _, inline = token.partition("=")
        if flag != "--env-file":
            continue
        if inline:
            return Path(inline)
        if index + 1 < len(tokens):
            return Path(tokens[index + 1])
    return config.DEFAULT_ENV_DIR / config.CONFIG_FILE


def targets_dir_from(tokens: list[str]) -> "str | None":
    """Where targets live for this invocation, resolved as the stages resolve it.

    ``dast`` validates the positional against the target registry before any stage
    runs, so the registry has to point at the configured directory first. Order:
    an explicit ``--targets-dir`` > ``SHARED_TARGETS_DIR`` in the env file > the
    real environment > ``None`` (the tool's own ``targets/``, applied by
    :func:`~dast_orchestrator.adapters.targets.use_dir`).
    """
    for index, token in enumerate(tokens):
        flag, _, inline = token.partition("=")
        if flag != "--targets-dir":
            continue
        if inline:
            return inline
        if index + 1 < len(tokens):
            return tokens[index + 1]
    from_file = config.parse_env_file(env_file_from(tokens)).get("SHARED_TARGETS_DIR")
    return from_file or os.getenv("SHARED_TARGETS_DIR")


def _plan_table(steps: list[stage_table.Step]) -> None:
    """The plan as a ``stage | in | out`` table: what each stage looks for in the
    run directory and what it writes there, one file per row.

    Files are stacked (one per row) rather than comma-joined because ``scan``
    alone produces four, and a joined line runs off the terminal and wraps into
    the next column. Only a **missing** input is annotated — present and
    to-be-produced are the normal cases and need no marker; a missing one is the
    problem the plan exists to surface.
    """
    from itertools import zip_longest

    rows = []
    for step in steps:
        ins = [name + (" [missing]" if state == stage_table.MISSING else "")
               for name, state in sorted(step.inputs.items())]
        outs = list(step.stage.produces)
        rows.append((step.stage.name, ins or ["—"], outs or ["—"]))

    name_w = max([len("stage"), *(len(n) for n, _, _ in rows)])
    in_w = max([len("in"), *(len(x) for _, ins, _ in rows for x in ins)])

    def line(a: str, b: str, c: str) -> str:
        return f"{a:<{name_w}}  {b:<{in_w}}  {c}".rstrip()

    ui.step(line("stage", "in", "out"))
    for name, ins, outs in rows:
        for i, (b, c) in enumerate(zip_longest(ins, outs, fillvalue="")):
            ui.step(line(name if i == 0 else "", b, c))


def run(stages: list[stage_table.Stage], kind: str, value: str,
        per_stage: dict[str, list[str]], data_dir: Path,
        env_file: "Path | None" = None) -> int:
    """Echo the plan, refuse an unsatisfiable sequence, then run it in order."""
    run_dir = None if kind == "target" else run_paths.RunLayout(data_dir, value).dir
    steps = stage_table.plan([s.name for s in stages], run_dir)
    total = len(steps)

    # The wrapper and its scaffolding are ruled with `#`, the stages with `=`, so
    # a reader can tell the orchestrator's own lines from a stage starting.
    ui.section(
        "dast — " + " → ".join(s.name for s in stages),
        f"{'target' if kind == 'target' else 'run'} {value}",
    )
    # A lighter rule than the wrapper's: the plan is a subsection of the run, not
    # a second frame around it, so two `####` blocks do not stack back to back.
    ui.phase("Plan")
    env = env_file or config.DEFAULT_ENV_DIR / config.CONFIG_FILE
    ui.item("env file", ui.short_path(env) if Path(env).is_file()
            else f"{ui.short_path(env)} (absent — built-in defaults)")
    if kind == "target":
        ui.item("target.yml", ui.short_path(
            targets.TARGETS_DIR / value / targets.DEFINITION_NAME))
    _plan_table(steps)
    problems = stage_table.unsatisfied(steps)
    if problems:
        # Refused, not started: this is knowable now, and the alternative is
        # discovering it after the expensive stage has already run.
        for problem in problems:
            ui.fail(problem)
        ui.fail("sequence cannot complete — nothing was run.")
        return 2

    # The same "refuse before the expensive stage" applies to secrets: a chain
    # whose triage/verify need a key the environment does not hold would run the
    # 45-minute scan first and only then fail. Named all at once, here, before
    # anything runs — a later stage's missing key is knowable now.
    absent = missing_secrets(stages, per_stage, value)
    if absent:
        for var, owners in absent:
            ui.fail(f"{var} is not set, needed by {', '.join(owners)} "
                    f"({_SECRET_REMEDY.get(var, 'set it in the environment')})")
        ui.fail("sequence cannot complete — nothing was run.")
        return 2

    current_kind, current_value = kind, value
    for number, step in enumerate(steps, start=1):
        before = set(run_paths.RunLayout.runs(data_dir))
        argv = stage_argv(step.stage, current_kind, current_value,
                          per_stage.get(step.stage.name, []))
        # The stage carries its position through its own headline and finished
        # line (ui.set_stage); the orchestrator no longer echoes a `[n/N]` line.
        ui.set_stage(f"{number}/{total}")
        try:
            code = step.stage.load().main(argv)
        except SystemExit as exc:            # argparse rejected the stage's flags
            code = exc.code if isinstance(exc.code, int) else 2
        except KeyboardInterrupt:
            ui.set_stage("")
            ui.fail(f"interrupted during `{step.stage.name}`")
            return 130

        if step.stage.mints_run:
            # The rest of the sequence inherits the id this scan minted, so a
            # later stage can never act on a different run than the one just made.
            minted = stage_table.new_run_id(data_dir, before)
            if minted is None:
                ui.set_stage("")
                ui.fail(f"`{step.stage.name}` created no run directory")
                return code or 1
            current_kind, current_value = "run", minted

        if code:
            ui.set_stage("")
            skipped = [s.stage.name for s in steps[number:]]
            ui.fail(f"`{step.stage.name}` failed (exit {code})"
                    + (f" — skipped: {', '.join(skipped)}" if skipped else ""))
            return code
    ui.set_stage("")

    # One table for the whole sequence. Four separate per-stage metrics blocks
    # answer "what did this stage cost" four times and "what did this run cost"
    # not at all — which is the question the CI argument actually asks.
    summary = run_metrics.run_summary(data_dir, current_value)
    if summary and total > 1:
        ui.section(f"Run summary — {current_value}")
        for line in summary.splitlines():
            ui.step(line)

    ui.finished(f"{' → '.join(s.name for s in stages)} on {current_value}")
    return 0


# -- entry point -----------------------------------------------------------


def _usage() -> str:
    # Only the chain stages under "stages:" — `static-analysis` is dispatchable
    # through the same entry point but is a standalone command, listed above, not
    # a stage of the pipeline.
    return USAGE.format(
        stages=", ".join(stage_table.FULL_CHAIN),
        targets=", ".join(sorted(targets.REGISTRY)) or "(none defined)",
    )


def main(argv: "list[str] | None" = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(_usage(), file=sys.stderr)
        return 2

    # `dast harness <sheet>` is its own grammar, not a stage: it acts on a sheet
    # rather than on a run, and it is the *unattended* front end reached through
    # the interactive one for consistency. Delegated whole — before the help
    # handling below, so `dast harness --help` is the harness's help and not a
    # description of a grammar it does not use.
    if argv[0] == "harness":
        from dast_harness import main as harness_main

        return harness_main(argv[1:])

    # `cve` and `costs` are NOT pipeline stages — they measure the
    # pipeline (detection against `cve-markers.yml`) or read across finished runs
    # (`costs`), rather than transforming one run's artifacts. But a single
    # command is a single command: they were standalone console scripts and are
    # now folded under `dast`, delegated whole like `harness` because each has
    # its own positional grammar the stage router does not model. There is one
    # entry point; what a verb *is* is documented, not encoded in whether it has
    # its own binary.
    if argv[0] == "cve":
        from dast_orchestrator.stages.ground_truth import main as cve_main

        return cve_main(argv[1:])
    if argv[0] == "costs":
        from dast_orchestrator.foundation.metrics import main as costs_main

        return costs_main(argv[1:])
    # `dast commands` regenerates the Markdown command reference from the parsers.
    # Its own grammar (an output path, an env file), delegated whole like the
    # others; the live `--help` pages need no regeneration.
    if argv[0] == "commands":
        from dast_orchestrator.cli.command_docs import main as commands_main

        return commands_main(argv[1:])
    # `dast docs` regenerates the Markdown API reference (docs/api/) from the
    # package docstrings — the same "generate, do not hand-write" idiom.
    if argv[0] == "docs":
        from dast_orchestrator.cli.api_docs import main as docs_main

        return docs_main(argv[1:])

    # `dast <stage> --help` shows that stage's own flags; `dast --help` the
    # grammar. Handled before routing, since help is the thing you reach for
    # when routing is what you got wrong.
    if any(token in ("-h", "--help") for token in argv):
        named = [t for t in argv if t in stage_table.STAGES]
        if len(named) == 1:
            parser = stage_table.STAGES[named[0]].parser()
            # The stage builds its parser not knowing how it was reached, so its
            # usage line would read `usage: dast …`. Here we know it is
            # `dast <stage>`, so name it that — the help you asked for should
            # echo the command you typed.
            parser.prog = f"dast {named[0]}"
            parser.print_help()
            return 0
        print(_usage())
        return 0

    try:
        names, positional, flag_tokens = split_argv(argv)
        stages = stage_table.resolve(names or stage_table.FULL_CHAIN)
        data_dir = data_dir_from(flag_tokens)
        env_file = env_file_from(flag_tokens)
        # Point the target registry at the configured dir before the positional
        # is validated against it — the stages re-apply the same resolution.
        targets.use_dir(targets_dir_from(flag_tokens))
        per_stage = route_flags(flag_tokens, stages)
        kind, value = resolve_positional(stages, positional, data_dir)
    except (CliError, stage_table.StageError) as exc:
        print(f"ERROR: {exc}\n", file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2

    return run(stages, kind, value, per_stage, data_dir, env_file)


if __name__ == "__main__":
    raise SystemExit(main())
