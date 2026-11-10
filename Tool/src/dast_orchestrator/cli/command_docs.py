"""``dast commands``: regenerate the command & flag reference (COMMANDS.md) from the live
argparse parsers.

The per-command ``--help`` pages need no regeneration (argparse renders them from the same
strings), but the Markdown reference is not free: every row is introspected from each
stage's ``build_parser()`` plus :data:`config.STAGE_FLAGS` and the module docstrings, the
only authored constants being the value-column legend and :data:`VALUE_OVERRIDE`. Defaults
resolve from ``config/scanner/default.env`` (committed, so the doc is machine-independent);
point ``--env-file`` elsewhere to see another file's defaults.
"""
from __future__ import annotations

import argparse
import importlib
import os
import re
import sys
from pathlib import Path

from dast_orchestrator.foundation import config

#: The pipeline stages, in order, and the module that owns each parser. ONLY the
#: chain stages — ``static-analysis`` is a standalone command (documented with the
#: other non-stage commands below), not a stage, so it is deliberately absent so
#: it never counts toward "shared across stages" or gets a "Stage N" label.
STAGES = {
    "scan": "dast_orchestrator.stages.scan",
    "triage": "dast_orchestrator.stages.triage",
    "verify": "dast_orchestrator.stages.verify",
    "report": "dast_orchestrator.stages.report",
}
#: How each stage's positional is shown in the reference (its ``<…>`` name).
POS = {"scan": "target", "triage": "run_id", "verify": "run_id",
       "report": "run_id"}
#: The stage's own name and its number in the chain.
STAGE_NAME = {"scan": "Scan", "triage": "Triage", "verify": "Verify",
              "report": "Report"}
STAGE_NUM = {"scan": 1, "triage": 2, "verify": 3, "report": 4}


#: Value hints argparse cannot derive — freeform strings the code parses itself.
VALUE_OVERRIDE = {
    "spiders": "traditional, ajax, client",
    "disabled_rules": "<rule-id> …",
    "path_var": "<name>=<value> …",
    "rulesets": "<dir> …",
    "max_dispatch_rule": "<id>=<n> …",
}

_MODEL_VENDORS = ("deepseek|minimax|anthropic|z-ai|x-ai|qwen|openai|google|"
                  "meta-llama|mistralai")
_MODEL_RE = re.compile(rf"(?<![`\w])((?:{_MODEL_VENDORS})/[\w.\-]+)")


def _nolink(text: str) -> str:
    """Backtick model ids so a Markdown renderer does not autolink vendor/model."""
    return _MODEL_RE.sub(r"`\1`", text)


def _relpath(value):
    if isinstance(value, Path):
        try:
            return str(value.relative_to(config.REPO_ROOT))
        except ValueError:
            return str(value)
    return value


def _typename(action) -> str:
    """The value-type name, shared with the ``--help`` metavars via
    :func:`config.arg_type` so the two never disagree about what a flag takes."""
    return config.arg_type(action)


def _value_of(dest: str, actions: list) -> str:
    """The value-column notation: choices with ``/``, a ``<type>``, or ``—``."""
    if dest in VALUE_OVERRIDE:
        return VALUE_OVERRIDE[dest]
    action = actions[0]
    kinds = {type(a).__name__ for a in actions}
    if "_StoreTrueAction" in kinds or "_StoreFalseAction" in kinds:
        return "—"
    if action.choices:
        return " / ".join(map(str, action.choices))
    if "_AppendAction" in kinds:
        return f"<{_typename(action)}> …"
    return f"<{_typename(action)}>"


def _collapse(parser) -> list:
    """One entry per dest, pairing e.g. ``--x``/``--no-x`` under one row."""
    seen: dict = {}
    order: list = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if action.dest not in seen:
            seen[action.dest] = {"acts": [], "opts": [], "help": "",
                                 "positional": not action.option_strings,
                                 "default": action.default}
            order.append(action.dest)
        seen[action.dest]["acts"].append(action)
        seen[action.dest]["opts"] += action.option_strings or [f"<{action.dest}>"]
        if (action.help or "").strip() and not seen[action.dest]["help"]:
            seen[action.dest]["help"] = action.help.strip()
    return [(d, seen[d]) for d in order]


def _default_cell(dest: str, meta: dict, env: str) -> str:
    if env in config.SECRET_VARS:
        return f"`<from {env}>`"
    default = meta["default"]
    if default is None:
        # A ``None`` argparse default is a *sentinel* ("do not override"); for
        # several flags — the verify budget caps, ``--max-rule-minutes`` — the
        # effective default is resolved a layer deeper (``DispatchBudget``,
        # ``resolve_max_rule_minutes``) from the env var, so argparse never sees
        # it. Show what the env file sets that var to — the doc's stated source
        # of defaults — rather than a blank that hides a real default. A var the
        # file leaves unset (a pure override like ``--target``) still shows blank.
        env_value = os.environ.get(env) if env else None
        return f"`{env_value}`" if env_value not in (None, "") else ""
    if default == "":
        # An empty-string default is "nothing by default", the same as ``None``
        # to a reader — shown blank, not as a `''` artifact, so the column reads
        # one way for "no default".
        return ""
    if isinstance(default, bool):
        # Show the word the env file uses (`on`/`off`), not Python's `True`/
        # `False`, so the default column and default.env read the same.
        return "`on`" if default else "`off`"
    return f"`{_relpath(default)}`"


#: The mark placed in the env column beside a variable that must be set. The
#: FILLED flag (U+2691), matching the one docs/OUTCOMES.md uses, so the two docs
#: read with one glyph vocabulary rather than two near-identical ones.
def _env_cell(env: str) -> str:
    """The env column: the variable name. Which two are required is stated in the
    Required-secrets block, so no per-row marker is needed."""
    return env


def _help(meta: dict) -> str:
    text = _nolink(meta["help"].replace("%%", "%")).replace("|", "\\|")
    # A `\n` in a help string separates the description's parts (what it does /
    # relations / fallbacks). argparse collapses it to a space in --help; the
    # Markdown table wants a line break, which is `<br>`.
    return text.replace("\n", "<br>")


def _summary(doc: "str | None") -> str:
    """A one-line purpose for the command table: the FIRST SENTENCE of the first
    paragraph, not the first physical line.

    ``__doc__.splitlines()[0]`` (the old approach) cut a wrapped opening sentence
    mid-word — ``scan``'s read "...save the raw alerts and", and
    ``command_docs``'s leaked its own ````dast commands````: label — so the
    command table diverged from what the sentences actually say. This joins the
    first paragraph, strips a leading ````dast x````: label some docstrings
    carry, and keeps up to the first sentence.
    """
    para = (doc or "").strip().split("\n\n")[0].replace("\n", " ").strip()
    para = re.sub(r"^``dast [^`]+``:\s*", "", para)   # drop a self-referential label
    m = re.match(r"(.+?\.)(?:\s|$)", para)            # first sentence, if any
    return _nolink((m.group(1) if m else para).strip()).replace("|", "\\|")


def _render_body() -> list:
    out: list = []
    def w(line: str = "") -> None:
        out.append(line)

    w("# DAST CLI — command & flag reference")
    w("_Generated by `dast commands` from the argparse parsers; defaults from "
      "`config/scanner/default.env`. Do not edit by hand — edit the `help=` / "
      "`description` strings in the code and regenerate._\n")
    w("**Value column**")
    w("- `a / b` — pick **exactly one**")
    w("- `a, b` — a list; choose **any number** (comma-separated)")
    w("- `<int>` `<float>` `<url>` `<path>` `<string>` — a free value of that kind")
    w("- `—` — a **switch**: takes no value, its presence sets it\n")

    # 1 — commands
    w("## 1 · Commands\n")
    w("| command | arguments | purpose |")
    w("|---|---|---|")
    rows = [("`dast <target>`", "target",
             "the whole chain: scan → triage → verify → report")]
    for stage, module in STAGES.items():
        doc = _summary(importlib.import_module(module).__doc__)
        rows.append((f"`dast {stage} <{POS[stage]}>`", POS[stage], doc))
    # Non-stage commands. The name and args are stated here because they are not
    # single-parser stages, and each MUST match the actual CLI verb (a doc
    # advertising a command that errors is worse than none). `dast cve` takes one
    # or two run ids: two are compared, one auto-runs its --oracle counterpart.
    for name, args, module in [
            ("`dast static-analysis <target-or-run>`", "target-or-run",
             "dast_orchestrator.stages.static_analysis.analyze"),
            ("`dast harness <sheet>`", "sheet", "dast_harness"),
            ("`dast cve <run-id> [<run-id>]`", "run-id",
             "dast_orchestrator.stages.ground_truth"),
            ("`dast costs`", "—", "dast_orchestrator.foundation.metrics"),
            ("`dast commands`", "—", "dast_orchestrator.cli.command_docs")]:
        mod = importlib.import_module(module)
        # The command's OWN --help description where it exposes a parser (the
        # SSOT), so the purpose here matches the help page — falling back to the
        # module docstring only for a command that builds its parser inline.
        build = getattr(mod, "build_parser", None)
        doc = ((build().description if build else None)
               or mod.__doc__ or getattr(getattr(mod, "main", None), "__doc__", ""))
        rows.append((name, args, _summary(doc)))
    for command, positional, purpose in rows:
        w(f"| {command} | {positional} | {purpose} |")

    # 2 — shared flags: EVERY flag that reaches more than one stage, computed
    # from the live parsers so the section can never drift. "Shared" means the
    # same dest on two or more DISTINCT stages — a `--x`/`--no-x` switch pair on
    # one stage is one flag, not two stages. The `stages` column says which; the
    # env column shows the variable, or the per-stage variables where a
    # same-named flag configures each stage separately (`--dry-run`).
    stage_fields = {s: dict(_collapse(importlib.import_module(m).build_parser()))
                    for s, m in STAGES.items()}
    shared: dict[str, dict] = {}
    for stage, fields in stage_fields.items():
        for dest, meta in fields.items():
            if meta["positional"]:
                continue
            entry = shared.setdefault(dest, {"stages": [], "meta": meta, "envs": {}})
            if stage not in entry["stages"]:
                entry["stages"].append(stage)
            env = config.STAGE_FLAGS.get(stage, {}).get(dest, "")
            if env:
                entry["envs"].setdefault(stage, env)
    shared = {d: e for d, e in shared.items() if len(e["stages"]) >= 2}

    def _shared_stages(dest: str) -> str:
        stages = shared[dest]["stages"]
        return ("all" if len(stages) == len(STAGES)
                else ", ".join(STAGE_NAME[s] for s in stages))

    def _shared_env(dest: str) -> tuple[str, str]:
        """(env cell, the single env var or "" when per-stage/none)."""
        variables = list(dict.fromkeys(shared[dest]["envs"].values()))
        if not variables:
            return "", ""
        if len(variables) == 1:
            return _env_cell(variables[0]), variables[0]
        return " / ".join(variables), ""   # per-stage vars, e.g. --dry-run

    w("\n## 2 · Shared flags\n")
    w("Flags that reach more than one stage — an option reaches every stage that "
      "means one setting by it. The **stages** column says which; where a "
      "same-named flag configures each stage separately (`--dry-run`), the env "
      "column lists the per-stage variables.\n")
    w("| flag | value | stages | env | default | description |")
    w("|---|---|---|---|---|---|")
    # Stable order: the run-wide infra, then the suffix pair, then the rest by flag.
    lead = ["env_file", "data_dir", "force", "out_suffix", "in_suffix"]
    rest = sorted((d for d in shared if d not in lead),
                  key=lambda d: sorted(shared[d]["meta"]["opts"])[0])
    for dest in [d for d in lead if d in shared] + rest:
        meta = shared[dest]["meta"]
        opts = ", ".join(dict.fromkeys(meta["opts"]))
        env_cell, env_var = _shared_env(dest)
        w(f"| `{opts}` | `{_value_of(dest, meta['acts'])}` | {_shared_stages(dest)} | "
          f"{env_cell} | {_default_cell(dest, meta, env_var)} | {_help(meta)} |")

    # Required secrets — the two variables that must be set. `SCAN_ZAP_API_KEY` also
    # has the `--api-key` flag (below); `SHARED_OPENROUTER_API_KEY` has no flag at all,
    # so without this block it would be absent from the reference entirely.
    w("\n**Required secrets** — must be set; supply them through the env/secrets "
      "file, never on a command line.\n")
    w("| env | needed by | note |")
    w("|---|---|---|")
    w("| `SHARED_OPENROUTER_API_KEY` | triage, verify (LLM path) | "
      "the paid model calls; the deterministic control arms need no key |")
    w("| `SCAN_ZAP_API_KEY` | scan | the ZAP daemon's REST key; also "
      "settable with `--api-key`, though a key on a command line is visible to "
      "every process |")

    # 3.. — one numbered section per command: the five pipeline stages (each
    # labelled "Stage N"), then the commands that are NOT stages (cve, harness,
    # costs). Each section's blockquote is the command's OWN --help description
    # (`parser.description`), so the reference and the help page cannot drift.
    section = 3

    def _command_section(title: str, invocation: str, parser, pos_name: str,
                         stage_key: str, exclude_shared: bool) -> None:
        nonlocal section
        fields = dict(_collapse(parser))
        positional = next((m for _, m in fields.items() if m["positional"]), None)
        w(f"\n## {section} · {title} — `{invocation}`\n")
        section += 1
        w(f"> {_nolink((parser.description or '').strip())}\n")
        if positional and pos_name:
            w(f"**`<{pos_name}>`** — {_nolink(positional['help'].replace('%%', '%'))}\n")
        w("| flag | value | env | default | description |")
        w("|---|---|---|---|---|")
        for dest, meta in fields.items():
            # A chain stage's shared flags live in §2; a standalone command lists
            # all of its own flags (its env vars still come from STAGE_FLAGS).
            if meta["positional"] or (exclude_shared and dest in shared):
                continue
            opts = ", ".join(dict.fromkeys(meta["opts"]))
            env = config.STAGE_FLAGS.get(stage_key, {}).get(dest, "")
            w(f"| `{opts}` | `{_value_of(dest, meta['acts'])}` | {_env_cell(env)} | "
              f"{_default_cell(dest, meta, env)} | {_help(meta)} |")

    for stage, module in STAGES.items():
        prefix = f"Stage {STAGE_NUM[stage]} · {STAGE_NAME[stage]}"
        _command_section(prefix, f"dast {stage} <{POS[stage]}>",
                         importlib.import_module(module).build_parser(),
                         POS[stage], stage, exclude_shared=True)

    # The standalone commands — NOT pipeline stages. Each lists all of its own
    # flags (§2 covers only the chain stages). `static-analysis` keeps its
    # STAGE_FLAGS key so its env vars still render; the rest have none.
    for title, invocation, module, pos_name, stage_key in [
            ("Static-analysis", "dast static-analysis <target-or-run>",
             "dast_orchestrator.stages.static_analysis.analyze", "target-or-run",
             "static-analysis"),
            ("CVE", "dast cve <run-id> [<run-id>]",
             "dast_orchestrator.stages.ground_truth", "run-id", ""),
            ("Harness", "dast harness <sheet>", "dast_harness", "sheet", ""),
            ("Costs", "dast costs", "dast_orchestrator.foundation.metrics", "", "")]:
        _command_section(title, invocation,
                         importlib.import_module(module).build_parser(),
                         pos_name, stage_key, exclude_shared=False)
    return out


def render(env_file: "str | Path | None" = None) -> str:
    """The full COMMANDS.md, with flag defaults resolved from ``env_file``.

    The env file's values are set into the environment while the parsers are
    built (so every ``os.getenv`` default sees them) and restored afterwards, so
    the render is a pure function of the file and the code — no leak into the
    caller's environment.
    """
    envfile = Path(env_file) if env_file else config.DEFAULT_ENV_DIR / "default.env"
    values = config.parse_env_file(envfile)
    flag_vars = {var for stage in config.STAGE_FLAGS.values() for var in stage.values()}
    saved = dict(os.environ)
    try:
        # Every flag env var starts cleared, so one the file does not set (or
        # leaves commented) shows its built-in default rather than leaking a
        # shell value into the doc; then the file's values win.
        for var in flag_vars:
            os.environ.pop(var, None)
        os.environ.update(values)
        body = _render_body()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return "\n".join(body) + "\n"


def main(argv: "list[str] | None" = None) -> int:
    """Regenerate the command & flag reference (COMMANDS.md) from the parsers."""
    parser = argparse.ArgumentParser(
        prog="dast commands", description=main.__doc__)
    parser.add_argument(
        "--env-file", metavar="PATH",
        default=str(config.DEFAULT_ENV_DIR / "default.env"),
        help="Where flag DEFAULTS are read from (default the committed "
             "config/scanner/default.env, so the doc is reproducible). Point it "
             "at config/scanner/.env to see your local defaults.",
    )
    parser.add_argument(
        "--write", metavar="PATH", default="docs/COMMANDS.md",
        help="Where to write the Markdown (default docs/COMMANDS.md). Mirrors "
             "``dast docs``, which writes docs/api/ by default.",
    )
    parser.add_argument(
        "--stdout", action="store_true",
        help="Print to stdout instead of writing the file.",
    )
    args = parser.parse_args(argv)
    markdown = render(args.env_file)
    if args.stdout:
        sys.stdout.write(markdown)
    else:
        path = Path(args.write)
        path.write_text(markdown)
        print(f"wrote {path} ({markdown.count(chr(10))} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
