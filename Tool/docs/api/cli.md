# cli

The front end that routes to stages.

### `dast_orchestrator.cli`

The interactive front end (console script `dast`): split `[stage …] <target-or-run>
[flags]`, route each flag to the stage(s) that mean one setting by it, echo the plan, and
refuse an unsatisfiable sequence — adding no behaviour of its own.

The trailing argument is positional and required (a target for `scan`, a run id
otherwise; `latest` is legal, never a flag, never defaulted); staged runs execute in
order sharing one resolved run id; the bare form is the full chain. Prerequisites are
checked before any work (`plan`) so a gap is refused before a 45-minute scan, and a
flag is broadcast to every invoked stage sharing its argparse `dest`
(`config.STAGE_FLAGS`). → docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `class CliError` | A usage error: bad stage, missing positional, ambiguous or unknown flag. |
| `def split_argv(argv: 'list[str]') -> 'tuple[list[str], str, list[str]]'` | `["scan", "triage", "gitea", "--auth", "user"]` -> its three parts. |
| `def owners_of(flag: 'str', stages: 'list[stage_table.Stage]') -> 'tuple[list[str], set[str], Any]'` | Which of `stages` accept `flag`, what each calls it, and its action. |
| `def route_flags(tokens: 'list[str]', stages: 'list[stage_table.Stage]') -> 'dict[str, list[str]]'` | Assign each flag to the stage — or stages — it belongs to. |
| `def resolve_positional(stages: 'list[stage_table.Stage]', positional: 'str', data_dir: 'Path') -> 'tuple[str, str]'` | Decide whether the positional names a target or a run, and resolve it. |
| `def stage_argv(stage: 'stage_table.Stage', kind: 'str', value: 'str', own_flags: 'list[str]') -> 'list[str]'` | The argv one stage is called with — its own flags plus what it acts on. |
| `def missing_secrets(stages: 'list[stage_table.Stage]', per_stage: 'dict[str, list[str]]', positional: 'str') -> 'list[tuple[str, list[str]]]'` | Every required secret absent for the arms this whole chain will run, as |
| `def data_dir_from(tokens: 'list[str]') -> 'Path'` | Where artifacts live for this invocation, per `--data-dir`. |
| `def env_file_from(tokens: 'list[str]') -> 'Path'` | The env file the stages will read, per `--env-file` or the default pair. |
| `def targets_dir_from(tokens: 'list[str]') -> "'str \| None'"` | Where targets live for this invocation, resolved as the stages resolve it. |
| `def run(stages: 'list[stage_table.Stage]', kind: 'str', value: 'str', per_stage: 'dict[str, list[str]]', data_dir: 'Path', env_file: "'Path \| None'" = None) -> 'int'` | Echo the plan, refuse an unsatisfiable sequence, then run it in order. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.cli.api_docs`

`dast docs`: generate the Markdown API reference under `docs/api/` from the
package's own docstrings.

One Markdown file per layer (foundation/domain/…), plus an index, so the API reads
on GitHub the way `dast_orchestrator.cli.command_docs` makes the flags read.
The docstrings are the source of truth; this only introspects them, converting the
reST inline markup (`:func:` roles, ``\`\`literal\`\``) to Markdown. Do not edit
the output by hand — edit the docstrings and regenerate.

| member | summary |
|---|---|
| `def rst_to_md(text: "'str \| None'") -> 'str'` | Convert the reST inline markup used in docstrings to Markdown. |
| `def render_module(dotted: 'str') -> 'str'` |  |
| `def render_layer(layer: 'str') -> 'str'` |  |
| `def render_index() -> 'str'` |  |
| `def write(out_dir: 'Path') -> 'list[Path]'` |  |
| `def build_parser() -> 'argparse.ArgumentParser'` |  |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.cli.command_docs`

`dast commands`: regenerate the command & flag reference (COMMANDS.md) from the live
argparse parsers.

The per-command `--help` pages need no regeneration (argparse renders them from the same
strings), but the Markdown reference is not free: every row is introspected from each
stage's `build_parser()` plus `config.STAGE_FLAGS` and the module docstrings, the
only authored constants being the value-column legend and `VALUE_OVERRIDE`. Defaults
resolve from `config/scanner/default.env` (committed, so the doc is machine-independent);
point `--env-file` elsewhere to see another file's defaults.

| member | summary |
|---|---|
| `def render(env_file: "'str \| Path \| None'" = None) -> 'str'` | The full COMMANDS.md, with flag defaults resolved from `env_file`. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` | Regenerate the command & flag reference (COMMANDS.md) from the parsers. |
