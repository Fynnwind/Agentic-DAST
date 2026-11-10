# foundation

Infrastructure with no domain knowledge.

### `dast_orchestrator.foundation.config`

Per-stage configuration: one env file per command, and every value is also a flag.

`config/scanner/{.env,secrets.env}` splits secrets from the rest, so the agent can read
config to keep variables/flags/docs in sync without seeing a key; `STAGE_FLAGS` is
the single value↔flag table, drift-tested both ways. Precedence, most specific first: an
explicit flag > a named `--env-file` > a default file > the built-in default (values load
into the environment before argparse computes defaults). → DECISIONS.md.

| member | summary |
|---|---|
| `def env_bool(name: 'str', default: 'bool' = False) -> 'bool'` | Read a boolean env var by word (`on`/`off`/…), not by truthiness. |
| `def unbounded(args: 'Any', extra: "'dict[str, Any] \| None'" = None) -> 'list[str]'` | Which ceilings this invocation switched off, in readable form. |
| `def warn_if_unbounded(args: 'Any', extra: "'dict[str, Any] \| None'" = None) -> 'None'` | Say so, once, before the stage runs. Never refuses. |
| `class LoadedEnv(stage: ForwardRef('str'), files: ForwardRef('list[Path]'), values: ForwardRef('dict[str, str]'), explicit: ForwardRef('bool'))` | What a stage's configuration load did, so a command can report it. |
| `def parse_env_file(path: 'Path') -> 'dict[str, str]'` | Parse `KEY=value` lines. Comments, blanks and `export` are ignored. |
| `def default_for(var: 'str') -> 'str'` | The default a flag resolves to — the single source of truth. |
| `def config_and_secrets(env_file: "'str \| Path \| None'" = None, env_dir: "'str \| Path \| None'" = None) -> "'tuple[Path, Path]'"` | The `(config file, its secrets.env neighbour)` a stage loads, in ONE place. |
| `def load_stage_env(stage: 'str', env_file: "'str \| Path \| None'" = None, env_dir: "'str \| Path \| None'" = None) -> 'LoadedEnv'` | Load one stage's configuration into `os.environ` and report what it did. |
| `def apply_explicit_overrides(env: 'LoadedEnv', args: 'Any', parser: 'Any' = None, argv: "'list[str] \| None'" = None) -> 'list[str]'` | Apply a *named* env file to the flags the user did NOT type. Returns the |
| `def add_env_flags(parser: 'Any', stage: 'str') -> 'None'` | Add the two configuration flags every command shares. |
| `def add_targets_dir_flag(parser: 'Any') -> 'None'` | The shared `--targets-dir` flag, for the four stages that read a target's |
| `def arg_type(action: 'argparse.Action') -> 'str'` | The value-type of a flag's argument — `int` / `float` / `url` / |
| `def normalize_metavars(parser: 'argparse.ArgumentParser') -> 'None'` | Give every scalar value flag a consistent `<type>` metavar in `--help`. |
| `def command_description(doc: "'str \| None'") -> 'str'` | A command's `--help` description, from its module docstring. |
| `def redact(values: 'dict[str, str]') -> 'dict[str, str]'` | Configuration with every secret replaced — safe to print or record. |


### `dast_orchestrator.foundation.manifest`

A run's self-description: `manifest.json` lists the artifacts present in a run
directory, each with the schema that governs it and its `schema_version`.

Regenerated (a full scan of the directory, so it never drifts from disk) whenever a
stage records metrics. It lets a reader — the report, the analyzer, a person — learn
what a run contains by reading ONE file, instead of probing well-known names.
→ docs/DATA.md.

| member | summary |
|---|---|
| `def build_manifest(layout: 'run_paths.RunLayout') -> 'dict[str, Any]'` | Describe every artifact in `layout.dir` — name, size, schema, version. |
| `def write_manifest(layout: 'run_paths.RunLayout') -> 'Path'` | (Re)write `manifest.json` for a run. Best-effort: a manifest is a |


### `dast_orchestrator.foundation.metrics`

Central run metrics: every stage measured the same way, one
`data/<run>/<kind>-metrics.json` per stage; the cross-run table (`dast costs`)
is derived on read, with no stored index.

The thesis answers "what does a DAST-plus-LLM stage cost in CI" with numbers across
components that otherwise report nothing comparable. Rules: measured never estimated (the
unmeasurable is `null`, so a missing measurement and a measured zero never look alike),
every metric names its run, provenance (image tags, versions, host) travels with the
numbers, and secrets never appear. → DECISIONS.md.

| member | summary |
|---|---|
| `class StageTiming(name: 'str', seconds: 'float \| None' = None, counters: 'dict[str, Any]' = <factory>) -> None` | Wall time and free-form counters for one pipeline stage. |
| `class RunMetrics(run_id: 'str', kind: 'str' = 'scan', label: 'str' = '') -> 'None'` | Collects metrics for one run and writes them as a single artifact. |
| `def read_run_records(data_dir: 'Path', run_id: 'str') -> 'list[dict[str, Any]]'` | Every metrics record in one run's directory, oldest first. |
| `def run_cost_so_far(data_dir: 'Path', run_id: 'str', label: 'str' = '') -> 'float'` | What the stages of *this experiment* have already spent, in USD. |
| `def run_summary(data_dir: 'Path', run_id: 'str') -> 'str'` | One table for one run: what each stage cost and what it produced. |
| `def index_row(record: 'dict[str, Any]') -> 'dict[str, Any]'` | Flatten a metrics record into one comparable row for the costs table. |
| `def derive_limits(kind: 'str', stages: 'dict[str, Any]', results: 'dict[str, Any]', abort: "'dict[str, str] \| None'" = None) -> 'list[dict[str, Any]]'` | Normalise the ceilings and degradations a stage hit into one list. |
| `def record_limits(record: 'dict[str, Any]') -> 'list[dict[str, Any]]'` | The normalised limits of a metrics record, recomputing for old records. |
| `def read_index(data_dir: 'Path') -> 'list[dict[str, Any]]'` | Every recorded execution under `data_dir`, oldest first, **derived on |
| `def host_facts() -> 'dict[str, Any]'` | CPU, RAM and OS of the machine that produced the numbers. |
| `def docker_image_digest(image: 'str') -> 'str \| None'` | Resolve an image tag to its digest, pinning what actually ran. |
| `def container_stats(names: 'list[str]') -> 'dict[str, Any]'` | One instantaneous `docker stats` reading for the named containers. |
| `def format_index(rows: 'list[dict[str, Any]]') -> 'str'` | Render the derived run index as a table for the writeup. |
| `def read_all_indexes(data_root: 'Path') -> 'list[dict[str, Any]]'` | Every recorded run across `data/runs` AND every harness sheet, oldest first. |
| `def build_parser() -> "'Any'"` | The `dast costs` parser, built without parsing — so `dast commands` |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` | The record of every run this project has produced — one row per stage-run, |
| `class ResourceSampler(containers: 'list[str]', interval: 'float' = 15.0) -> 'None'` | Poll container CPU and memory in the background and keep the peaks. |


### `dast_orchestrator.foundation.prompts`

Versioned prompt files: `prompts/<group>/<pass>.v<N>.md`, loaded recursively (the
filename is the identity, not the location).

The filename's `vN` is the version, so a prompt cannot drift from its content: to
change one you add `v<N+1>` and leave the old, and a run records which it used — never
edit in place. Three passes (`screening`, `synthesis`, `verify`); selecting a
version is ordinary config (`TRIAGE_PROMPT_VERSION` etc.) so a sheet can A/B two
wordings over one scan. → DECISIONS.md.

| member | summary |
|---|---|
| `class PromptError` | An unknown pass, or a version that is not on disk. |
| `class Prompt(name: 'str', version: 'int', text: 'str', path: 'Path') -> None` | One prompt file: what it is, which version, and its verbatim text. |
| `def available(name: 'str', prompts_dir: "'Path \| None'" = None) -> 'list[int]'` | Every version of one pass present on disk, ascending. |
| `def load(name: 'str', version: "'int \| str \| None'" = None, prompts_dir: "'Path \| None'" = None) -> 'Prompt'` | The prompt for one pass, at `version` or the newest on disk. |
| `def load_oracle(name: 'str', prompts_dir: "'Path \| None'" = None) -> 'Prompt'` | One **unversioned** oracle block (`prompts/oracle/<name>.md`). |


### `dast_orchestrator.foundation.redaction`

Strip stored credentials from on-disk artifacts (NFR-06).

A live scan or verification needs the session cookie and the target's seeded
login password to authenticate; the *stored* exchange does not. This scrubs them
the moment an artifact is serialised, and the same `scrub` runs over
already-stored artifacts (the one-time pass over the corpus).

A credential reaches an artifact in four shapes, so four rules cover them:
  1. a raw-HTTP header line — `Cookie: <value>` inside a CRLF-joined block;
  2. a header passed in a tool command — `curl -H 'Cookie: <value>'`;
  3. a structured header — the JSON object `{"Cookie": "<value>"}`;
  4. a cookie flag — `sqlmap --cookie <name>=<value>` — or the seeded
     password in a replayed form body.
Rules 1–2 are the header-value regex, 3 is the header-keyed dict blank, and 4 is
the by-name cookie redaction plus the exact-string pass. The marker is
`==REDACTED==`: upper-case and delimited so it is obvious in a diff or an
evidence pack. → NFR-06.

| member | summary |
|---|---|
| `def scrub(obj: 'Any', secrets: 'Iterable[str]' = (), cookie_names: 'Iterable[str]' = ()) -> 'Any'` | A copy of `obj` with credentials replaced by `PLACEHOLDER`. |
| `def target_secrets(target: 'Any') -> 'list[str]'` | The seeded secret strings a target's config carries — its login passwords. |
| `def target_cookie_names(target: 'Any') -> 'list[str]'` | The session and CSRF cookie names a target's auth config names. |


### `dast_orchestrator.foundation.run_lock`

The stage lock: one file per stage+suffix in the run directory
(`.lock-verify-hybrid`), holding pid/host/start/command so a refusal names what is
already running.

Stage AND suffix, because two `--out-suffix` variants legitimately share a run
directory and may run together while two of the same suffix write one file and may not.
A stale lock is reclaimed (liveness is `os.kill(pid, 0)`, so a pid from another host is
treated as live); it is a guard rail not a scheduler (`--force` overrides), claimed
inside each stage's `main` where the run dir is known. → DECISIONS.md.

| member | summary |
|---|---|
| `class Busy` | A live process already holds this stage's lock on this run directory. |
| `def lock_name(stage: 'str', suffix: 'str' = '') -> 'str'` | `("verify", "hybrid")` -> `".lock-verify-hybrid"`. |
| `def lock_path(run_dir: "'Path \| str'", stage: 'str', suffix: 'str' = '') -> 'Path'` |  |
| `def describe(record: 'dict[str, Any]') -> 'str'` | The holder, as two indented lines for a refusal or a warning. |
| `def claim(run_dir: "'Path \| str'", stage: 'str', suffix: 'str' = '', force: 'bool' = False) -> 'Path'` | Take this stage's lock on `run_dir`, or raise `Busy`. |
| `def release(path: "'Path \| str'") -> 'None'` | Remove a lock this process holds. Never removes anyone else's. |
| `def held(run_dir: "'Path \| str'", stage: 'str', suffix: 'str' = '', force: 'bool' = False) -> 'Iterator[Path]'` | `claim` with a scope of its own, for callers that are not a stage. |
| `def guarded(main: 'Callable[..., int]') -> 'Callable[..., int]'` | Wrap a stage's `main`: release its locks, and refuse rather than raise. |


### `dast_orchestrator.foundation.run_paths`

The run-directory layout — the single source of truth for where a run's files live.

Every artifact lands under `data/<run-id>/` with a stable basename (one run is one
folder), and a downstream variant is a suffixed sibling in the same folder, not a new
directory. `run-id = <timestamp>-<target>-<config-digest>` (timestamp first so it sorts;
the target contains no `-`; the digest covers only global+scan config, so re-triage is a
variant told apart by `--out-suffix` — which is why `scan` takes no suffix, it *is* the
directory), and a person's runs live in `data/runs/`, a sheet's under `data/harness/`.
→ docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `def default_runs_dir(data_root: "'Path \| None'" = None) -> 'Path'` | Where a run a *person* started lives: `data/runs`. |
| `def harness_runs_dir(sheet_run_id: 'str', data_root: "'Path \| None'" = None) -> 'Path'` | Where the runs of one *sheet* live: `data/harness/<sheet-id>`. |
| `def scratch_runs_dir(sheet_run_id: 'str', data_root: "'Path \| None'" = None) -> 'Path'` | Where an *ephemeral* sheet (dry-run / smoke) lives: `data/scratch/<sheet-id>`. |
| `def now_timestamp() -> 'str'` | The one place a run's timestamp is minted, so every command agrees. |
| `def is_latest(ident: 'str \| None') -> 'bool'` |  |
| `def config_digest(config: "'Mapping[str, Any] \| None'") -> 'str'` | A short, stable hash of the configuration one run was made with. |
| `def make_run_id(timestamp: 'str', target: 'str', digest: 'str' = '') -> 'str'` | `("20260824T103111Z", "gitea", "a3f19c")` -> `"…Z-gitea-a3f19c"`. |
| `class RunId(timestamp: ForwardRef('str'), target: ForwardRef('str'), config: ForwardRef('str'))` | The three fields of a run id. `target`/`config` are `""` if absent. |
| `def split_run_id(run_id: 'str') -> 'RunId'` | `"20260824T103111Z-gitea-a3f19c"` -> its three fields. |
| `class SuffixError` | An `--out-suffix` collides with a reserved filename convention. |
| `def metrics_basename(kind: 'str', suffix: 'str' = '') -> 'str'` | `("triage", "qwen") -> "triage-metrics-qwen.json"`. |
| `class RunLayout(data_dir: 'Path', run_id: 'str') -> 'None'` | The directory and named paths for one run under `data/`. |


### `dast_orchestrator.foundation.schema`

Validate a `data/` artifact against its JSON Schema (`Tool/schemas/*.schema.json`)
where a stage reads it, so a truncated or wrong-shaped artifact fails with a named field
rather than a KeyError deep in a stage.

Policy by result: a violated **required** field (absent or wrong-shaped) raises
`ArtifactError`, a looser deviation warns and the run continues, and an
unregistered file type is not checked. Distinct from the inline LLM-output schemas,
which constrain a model response rather than a file on disk. → DECISIONS.md §R5.

| member | summary |
|---|---|
| `class ArtifactError` | A `data/` artifact violated a REQUIRED part of its schema on read. |
| `def schema_file_for(name: 'str') -> "'Path \| None'"` | The schema file registered for an artifact basename, or `None`. |
| `def violations(name: 'str', data: 'Any') -> "'list[str]'"` | Every schema violation for `data`, as readable `path: message` lines. |
| `def check(name: 'str', data: 'Any', source: "'str \| Path'" = '') -> "'list[str]'"` | Validate `data` (read from an artifact named `name`) against its schema. |


### `dast_orchestrator.foundation.ui`

Consistent console output: one shape for every phase of every command, because a run's
log is read far more often than any artifact.

Four rule characters in descending density (`#` session, `=` run/row, `+` stage,
`-` phase) so the hierarchy reads before the words. `phase` opens and
`done` closes (the only place a duration prints, always last); files sit
second-to-last; `warn`/`fail`/`error` go to stderr; every line is one write so a
background sampler cannot interleave.

| member | summary |
|---|---|
| `def short_path(value: 'Any') -> 'str'` | A path relative to the repo root when it is inside it, else unchanged. |
| `def short_command(argv: "'list[str]'") -> 'str'` | A spawned command with every in-repo path shortened, for the log. |
| `def session(title: 'str', subtitle: 'str' = '', facts: "'dict[str, Any] \| None'" = None, note: 'str' = '') -> 'None'` | Open something that *contains* commands — a harness sheet, not a stage. |
| `def session_divider(label: 'str') -> 'None'` | Separate one member of a session from the next. |
| `def session_end(title: 'str', facts: "'dict[str, Any] \| None'" = None) -> 'None'` | Close a session with the same rule it opened with. |
| `def set_stage(label: 'str') -> 'None'` | Set (or clear, with `""`) the `n/N` a stage's banners carry. |
| `def section(title: 'str', subtitle: 'str' = '') -> 'None'` | A run-level banner ruled with `=`, framing one run: the `dast —` wrapper |
| `def headline(title: 'str', subtitle: 'str' = '') -> 'None'` | Open a whole command: what ran, which run it belongs to, and when. |
| `def finished(what: 'str' = '') -> 'None'` | Close a command with the wall-clock time it ended, carrying the stage's |
| `def now() -> 'str'` | The local wall-clock time, for a caller that wants to stamp its own line. |
| `def phase(title: 'str') -> 'None'` | Open a phase with a centred banner. Pairs with `done`. |
| `def step(message: 'str') -> 'None'` | Progress while a phase runs, e.g. a poll or a per-item counter. |
| `def blank() -> 'None'` | One empty line, to separate a block from what follows it. |
| `def found(message: 'str') -> 'None'` | What the phase produced: counts, outcomes, findings. |
| `def item(label: 'str', value: 'Any') -> 'None'` | One `label:   value` line, for configuration and settings. |
| `def wrote(path: 'Any', label: 'str' = '') -> 'None'` | A file this phase wrote. Always after `found`, before `done`. |
| `def two_columns(left_header: 'str', right_header: 'str', left: "'list[str]'", right: "'list[str]'", gap: 'int' = 3) -> 'None'` | Two aligned columns — an in→out summary read down each side. |
| `def warning_count() -> 'int'` |  |
| `def warn(message: 'str') -> 'None'` |  |
| `def error(message: 'str') -> 'None'` | A refusal the run stops on, in the `[Warning]` house style. |
| `def fail(message: 'str') -> 'None'` |  |
| `def done(seconds: 'float', note: 'str' = '') -> 'None'` | Close a phase with its duration — the last line, every time. |
| `class Progress(label: 'str', step: 'int' = 5, heartbeat: 'float' = 300.0, stream: 'Any' = None) -> 'None'` | A progress indicator for a stage whose percentage is actually known. |
| `class OpenPhase(title: 'str') -> 'None'` | A phase whose body is not a single block, closed with `close`. |
| `def open_phase(title: 'str') -> 'OpenPhase'` |  |
| `def timed_phase(title: 'str', note: 'str' = '') -> 'Iterator[dict[str, Any]]'` | Open a phase, time it, and close it even if the body raises. |
