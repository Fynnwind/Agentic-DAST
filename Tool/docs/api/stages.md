# stages

The stage drivers: argparse plus orchestration.

### `dast_orchestrator.stages.ground_truth`

The correctness axis (`dast cve`): the project's only external measure of correctness
(everything else is internal agreement), which is why each target is pinned to a
CVE-bearing version.

Detectability is **measured, never asserted** (docs/DETECTABILITY.md): per run the tool
measures the two links it can observe — `reach` (did a request arrive at the marker's
sink) and `observe` (did success leave a signal, in-band or out-of-band) — and derives a
descriptive single-run `outcome`; the blind-vs-seeded split is a two-run comparison of a
blind run against its `--oracle` counterpart. The marker file holds FACTS ONLY (identity,
one probe, `zap_rules`, `seed`, and the `auth` the CVE requires), no detectability
claim. → DECISIONS.md, docs/DETECTABILITY.md.

| member | summary |
|---|---|
| `def markers_path(target_name: 'str') -> 'Path'` |  |
| `def has_markers(target_name: 'str') -> 'bool'` | Whether a target carries a ground-truth marker set at all. |
| `def auth_applicable(marker_auth: 'str', run_auth_mode: 'str') -> 'bool'` | Whether a run at `run_auth_mode` can exercise a marker needing `marker_auth`. |
| `class Marker(id: 'str', name: 'str', cve: 'str', fixed_in: 'str', description: 'str', cwe: 'str', zap_rules: 'tuple[str, ...]', probe_method: 'str', probe_path: 'str', expect_status: 'tuple[int, ...]', signal: 'str', auth: 'str' = 'none', fix_pr: 'str' = '', fix_location: 'str' = '', seed: 'tuple[str, ...]' = ()) -> None` | One documented vulnerability, mapped to a request that exercises it. |
| `class MarkerSet(target: 'str', version: 'str', markers: 'list[Marker]' = <factory>) -> None` | MarkerSet(target: 'str', version: 'str', markers: 'list[Marker]' = <factory>) |
| `def route_reaches_sink(marker: 'Marker', url: 'str') -> 'bool'` | Did a request at `url` land on the marker's sink ROUTE (reach, not observe). |
| `def on_the_markers_own_sink(marker: 'Marker', url: 'str', param: 'str') -> 'bool'` | Did this alert fire on the marker's actual sink, or merely somewhere? |
| `def assess_marker(marker: 'Marker', alerts: 'list[Mapping[str, Any]]', correlation: 'Mapping[str, Any]', verification: 'Mapping[str, Any]', reach_paths: "'frozenset[str] \| None'" = None, run_auth_mode: 'str' = 'none') -> 'dict[str, Any]'` | One marker's MEASURED assessment for a finished run. |
| `def single_run_table(assessments: 'list[dict[str, Any]]') -> 'dict[str, Any]'` | The single-run summary: markers grouped by their measured outcome. |
| `def assess_run(marker_set: 'MarkerSet', run: 'run_paths.RunLayout', suffix: 'str' = '') -> 'dict[str, Any]'` | One run's measured assessment — the single-run `cve-detection.json`. |
| `def compare_runs(blind: 'Mapping[str, Any]', oracle: 'Mapping[str, Any]') -> 'dict[str, Any]'` | The blind-vs-`--oracle` ladder, from two single-run assessments. |
| `def build_parser() -> 'argparse.ArgumentParser'` |  |
| `def resolve_run_anywhere(ident: 'str') -> "'run_paths.RunLayout \| None'"` | Find a run by id across `data/runs` AND every `data/harness/<sheet>`. |
| `def run_flipped_counterpart(run: 'run_paths.RunLayout', oracle_guided: 'bool') -> 'str'` | Re-execute the pipeline with `run`'s scan config and `--oracle` toggled; |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.stages.report`

Merge the three readings into a SARIF 2.1.0 report and a Markdown summary (`dast report`).

Two rule-id namespaces, as the architecture requires: ZAP's rules mirrored on an
`owasp-zap` tool extension, and the self-authored cross-endpoint synthesis rules on the
driver — linked via each synthesis rule's `relationships` and result-level
`relatedLocations` / `supportingFindingGuids` (SARIF 2.1.0 has no
`result.relationships`). The verification outcome rides in a result's `properties` and
colours the summary but never changes `level` (ZAP's risk sets that), and no model writes
findings prose — templates only. → DECISIONS.md.

| member | summary |
|---|---|
| `def zap_rules(findings: 'list[dict[str, Any]]') -> 'tuple[list[dict[str, Any]], dict[str, int]]'` | One reportingDescriptor per ZAP plugin that fired, plus an id->index map. |
| `def synthesis_rules(correlated: 'list[dict[str, Any]]', findings_by_id: 'dict[str, dict[str, Any]]', zap_index: 'dict[str, int]', extra_patterns: "'Iterable[str]'" = ()) -> 'tuple[list[dict[str, Any]], dict[str, int]]'` | Synthesis reportingDescriptors, each linked to the ZAP rules it rests on. |
| `def confirmed_siblings(verification_artifact: "'dict[str, Any] \| None'") -> 'list[dict[str, Any]]'` | The sibling probes that reproduced the weakness, and only those. |
| `def build_sarif(correlation: 'dict[str, Any]', verification_artifact: 'dict[str, Any] \| None') -> 'dict[str, Any]'` |  |
| `def build_summary_md(correlation: 'dict[str, Any]', verification_artifact: 'dict[str, Any] \| None', scan: 'dict[str, Any] \| None' = None, data_dir: "'Path \| None'" = None, cve_detection: "'dict[str, Any] \| None'" = None) -> 'str'` | The human-readable report: what ran, what it found, and what it is worth. |
| `def run_limits(data_dir: "'Path \| None'", run_id: "'str \| None'") -> 'list[dict[str, Any]]'` | Every ceiling/degradation any stage of this run hit, newest stage last. |
| `def build_parser() -> 'argparse.ArgumentParser'` | This stage's argument parser, built without parsing anything. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.stages.scan`

Scan a target: Noir static extraction seeds ZAP's site tree, then a bounded spider and
active scan write the raw alerts and an HTTP-exchange sidecar.

Target-agnostic — which system is scanned comes from a `Target`
(`--target-name`, default `gitea`), supplying the base URL, source tree, placeholder
substitutions and login flow. Flow: Noir extraction → seed → spider → passive drain →
bounded active scan → fetch alerts → write `data/<run-id>/` (`--no-noir` reproduces the
spider-only behaviour, and the coverage delta is itself a result). → docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `def source_is_foreign(source_dir: "'Path \| str'", target_name: 'str') -> 'bool'` | True when `source_dir` is not inside `targets/<target_name>/`. |
| `def marker_kind(marker: 'str') -> "'tuple[str, str]'"` | Split a route marker into `(kind, text)`. |
| `def logout_regex(marker: 'str') -> 'str'` | The whole-URL Java regex ZAP's exclusion lists take for a literal `marker`. |
| `def drop_logout_seeds(seeds: "'list[SeedRequest]'", markers: "'tuple[str, ...]'") -> "'tuple[list[SeedRequest], int]'"` | Remove every seed a route marker blocks: a URL marker anywhere in its URL, a |
| `def resolve_rule_minutes(flag: "'int \| None'", target: "'targets.Target \| None'") -> 'int'` | Per-rule ceiling: flag, then env, then the target, then the default. |
| `def describe_injectable_targets(mask: 'int') -> 'str'` | Render an injectable-target bitmask as `"query-string, url-path"`. |
| `def seed_zap(zap: 'ZapClient', seeds: 'list[SeedRequest]', required: "'Collection[SeedRequest]'" = ()) -> 'int'` | Push seed requests into ZAP's site tree. Returns the number accepted. |
| `def parse_spiders(value: "'str \| Iterable[str]'") -> 'tuple[str, ...]'` | Parse `traditional,client` into an ordered, de-duplicated tuple. |
| `def run_spiders(zap: 'ZapClient', target_url: 'str', spiders: "'tuple[str, ...]'", browser_minutes: 'int' = 5) -> 'dict[str, Any]'` | Run each requested crawler in order, recording what each left behind. |
| `def scan_health(seconds: 'float', cap_minutes: 'int', active_alerts: 'int', urls_in_tree: 'int') -> "'str \| None'"` | Why this active scan looks like it did not happen, or `None`. |
| `def run_noir_stage(source_dir: 'Path', target_url: 'str', noir_image: 'str', path_vars: 'dict[str, str]', timestamp: 'str', run_id: 'str' = '', data_dir: "'Path \| None'" = None, ignore_technologies: "'tuple[str, ...]'" = ()) -> 'tuple[list[SeedRequest], dict[str, object]]'` | Run Noir, write both artifacts, and return the seeds plus run metadata. |
| `def scan_config(**values: 'Any') -> 'dict[str, Any]'` | The scan settings that go into the run id's configuration digest. |
| `def run_scan(zap_addr: 'str', api_key: 'str', target_url: 'str', max_scan_minutes: 'int', max_rule_minutes: 'int', use_noir: 'bool' = True, source_dir: 'Path' = PosixPath('<targets>/gitea/src'), noir_image: 'str' = 'ghcr.io/owasp-noir/noir:1.2.1@sha256:5332bdb800dc281d4d7067aa14bd15986144f9121b92d7f466c02ba807b00103', path_vars: 'dict[str, str] \| None' = None, injectable_targets: 'int' = 19, add_query_param: 'bool' = False, auth_session: "'object \| None'" = None, target_name: 'str' = '', disabled_rules: "'tuple[str, ...]'" = ('10104', '50000', '100043'), max_alerts_per_rule: 'int' = -1, data_dir: "'Path \| None'" = None, noir_ignore_technologies: "'tuple[str, ...]'" = (), oracle_seeds: "'tuple[str, ...]'" = (), openapi_specs: 'tuple' = (), target_dir: "'Path \| None'" = None, spiders: "'tuple[str, ...]'" = ('traditional',), browser_spider_minutes: 'int' = 5, zap_mode: 'str' = 'rest', plan_path: "'Path \| None'" = None, zap_container: 'str' = 'dast-zap', structural_parameters: "'tuple[str, ...]'" = (), scan_headers: "'dict[str, str] \| None'" = None, reset_mode: 'str' = 'restart', scan_rules: "'tuple[targets.ScanRule, ...]'" = (), keep_session: 'bool' = False, passive_only: 'bool' = False, reset_target: 'bool' = False, force: 'bool' = False) -> 'Path'` | Run the full pipeline and write the run's artifacts to `data/`. |
| `def recover_target(target_name: 'str', *, attempts: 'int' = 90, delay: 'float' = 2.0) -> 'bool'` | Restart a wedged target's container(s) and wait until it is loginable. |
| `class PendingLogin(mode: 'str') -> None` | An authenticated run whose login waits for the `--reset-target` reset. |
| `def build_parser() -> 'argparse.ArgumentParser'` | This stage's argument parser, built without parsing anything. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.stages.static_analysis`

SAST + SCA static-analysis findings, standalone: Semgrep and OSV-Scanner over the target's
`src/` (the tree Noir reads), emitting SARIF into `data/` for the SAST↔DAST and
SCA↔DAST cross-sections.

Not a pipeline stage: nothing is dispatched, correlated, verified or fed to a model, no key
is read, and there is deliberately no feedback loop (these findings do not direct the DAST
scan) — only project infrastructure (`run_paths`/`metrics`/`targets`) is shared. Both
tools run offline (`--network none`) so a number is re-runnable — Semgrep's rules are a
pinned checkout, OSV reads a hashed snapshot — and raw output is written unmodified.
→ DECISIONS.md.

| member | summary |
|---|---|
| `class StaticAnalysisError` | Raised when a static-analysis tool could not run or did not return SARIF. |
| `class ToolRun(argv: 'list[str]', exit_code: 'int \| None', stdout: 'str', stderr: 'str', seconds: 'float', timed_out: 'bool' = False) -> None` | One `docker run` of a static-analysis tool, before any interpretation. |
| `def docker_run(image: 'str', args: 'list[str]', *, timeout: 'float', volumes: 'Iterable[str]' = (), env: 'Iterable[str]' = (), workdir: 'str \| None' = None, network: 'str' = 'none') -> 'ToolRun'` | Run one pinned analyser image once and capture stdout/stderr. |
| `def parse_sarif_stdout(run: 'ToolRun', tool: 'str') -> 'dict[str, Any]'` | Parse a tool's stdout as SARIF. |
| `def empty_sarif(tool: 'str') -> 'dict[str, Any]'` | A valid, result-free SARIF 2.1.0 document for a tool that ran but had |
| `def sarif_results(sarif: 'dict[str, Any]') -> 'list[dict[str, Any]]'` |  |
| `def sarif_rules(sarif: 'dict[str, Any]') -> 'list[dict[str, Any]]'` |  |
| `def rule_index(sarif: 'dict[str, Any]') -> 'dict[str, dict[str, Any]]'` |  |
| `def cwe_ids(rule: 'dict[str, Any]') -> 'list[str]'` | CWE identifiers a rule declares, as `["CWE-89", ...]`. |
| `def top_rules(results: 'list[dict[str, Any]]', limit: 'int' = 10) -> 'list[dict[str, Any]]'` | The rules that produced the most findings, most first. |


### `dast_orchestrator.stages.table`

One table, `STAGES`, naming the five commands and, per command, the artifacts it
requires in a run directory and the ones it produces — the description the harness and the
CLI share, so the two front ends can never disagree about what a stage is. Nothing here
executes.

Recording requirements is to refuse early: `scan` then `report` is unsatisfiable
(nothing writes what `report` reads), knowable before the first container rather than
after a 45-minute scan (`plan` resolves a sequence as present / produced-earlier /
missing). `scan` alone mints a run; every stage locks the directory it writes, and
`Stage.lock_name` carries the output suffix for the three stages that have one.
→ docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `def new_run_id(data_dir: "'Path'", before: "'set[str]'") -> 'str \| None'` | Which run directory appeared since `before` was taken, if any. |
| `class Stage(name: 'str', module: 'str', requires: 'tuple[str, ...]' = (), produces: 'tuple[str, ...]' = (), mints_run: 'bool' = False, suffix_flag: 'str' = '') -> None` | One command of the pipeline, described rather than executed. |
| `class StageError` | An unknown stage name, or a sequence that cannot complete. |
| `class Step(stage: 'Stage', inputs: 'dict[str, str]') -> None` | One stage of a planned sequence, with where its inputs come from. |
| `def resolve(names: "'list[str] \| tuple[str, ...]'") -> 'list[Stage]'` | Stage objects for the names given, in the order written. |
| `def plan(names: "'list[str] \| tuple[str, ...]'", run_dir: "'Path \| None'" = None) -> 'list[Step]'` | Resolve a sequence against a run directory, marking every input's source. |
| `def unsatisfied(steps: 'list[Step]') -> 'list[str]'` | Human-readable reasons the sequence cannot complete, empty if it can. |


### `dast_orchestrator.stages.triage`

Triage a finished scan: join ZAP alerts to Noir endpoints, then run the deterministic arm
and the LLM arm; writes `triage.json`.

Reads artifacts off disk instead of running inside `scan`, for two reasons: triage can
be re-run against a stored scan without paying for another active scan, and the control arm
can be evaluated with `--no-llm` on a machine with no API key. The LLM arm is two passes —
screening (per-endpoint) and synthesis (whole-corpus). See docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `def collapse_systemic(work: "list[tuple['Bundle', list[tuple[str, Any]]]]") -> "tuple[list[tuple['Bundle', list[tuple[str, Any]]]], dict[str, str]]"` | Fold site-wide (`SYSTEMIC`-tagged) findings to one representative each. |
| `def fan_systemic_verdicts(findings: 'list[dict[str, Any]]', fanout: 'dict[str, str]') -> 'int'` | Copy each representative's verdict onto the systemic instances folded into it. |
| `def triage_config(**values: 'Any') -> 'dict[str, Any]'` | The triage settings that make two runs of one scan different experiments. |
| `def pass1_candidates(bundles: 'list[Bundle]', max_endpoints: 'int' = 0, prune_noninteractive_php: 'bool' = False) -> 'tuple[list[Bundle], int]'` | The endpoints pass 1 sends to the model, and how many php_pure were pruned. |
| `class Pass1Plan(work: 'list[tuple[Bundle, list[tuple[str, Any]]]]', fanout: 'dict[str, str]', asked_ids: 'list[str]', deferred_ids: 'list[str]', unmatched: 'int', unmatched_sent: 'int', deferred_by_risk: 'dict[str, int]') -> None` | What pass 1 sends, fixed before the first call (`plan_pass1`). |
| `def plan_pass1(candidates: 'list[Bundle]', findings: 'list[dict[str, Any]]', max_unmatched_findings: 'int' = -1, has_source: "'Callable[[Bundle], bool] \| None'" = None) -> 'Pass1Plan'` | The findings pass 1 asks, decided before any call so a repeat asks the same. |
| `class CodeContextUngrounded` | Code context is on, yet no endpoint pass 1 would send has its own handler. |
| `def require_located_handlers(assembler: "'evidence.Assembler \| None'", candidates: 'list[Bundle]') -> 'None'` | Refuse a run whose code context locates the handler of none of its endpoints. |
| `def run_llm_arm(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', model: 'str', max_endpoints: 'int', api_key: 'str \| None' = None, concurrency: 'int' = 10, pass1_context: 'str' = 'full', prompt: "'prompts.Prompt \| None'" = None, stage_max_cost_usd: 'float' = -1.0, run_max_cost_usd: 'float' = -1.0, prior_cost_usd: 'float' = 0.0, assembler: "'evidence.Assembler \| None'" = None, retrieval_mode: 'str' = 'push', max_retrievals: 'int' = 6, messages_path: "'Path \| None'" = None, source_dir: "'Path \| None'" = None, oracle: "'dict[str, Any] \| None'" = None, provider: 'str' = '', prune_noninteractive_php: 'bool' = False, max_alerts_per_call: 'int' = 6, max_unmatched_findings: 'int' = -1, max_minutes: 'float' = -1) -> 'dict[str, Any]'` | Pass 1: call the model once per candidate bundle, merging verdicts in. |
| `def run_synthesis_arm(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', scan_summary: 'dict[str, Any]', model: 'str', api_key: 'str \| None' = None, prompt: "'prompts.Prompt \| None'" = None, repeats: 'int' = 5, concurrency: 'int' = 10, models: "'list[str] \| None'" = None, oracle: "'dict[str, Any] \| None'" = None, provider: 'str' = '', providers: "'list[str] \| None'" = None, timeout: "'float \| None'" = None, max_prompt_tokens: 'int' = 0) -> 'tuple[list[dict[str, Any]], dict[str, Any]]'` | Pass 2: N complete calls over the whole triaged scan, unioned. |
| `def llm_synthesize_client(api_key: 'str \| None', model: 'str', provider: 'str' = '')` | The synthesis pass uses the same client, and reports its cost separately. |
| `def print_summary(artifact: 'dict[str, Any]') -> 'None'` | One section: what triage was given on the left, what it produced on the |
| `def print_model_usage(artifact: 'dict[str, Any]') -> 'None'` | Report what the whole LLM arm cost, both passes together. |
| `def dry_run(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', out_dir: 'Path', timestamp: 'str', scan_summary: 'dict[str, Any] \| None' = None, pass1_context: 'str' = 'full', assembler: "'evidence.Assembler \| None'" = None, synthesis_calls: 'int' = 1, oracle_target: "'targets.Target \| None'" = None, prune_noninteractive_php: 'bool' = False, max_alerts_per_call: 'int' = 6, max_unmatched_findings: 'int' = -1) -> 'Path'` | Write exactly what both LLM passes would send, without sending anything. |
| `def build_parser() -> 'argparse.ArgumentParser'` | This stage's argument parser, built without parsing anything. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |


### `dast_orchestrator.stages.verify`

Verify triaged findings with independent tools — one bounded loop per finding, the third
and last reading (after the deterministic table and LLM triage): a tool actually trying
the attack, recorded confirmed / refuted / inconclusive / not-attempted.

Reads `triage.json` off disk (never re-scans) and writes `verification.json`, talking
to the tools over stdio MCP. One loop whose single axis is `VERIFY_INVOCATION`
(`llm`|`deterministic`, how the tool is called); which tool is always the
deterministic lookup, and `deterministic` invocation is the free, key-less control
that stays first-class. → DECISIONS.md.

| member | summary |
|---|---|
| `class ProbeTarget(url: 'str', param: 'str', injection_point: 'str', url_source: 'str') -> None` | What a verification tool should aim at, and how that was decided. |
| `def probe_target(finding: 'dict[str, Any]', fillers: 'dict[str, str] \| None' = None) -> 'ProbeTarget'` | The clean URL to probe for one finding. |
| `def looks_like_payload(attack: 'str') -> 'bool'` | Whether an `attack` string is recognisably a payload, not a plain value. |
| `def restore_path_payload(path: 'str', param: 'str', attack: 'str') -> 'tuple[str \| None, bool]'` | Put a path segment carrying an attack payload back to its clean value. |
| `def mark_path_injection(url: 'str', param: 'str', template: 'str' = '') -> 'str \| None'` | Mark a path parameter with sqlmap's `*` injection point. |
| `def sqlmap_can_address(target: 'str', param: 'str', data: 'str') -> 'bool'` | Whether sqlmap has an injection point it can actually reach. |
| `def filler_for(name: 'str', fillers: 'dict[str, str]') -> "'str \| None'"` | A declared value for this form field, tolerating PHP array-style names. |
| `def placeholder_fields(body: 'str') -> 'list[str]'` | Body fields that carry the placeholder rather than a declared value. |
| `def build_dispatch(finding: 'dict[str, Any]', findings_by_endpoint: 'dict[Any, list[dict[str, Any]]]', fillers: 'dict[str, str] \| None' = None, auth_ctx: 'dict[str, Any] \| None' = None, oob: 'bool' = False, oracle: 'bool' = False) -> 'dict[str, Any] \| None'` | The tool + arguments a finding should be verified with. |
| `def oracle_seed_tool(zap_rules: "'Any'") -> "'str \| None'"` | The tool the rescan table routes a marker's own rule(s) to, or `None`. |
| `def build_oracle_seed_dispatch(marker: "'Any'", target: "'targets.Target'", auth_ctx: "'dict[str, Any] \| None'" = None, oob: 'bool' = False) -> "'dict[str, Any] \| None'"` | Synthesise one verify dispatch from a ground-truth marker's own sink. |
| `def build_correlated_dispatch(correlated: 'dict[str, Any]', findings_by_id: 'dict[str, dict[str, Any]]', auth_ctx: 'dict[str, str] \| None' = None, oob: 'bool' = False) -> 'dict[str, Any] \| None'` | Route a correlated finding by borrowing a supporting finding's concrete URL. |
| `def parse_route(entry: 'str') -> "'tuple[str, str] \| None'"` | Split an `affected_routes` entry into method and route template. |
| `def sibling_url(base_url: 'str', template: 'str', path_vars: 'dict[str, str]', param: 'str', value: 'str' = '1') -> 'str'` | A concrete, probeable URL for a route the scanner never visited. |
| `def build_sibling_dispatches(correlated: 'dict[str, Any]', plan: "'dict[str, Any] \| None'", support: "'dict[str, Any] \| None'", target: "'targets.Target \| None'", already_verified: "'set[str]'", cap: 'int' = 0, auth_ctx: "'dict[str, str] \| None'" = None, oob: 'bool' = False) -> 'list[dict[str, Any]]'` | One probe per unflagged sibling route a propagation claim predicts. |
| `def route_checker(fetch=None, timeout: 'float' = 10.0)` | A `url -> status` callable for the sibling reachability pre-check. |
| `def sibling_finding_id(claim_id: 'str', route: 'str') -> 'str'` | A stable id for a finding reached by propagation, in its own `s-` space. |
| `def sibling_record(probe: 'dict[str, Any]', result: 'dict[str, Any]', claim: 'dict[str, Any]', cfg: 'dict[str, Any]', route_status: "'int \| None'" = None, not_attempted_reason: 'str' = '') -> 'dict[str, Any]'` | One sibling probe's verdict, with the provenance that makes it readable. |
| `def verify_config(**values: 'Any') -> 'dict[str, Any]'` | The verification settings that make two runs of one triage different. |
| `class Dispatcher(budget: 'DispatchBudget', stack: 'AsyncExitStack') -> 'None'` | Holds one persistent stdio session per tool and enforces the budget. |
| `def directed_arguments(finding: 'dict[str, Any]', tool: 'str', proposal: 'dict[str, Any]', findings_by_endpoint: 'dict[Any, list[dict[str, Any]]]', fillers: 'dict[str, str] \| None', auth_ctx: 'dict[str, Any] \| None', oob: 'bool') -> 'dict[str, Any] \| None'` | Executor arguments for one model-directed round, target derived deterministically. |
| `def loop_config(invocation: 'str' = 'llm', max_rounds: 'int' = 3) -> 'dict[str, Any]'` | The invocation axis plus the round cap, as one block recorded on every record. |
| `def run_loop(dispatcher: "'Dispatcher'", finding: 'dict[str, Any]', plan: "'dict[str, Any] \| None'", ctx: 'dict[str, Any]', cfg: 'dict[str, Any]', client: "'OpenRouterCorrelator \| None'", findings_by_endpoint: 'dict[Any, list[dict[str, Any]]]', fillers: "'dict[str, str] \| None'" = None, auth_ctx: "'dict[str, str] \| None'" = None, oob: 'bool' = False, system_prompt: "'str \| None'" = None, oracle: "'dict[str, Any] \| None'" = None, retrieval: "'retrieval_mod.Retrieval \| None'" = None, session: 'Any' = None) -> 'verification.LoopVerdict'` | Verify one finding: up to `max_rounds` tool invocations, then a verdict. |
| `def verify_all(dispatchable: 'list[dict[str, Any]]', correlated_plans: 'list[tuple[dict[str, Any], dict[str, Any] \| None]]', budget: 'DispatchBudget', findings_by_endpoint: 'dict[Any, list[dict[str, Any]]]', cfg: 'dict[str, Any]', client: "'OpenRouterCorrelator \| None'" = None, findings_by_id: "'dict[str, dict[str, Any]] \| None'" = None, fillers: "'dict[str, str] \| None'" = None, auth_ctx: "'dict[str, str] \| None'" = None, oob: 'bool' = False, contexts: "'dict[str, dict[str, Any]] \| None'" = None, system_prompt: "'str \| None'" = None, target: "'targets.Target \| None'" = None, max_siblings: 'int' = 0, oracle: "'dict[str, Any] \| None'" = None, check_route: "'Any \| None'" = None, retrieval: "'retrieval_mod.Retrieval \| None'" = None, oracle_seed_markers: "'list[Any] \| None'" = None, run_auth_mode: 'str' = 'none') -> 'tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, Any], list[dict[str, Any]]]'` | Run one loop per selected finding, all within one dispatcher and budget. |
| `def select_findings(findings: 'Iterable[dict[str, Any]]') -> 'list[dict[str, Any]]'` | Findings either arm flagged, most-important-first. |
| `def summarise(verifications: 'list[dict[str, Any]]', correlated: 'list[dict[str, Any]]', per_rule: 'dict[str, int]', loop_info: "'dict[str, Any] \| None'" = None, siblings: "'list[dict[str, Any]] \| None'" = None, oracle_seeded: "'list[dict[str, Any]] \| None'" = None) -> 'dict[str, Any]'` | The run's outcome counts, plus the two-reading agreement rate. |
| `def build_artifact(source_name: 'str', run_id: 'str', budget: 'DispatchBudget', verifications: 'list[dict[str, Any]]', correlated: 'list[dict[str, Any]]', per_rule: 'dict[str, int]', loop_info: "'dict[str, Any] \| None'" = None, oob: 'bool' = False, siblings: "'list[dict[str, Any]] \| None'" = None, table_version: "'int \| None'" = None, oracle_seeded: "'list[dict[str, Any]] \| None'" = None) -> 'dict[str, Any]'` |  |
| `def print_summary(artifact: 'dict[str, Any]') -> 'None'` | One section: what was selected on the left, what the tools returned on the |
| `def print_model_usage(loop_info: 'dict[str, Any]') -> 'None'` | What the verification loop's model calls cost — the verify analogue of |
| `def build_contexts(layout: 'run_paths.RunLayout', correlation: 'dict[str, Any]', findings: 'list[dict[str, Any]]', target: 'Any') -> 'dict[str, dict[str, Any]]'` | The HTTP exchange and the handler source behind each selected finding. |
| `def count_grounded(contexts: 'dict[str, dict[str, Any]]') -> 'int'` | How many of these contexts actually carry handler source. |
| `def dry_run(dispatchable: 'list[dict[str, Any]]', correlated_plans: 'list[tuple[dict[str, Any], dict[str, Any] \| None]]', findings_by_endpoint: 'dict[Any, list[dict[str, Any]]]', budget: 'DispatchBudget', fillers: 'dict[str, str] \| None' = None, auth_ctx: 'dict[str, str] \| None' = None, cfg: 'dict[str, Any] \| None' = None, contexts: "'dict[str, dict[str, Any]] \| None'" = None, system_prompt: "'str \| None'" = None, findings_by_id: "'dict[str, dict[str, Any]] \| None'" = None, target: "'targets.Target \| None'" = None, max_siblings: 'int' = 0, oracle: "'dict[str, Any] \| None'" = None) -> 'None'` | The plan, and — when the loop would run — the exact round-1 prompt. |
| `def build_parser() -> 'argparse.ArgumentParser'` | This stage's argument parser, built without parsing anything. |
| `def main(argv: "'list[str] \| None'" = None) -> 'int'` |  |
