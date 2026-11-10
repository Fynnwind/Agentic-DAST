# analysis

The judgement logic — the triage arms and the verify loop.

### `dast_orchestrator.analysis.join`

The join: correlate ZAP alerts (concrete URLs) with Noir endpoints (route templates) so
a finding carries its handler's static context.

Resolved in three tiers, recorded per finding: `seed` (the exact template→URL map,
zero inference), `regex` (the template read backwards, for spider-found URLs; ambiguous
matches ranked, losers kept as `alternatives`), and `regex-path-only` (path matches,
method does not). A template's literal query (`admin-ajax.php?action=X`) must also be
present in the URL's query, in every tier. Unmatched findings get no context with the reason recorded; the LLM
pass still sees them, on dynamic evidence alone, and skips only bundles with no
flagged or non-informational alert. → DECISIONS.md.

| member | summary |
|---|---|
| `class JoinError` | Raised when a run's artifacts are missing or do not belong together. |
| `class RunArtifacts(timestamp: 'str', ai_context: 'dict[str, Any]', zap_report: 'dict[str, Any]', seed_map: 'dict[str, Any] \| None', ai_context_path: 'Path', zap_report_path: 'Path', seed_map_path: 'Path \| None') -> None` | The files of one scan run, all sharing a timestamp. |
| `def find_latest_timestamp(data_dir: 'Path') -> 'str'` | The newest run directory, if it holds what the correlation needs. |
| `def load_run(data_dir: 'Path', timestamp: 'str \| None' = None) -> 'RunArtifacts'` | Load one run's artifacts. |
| `class Match(endpoint_key: 'str \| None', how: 'str', alternatives: 'tuple[str, ...]' = ()) -> None` | Result of resolving one (method, path, query) onto a Noir route template. |
| `class EndpointJoiner(endpoints: 'Iterable[dict[str, Any]]', seed_map: 'dict[str, Any] \| None' = None) -> 'None'` | Resolves concrete (method, URL path) pairs back onto route templates. |
| `class AlertGroup(plugin_id: 'str', name: 'str', risk: 'str', confidence: 'str', param: 'str', evidence: 'str', method: 'str', cweid: 'str' = '', alert_ref: 'str' = '', attack: 'str' = '', description: 'str' = '', other: 'str' = '', solution: 'str' = '', wascid: 'str' = '', tags: 'dict[str, str]' = <factory>, input_vector: 'str' = '', source: 'str' = '', urls: 'list[str]' = <factory>, zap_alert_ids: 'list[str]' = <factory>, message_ids: 'list[str]' = <factory>, source_message_ids: 'list[str]' = <factory>, tiers: 'dict[str, int]' = <factory>) -> None` | Identical alerts across many concrete URLs, collapsed into one finding. |
| `class Bundle(endpoint_key: 'str \| None', match_how: 'str', method: 'str', path: 'str', alternatives: 'tuple[str, ...]' = (), static_context: 'dict[str, Any] \| None' = None, groups: 'list[AlertGroup]' = <factory>) -> None` | Everything known about one endpoint: static context plus its findings. |
| `def signal_names(bundle: 'Bundle', category: 'str') -> 'list[str]'` | Distinct Noir signal names of one category on one endpoint, capped. |
| `def shared_handlers(bundles: 'Iterable[Bundle]', routes_with_findings: 'set[str]') -> 'dict[str, list[str]]'` | Handler functions reached by more than one route: the propagation links. |
| `def build_bundles(run: 'RunArtifacts') -> 'list[Bundle]'` | Group every alert of a run under the endpoint it belongs to. |
| `def finding_id(bundle: 'Bundle', group: 'AlertGroup') -> 'str'` | Content hash: same endpoint + rule + evidence yields the same id. |
| `def is_llm_candidate(bundle: 'Bundle') -> 'bool'` | Whether this bundle is worth a model call. See the module docstring. |
| `def is_noninteractive_php(bundle: 'Bundle') -> 'bool'` | A `php_pure` endpoint whose source lives under `cli/`. |
| `def select_llm_candidates(bundles: 'Iterable[Bundle]', prune_noninteractive_php: 'bool' = False) -> 'tuple[list[Bundle], int]'` | The bundles pass 1 will call the model on, and how many the gated |
| `def build_findings(bundles: 'Iterable[Bundle]') -> 'list[dict[str, Any]]'` | One finding per (endpoint, collapsed alert), with the control-arm verdict. |
| `def label_agreement(finding: 'dict[str, Any]') -> 'str'` | Compare the two arms on one finding. The delta metric of Phase 3. |
| `def mark_asked(findings: 'list[dict[str, Any]]', finding_ids: 'Iterable[str]') -> 'None'` | Record that these findings were put in front of the model. |
| `def mark_deferred(findings: 'list[dict[str, Any]]', finding_ids: 'Iterable[str]') -> 'None'` | Record that pass 1's limit left these candidates unsent. |
| `def top_rules(bundles: 'Iterable[Bundle]', limit: 'int' = 10) -> 'list[dict[str, Any]]'` | Which ZAP rules produced the alert volume, most first. |
| `def summarise(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', correlated: 'list[dict[str, Any]]', run_alerts: 'Iterable[dict[str, Any]]' = ()) -> 'dict[str, Any]'` | Counts the writeup needs, computed once and stored in the artifact. |
| `def self_consistency(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]') -> 'dict[str, Any]'` | How often the LLM arm gave one rule two different verdicts. |
| `def build_artifact(run: 'RunArtifacts', bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', correlated: 'list[dict[str, Any]]', llm_metadata: 'dict[str, Any] \| None', synthesis_metadata: 'dict[str, Any] \| None' = None, evidence_metadata: 'dict[str, Any] \| None' = None) -> 'dict[str, Any]'` | Assemble the versioned correlation artifact written to `data/`. |


### `dast_orchestrator.analysis.oracle`

Oracle-guided mode (`--oracle`): hand the pipeline a target's documented
vulnerabilities (`targets/<name>/oracle.md`, prose about the application) and measure
what it still confirms — a CEILING, never a detection number.

The gap from the blind run is the "detectable but missed" set. Kept honest by rule: a
ceiling run never shares a table with a blind one (every artifact carries
`oracle_guided: true`), the oracle text carries no rule id / verdict / finding id (which
is why it is prose, not the `cve-markers.yml` answer key), and one source per target is
read identically by triage / synthesis / verification. → DECISIONS.md.

| member | summary |
|---|---|
| `def instruction(stage: 'str') -> "'prompts.Prompt'"` | The oracle block for one stage — an unversioned prompt (`prompts.load_oracle`). |
| `class OracleError` | Raised when `--ceiling` is asked for and the target has no oracle. |
| `def path_for(target: "'targets.Target \| None'") -> "'Path \| None'"` | Where this target's oracle document lives, whether or not it exists. |
| `def load(target: "'targets.Target \| None'") -> "'str \| None'"` | The target's oracle document, or `None` when it has none. |
| `def require(target: "'targets.Target \| None'") -> 'str'` | The oracle document, or an actionable error naming where it should be. |
| `def block(target: "'targets.Target \| None'", stage: 'str') -> "'dict[str, Any] \| None'"` | The oracle block one stage's prompt carries, or `None` when off. |


### `dast_orchestrator.analysis.screening`

The experimental LLM screening arm — the triage stage's pass 1 (per-endpoint, rescan
proposals only; the control is `rescan_table`, pass 2 is
`synthesize`), plus the shared `OpenRouterCorrelator`
client the verify loop reuses.

One call per candidate endpoint through the official OpenRouter SDK (no LangChain) — the
request assembled here is the whole of it, and every output-affecting knob is a
version-controlled constant copied into the artifact's `llm` block. The model may
re-flag a finding or propose a correlated-synthesis finding tied to no single alert
(hence the second SARIF rule-id namespace). → DECISIONS.md.

| member | summary |
|---|---|
| `def build_provider(pin: 'str' = '') -> "'dict[str, Any]'"` | The `ProviderPreferences` (as a dict the SDK accepts) for ONE model's calls. |
| `def sampling_params(temperature: 'float', capabilities: "'dict[str, Any] \| None'") -> "'dict[str, Any]'"` | The decoding parameters for one call — `temperature` and `seed` — with |
| `def verdicts_schema(expected: 'int') -> 'dict[str, Any]'` | `RESPONSE_SCHEMA` with the verdict count pinned to this call's alerts. |
| `def missing_verdict_ids(response: 'dict[str, Any]', asked: "'list[str]'") -> 'list[str]'` | Ids that were asked about and have no verdict in this response. |
| `class LlmError(message: 'str', kind: 'str' = 'unknown') -> 'None'` | Raised when the model call fails or returns something unusable. |
| `def over_budget(spent: 'float', cap: 'float') -> 'bool'` | Whether `spent` has reached a cap. A negative cap is no cap. |
| `def headroom(stage_cap: 'float', run_cap: 'float', prior: 'float') -> 'float'` | What one stage may spend, given both ceilings and the run's earlier spend. |
| `def model_vendor(model_id: "'str \| None'") -> 'str'` | The model's vendor — the segment before `/` in an OpenRouter id. |
| `class LlmUsage(calls: 'int' = 0, prompt_tokens: 'int' = 0, completion_tokens: 'int' = 0, cached_prompt_tokens: 'int' = 0, cost_usd: 'float' = 0.0, stage_max_cost_usd: 'float' = -1.0, run_max_cost_usd: 'float' = -1.0, prior_cost_usd: 'float' = 0.0, max_minutes: "'float \| None'" = None, deadline: "'float \| None'" = None, failures: 'int' = 0, retries: 'int' = 0, splits: 'int' = 0, calls_log: 'list[dict[str, Any]]' = <factory>, _lock: "'threading.Lock'" = <factory>, failure_kinds: 'dict[str, int]' = <factory>, failure_details: 'list[dict[str, str]]' = <factory>) -> None` | Per-run accounting, stored in the artifact so cost is a reported number. |
| `def chunk_alerts(findings_for_bundle: 'list[tuple[str, AlertGroup]]', size: 'int' = 6) -> 'list[list[tuple[str, AlertGroup]]]'` | Split one endpoint's findings into per-call batches. |
| `def render_static_context(bundle: 'Bundle') -> 'dict[str, Any]'` | Compact the Noir context down to what the prompt actually uses. |
| `def render_alert(finding_id: 'str', group: 'AlertGroup', assembler: "'evidence.Assembler \| None'" = None, bundle: 'Bundle \| None' = None) -> 'dict[str, Any]'` | One alert as the model sees it: ZAP's summary, plus its actual evidence. |
| `def build_cross_endpoint_context(bundles: 'Iterable[Bundle]', level: 'str' = 'full') -> 'dict[str, dict[str, Any]]'` | What each pass-1 call is told about the endpoints it is not being shown. |
| `def build_user_payload(bundle: 'Bundle', findings_for_bundle: 'list[tuple[str, AlertGroup]]', cross_endpoint: 'dict[str, Any] \| None' = None, assembler: "'evidence.Assembler \| None'" = None, oracle: "'dict[str, Any] \| None'" = None) -> 'dict[str, Any]'` | The per-endpoint JSON handed to the model. |
| `def build_messages(bundle: 'Bundle', findings_for_bundle: 'list[tuple[str, AlertGroup]]', cross_endpoint: 'dict[str, Any] \| None' = None, system_prompt: 'str \| None' = None, assembler: "'evidence.Assembler \| None'" = None, oracle: "'dict[str, Any] \| None'" = None) -> 'list[dict[str, str]]'` |  |
| `def caching_enabled(site: 'str' = '') -> 'bool'` | Whether this call site should mark a cacheable prefix. |
| `def cached_tokens(usage: 'Any') -> 'int'` | Prompt tokens the provider served from its cache, across reporting shapes. |
| `def api_key_from_env() -> 'str'` |  |
| `class OpenRouterCorrelator(api_key: 'str \| None' = None, model: 'str' = 'deepseek/deepseek-v4-flash-0731', temperature: 'float' = 0.0, stage_max_cost_usd: 'float' = -1.0, run_max_cost_usd: 'float' = -1.0, prior_cost_usd: 'float' = 0.0, max_minutes: 'float' = -1.0, provider: 'str' = '', capabilities: "'dict[str, Any] \| None'" = None) -> 'None'` | One thin call per endpoint. Deliberately not batched across endpoints. |
| `def merge_verdicts(findings: 'list[dict[str, Any]]', response: 'dict[str, Any]', bundle_finding_ids: 'Iterable[str]', had_source: 'bool' = False) -> 'tuple[int, list[str]]'` | Write the model's verdicts onto the matching findings. |
| `def is_pinned(model_id: 'str') -> 'bool'` | Whether this id is *known* to name one fixed set of weights. |
| `def model_capabilities(model: 'str', timeout: 'float' = 10.0) -> 'dict[str, Any] \| None'` | What the served model advertises, or `None` if the catalogue is unreachable. |
| `def run_metadata(model: 'str', usage: 'LlmUsage', candidates: 'int', concurrency: 'int' = 1, pass1_context: 'str' = 'full', prompt: "'prompts.Prompt \| None'" = None, provider: "'dict[str, Any] \| None'" = None) -> 'dict[str, Any]'` | The `llm` block of the artifact: everything needed to rerun the pass. |


### `dast_orchestrator.analysis.synthesize`

Pass 2 of the triage LLM arm — global synthesis: one call over the whole screened scan,
emitting only cross-endpoint (correlated) findings, never re-screening.

A separate pass because pass 1 (`screening`) calls the
model once per endpoint and structurally cannot notice that two endpoints share a handler
or a missing guard; this pass is shallow-but-wide (names without snippets, flagged findings
only, the whole run in one call). It is downstream of pass 1 — the corpus carries pass 1's
per-finding verdict so it can tell judged / asked-unanswered / never-asked apart — and is
built around Noir's shared-handler map. → DECISIONS.md.

| member | summary |
|---|---|
| `def is_interesting(finding: 'dict[str, Any]') -> 'bool'` | What earns a finding a place in the corpus. |
| `def build_corpus(bundles: 'list[Bundle]', findings: 'list[dict[str, Any]]', scan_summary: 'dict[str, Any]', max_endpoints: 'int' = 120, oracle: "'dict[str, Any] \| None'" = None) -> 'dict[str, Any]'` | The whole screened scan, compressed to what a cross-endpoint view needs. |
| `def build_messages(corpus: 'dict[str, Any]', system_prompt: 'str \| None' = None) -> 'list[dict[str, str]]'` |  |
| `def collect(response: 'dict[str, Any]', known_finding_ids: 'Iterable[str]') -> 'tuple[list[dict[str, Any]], int]'` | Normalise and validate the pass-2 output. |
| `def claim_key(finding: 'dict[str, Any]') -> 'tuple[str, tuple[str, ...]]'` | Identity of a synthesis claim: its pattern plus the exact evidence it cites. |
| `class Sample(model: 'str', claims: 'list[dict[str, Any]]') -> None` | One whole-corpus synthesis call: which model made it, and what it claimed. |
| `def merge_repeats(runs: 'list[list[dict[str, Any]]]', model: 'str' = '') -> 'list[dict[str, Any]]'` | `merge_samples` for N calls to one model. Kept as the simple case. |
| `def merge_samples(samples: 'list[Sample]') -> 'list[dict[str, Any]]'` | Union the claims of N independent calls, scored by how many produced each. |


### `dast_orchestrator.analysis.verify_loop`

The verification loop: one loop per finding, up to
`DEFAULT_MAX_ROUNDS` rounds of propose →
react → refine, each round feeding the tool's raw output back to the model.

Two load-bearing invariants: the loop is given the handler source but NOT what triage
concluded (anti-circularity, so "verification agrees with triage" cannot be circular),
and each round the wrapper also classifies the output with fixed rules so
`resolve_verdict` decides what is reported.
→ DECISIONS.md.

| member | summary |
|---|---|
| `def build_context(finding: 'dict[str, Any]', exchange: "'dict[str, Any] \| None'" = None, source: "'dict[str, Any] \| None'" = None, fixed_tool: "'str \| None'" = None, max_rounds: 'int' = 3, oracle: "'dict[str, Any] \| None'" = None, earlier_triage: "'dict[str, Any] \| None'" = None) -> 'dict[str, Any]'` | The task handed to the model for one finding, on round 1. |
| `def triage_view(finding: 'dict[str, Any]') -> "'dict[str, Any] \| None'"` | What pass 1 concluded about this finding, for an oracle-guided run only. |
| `def build_messages(context: 'dict[str, Any]', system_prompt: "'str \| None'" = None) -> 'list[dict[str, Any]]'` | The opening conversation for a loop. Later rounds append to it. |
| `def round_result_message(record: 'RoundRecord', rounds_left: 'int') -> 'dict[str, str]'` | The tool's actual output, handed back for the next round. |
| `def normalise_round(raw: 'dict[str, Any]', fixed_tool: "'str \| None'" = None, last_round: 'bool' = False) -> 'dict[str, Any]'` | Coerce a raw model round into a safe, executable shape. |
| `def unattempted(finding_id: 'str', reason: 'str', wrapper_outcome: 'str' = 'not-attempted', code: 'str' = '') -> 'LoopVerdict'` | A finding the loop could not start on, recorded rather than dropped. |
| `def settle(finding_id: 'str', rounds: 'list[RoundRecord]', llm_category: "'str \| None'", stopped_because: 'str', alert: "'dict[str, Any] \| None'" = None) -> 'LoopVerdict'` | Resolve a finished loop's two readings into the one reported verdict. |
| `def run_metadata(model: 'str', usage: 'Any', config: 'dict[str, Any]', looped: 'int', rounds_run: 'int', agreement: 'dict[str, int]', prompt: "'prompts.Prompt \| None'" = None, capabilities: "'dict[str, Any] \| None'" = None) -> 'dict[str, Any]'` | The `loop` block of the verification artifact — enough to rerun it. |
| `def empty_agreement() -> 'dict[str, int]'` |  |
| `def signal_counts(rounds: "'list[RoundRecord]'") -> 'dict[str, int]'` | How each round's declared signal related to the tool's own verdict. |
