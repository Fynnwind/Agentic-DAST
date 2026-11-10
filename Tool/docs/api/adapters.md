# adapters

Isolate every external tool behind one place.

### `dast_orchestrator.adapters.auth`

Seeded-session login (target-agnostic): one login obtains the session cookie, injected into
every ZAP request via a Replacer rule and handed to the verification tools — enough for the
authenticated-vs-unauthenticated coverage delta (its one limit, no re-auth, is immaterial
for a bounded scan).

The login runs as a one-shot container on `dast-net` (the Noir/wrapper idiom), so it
reaches the target by the same container name ZAP uses; the CSRF flow (fetch page, read the
hidden field, POST, keep the cookie) is generic, driven from the target's
`AuthProfile`. It also owns the transport that idiom is built on
(`container_fetch` and its host-side counterpart), which the ground-truth prober and
verify driver reuse. → DECISIONS.md.

| member | summary |
|---|---|
| `class AuthError` | Raised when a login attempt cannot produce a session. |
| `def httpx_fetch(method: 'str', url: 'str', timeout: 'float') -> 'ProbeResponse'` | Host-side transport: reach a host-published port directly. |
| `def container_fetch(network: 'str' = 'dast-net', image: 'str' = 'curlimages/curl:8.10.1', cookie: 'str' = '', headers: "'dict[str, str] \| None'" = None)` | Transport that reaches the target by container name on a docker network. |
| `class AuthSession(mode: 'str', username: 'str', cookie_name: 'str', cookie_value: 'str', status: 'int', cookies: 'str' = '', authenticated: 'bool' = False) -> None` | An authenticated session: the cookies to replay, and how it was obtained. |
| `def parse_login_result(stdout: 'str') -> 'tuple[int, str, str]'` | Extract `(status, cookie_value, jar)` from the login flow's JSON line. |
| `def login(base_url: 'str', profile: 'AuthProfile', mode: 'str', network: 'str' = 'dast-net', timeout: 'int' = 30, runner=<function _default_runner>, fetch_factory=<function container_fetch>) -> 'AuthSession'` | Log in as the account for `mode` and return a CONFIRMED session to replay. |


### `dast_orchestrator.adapters.noir_runner`

Run OWASP Noir over a target's source tree (`targets/<name>/src/`) as a one-shot `docker
run --rm` to extract endpoints and per-endpoint AI context, with raw output written
unmodified.

One run (`-f json --ai-context`) yields three artifacts: the endpoint inventory
(`scan-noir-endpoints.json`), the per-endpoint AI context the LLM arm reads
(`scan-noir-ai-context.json`), and the seed map (`scan-noir-seed-map.json`) — the concrete-URL →
route-template table without which the two cannot be joined (see `join.py`).

| member | summary |
|---|---|
| `class NoirError` | Raised when Noir fails to run or returns an unexpected shape. |
| `class NoirEndpoint(method: 'str', path: 'str', technology: 'str', code_paths: 'tuple[tuple[str, int], ...]' = (), params: 'tuple[dict[str, Any], ...]' = (), tags: 'tuple[dict[str, Any], ...]' = (), ai_context: 'dict[str, list[dict[str, Any]]]' = <factory>) -> None` | One HTTP endpoint as Noir statically extracted it (route template form). |
| `class SeedRequest(method: 'str', url: 'str', endpoint_key: 'str') -> None` | A concrete request ready to hand to ZAP, from Noir, a spec or an oracle seed. |
| `def build_command(source_dir: 'Path', image: 'str' = 'ghcr.io/owasp-noir/noir:1.2.1@sha256:5332bdb800dc281d4d7067aa14bd15986144f9121b92d7f466c02ba807b00103', use_all_taggers: 'bool' = True) -> 'list[str]'` | Build the one-shot `docker run` argv. |
| `def run_noir(source_dir: 'Path', image: 'str' = 'ghcr.io/owasp-noir/noir:1.2.1@sha256:5332bdb800dc281d4d7067aa14bd15986144f9121b92d7f466c02ba807b00103', timeout: 'float' = 900.0) -> 'dict[str, Any]'` | Run Noir over `source_dir` and return its parsed JSON output. |
| `def parse_endpoints(raw: 'dict[str, Any]', ignore_technologies: "'frozenset[str] \| tuple[str, ...]'" = ()) -> 'list[NoirEndpoint]'` | Extract the HTTP endpoints from Noir's JSON, dropping CLI/docs entries. |
| `def substitute_path(path: 'str', path_vars: 'dict[str, str]') -> 'str'` | Replace chi placeholders in a route template with concrete values. |
| `def classify_guard(name: 'str') -> 'str'` | Say whether a Noir guard actually enforces authentication. |
| `def template_to_regex(path: 'str') -> 're.Pattern[str]'` | Compile a route template into a pattern that matches concrete URL paths. |
| `def bind_path_vars(template: 'str', path: 'str') -> "'dict[str, str] \| None'"` | Recover the values a concrete URL supplied for a template's placeholders. |
| `def split_template_query(template: 'str') -> 'tuple[str, tuple[tuple[str, str], ...]]'` | A route template's path, and the literal query parameters it requires. |
| `def query_satisfies(required: 'Iterable[tuple[str, str]]', query: 'str') -> 'bool'` | Whether a concrete query string carries every required `name=value` pair. |
| `def template_specificity(path: 'str') -> 'tuple[int, int, int]'` | Rank key for choosing between templates that match the same URL. |
| `def to_seed_requests(endpoints: 'Iterable[NoirEndpoint]', base_url: 'str', path_vars: 'dict[str, str] \| None' = None) -> 'list[SeedRequest]'` | Turn route templates into concrete `(method, absolute URL)` requests. |
| `def parse_path_vars(assignments: 'Iterable[str]') -> 'dict[str, str]'` | Parse repeated `--path-var name=value` CLI arguments. |
| `def build_seed_map_artifact(endpoints: 'Iterable[NoirEndpoint]', base_url: 'str', generated_at: 'str', path_vars: 'dict[str, str] \| None' = None) -> 'dict[str, Any]'` | Record which route templates produced which concrete URL. |
| `def build_ai_context_artifact(endpoints: 'Iterable[NoirEndpoint]', source_dir: 'Path', generated_at: 'str', noir_image: 'str' = 'ghcr.io/owasp-noir/noir:1.2.1@sha256:5332bdb800dc281d4d7067aa14bd15986144f9121b92d7f466c02ba807b00103') -> 'dict[str, Any]'` | Distil Noir's per-endpoint AI context into the correlation-pass input. |
| `def write_artifacts(raw: 'dict[str, Any]', endpoints: 'list[NoirEndpoint]', source_dir: 'Path', out_dir: 'Path', timestamp: 'str', base_url: 'str', path_vars: 'dict[str, str] \| None' = None, run_id: 'str' = '') -> 'tuple[Path, Path, Path]'` | Write the inventory, the AI context and the seed map. Returns all paths. |


### `dast_orchestrator.adapters.openapi_import`

Seed ZAP's site tree from an OpenAPI/Swagger document — the framework-agnostic alternative
to Noir's source extraction, for a target whose router Noir cannot model.

A spec declares routes as literal `paths` strings whatever the framework, so a target
points at one (served URL or committed file) and its routes seed ZAP exactly as Noir's do.
It widens discovery to the declared API surface only — not static-asset/admin routes no
spec declares, where a marker's `--oracle seed:` stays the honest lever — and parses into
the same `SeedRequest` list, never ZAP's
opaque importer. → DECISIONS.md.

| member | summary |
|---|---|
| `class OpenApiError` | Raised when a declared spec cannot be fetched, parsed, or read. |
| `class OpenApiSpec(url: 'str' = '', file: 'str' = '', base_path: 'str' = '') -> None` | One declared route source: a served `url` XOR a committed `file`. |
| `def spec_paths(doc: 'dict', base_path_override: 'str' = '') -> 'list[tuple[str, str]]'` | `(method, path-template)` for every operation the spec declares. |
| `def spec_to_seeds(doc: 'dict', base_url: 'str', path_vars: 'dict[str, str]', base_path_override: 'str' = '', source: 'str' = 'openapi') -> 'list[SeedRequest]'` | Turn a parsed spec into deduplicated, fetchable seed requests. |
| `def load_doc(spec: 'OpenApiSpec', target_dir: 'Path', fetch=None, timeout: 'float' = 15.0) -> 'dict'` | Fetch/read a spec and parse it (JSON or YAML — `yaml.safe_load` does both). |


### `dast_orchestrator.adapters.retrieval`

The client half of `TRIAGE_RETRIEVAL=pull`: hand the model a minimal pack plus the
ability to ask, and let it pull the exchange or source it wants from
`mcp/context_server.py` (the counterpart of pushed evidence; push stays the default).

Client side only — open a session, declare its tools, execute a tool call, record every
retrieval; the loop lives in
`complete`. Sync over
async so pass-1 concurrency stays synchronous (its determinism invariants are load-bearing):
one session per worker, opened lazily so an endpoint that asks for nothing spawns nothing.
→ DECISIONS.md.

| member | summary |
|---|---|
| `class RetrievalError` | The context server could not be reached or spoke unintelligibly. |
| `def server_command(messages_path: "'Path \| None'" = None, source_dir: "'Path \| None'" = None, index_path: "'Path \| None'" = None, max_chars: 'int' = 0, python: 'str' = '') -> 'StdioServerParameters'` | How to spawn the context server for one run. |
| `def as_function_tool(name: 'str', description: 'str', schema: "'dict[str, Any] \| None'") -> 'dict[str, Any]'` | One MCP tool in the shape `chat.send(tools=...)` takes. |
| `def declare_tools(command: 'StdioServerParameters') -> 'list[dict[str, Any]]'` | Ask the context server what it exposes, once, before the pass starts. |
| `class RetrievalLog(calls: 'int' = 0, failures: 'int' = 0, bytes_returned: 'int' = 0, over_budget: 'int' = 0, log: 'list[dict[str, Any]]' = <factory>, _lock: "'threading.Lock'" = <factory>) -> None` | Every retrieval this run made, and what it cost. |
| `class RetrievalSession(command: 'StdioServerParameters', log: 'RetrievalLog', label: 'str' = '') -> 'None'` | A synchronous handle on one stdio session to the context server. |
| `def parse_tool_calls(message: 'Any') -> 'list[dict[str, Any]]'` | The tool calls on one assistant message, as plain dicts. |
| `def assistant_turn(message: 'Any', calls: 'list[dict[str, Any]]') -> 'dict[str, Any]'` | The assistant message to append before the tool results. |
| `def tool_turn(call: 'dict[str, Any]', content: 'str') -> 'dict[str, Any]'` |  |
| `class Retrieval(command: 'StdioServerParameters', tools: 'list[dict[str, Any]]', max_calls: 'int' = 6, log: 'RetrievalLog' = <factory>, withheld: 'tuple[str, ...]' = ()) -> None` | Everything pull mode needs for one run, built once before the pool starts. |
| `def refusal(reason: 'str') -> 'str'` |  |
| `def index_path_for(source_dir: "'Path \| None'") -> "'Path \| None'"` | Where the run's ctags index lives, if the target has a source tree. |
| `def normalise_mode(value: 'str') -> 'str'` |  |


### `dast_orchestrator.adapters.targets`

Target isolation: the orchestrator is target-agnostic, and the few things that are not
(base URL, the source tree Noir reads, route-placeholder values, POST-body fillers, the
login flow) are declared as data — one `target.yml` per target in its own directory.

A new target is one new directory plus one `include:` line in `Targets/persistent.yml`.
Definitions are not package data (a wheel resolves no targets — honest, since a definition
points at a gitignored clone and a bind-mounted container); they live in the sibling
`Targets/` dir, found through `TARGETS_DIR` (`SHARED_TARGETS_DIR`), and the only
thing YAML cannot express is a login mechanism differing in kind (`AuthProfile`).
→ docs/ARCHITECTURE.md.

| member | summary |
|---|---|
| `class AuthUser(role: 'str', username: 'str', password: 'str') -> None` | One seeded account the scan can log in as. |
| `class AuthProfile(login_path: 'str', csrf_field: 'str', session_cookie: 'str', logged_in_indicator: 'str', logged_in_check_path: 'str' = '', users: 'tuple[AuthUser, ...]' = (), strategy: 'str' = 'form', username_field: 'str' = 'user_name', password_field: 'str' = 'password', extra_login_fields: 'tuple[tuple[str, str], ...]' = (), logout_markers: 'tuple[str, ...]' = (), destructive_markers: 'tuple[str, ...]' = ()) -> None` | How to obtain and recognise an authenticated session on a target. |
| `class SourceAnalysis(semgrep_rulesets: 'tuple[str, ...]' = ()) -> None` | Which rule sets the standalone SAST pass runs against this target. |
| `class CodeContext(scope: 'tuple[str, ...]' = (), languages: 'tuple[str, ...]' = (), kinds: 'dict[str, str]' = <factory>) -> None` | Where this target's route handlers live, for the scoped code extractor. |
| `class Recovery(containers: 'tuple[str, ...]') -> None` | How to bring a wedged target back to a loginable state (optional). |
| `class Target(name: 'str', base_url: 'str', source_dir: 'str', path_vars: 'dict[str, str]' = <factory>, form_fillers: 'dict[str, str]' = <factory>, auth: 'AuthProfile \| None' = None, source_analysis: 'SourceAnalysis' = <factory>, code_context: 'CodeContext' = <factory>, noir_ignore_technologies: 'tuple[str, ...]' = (), openapi_specs: 'tuple' = (), spiders: 'tuple[str, ...]' = (), structural_parameters: 'tuple[str, ...]' = (), scan_headers: 'dict[str, str]' = <factory>, scan_rules: "tuple['ScanRule', ...]" = (), max_rule_minutes: "'int \| None'" = None, recovery: "'Recovery \| None'" = None) -> None` | One system under test, and the minimal per-target knobs the pipeline needs. |
| `class ScanRule(plugin_id: 'str', enabled: 'bool' = True, strength: 'str' = 'DEFAULT', threshold: 'str' = 'DEFAULT', why: 'str' = '') -> None` | One active-scan rule's per-target settings. |
| `class TargetError` | Raised when a target definition is missing or malformed. |
| `def target_from_dict(data: 'dict', where: 'str' = '<dict>') -> 'Target'` | Build a `Target` from a parsed YAML mapping. |
| `def load_target(path: 'Path') -> 'Target'` | Parse one `targets/<name>/target.yml` into a `Target`. |
| `def register(target: 'Target') -> 'Target'` |  |
| `def marker_rule_ids(targets_dir: "'Path \| None'" = None) -> 'frozenset[str]'` | Every ZAP rule id any target's `cve-markers.yml` names. |
| `def load_all(targets_dir: "'Path \| None'" = None) -> 'None'` | (Re)load every `<name>/target.yml` under `targets_dir`. |
| `def use_dir(targets_dir: "'str \| Path \| None'") -> 'Path'` | Point discovery and source resolution at `targets_dir` and reload. |
| `def target_source(target: 'Target') -> 'Path'` | The absolute path to a target's source tree, under the configured dir. |
| `def get(name: 'str') -> 'Target'` |  |
| `def for_url(url: 'str', default: 'str' = 'gitea') -> 'Target'` | The registered target whose base URL has the same host, else the default. |


### `dast_orchestrator.adapters.zap_client`

Thin, transparent wrapper over the OWASP ZAP REST API.

Deliberately raw: every call maps to a documented ZAP endpoint
(https://www.zaproxy.org/docs/api/) so behaviour stays inspectable and
reproducible for the thesis writeup. No baseline/full-scan wrapper scripts,
no hidden state.

| member | summary |
|---|---|
| `class ZapError` | Raised when the ZAP API returns an error or an unexpected shape. |
| `def zap_uri(url: 'str') -> 'str'` | `url` with every character ZAP's URI parser refuses percent-encoded. |
| `def alert_source_name(alert: 'dict[str, Any]') -> 'str'` | Decode which ZAP stage produced an alert. |
| `def count_alert_sources(alerts: 'list[dict[str, Any]]') -> 'dict[str, int]'` | Count alerts per producing stage. |
| `def build_raw_request(method: 'str', url: 'str') -> 'str'` | Build the raw HTTP/1.1 request string `core/action/sendRequest` expects. |
| `def zap_unlimited(value: 'int') -> 'int'` | Translate this project's no-limit sentinel into ZAP's. |
| `class ZapClient(base_url: 'str', api_key: 'str', timeout: 'float' = 30.0) -> 'None'` | Minimal client for the subset of the ZAP API the driver needs. |


### `dast_orchestrator.adapters.zap_context`

Structural parameters: make `?action=<name>` part of a URL's identity.

ZAP builds its site tree from paths, so WordPress's `admin-ajax.php?action=…` endpoints
collapse to one node; declaring `action` structural (`target.yml`
`zap_context.structural_parameters`) splits it into one scan target per value. ZAP 2.17's
REST API cannot set this (upstream #2141), so the only route is export → rewrite the
context's `struct` JSON → import; it changes what a scan contains, so it is in the run-id
digest and invalidates that target's earlier baseline. → DECISIONS.md.

| member | summary |
|---|---|
| `def container_path(run_id: 'str') -> 'str'` |  |
| `class ContextError` | Raised when the context could not be created, edited or loaded. |
| `def structural_config(existing: 'str', parameters: 'list[str]') -> 'str'` | The parser config with `parameters` as its `struct` list. |
| `def rewrite(xml: 'str', parameters: 'list[str]') -> 'str'` | An exported context XML with its URL parser's `struct` list replaced. |
| `def apply(zap: 'ZapClient', target_url: 'str', parameters: 'list[str]', container: 'str', work_dir: 'Path', name: 'str' = 'dast') -> 'dict[str, Any]'` | Create the run's context and make `parameters` structural in it. |


### `dast_orchestrator.adapters.zap_plan`

The Automation Framework mode (`SCAN_ZAP_MODE=af`): run a ZAP AF plan (one YAML file)
instead of the default explicit REST sequence.

The REST path stays the default; AF is opt-in because it is how ZAP is normally driven in
CI, which matters for a thesis about DAST in CI/CD. The plan is `docker cp`'d in and run
from `/tmp` (the daemon has no bind mount); it is not versioned like prompts but its
SHA-256 is recorded, and since ZAP silently runs an unrecognised job type, the job list ZAP
echoes back is recorded as the only evidence of what ran. → DECISIONS.md.

| member | summary |
|---|---|
| `class PlanError` | The plan could not be found, delivered, or run. |
| `def plan_for_target(target_name: 'str', targets_dir: 'Path') -> "'Path \| None'"` | The plan shipped with a target, or `None`. |
| `def resolve_plan(explicit: "'str \| Path \| None'", target_name: 'str', targets_dir: 'Path') -> "'Path \| None'"` | Which plan a run should use: the named one, else the target's own. |
| `def plan_digest(path: 'Path') -> 'str'` | SHA-256 of the plan's bytes, so a result can be tied to the file. |
| `def deliver(path: 'Path', container: 'str') -> 'str'` | Copy the plan into the daemon container; return the path inside it. |
| `def run_plan(zap: 'ZapClient', container_path: 'str', poll_seconds: 'float' = 5.0) -> 'dict[str, Any]'` | Run a delivered plan to completion and return what ZAP reported. |


### `dast_orchestrator.adapters.zap_session`

Give ZAP a named session at an explicit on-disk path, one directory per run, removed
afterwards.

An unnamed ZAP session is temporary and keeps every request/response in the JVM heap — the
actual cause of every ZAP OOM here — while a named session puts the store on disk. Cleanup
releases the session (`newSession` with no name) then removes the directory by its full
explicit path (no glob; see CLAUDE.md); the raw session is not copied into `data/` (it is
gigabytes and duplicates the message sidecar), and `keep=True` sets it aside for ZAP
Desktop. A `docker restart` between runs gives a fresh *process* (clearing the heap) but
keeps the container's writable layer, so a cleanup that timed out leaves its directory
behind; `sweep_stale`, run by `prepare` at the start of each run, reclaims those
so the disk cannot fill. → DECISIONS.md.

| member | summary |
|---|---|
| `class SessionError` | Raised when the run's session directory cannot be created or removed. |
| `def container_dir(run_id: 'str') -> 'str'` | The run's own session directory inside the ZAP container. |
| `def session_path(run_id: 'str') -> 'str'` | The full path handed to `core/action/newSession`. |
| `def prepare(run_id: 'str', container: 'str') -> 'str'` | Create the run's session directory and return the session path. |
| `def sweep_stale(container: 'str', *, keep_run_id: 'str \| None' = None) -> 'None'` | Remove every prior run's session directory still in the container. |
| `def discard(run_id: 'str', container: 'str', keep: 'bool' = False) -> 'None'` | Remove the run's session directory, if it is ours and we may. |
