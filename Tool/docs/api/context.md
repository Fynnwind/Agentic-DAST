# context

Assemble the evidence a prompt reasons from.

### `dast_orchestrator.context.code_context`

The scoped code extractor: resolve a finding's handler symbol to real source.

Noir's `--ai-context` names a callee's reference site, not its definition, so the chain is
Noir scopes → universal-ctags locates → we read: a ctags symbol index gives the exact
function extent and one bounded same-package hop reaches the flagged parameter. Its rule:
structure that says WHERE things are is cheap and safe, what things MEAN belongs to the
model — so it emits raw source plus non-semantic navigation and never synthesises
`sinks`/`validators` (that is SAST, kept as the independent Semgrep baseline).
→ DECISIONS.md.

| member | summary |
|---|---|
| `class CodeContextError` | Raised when the symbol index cannot be built or read. |
| `class Symbol(name: 'str', package: 'str', path: 'str', start: 'int', end: 'int', kind: 'str' = '', signature: 'str' = '', scope: 'str' = '') -> None` | One definition, located. No interpretation of any kind. |
| `def build_command(source_dir: 'Path', scope: 'Sequence[str]', languages: 'Sequence[str]', kinds: 'Mapping[str, str]', image: 'str' = 'dast-ctags:6.1.0') -> 'list[str]'` | The exact `docker run` that produces the index. |
| `def parse_tags(text: 'str') -> 'list[Symbol]'` | Parse ctags' own output format. |
| `def backfill_extents(symbols: 'Sequence[Symbol]', source_dir: 'Path') -> 'list[Symbol]'` | Give every `UNKNOWN_END` symbol an extent, without a language parser. |
| `class SymbolIndex(symbols: 'Iterable[Symbol]', provenance: 'Mapping[str, Any] \| None' = None) -> 'None'` | Name -> definition. A dict lookup, built once per source tree version. |
| `def index_cache_path(source_dir: 'Path') -> 'Path'` | Beside the source it indexes: it is valid for a *source tree version*. |
| `def build_index(source_dir: 'Path', scope: 'Sequence[str]', languages: 'Sequence[str]' = (), kinds: 'Mapping[str, str] \| None' = None, image: 'str' = 'dast-ctags:6.1.0', timeout: 'float' = 300.0) -> 'SymbolIndex'` | Run ctags once over the scoped tree. |
| `def load_index_file(path: 'Path') -> 'SymbolIndex'` | Read one cached index file. Never builds, so it needs no Docker. |
| `def load_or_build_index(source_dir: 'Path', scope: 'Sequence[str]', languages: 'Sequence[str]' = (), kinds: 'Mapping[str, str] \| None' = None, image: 'str' = 'dast-ctags:6.1.0', refresh: 'bool' = False) -> 'SymbolIndex'` | The cached index for this source tree, building it if it is stale. |
| `class Block(symbol: 'Symbol', text: 'str', depth: 'int', reached_from: 'str' = '') -> None` | One definition's source, and how the walk arrived at it. |
| `def read_block(source_dir: 'Path', symbol: 'Symbol') -> 'str'` | The exact lines `end:` delimits, numbered. |
| `def resolve_reference(index: 'SymbolIndex', reference: 'str', package: 'str' = '') -> 'Symbol \| None'` | One reference, under the package rules `callees` documents. |
| `def callees(text: 'str', index: 'SymbolIndex', package: 'str') -> 'list[Symbol]'` | Definitions in the index that this block calls, in first-appearance order. |
| `def extract(index: 'SymbolIndex', source_dir: 'Path', roots: 'Sequence[str]', max_hops: 'int' = 1, max_lines: 'int' = 600) -> 'tuple[list[Block], list[str]]'` | Walk from Noir's named symbols outward, breadth first. |
| `def extract_from_symbols(index: 'SymbolIndex', source_dir: 'Path', seeds: 'Sequence[Symbol]', max_hops: 'int' = 1, max_lines: 'int' = 600) -> 'tuple[list[Block], list[str]]'` | The bounded walk from symbols already located — e.g. by a registration. |
| `def index_relative_path(path: 'str') -> 'str'` | A Noir `code_paths` path, relative to `source_dir` like the index. |
| `def symbols_in_file(index: 'SymbolIndex', rel_path: 'str', line: 'int' = 0) -> 'list[Symbol]'` | The index's symbols defined in `rel_path`. |
| `def extract_from_paths(index: 'SymbolIndex', source_dir: 'Path', code_paths: 'Sequence[tuple[str, int]]', max_hops: 'int' = 1, max_lines: 'int' = 600) -> 'tuple[list[Block], list[str]]'` | Resolve handler source from the FILE Noir located, not its callee names. |
| `def strip_php_comments(text: 'str', start_in_php: 'bool' = False) -> 'str'` | `text` reduced to PHP code: comments and inline HTML blanked, strings kept. |
| `def php_names(text: 'str') -> 'tuple[str, dict[str, str]]'` | A PHP file's `namespace` and its `use` imports (alias -> full name). |
| `def class_candidates(name: 'str', namespace: 'str', uses: 'dict[str, str]') -> 'list[str]'` | Full class names `name` may mean in a file, most likely first. |
| `def find_method(index: 'SymbolIndex', method: 'str', classes: 'Sequence[str]') -> 'Symbol \| None'` | `method` defined on the first of `classes` that defines it. |
| `def find_function(index: 'SymbolIndex', name: 'str') -> 'Symbol \| None'` | A free (class-less) function named `name`, only when it is unique. |
| `def php_callees(text: 'str', index: 'SymbolIndex', symbol: 'Symbol', source_dir: 'Path') -> 'list[Symbol]'` | Definitions a PHP block calls, by PHP's own receiver rules, in order. |
| `def parameter_sites(blocks: 'Iterable[Block]', parameter: 'str', limit: 'int' = 8) -> 'list[dict[str, Any]]'` | Where the flagged parameter literally appears in the included source. |
| `def call_chain(blocks: 'Iterable[Block]') -> 'list[str]'` | `repo.Issues -> issues` for each edge the walk actually followed. |
| `def build_context(index: 'SymbolIndex', source_dir: 'Path', roots: 'Sequence[str]', parameter: 'str' = '', level: 'str' = 'handler+trace', max_hops: 'int' = 1, max_lines: 'int' = 600) -> 'dict[str, Any] \| None'` | The `handler_source` block an evidence pack carries, or `None`. |


### `dast_orchestrator.context.dispatch`

How a framework dispatches a request to its handler, and locating that handler statically.

Keyed on Noir's per-endpoint `technology`, never on a target name: a registration
resolver reads the call that registers an endpoint (WordPress's `add_action` /
`register_rest_route`) and names the callable it hands over, which ctags then
locates. It emits WHERE the handler is — the symbol and the registration site —
never what it does. → DECISIONS.md §"WordPress code context was never grounded".

| member | summary |
|---|---|
| `class Registration(symbol: 'cc.Symbol \| None', reason: 'str' = '', site: 'str' = '', call: 'str' = '', closure: 'bool' = False) -> None` | What a registration resolver found for one endpoint. |
| `def split_args(text: 'str', open_index: 'int') -> 'tuple[list[str], int] \| None'` | The top-level arguments of the call whose `(` is at `open_index`. |
| `def parse_callable(expr: 'str') -> 'tuple[str, str, str] \| None'` | Read a PHP callable expression. `None` when it is dynamic (a variable). |
| `def resolve_callable(index: 'cc.SymbolIndex', rel_path: 'str', line: 'int', text: 'str', expr: 'str') -> 'tuple[cc.Symbol \| None, str, bool]'` | The symbol a callable registered at `rel_path:line` names. |
| `def wordpress_handler(endpoint: 'dict[str, Any]', index: 'cc.SymbolIndex', source_dir: 'Path') -> 'Registration'` | Locate a WordPress admin-ajax / admin-post / REST endpoint's handler. |
| `def locate_handler(endpoint: 'dict[str, Any]', index: 'cc.SymbolIndex', source_dir: 'Path') -> 'Registration \| None'` | The handler the endpoint's registration names, or `None` when its |


### `dast_orchestrator.context.evidence`

The evidence assembler: build the per-finding pack every LLM prompt carries.

The pack is **pushed, not pulled** — assembled deterministically and always attached, so
the same finding always yields the same pack (the baseline for the model-retrieval
experiment); `Assembler` is built once per run and read-only under concurrency.
**Storage is generous, excerpting strict**: a body dropped at scan time is unrecoverable,
but long irrelevant context degrades attention, so what reaches a prompt is as small as
the policy (`config/excerpts/`) allows. → DECISIONS.md.

| member | summary |
|---|---|
| `class EvidenceError` | Raised when an excerpt policy is missing or unreadable. |
| `def retain_body(classes: 'Iterable[str]') -> 'bool'` | Whether a stored message keeps its response body. |
| `def message_ids(alerts: 'Iterable[Mapping[str, Any]]') -> 'list[str]'` | Every ZAP message id an alert points at, in first-seen order. |
| `def build_message_sidecar(alerts: 'Iterable[Mapping[str, Any]]', messages: 'Mapping[str, Mapping[str, Any]]', max_body_chars: 'int' = 262144) -> 'dict[str, Any]'` | Reduce fetched ZAP messages to the gitignored `scan-zap-messages.json`. |
| `class Exchange(message_id: 'str', method: 'str' = '', uri: 'str' = '', status: 'int \| None' = None, reason: 'str' = '', request_headers: 'tuple[tuple[str, str], ...]' = (), response_headers: 'tuple[tuple[str, str], ...]' = (), request_body: 'str' = '', response_body: 'str' = '', body_omitted: 'bool' = False) -> None` | One HTTP request/response pair, parsed out of the sidecar. |
| `def parse_exchange(message: 'Mapping[str, Any]') -> 'Exchange'` | Turn one sidecar entry into a structured `Exchange`. |
| `def rule_tags(group: 'Any') -> 'list[str]'` | ZAP's own classification of the rule, as bare tag names. |
| `def normalise_observation(alert: 'Mapping[str, Any]') -> 'dict[str, str]'` | Collect whatever this plugin stored, labelled by the field it came from. |
| `def reachability(auth_mode: 'str', exchange: 'Exchange \| None') -> 'dict[str, Any]'` | What the run itself proves about who can reach this route. |
| `class ExcerptRule(body: 'str' = 'head', body_chars: 'int' = 800, request_headers: 'str' = 'all', response_headers: 'str' = 'all') -> None` | What one rule class gets in its prompt. |
| `class ExcerptPolicy(name: 'str', description: 'str', default: 'ExcerptRule', by_class: 'Mapping[str, ExcerptRule]' = <factory>, attach: 'bool' = True, source_text: 'str' = '', path: 'Path \| None' = None) -> None` | A named, file-backed policy, copied verbatim into every run's artifact. |
| `def available_policies(policy_dir: 'Path \| None' = None) -> 'list[str]'` |  |
| `def load_policy(name: 'str \| None' = None, policy_dir: 'Path \| None' = None) -> 'ExcerptPolicy'` | Read `config/excerpts/<name>.yml`. |
| `def excerpt_body(body: 'str', rule: 'ExcerptRule', needles: 'Iterable[str]' = ()) -> 'dict[str, Any]'` | Cut the slice this rule class needs, and say what was cut. |
| `def render_headers(pairs: 'tuple[tuple[str, str], ...]', mode: 'str') -> 'Any'` |  |
| `def excerpt_exchange(exchange: 'Exchange', rule: 'ExcerptRule', needles: 'Iterable[str]' = ()) -> 'dict[str, Any]'` | One exchange, cut to what the rule class needs. |
| `class MessageStore(messages: 'Mapping[str, Mapping[str, Any]] \| None' = None, counts: 'Mapping[str, int] \| None' = None) -> 'None'` | The sidecar, loaded once and shared read-only by every worker. |
| `def build_pack(finding_id: 'str', group: 'Any', store: 'MessageStore', policy: 'ExcerptPolicy', auth_mode: 'str' = 'none', code_context: 'Mapping[str, Any] \| None' = None, retrieval_mode: 'str' = 'push') -> 'dict[str, Any]'` | Everything a judgement of this finding is entitled to rest on. |
| `def exchange_manifest(exchange: 'Exchange') -> 'dict[str, Any]'` | What is retrievable about this finding's exchange, without the bytes. |
| `class Assembler(store: 'MessageStore \| None' = None, policy: 'ExcerptPolicy \| None' = None, auth_mode: 'str' = 'none', code_level: 'str' = 'none', index: 'Any' = None, source_dir: 'Path \| None' = None, max_hops: 'int' = 1, max_lines: 'int' = 600, retrieval_mode: 'str' = 'push') -> 'None'` | The one place a prompt's evidence comes from. |
| `def handler_symbols(bundle: 'Any') -> 'list[str]'` | The symbol names Noir scoped this endpoint to. |
| `def handler_code_paths(bundle: 'Any') -> 'list[tuple[str, int]]'` | The handler file(s) Noir located for this endpoint — the fallback for |
| `def assembler_for_run(zap_report: 'Mapping[str, Any]', messages_path: 'Path', excerpt_policy: 'str' = '', code_level: 'str' = 'none', target: 'Any' = None, source_dir: 'Path \| None' = None, max_hops: 'int' = 1, max_lines: 'int' = 600, refresh_index: 'bool' = False, retrieval_mode: 'str' = 'push') -> "'Assembler'"` | Build the assembler a stage should use for one stored run. |
