# domain

Pure data and vocabulary, no I/O.

### `dast_orchestrator.domain.evidence_class`

What kind of evidence a rule's verdict rests on — pure classification vocabulary answering
only *"which bytes would settle this alert?"* (not a severity, not a taxonomy).

Domain vocabulary: the `context` layer's storage/excerpt rules and the `domain`
verification layer both ask it, so it lives here rather than in `context.evidence` (where
it forced an upward import). No I/O — a lookup over three static tables, in decreasing order
of confidence (explicit rule, then CWE, then name).

| member | summary |
|---|---|
| `def nuclei_dast_tag(alert: "'Mapping[str, Any]'") -> 'str'` | The nuclei DAST tag scoping a probe to this finding's class, `""` if none. |
| `def rule_class(alert: 'Mapping[str, Any]') -> 'str'` | Which kind of evidence would settle this alert. |


### `dast_orchestrator.domain.rescan_table`

The control arm: pure data plus a pure function, no model — the LLM triage pass must
beat this baseline, so it stays simple enough to state as one table.

It answers not "is this a true positive?" but *would an independent tool change what we
know?*, splitting ZAP's rules three ways: self-evident passive (ZAP holds the proof) →
NEVER, heuristic passive (a job for the LLM arm) → NEVER with the reason recorded, and
active-injection → ALWAYS or `WHEN_UNCERTAIN`. Confidence is the second key: a rule at
High may carry a proof, at Medium be the false positive this layer settles.
→ DECISIONS.md.

| member | summary |
|---|---|
| `class RescanPolicy(*values)` | What the table says about a rule, independent of a single alert. |
| `class RuleEntry(plugin_id: 'str', name: 'str', policy: 'RescanPolicy', rationale: 'str', tool: 'str \| None' = None) -> None` | One row of the table. `rationale` is quoted directly in the writeup. |
| `class RescanDecision(needs_rescan: 'bool', reason: 'str', policy: 'RescanPolicy', plugin_id: 'str', confidence: 'str', tool: 'str \| None' = None, in_table: 'bool' = True) -> None` | The per-alert outcome, carried into the correlation artifact. |
| `def decide(alert: 'dict[str, Any]') -> 'RescanDecision'` | Classify one raw ZAP alert dict. Deterministic; no I/O, no model. |
| `def needs_rescan(alert: 'dict[str, Any]') -> 'bool'` | The one-bit form of `decide`, as specified for the control arm. |
| `def table_as_rows() -> 'list[dict[str, str]]'` | The table in a form the report (and the thesis appendix) can render. |


### `dast_orchestrator.domain.verification`

Verification: outcomes + resolution vocabulary and logic.

Split into submodules (outcomes / dispatch / loop); this __init__ re-exports every public name so `from dast_orchestrator.domain import verification`
and `verification.X` keep working exactly as before.

| member | summary |
|---|---|
| `def tool_capabilities(tools: "'Iterable[str] \| None'" = None) -> 'dict[str, Any]'` | The capability block a prompt carries, optionally narrowed to some tools. |
| `def cwe_family(cwe: "'int \| str \| None'") -> 'str \| None'` | The family a CWE id belongs to, or `None` if it is unspecific/unknown. |
| `def classification_match(alert_cwe: "'int \| str \| None'", matched_templates: "'list[dict[str, Any]] \| None'", rule_id: 'str' = '', tool: "'str \| None'" = None) -> 'dict[str, Any]'` | Whether a confirming tool's match belongs to the flagged rule's class. |
| `def class_gate(reported: 'str', alert_cwe: "'int \| str \| None'", matched_templates: "'list[dict[str, Any]] \| None'", rule_id: 'str' = '', tool: "'str \| None'" = None) -> "'tuple[str, dict[str, Any]]'"` | Gate a `confirmed` on class agreement — the precondition, not an afterthought. |
| `def parse_rule_caps(assignments: "'Iterable[str]'") -> 'dict[str, int]'` | Parse repeated `--max-dispatch-rule ID=N` arguments (and the env list). |
| `class DispatchBudget(tool_timeout_seconds: 'int' = 150, max_dispatch_all_rules: 'int' = 15, rule_caps: "'tuple[tuple[str, int], ...]'" = (), max_dispatches_total: 'int' = 40, max_minutes: 'int' = 20) -> None` | Every ceiling a verification run is bound by, resolved from the env. |
| `def selected_tool(finding: 'dict[str, Any]') -> 'str \| None'` | The tool a flagged finding should be dispatched to, or `None`. |
| `def is_dispatchable(finding: 'dict[str, Any]') -> 'bool'` |  |
| `def is_attack_backed(finding: 'dict[str, Any]') -> 'bool'` | Did a scanner actually inject for this finding, or merely observe? |
| `def dispatch_priority(finding: 'dict[str, Any]') -> 'tuple[int, int, int, str]'` | Sort key: most worth the budget first. |
| `def classify_finding(finding: 'dict[str, Any]', verification: 'dict[str, Any] \| None' = None) -> 'tuple[str, str]'` | The one true disposition of a finding across all three arms. |
| `def disposition_summary(findings: 'list[dict[str, Any]]', verifications: 'list[dict[str, Any]] \| None' = None) -> 'dict[str, Any]'` | Bucket every finding into the three the report presents, plus counts. |
| `def classify_synthesis(claim: 'dict[str, Any]', verif_record: 'dict[str, Any] \| None' = None, finding_dispositions: "'dict[str, str] \| None'" = None) -> 'tuple[str, str]'` | The disposition of one cross-endpoint synthesis claim — accountably. |
| `def disposition_report(findings: 'list[dict[str, Any]]', verifications: 'list[dict[str, Any]] \| None' = None, synthesis: 'list[dict[str, Any]] \| None' = None, correlated_verifications: 'list[dict[str, Any]] \| None' = None) -> 'dict[str, Any]'` | The whole run's disposition: per-finding and cross-endpoint synthesis. |
| `def validate_probe(tool: 'str', proposed: "'dict[str, Any] \| None'") -> 'tuple[dict[str, Any], list[str]]'` | Clean a model-proposed invocation down to what the executor may run. |
| `class DeclaredSignal(expect: 'tuple[str, ...]' = (), reject: 'tuple[str, ...]' = (), require_tool_confirmed: 'bool' = False, description: 'str' = '') -> None` | The observable the model commits to before the tool runs. |
| `class SignalCheck(observed: "'bool \| None'", detail: 'str', code: 'str' = 'not-declared') -> None` | Whether the declared signal was observed in the tool's output. |
| `def format_words(tool: "'str \| None'") -> 'frozenset[str]'` | Output-format vocabulary for one tool; empty for an unknown one. |
| `def check_signal(signal: 'DeclaredSignal', tool_result: "'dict[str, Any]'") -> 'SignalCheck'` | Was the model's declared signal actually observed in the tool output? |
| `def tool_ran(tool_result: "'dict[str, Any]'") -> 'bool'` | Did this tool invocation validly put the question to the target? |
| `def resolve_verdict(wrapper_outcome: "'str \| None'", llm_category: "'str \| None'", ran: 'bool' = True) -> 'tuple[str, str]'` | The reported category, and whether the two readings agreed. |
| `class RoundRecord(index: 'int', tool: "'str \| None'", arguments: 'dict[str, Any]' = None, declared_signal: 'dict[str, Any]' = None, signal_check: 'dict[str, Any]' = None, wrapper_outcome: 'str' = 'inconclusive', tool_ran: 'bool' = True, tool_result: 'dict[str, Any]' = None, model_note: 'str' = '', model_category: "'str \| None'" = None, violations: 'tuple[str, ...]' = (), model_directed: 'bool' = False) -> None` | One round of the loop: what the model asked for, and what came back. |
| `def route_probeable(status: "'int \| None'") -> "'str \| None'"` | Why a sibling route cannot be probed at this status, or `None`. |
| `class LoopVerdict(finding_id: 'str', reported: 'str', wrapper_verdict: 'str', llm_verdict: "'str \| None'", agreement: 'str', rounds: 'tuple[RoundRecord, ...]' = (), tool: "'str \| None'" = None, detail: 'str' = '', stopped_because: 'str' = '', not_attempted_reason: 'str' = '', classification: "'dict[str, Any] \| None'" = None, outcome_downgraded_from: "'str \| None'" = None) -> None` | What one finding's loop settled on, with both readings kept side by side. |
| `def build_worklist(findings: 'list[dict[str, Any]]', verifications: 'list[dict[str, Any]] \| None' = None, synthesis: 'list[dict[str, Any]] \| None' = None, correlated_verifications: 'list[dict[str, Any]] \| None' = None, siblings: 'list[dict[str, Any]] \| None' = None) -> 'dict[str, Any]'` | Every reported item placed on one ordered list of lines, plus ZAP risk × section. |
