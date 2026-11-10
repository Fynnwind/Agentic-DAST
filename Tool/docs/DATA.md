# Data inventory — what a run writes, where, and in what shape

*The reference for `data/`: every artifact a stage produces, the schema that
describes it, and how a single run and a harness sheet bundle them. The naming
rules live in [`run_paths.py`](../src/dast_orchestrator/foundation/run_paths.py)
(the single source of truth for basenames) and the contracts in
[`schemas/`](../schemas/); this file is the map over both. Built for the
§T3 analyzer, which reads these artifacts read-only through the vendored
`schemas/` contract and never imports the tool.*

## 1. The run directory

One run is **one directory**; a downstream variant is a **suffixed sibling in the
same directory**, never a new directory. A run id is
`<timestamp>-<target>-<config-digest>` (e.g. `20260923T152305Z-grafana-4c733a`) —
timestamp first so it sorts, target carries no `-`, digest covers *scan+global*
config only (so a re-triage is a variant, not a new corpus). Both trailing fields
are optional for ids predating them.

Three namespaces under `data/` (all gitignored):

| Path | Holds | Read by corpus tools? |
|---|---|---|
| `data/runs/<run-id>/` | a run a **person** started | yes |
| `data/harness/<sheet-id>/<run-id>/` | the runs of one **sheet** | yes |
| `data/scratch/<sheet-id>/` | **ephemeral** dry-run / smoke | **no** — auto-cleaned on a clean finish; `dast costs`, this inventory and the analyzer never look here |

**The suffix rule.** `scan` takes no suffix — it *is* the directory (the config
digest already distinguishes scans). Every downstream stage may take
`--out-suffix <s>`, which splices as `<base>-<s>.json` (multi-part extensions
survive: `report.sarif.json` → `report-<s>.sarif.json`). Two suffixes are
**reserved** and refused (`SuffixError`): `metrics` and `prompts`, because they
would collide with the `<kind>-metrics.json` and `triage-prompts.json`
conventions. The harness sets the suffix to the sheet **row label** (e.g.
`grafana-baseline`), which is why a sheet's run dir shows `triage-grafana-baseline.json`
while a manual run shows plain `triage.json`.

## 2. Artifacts per stage

`P` = produced by that stage. `→schema` names the contract in `schemas/`
(∅ = no schema file; see §5). Suffix column: `dir` = names the directory, no
suffix; `yes` = takes `--out-suffix`; `fixed` = always this basename.

### `dast scan` — Noir → seed → ZAP

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `scan-noir-endpoints.json` | raw Noir endpoint extraction | ∅ (raw Noir) | dir |
| `scan-noir-ai-context.json` | per-endpoint guards/callees/sources/sinks/validators/signals for triage | `noir-ai-context` | dir |
| `scan-noir-seed-map.json` | which endpoints seeded which ZAP tree nodes (0→N delta) | `noir-seed-map` | dir |
| `scan-zap-alerts.json` | ZAP alerts (the finding set) | `zap-alerts` | dir |
| `scan-zap-messages.json` | HTTP exchanges behind the alerts, keyed+deduped by ZAP message id — **gitignored sidecar**, order-of-magnitude largest file, sole reader `context.evidence` | ∅ (sidecar) | dir |
| `scan-zap-context.xml` | ZAP's exported context (structural params) — **only when the target sets a structural param** | ∅ (ZAP export) | dir |
| `scan-metrics.json` | the scan metrics record (§3) | `run-metrics` | dir |

### `dast triage` — two arms (deterministic table + LLM two-pass)

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `triage.json` | both arms' verdicts + pass-2 synthesis claims | `triage-result` | yes |
| `triage-prompts.json` | the exact prompts (dry-run dump / audit); `pass1_screening` = `{system, calls[]}` with the shared pass-1 header stored once. **Not** suffixed today (fixed basename) | ∅ | fixed |
| `triage-metrics.json` | triage metrics record; `calls_log` lives here (§3) | `run-metrics` | yes |

### `dast verify` — one loop, two axes

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `verification.json` | per-finding confirmed/refuted/inconclusive/not-attempted + wrapper-vs-model readings | `verification-result` | yes |
| `verify-metrics.json` | verify metrics record; the per-call `calls_log` lives under `stages/dispatch` (§3), mirroring triage | `run-metrics` | yes |

### `dast report` — SARIF + Markdown

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `report.sarif.json` | SARIF 2.1.0, two rule-id namespaces linked by `relationships`; each result carries its `rank` and `properties.disposition` / `worklist_section` / `worklist_group` / `worklist_line` | standard SARIF | yes |
| `report.md` | human summary; all numbers computed from the artifacts | — | yes |
| `report-metrics.json` | report metrics record | `run-metrics` | yes |

### `dast cve` — ground truth (OPTIONAL; no-ops on a markerless target)

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `cve-detection.json` | one run's MEASURED assessment — per marker `reach`/`observe`/`outcome` + the run's `auth_mode`/`oracle_guided`, joined to its alerts/triage/verification | `cve-detection` (registered) | yes |

**`dast cve` writes no metrics record** (§6) and persists no ladder: the
blind-vs-`--oracle` ladder is PRINTED by `dast cve <blind> <oracle>` (or a single
run auto-runs its flipped counterpart), and the analyzer re-derives it from two
`cve-detection.json` files (derive-on-read). → `docs/DETECTABILITY.md`.

### `dast static-analysis` — Semgrep + OSV (standalone, not a pipeline stage)

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `semgrep.sarif.json` | Semgrep SAST findings | standard SARIF | yes |
| `osv.sarif.json` | OSV-Scanner SCA findings | standard SARIF | yes |
| `static-analysis.md` | human summary | — | yes |
| `analysis-metrics.json` | metrics record, **kind `analysis`** (basename `static-analysis.md` vs metrics-kind `analysis` is the one naming mismatch) | `run-metrics` | yes |

### Per run, once

| Basename | Content | →schema | Suffix |
|---|---|---|---|
| `manifest.json` | the run's self-description: which artifacts exist + each one's schema/version, rescanned whenever a stage records metrics | ∅ | fixed |

(`manifest.json` is absent from corpora written before it was added — e.g. the
canonical baseline; it is not backfilled.)

## 3. Metrics records — the `<kind>-metrics.json` family

One record per stage-invocation, `kind ∈ {scan, triage, verify, report,
analysis}`. Top-level keys (from `RunMetrics`):

```
schema_version · run · kind · label · harness_id · harness_row ·
started_at · total_seconds · host · config · tools · stages · results · abort
```

The record is **always written — on a clean finish or a crash** — by
`RunMetrics.guard(data_dir)`, the context manager each driver wraps its work in.
So a stage that dies mid-run still leaves a metrics file that says what it cost.

- **`config`** — the run's settings for that stage (triage e.g. `triage_model`,
  `synthesis_repeats`, `code_context`, `retrieval`, `max_cost_usd`, …). *Folding
  the run's full env values in here is `NEXT_SESSION.md` TODO 1.*
- **`stages`** — a map of the stage's internal phases (triage: `join` /
  `llm_screening` / `llm_synthesis`). The **per-call LLM log lives here**, at
  `stages/<phase>/calls_log[]`, each call:

  ```
  at · pass · label · latency_ms · model_requested · model_served ·
  vendor · provider · routing_strategy · region · generation_id ·
  finish_reason · prompt_tokens · completion_tokens ·
  cached_prompt_tokens · cost_usd · outcome
  ```

  This is the source of the whole §T3 cost / latency / cache-hit family and the
  `dast costs` provider column, and it **is** described by
  `run-metrics.schema.json` (the `stages` additionalProperties carry a `calls_log`
  definition covering `llm_screening`, `llm_synthesis`, and now the verify stage).
- **`results`** — the stage's outcome counters; the comparable subset per kind is
  `metrics.TABLE_COLUMNS` (what `dast costs` and the harness table print).
- **`abort`** — `null` on a clean finish, else `{type, reason}`: `type` is
  `error` (unhandled exception) / `cancelled` (Ctrl-C or a cancelled task) /
  `budget-ceiling` (a controlled cost stop), `reason` keeps the exception's type
  and message. `dast costs` reads the type into its own `abort` column (`-` when
  null). Always present, so "no abort" is never confused with a record predating
  abort tracking.

A **measured zero and a missing measurement never look alike**: an unmeasured
value stays `null`, a provider that reports nothing is recorded as such.

## 4. How a run bundles — single run vs harness sheet

**A manual full chain** (`dast <target>` then triage/verify/report) writes, in
`data/runs/<run-id>/`, unsuffixed basenames: the seven scan files, `triage.json`
(+`triage-prompts.json`, `triage-metrics.json`), `verification.json`
(+metrics), `report.{sarif.json,md}` (+metrics), `manifest.json`, and — if the
target has markers and `dast cve` was run — `cve-detection.json`.

**A harness sheet** (`dast harness`) writes to `data/harness/<sheet-id>/` and
adds a layer *around* the runs:

| Sheet-level file | Content |
|---|---|
| `<row-label>.env` | the exact env overlay for each row (one per row) |
| `<run-id>/…` | one run directory per row, artifacts **suffixed with the row label** |
| `<run-id>/harness-<row-label>.env` | the overlay copied into the run dir it produced |
| `results.json` | the machine record of the sheet: per-row counters + variance across repeats | (`harness-results`) |
| `comparison.md` | the human comparison table |

So a sheet run dir looks like `triage-grafana-baseline.json`,
`triage-metrics-grafana-baseline.json`, … — the same artifacts as a manual run,
each carrying the row label as its suffix, plus the copied `.env`. `scan-*` files
stay unsuffixed (scan names the directory).

## 5. Schema coverage — what is validated on read

`schema.py`'s `_REGISTRY` maps a basename to its contract; a `data/` artifact is
validated against it on read. Registered today (metrics pattern ordered **first**
so `triage-metrics.json` is not misread as a triage result):

`*-metrics[-*].json` → run-metrics · `scan-noir-ai-context` · `scan-noir-seed-map`
· `scan-zap-alerts` · `triage[-*]` (not `-prompts`) · `verification[-*]` ·
`results.json` → harness-results.

**Present as a file but NOT registered** (so not validated on read):

- `cve-markers.schema.json` — describes `Targets/*/cve-markers.yml`, an input under
  `Targets/`, not a `data/` artifact, so its absence from the data registry is by
  design; it is validated by the target tests instead.

**No schema file** (raw third-party or sidecar output, intentionally): the two
SARIF outputs (standard SARIF schema), `scan-noir-endpoints.json` (raw Noir),
`scan-zap-messages.json` and `scan-zap-context.xml` (sidecars), `triage-prompts.json`,
`manifest.json`, the `.md` summaries.

## 6. Open inventory findings (act on before the measurement freeze)

Tracked in `NEXT_SESSION.md` TODO 1; recorded here where they touch the data shape:

1. ~~**verify does not populate `calls_log`**~~ RESOLVED — the driver now writes
   the full LLM usage (per-call log included) into the `dispatch` stage, exactly
   as triage does; the §T3 per-call cuts and the `dast costs` provider column
   cover verify. (Absent on the deterministic configuration, which calls no
   model.) Existing corpora predate the fix.
2. ~~**aborts are not persisted**~~ RESOLVED — every stage wraps its work in
   `RunMetrics.guard`, which writes the record on a crash too, with an `abort`
   `{type, reason}` object (`error` / `cancelled` / `budget-ceiling`). `dast
   costs` gained an `abort` column. The frozen corpus was backfilled with
   `abort: null` so it reads as new-code output.
3. ~~**`triage-prompts.json` redundancy**~~ RESOLVED — `pass1_screening` is now
   `{system, calls[]}`: the shared pass-1 header is stored once and each call
   keeps only its per-endpoint user turn. The `chars` token estimate is
   unchanged (it still counts the full messages — the live run sends the header
   on every call).
4. ~~**`cve-detection.json` unregistered / provisional**~~ RESOLVED — the
   measured-model rework reshaped it to the single-run `reach`/`observe`/`outcome`
   shape (schema_version 3) and REGISTERED it in `schema._REGISTRY`, so it is
   validated on read. The frozen corpus was re-derived (it is a derived artifact).
5. **`dast cve` writes no metrics record** — the only stage that doesn't;
   consistent per-stage metrics would let a detection pass show in `dast costs`.
   (Rides with the measured-model rework, which reworks that stage.)
6. **naming mismatch** — `static-analysis.md` (file) vs metrics-kind `analysis`.
   Cosmetic; noted so a reader joining the two knows they are the same stage.
