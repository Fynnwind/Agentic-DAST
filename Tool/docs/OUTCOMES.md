# Every status a finding can carry, per stage, and what it resolves to

The pipeline's categories are deliberately distinct: a status in one stage is not
the same as a similarly named status in another, and the design depends on not
merging them. This page collects every status a finding can carry, stage by stage,
and what each resolves to downstream. For the concepts behind the stages, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

The four end statuses are **confirmed / refuted / inconclusive / not-attempted**,
and they never become three.

---

## Stage 1 — Scan (`dast scan`)

ZAP produces alerts. Nothing here is a verdict yet; these are the inputs
everything downstream keys on.

| field        | values                                                 | why it matters                                                 |
| ------------ | ------------------------------------------------------ | -------------------------------------------------------------- |
| `risk`       | High, Medium, Low, Informational                       | orders dispatch (`dispatch_priority`)                          |
| `confidence` | False Positive, Low, Medium, High, Confirmed           | second key of the rescan table                                 |
| `sourceid`   | active-scanner, passive-scanner, manual, tool, unknown | a run that is 99% passive has not exercised the active scanner |
| `plugin_id`  | ZAP rule id                                            | the routing key for everything below                           |

---

## Stage 2 — Triage (`dast triage`), two independent arms

### Arm A — the deterministic rescan table (`rescan_table.py`)

Keyed on plugin id × confidence. Pure data, no model.

| policy           | meaning                                                         | leads to                                     |
| ---------------- | --------------------------------------------------------------- | -------------------------------------------- |
| `ALWAYS`         | an independent tool can settle it                               | `needs_rescan: true`                         |
| `WHEN_UNCERTAIN` | verifiable, but ZAP is already sure                             | `needs_rescan` only at Low/Medium confidence |
| `NEVER`          | self-evident from the response, or not decidable by any scanner | never dispatched                             |

Each row also carries a `tool` — `nuclei`, `sqlmap`, `ffuf`, `browser`, or none.
**A row with no tool still flags**, and that combination is the rule-40026 shape:
escalated on risk alone, dispatched nowhere, silent. It is counted as
`no-tool-routed` at the next stage rather than disappearing.

### Arm B, pass 1 — per-endpoint LLM screening (`analysis/screening.py`)

| `verdict`                             | meaning                                                                    |
| ------------------------------------- | -------------------------------------------------------------------------- |
| `likely-true-positive`                | the handler supports what ZAP reported                                     |
| `likely-false-positive`               | the source shows why it cannot be real                                     |
| `undecidable-without-verification`    | the source does not settle it — the case verification exists for           |
| `self-evident-no-verification-needed` | the response already proves it; a second tool would re-read the same bytes |

Plus `needs_rescan` and a `suggested_tool`. **The arm is never told what the
table decided** — that is the anti-circularity invariant, and every agreement
count depends on it.

A finding the arm was asked about but that came back unanswered is
`asked-but-unanswered`, never an implicit clean bill of health.

### Arm B, pass 2 — whole-corpus synthesis (`analysis/synthesize.py`)

Emits cross-endpoint claims in their own `c-` id space. Each carries a
**disposition**, which decides how it can ever be settled:

| `suggested_tool`                                        | how it resolves                                                                                                            |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `sqlmap` / `nuclei` / `ffuf` / `browser` / `interactsh` | dispatched; the tool's verdict decides                                                                                     |
| `self-evident`                                          | **confirmed only if every finding it cites is itself confirmed**, else requires-triage                                     |
| `out-of-scope`                                          | requires-triage, reported as "out of scope for automated verification" — the honest manual set, never counted as confirmed |

---

## Stage 3 — Verification (`dast verify`)

### The four end statuses

| status          | means                                                                                       | does **not** mean                                        |
| --------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `confirmed`     | an independent tool reproduced the vulnerability                                            | —                                                        |
| `refuted`       | the tool ran to completion and could not reproduce it                                       | that the finding is harmless in some other configuration |
| `inconclusive`  | the tool neither confirmed nor refuted: timed out, errored, or the target refused the probe | a clean bill of health                                   |
| `not-attempted` | selected, never dispatched                                                                  | "we checked and it was clean"                            |

### Why a finding was not attempted (`not_attempted_reason`)

`not-attempted` has one name and several distinct causes; each is recorded
separately, so a refusal to dispatch is never mistaken for a clean check.

| reason                        | cause                                                                                                                                                   | what to do about it                                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `no-tool-routed`              | flagged, but no arm named a tool — the rule is not in the table, or its row names none                                                                  | **indicts the table**, not the budget. This is the 40026 shape              |
| `no-probe-url`                | a tool was named and no honest URL could be built (no example URL; the payload sits in a path segment and the alert does not say what was there before) | nothing to do — probing would test the payload                              |
| `tool-cannot-reach-parameter` | a tool was named, the URL is fine, and the flagged parameter is not in the request that tool sends                                                      | route it to a body-capable tool (`sqlmap`, `browser`), or teach the wrapper |
| `budget`                      | a dispatch ceiling refused it                                                                                                                           | raise the cap that refused it — the message says which                      |
| `no-tool-applies`             | a synthesis claim whose own disposition is `self-evident` or `out-of-scope`                                                                             | a **decision**, not a gap                                                   |

### How the two readings become one status (`resolve_verdict`)

Every round produces two readings of the same raw output: the wrapper's, from
fixed rules, and the model's. One rule combines them — *the model's category is
reported, except it can never produce a `confirmed` the tool's own machinery did
not also report, and a tool that did not validly run cannot be rescued.*

| wrapper ↓ / model →     | confirmed          | refuted   | inconclusive   |
| ----------------------- | ------------------ | --------- | -------------- |
| **confirmed**           | confirmed          | refuted ⚑ | inconclusive ⚑ |
| **refuted**             | **inconclusive ⚑** | refuted   | inconclusive ⚑ |
| **inconclusive**        | **inconclusive ⚑** | refuted ⚑ | inconclusive   |
| **did not validly run** | wrapper ⚑          | wrapper ⚑ | wrapper        |

⚑ = recorded as a disagreement. The model may downgrade and raise doubt freely —
falsification is what this layer is measurably good at. The two bold cells are
the only place it is blocked, and they are what keeps a reported `confirmed`
worth the word: an unbacked "yes" lands as a *flagged* inconclusive, a countable
disagreement rather than silent trust.

A `confirmed` is additionally checked against the flagged rule's CWE family
(`classification_match`). That check **records** whether the confirming evidence
belongs to the class — `match`, `mismatch`, `unspecific`, `unknown` — and never
changes the verdict.

### Sibling probes have two extra statuses of their own

A sibling is a route a propagation claim *predicts*, at a URL this pipeline
built. It answers a different question from the flagged population, so it does
not share its whole vocabulary.

| status                  | means                                                                                                  | why not something else                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| `sibling-unreachable`   | the pre-check asked and the route answers 404/410 — it is not served                                   | a verdict on the **claim**. Not `not-attempted`, which has always meant *unexamined*   |
| `sibling-not-probeable` | the route IS served but answers 3xx or 5xx, so a probe would follow the redirect or read an error page | a verdict on the **probe**. Says nothing about the claim, so not `sibling-unreachable` |

401/403 stay probeable: that is the route's own answer, and a probe that gets one
has learned something about the route.

**Neither reaches the report as a finding.** They are counted in
`summary.siblings` (`considered`, `routes_not_served`, `routes_not_probeable`,
`by_route_status`) so the triage-stage measurement is complete — proposed,
immediately ruled out, logged. Only a **confirmed** sibling becomes a SARIF
result, in its own `s-` id space, because a refutation at a constructed URL may
only be a fact about the URL.

---

## Stage 4 — Report (`dast report`)

The three readings merge into one **disposition** per reported item, computed by
`classify_finding` (per-endpoint findings) and `classify_synthesis` (cross-endpoint
claims) in `domain/verification/dispatch.py`. The same two functions feed both the
Markdown summary and the SARIF `properties.disposition` on every result, so the two
outputs can never disagree. Precedence is by *authority of evidence*: a tool that
ran outranks the triage model's reading, which outranks the response being
self-evident, which outranks "nobody settled it".

### Per-finding (`classify_finding`)

| disposition       | reached when                                                                                                                                                                                                    |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `confirmed`       | an independent tool reproduced it; **or**, nothing having settled it, the finding is self-evident from the captured response — a header/cookie rule ZAP rates above Informational, flagged by neither arm or routed to no tool (`no-tool-routed`), so no tool could add to it |
| `refuted`         | the dispatched tool ran and could not reproduce it; **or** the triage model declined a rescan *and* cited a handler-source line (a source-grounded refutation, the kind that agrees with the independent tools) |
| `requires-triage` | verification was inconclusive or not-attempted for any reason but a header/cookie rule's `no-tool-routed`; **or** it was flagged for a rescan that has not settled it; **or** it is a semantic judgement no scanner can make (the default) |
| `informational`   | an identification / technology-fingerprint rule — no security claim to confirm or refute; **or** a header/cookie rule ZAP rates Informational, which claims no weakness |

### Cross-endpoint synthesis (`classify_synthesis`)

A synthesis claim reaches the report only under a disposition it *earns* (Phase 4),
never silently equal to a confirmed finding — keyed on its `suggested_tool`:

| disposition       | reached when                                                                                                                                                                                                                                                                           |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `confirmed`       | a **dispatchable tool** reproduced it; **or** it is **self-evident** and every finding it cites is itself confirmed                                                                                                                                                                    |
| `refuted`         | a dispatchable tool ran and could not reproduce it                                                                                                                                                                                                                                     |
| `requires-triage` | a dispatchable tool was selected but did not settle it; **or** it is declared self-evident but not all its cited findings are confirmed; **or** its tool is **out-of-scope** — *out of scope for automated verification*, the honest manual-evaluation set, never counted as confirmed |

### The order a reader works through (`build_worklist`)

`domain/verification/worklist.py` places every reported item in one **section**,
then one line per ZAP rule within it. The Markdown summary prints those lines; the
SARIF carries them on each result as `rank`, `properties.worklist_section`,
`worklist_group` and `worklist_line`.

| section         | holds                                                                                          | one line per   |
| --------------- | ---------------------------------------------------------------------------------------------- | -------------- |
| `reproduced`    | findings, claims and siblings an independent tool reproduced                                   | item           |
| `open`          | `requires-triage` ZAP findings, each line saying why it is still open                          | ZAP rule       |
| `claims`        | `requires-triage` synthesis claims, most models agreeing first, then most samples              | claim          |
| `evident`       | `confirmed` with no tool behind it: the self-evident rules and claims resting only on confirmed findings | ZAP rule, or claim |
| `refuted`       | `refuted` findings and claims, each line saying who refuted it                                 | ZAP rule, or claim |
| `informational` | `informational` findings                                                                       | ZAP rule       |

Within a section, lines order by the worst member's risk, then whether a scanner
attacked for it, then whether both arms flagged it (`dispatch_priority`'s keys), then
ZAP's confidence, then the rule id, so the tiebreak means the same in every run.

**This orders the evidence; it does not rank by true risk.** Nothing has measured
that it brings a true finding up sooner. `rank` is ordinal and encodes only this
order. `level` stays ZAP's risk, and `kind` stays unset, because SARIF §3.27.10
requires `level` `none` on any kind but `fail`.

No model writes any findings prose: every number is computed from the artifact it
cites, so a report can never disagree with its JSON.

---

## The rule behind all of it

**When a case does not fit a category, it gets its own name.** A budget refusal is
not "nothing routes here"; a synthesis decision is not a routing gap; a tool's
unasked question is not a refutation. Each has its own status above, because a
count that silently covers most of a population invites the wrong conclusion about
the rest. The four end statuses, and the several reasons a finding is
`not-attempted`, exist precisely to keep those cases countable.
