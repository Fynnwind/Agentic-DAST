# Harness sheets

**OBJECTIVE.md says what the series is optimising for** — the
claim that the LLM layer makes this scanner better than ZAP alone, the metrics
that test it, and the method rules that keep a sheet from measuring two things at
once. Read it before drafting a sheet.

Two kinds of file live here, and the name says which.

```
smoke.yml       a plumbing check, not an experiment. No number.
NN-<question>.yml   one optimisation pass. Numbered in the order they were run.
```

## Why the numbers

A sheet is one **question**, asked of one corpus, with one variable moving. The
series is therefore the record of an investigation, and its order is part of what
it records: sheet 2 exists because of what sheet 1 found, and sheet 3 because of
sheet 2. A flat set of topic names (`model-comparison.yml`, `pass1-context.yml`)
lost that, and lost it in the one direction that matters — you could not tell,
from the directory, which questions were still open.

The number is **assigned when the sheet is run**, not when it is drafted. An
unnumbered draft is a draft.

`dast harness` with no argument runs the **highest-numbered** sheet, so the
default is always the current experiment rather than a file someone has to
remember to update.

## The series so far

| sheet | asked | answered |
|---|---|---|
| `01-context-and-models.yml` | does pass-1 cross-endpoint context make triage self-consistent, and is a bigger model worth it? | Context: **no measurable effect**. Models: *invalidated* — the comparison was measuring the verdict-loss bug below. |
| `02-verdict-reliability.yml` | does the `minItems`/`maxItems` verdict contract close the silent loss, and does the model comparison survive honest denominators? | Loss closed (**51–87 → 1** unanswered of 286). Comparison **does not survive**: the two models are indistinguishable on flags, and the cheap one costs a third as much. |
| `03-residue-pass-two.yml` *(superseded)* | given residue a fixed probe cannot settle, does verification pass 2 settle any of it, and honestly? | **Closed, negative.** Pass 2 works and never self-confirms, but *every* transition is a downgrade (20 → refuted, 7 → not-attempted, 0 → confirmed) and only **2 of 7** findings get a stable verdict across six repeats. Disposition, not detection; advisory, never the settling word. **The pass it exercises no longer exists** (2026-09-02): verification is one loop with two axes, and its successor is sheet 09. Do not re-run this sheet — its variables are gone, so it would set nothing and silently produce a default run. |
| `04-synthesis-sampling.yml` | is the synthesis pass undersampled rather than unreliable, and does `seen_in` separate signal from noise? | **Yes, and partly.** Live sampling reproduced the bootstrap (4.3 / 8.7 / 12.0 claims at 1 / 3 / 5). `seen_in` predicts recurrence strongly (6.4% at 1/5 → 66.7% at 5/5) but **does not track severity** — 3 of 7 high-severity claims were one-offs. A reproducibility score, not an importance one. Default is now 5. |
| `05-triage-prompt-v4.yml` | is `llm-only` flat because the prompt asks the model to reproduce the table? | **Refuted; v4 not adopted** (no movement, fewer flags, 1.6× cost). But reading the flags found the real answer: the `llm-only` column is **rule 90035 (SSTI, High/High)**, which the table had no row for. Added — which should take `llm-only` to ~0. |
| `06-table-fix-confirms.yml` | does `llm-only` fall to ~0 once the table enumerates 90035? (predicted before the run) | **Confirmed.** 3/1/2 → **1/0/0**; `both` rose; `deterministic_rescans` 38 → 39. The one residual flag is Informational/Low noise. Not a regression — the control arm absorbing the experimental arm's only win. |
| `07-code-context.yml` | now that pass 1 has the handler's actual source (Phase 1), does `llm-only` finally flag what the table misses — or is the ceiling the workload, not the context? | **Discovery hypothesis REFUTED, but the counters hid the real result.** `llm-only` stayed flat at ~0 across none/source/source+nav. The reasoning text showed the actual effect: `both` falls 23→17→14 and `det-only` rises 11→16→20 (shift ~2× the within-spread), because the model **refutes the table's High-risk false positives from the source, citing lines** (avatar.go:46, auth.go:132, commit.go:390) — and its refutations agree with the independent tool verification. Value is false-positive *suppression*, not detection. `source+nav` adopted as default. |
| `08-wordpress-code-context.yml` *(void)* | does code context still earn its place on a target where it grounds only a sixth of the endpoints? | **Void, never run.** The sixth was an artefact: it counted grounding on the 197 `/src/….php` pseudo-endpoints the running install 404s, and `noir_ignore_technologies: [php_pure]` dropped every callee-bearing endpoint with them. Post-filter WordPress grounds **0 of 90**, so `source+nav` and `none` build the same prompt and the sheet compares an arm against itself. The honest question it was reaching for — what source grounding *requires* of a target — is answered by that number beside Gitea's 354/354, and belongs in the cross-target table rather than a sheet. Do not run it. |
| `09-verification-configurations.yml` | do the three verification configurations — deterministic (the free control), hybrid (the default), full-LLM — differ, and by how much? | **Answered 2026-09-04**, 12 rows over BOTH baselines, 1.9h/$0.74. **Prediction HOLDS**: hybrid matches full-LLM on verdicts and beats it on throughput — asking the model to pick the tool costs ~5 dispatches in the same budget and buys nothing. **Zero confirmations in all 12 rows.** The model's real contribution is elsewhere: 7 of 10 flagged records are it downgrading a `refuted` to `inconclusive` because the dispatched tool could not test the class — the same failure found by hand on rule 40026. Two earlier claims fall: the disagreement rate is 4.2% (gitea) / 16.7% (wordpress), not 0%, and extra rounds DO move verdicts (14 of 84 multi-round loops, 12 of them refuted→inconclusive). The one blocked confirmation vindicates the carve-out — the model confirmed while its own note argued against the finding. |
| `10-baseline.yml` | what does the whole pipeline do, end to end, on a fresh authenticated corpus at a realistic scan budget, before anything is tuned? | **Run 2026-09-04**, 2.1h/$0.3702, both rows clean. The CI number: **76 min / $0.2415** for Gitea and **53 min / $0.1287** for WordPress. It also produced this project's first ground-truth-confirmed detection (rule 40026 at the seeded wpdm frameid sink) and, through it, the discovery that the verification layer refutes what its tools cannot test. Corpus for sheets 09, 11 and 12. Do not tune from it. |
| `11-retrieval-push-vs-pull.yml` | does `RETRIEVAL=pull` earn its re-send once prompt caching is marked, and do the two targets disagree about it? | **Written 2026-09-04, not yet run.** A 2x2 per target — retrieval × prompt cache — because a closed gap has to be attributable to caching rather than to the corpus, and because Gitea grounds 354/354 endpoints in source against WordPress's 0/90. If pull's value is fetching source push omitted, the targets MUST disagree, and that disagreement is the finding. Fill the `run:` ids from the sheet-10 baselines first. |
| `12-synthesis-ensemble.yml` | is cross-MODEL agreement a better predictor of a real claim than cross-RUN recurrence? | **Written 2026-09-04, not yet run.** Sheet 04 showed `seen_in` measures reproducibility and not importance; `TRIAGE_SYNTHESIS_MODELS` shipped on the argument that agreement is the better signal and has never been measured. One row draws 5 samples from one model, the other 3 each from three vendors — the comparison is between the two scores *within* the ensemble row, cross-tabulated against each claim's post-verification disposition. `z-ai/glm-5.2` is excluded on purpose: it truncated at the completion ceiling and cost $0.348 for one call. |
| `11-retrieval-push-vs-pull.yml` | does pull earn its re-send once caching is marked, and do the targets disagree? | **Answered 2026-09-04**, 16 rows, 3.7h/$1.14. **The targets disagree, as predicted.** On Gitea (94% grounded) pull fetches 116-219KB of real source and nets ~26% CHEAPER than push (caches 2x better); on WordPress (0/8 grounded) it fetches ~14-20KB of nothing and costs ~28% MORE. Pull's value tracks grounding. Bonus finding: the prompt-cache toggle is a near-no-op — DeepSeek auto-caches regardless of our markers, so the CI-cost number is provider-controlled. |
| `12-synthesis-ensemble.yml` | does cross-model agreement predict a real claim better than cross-run recurrence? | **Answered 2026-09-04**, 4 rows, 1.7h/$0.99. **No — they converge.** Cross-model agreement is rare (3 of ~59 ensemble claims) and every agreeing claim is the SAME real finding (shared-handler XSS propagation) that recurrence already elevates. The interesting cell — claims several models reach that no single model produces stably — is EMPTY. The ensemble costs ~2x for the same answer; single-model repeats stay the default. Same shape as sheet 09. |
| *(no sheet — computed free from 46 stored runs)* | would the model have routed findings to better tools than the table? | **Closed.** The two arms name the same tool **96%** of the time; only 2 of 39 dispatches would change. The MCP question is about *invocation*, not *selection*. |
| *(no sheet — computed free from 20 stored runs)* | are cross-endpoint synthesis claims reproducible? | **62% of 32 claims appear in exactly one run of 20.** The one claim seen in most runs is *informational*; the high-severity SSTI-sink claim appears 6/20. Genuine findings, unreliably produced. Repeats are the mitigation. |

Sheet 1 ran as `overnight.yml` and sheet 2 as `reliability.yml`; their run
directories under `data/harness/` still carry those names, which is correct — a
directory records what was executed, not what the file was later called.

Two drafts that were never run, `model-comparison.yml` and `pass1-context.yml`,
were removed rather than numbered: sheet 1 asked both their questions, and
keeping them would have implied two open questions that are closed.

## Writing the next one

Copy the newest, change one thing, and say in the header **what the previous
sheet established** and **what this one asks**. That header is the reason these
files are readable a month later; the rows are the easy part.

```bash
uv run dast harness config/harness/03-....yml --dry-run   # costs nothing
uv run dast harness config/harness/03-....yml
```

Every sheet carries a `max_cost_usd` ceiling (default $5.00). Set it to what the
sheet should cost, not to what you can afford — it is there to stop a mistake
running all night.
