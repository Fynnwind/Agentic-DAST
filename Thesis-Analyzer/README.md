# Thesis-Analyzer — the read-only analysis layer

Turns the tool's finished run artifacts into the thesis's numbers, tables and
figures. The runs are the experiment; this directory is where their raw JSON
becomes machine tables (CSV/JSON the thesis cites), figures (font-matched to the
LaTeX body), and a Markdown/LaTeX-ready digest — every figure carrying the run ids
and config digests it was built from, so a number in the thesis traces back to its
runs.

**Status: the corpus is complete and the analyzer is built.** The index spine,
the load-bearing analyses (detection ladder, two-arm agreement, G9 cross-section),
the §9 metric definitions (`metrics.py`), the remaining result-cuts (`cuts.py`),
the G9 handler-source join, provenance stamping (`provenance.py`), the figure set
(`figures.py`, pgf), and the `dast-analyze` CLI + digest (`cli.py`) are implemented
under `src/dast_analyzer/` and tested against the corpus (`uv run pytest` — 54
tests, anchored to the SHEET-CATALOG numbers). The author-side decisions of that
time (repeat counts, marker identifiers, limiting-factor table) were tracked in
`NEXT_SESSION.md` §6, retired after the rescan (frozen copy:
`git show rerun-2026-11-03f:NEXT_SESSION.md`). Blocks 1–5 (G1–G10) are run and committed
under `../Tool/data/` (`data/harness/*` + the G9 `data/runs/*`); the pre-analyzer,
by-hand readings are in `SHEET-CATALOG.md`. The cuts that carry
the results are listed below.

Run it: `cd Thesis-Analyzer && uv sync`, then `uv run dast-analyze digest` (the full
Markdown digest), `uv run dast-analyze table <name>` (one table; `… list` names
them), `uv run dast-analyze figures --out-dir figures`, or `uv run dast-analyze
select --named <sel> --group-by <cols>` for an ad-hoc cut. Every output carries the
corpus commit and the run ids it was computed from.

**It is read-only over the tool's `data/` artifacts, reached through a vendored
copy of the tool's `schemas/`, and it does not import the tool** — that one-way
dependency is deliberate: the tool produces artifacts, the analyzer only consumes
them.

Intended stack: Python with pandas and matplotlib (the `pgf` backend, so figures
export to PDF/SVG matched to the thesis fonts). Inputs are a run directory, a set
of runs, or a harness `results.json`. Selection surface and metric definitions are
`RUN-PLAN.md` §8/§9 (the authority); do not restate them in code comments.

## What the campaign showed the analyzer must surface (learnings, 2026-10-14)

The results, not just the a-priori plan, now fix the load-bearing cuts. Each is
backed by data already in `data/`; detail and the interim numbers are in
`SHEET-CATALOG.md`.

1. **The two-arm triage agreement matrix** (both / det-only / **llm-only ≈ 0** /
   neither), per target and level. This is the central claim — the LLM arm never
   discovers what the deterministic table misses — so it is the first table.
2. **Detection per layer, blind vs ceiling, strict per marker-sink**
   (zap+noir → +det-triage → +llm-triage → +verify). Blind is 0 everywhere; the
   story is the **ceiling gap** (one confirmable marker, grafana) and the
   **verification layer** where the measured value (refutation) lives — not discovery.
3. **Alert volume as a range, detection as a point.** Report min/max/mean per target
   over the G3 repeats (wordpress ±34 %, gitea ±27 %; grafana/cacti stable); never
   quote a single-run aggregate. Triage `findings` is far steadier than raw alerts.
4. **Spread is the yardstick, and a single event can be noise.** Carry G5 error bars
   (synthesis claim-count ±3–6); flag that a verify "confirmed" seen in 1 of 4
   identical reps (gitea) is inside the spread, not a detection. "A difference
   smaller than the spread is not a difference."
5. **Source-grounded false-positive suppression:** High-risk table findings the LLM
   refutes with file:line, agreeing with independent tool verification — the
   measurable value, joined against the verification outcome.
6. **Synthesis scored by `seen_in` recurrence against post-verification disposition**
   (`models_agreeing` is out — no ensemble). The reproducibility-vs-disposition join
   is how a synthesis claim earns its place.
7. **G7 context joined *through* verification, not off triage counts.** Removing
   code/peer context does not move triage claim-counts beyond the G5 spread; code
   context's measured value is FP-suppression at verify, so join the codenone/peernone
   triage variants to their verification disposition.
8. **The G4 Noir-seeding delta is per target and direction-reversing** (expands
   sparse apps cacti/grafana, tightens link-dense gitea) and run-unstable — compute
   it analyzer-side (no `dast cve` on G4), report per target with a range, never one
   number.
9. **SAST↔DAST on the `security`-tagged SAST subset**, not raw totals (grafana is 99
   of 2340 — the rest is i18n/correctness noise). Join on CWE / handler source; the
   interesting cell is Semgrep flagging the source behind a DAST finding the pipeline
   *refuted*. SCA↔DAST on component identity (ZAP 10003 ↔ OSV); SCA scales with the
   dependency tree and wordpress SCA no-ops (no manifest). G10 OOB is a standalone
   record, never counted as a pipeline detection.
10. **Frontier (G8) read vs the G5/G6 default spread** — Opus added no value at any
    stage (fewer rescans, fewer synthesis claims, identical verify outcome), at
    18–37× cost. Report alongside it the **operational** finding: a frontier
    reasoning model could not reliably enforce the structured-JSON verify contract
    via OpenRouter (empty content / answer in the reasoning channel / a tool outside
    the enum, deterministic, independent of token budget). Cost projections use the
    validated re-pricing method in `SHEET-CATALOG.md` (default-model token volumes at
    a model's rates; reproduces the gitea actuals to the cent).

**Provenance caveats to carry into every figure:** targets are not restored between
scans; cost banners on the parallel-run sheets (blocks 3/4) are inflated by shared
cost accounting — use per-run metrics (`dast costs`), not the banner; synthesis is
preference-routed, so read the **served** provider from the call log, not a pin.

For what the runs record and how the pipeline produces it, see
[`../Tool/docs/ARCHITECTURE.md`](../Tool/docs/ARCHITECTURE.md).
