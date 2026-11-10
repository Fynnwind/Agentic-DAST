# DAST in CI/CD — thesis implementation

The practical artifact for the bachelor thesis *"DAST in CI/CD Pipelines — A Case
Study on Security Evaluation."* It scans self-hosted, deliberately vulnerable
targets with OWASP ZAP, adds an AI triage/verification layer, and reads the result
against independent SAST/SCA findings — all locally, in Docker, on arm64.

The project is three top-level directories:

| directory | what it is |
|---|---|
| [`Tool/`](Tool/) | the tool — the `dast` orchestrator and pipeline (scan → triage → verify → report), the harness, its Docker stacks, config, prompts, schemas and tests. Installable and driven from here. |
| [`Targets/`](Targets/) | the systems under test, as **data** — one directory per target, plus `persistent.yml` to run them as containers. |
| [`Thesis-Analyzer/`](Thesis-Analyzer/) | the read-only analyzer that turns finished run artifacts into the thesis's tables and figures. |

Each directory has its own `README.md`. **The tool's full documentation lives in
[`Tool/docs/`](Tool/docs/)** — start with
[`Tool/docs/ARCHITECTURE.md`](Tool/docs/ARCHITECTURE.md) for the vocabulary and how
the pipeline fits together.

One git repository holds all three for now; the tool reaches the targets through
`SHARED_TARGETS_DIR` (default `../Targets`), and the analyzer reads the tool's
`data/` artifacts through a vendored copy of its `schemas/` — a one-way dependency,
so the analyzer never imports the tool.

---

*Minor known limitation.* A single scan runs at one authentication mode, but a
target's documented CVEs can span auth levels (some unauthenticated, some needing a
user or admin session). The CVE-detection measurement handles this per marker — a
marker whose required auth a run did not provide is recorded `not-applicable (auth)`
rather than counted as a miss — so fully covering such a target needs runs at the
auth modes its markers require. Context for the write-up, not a blocker.

---

## About this repository

This is the public release of the thesis implementation, published without its
development history. The working records behind it (the decision log, the run
plans and the campaign notes) stay in a private repository, so a comment or
document that cites a file not in this repository (`DECISIONS.md §…`,
`RUN-PLAN §…`, `SHEET-CATALOG §…` and the like) points into that record. The run
corpus (`Tool/data/`) is not included.

Released under the [MIT License](LICENSE).
