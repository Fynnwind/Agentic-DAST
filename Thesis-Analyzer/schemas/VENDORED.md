# Vendored schemas — the analyzer's input contract

These are a **read-only copy** of the tool's `Tool/schemas/` plus the standard
SARIF 2.1.0 schema (from `Tool/tests/fixtures/`). The analyzer validates the
artifacts it consumes against these and never imports the tool, so the one-way
dependency (tool produces, analyzer consumes) is enforced at the file level.

Vendored from commit `038b96e` on 2026-10-14. The campaign corpus is the
frozen `bc30e8d` (P7) pin; re-copy from `../Tool/schemas/` only if the corpus is
ever regenerated at a newer schema version.
