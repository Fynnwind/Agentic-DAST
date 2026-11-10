# Prompts

Every system prompt the pipeline sends, one file per version, grouped by stage.

## Layout and the naming convention

```
prompts/
├── screening/    screening.v<N>.md     # pass 1 — per-endpoint screening
├── synthesis/    synthesis.v<N>.md     # pass 2 — one whole-corpus cross-endpoint call
├── verify/       verify.v<N>.md        # the verification loop, per flagged finding
└── oracle/       oracle-{screening,synthesis,verify}.md   # the --oracle (ceiling) blocks (unversioned)
```

The **filename is the identity**, not the folder: `<name>.v<N>.md`, where the
`name` says which call it is for and the `vN` is the version. The loader searches
`prompts/` **recursively** (`foundation/prompts.py`), so the subdirectories are for
readability only — moving a file between them changes nothing, renaming it changes
its version. The version lives in the filename precisely so it cannot drift from
the content.

| file | pass | one call per… |
|---|---|---|
| `screening/screening.v3.md` | triage pass 1 (screening) | endpoint (chunked) — per-alert rescan verdicts. **The pinned default is v3** (`TRIAGE_PROMPT_VERSION=3`), not the newest on disk: v4 was measured and **refuted** (sheet 05 — fewer flags at ~1.6x cost, no instance-level upside), and v5/v6 were added to *enable* features without displacing it — v5 adds the evidence-pack / handler-source blocks, v6 adds the `zap_rule_tags`/`zap_injection_point` fields and the optional **Retrieval** section (one prompt serving both the `push` and `pull` arms). v5/v6 are pinned per sheet for their own experiments; neither is the general default. |
| `synthesis/synthesis.v5.md` | triage pass 2 | run, one call over the whole triaged scan, shallow context — cross-endpoint findings only. **The pinned default is v5** (`TRIAGE_SYNTHESIS_PROMPT_VERSION=5`): v4 added the accountability classification (each claim declares how it can be settled, Phase 4), v5 the propagation route enumeration. |
| `verify/verify.v2.md` | the verification loop | flagged finding — one bounded conversation: propose an invocation and the signal it would show, read the tool's raw output, refine or conclude. **The pinned default is v2** (`VERIFY_PROMPT_VERSION=2`): it named **what the declared signal is checked against** (closing the wrapper-prose and command-echo false matches). v3 adds only the rule against predicting a word from the tool's own output *format*, which is **also enforced mechanically** (`verification.OUTPUT_FORMAT_WORDS`), so it moves no verdict and is not the default. |
| `oracle/oracle-screening.md` | oracle-guided pass 1 (`--oracle`) | endpoint, alongside `screening.vN`. Asks first: **is a ZAP alert here the alert a documented weakness would raise?** — matched by class, parameter and sink. |
| `oracle/oracle-synthesis.md` | oracle-guided pass 2 (`--oracle`) | run, alongside `synthesis.vN`. Works outward from the description to the sink's whole route family, reading pass 1's matches as anchors. |
| `oracle/oracle-verify.md` | oracle-guided verification (`--oracle`) | finding, alongside `verify.vN`. Aims the probe at the mechanism the description names and picks the oracle that can settle *that class*. |

**The oracle blocks are unversioned** — no `vN`. Unlike the pass prompts they are
generic scaffolding, not an A/B axis, so a change to one is a plain edit (still
recorded verbatim in every artifact). `oracle-screening` names pass 1 the way the
model config already does (`--screening-model`), not the old `oracle-triage`.

**The three `oracle-*` prompts are additive, never replacements.** An `--oracle`
run still sends `screening.vN` / `synthesis.vN` / `verify.vN` as its system prompt; the
oracle prompt rides in the payload beside the target's own `oracle.md`. So the
stage's job is unchanged and the ceiling is the only variable — which is what makes
a blind row and a ceiling row of one sheet comparable at all.

## To change a prompt, add a version — never edit one in place

Two recorded runs may both cite `screening.v6.md`. Editing it silently makes those
runs incomparable while both still claim the same version — the exact failure the
filename-as-version mechanism exists to prevent.

```bash
cp prompts/screening/screening.v6.md prompts/screening/screening.v7.md   # then edit v7
```

Leaving the old file in place is also what makes an A/B possible: both versions
exist at once, and a run records which it used.

## Selecting one

Each pass is **pinned** to its corpus-validated version in `config/scanner/.env`
(screening 3, synthesis 5, verify 2) — deliberately **not** the newest on disk, so
a newer prompt landing never silently changes what a run does or drifts from the
reported corpus. (`none`/empty still resolves to the newest at the loader level;
the pins are what keep the default off it.) Override per run as ordinary
configuration — a flag or its env var:

```bash
uv run dast triage latest --screening-prompt 5     # pin triage pass 1 to v5
TRIAGE_PROMPT_VERSION=5 uv run dast triage latest
```

The version vars are env-file variables like any other, so a **harness sheet row**
can pin them — which is how a prompt change becomes something measured rather than
argued about:

| flag | env var | selects |
|---|---|---|
| `--screening-prompt` | `TRIAGE_PROMPT_VERSION` | `screening/screening.vN.md` |
| `--synthesis-prompt` | `TRIAGE_SYNTHESIS_PROMPT_VERSION` | `synthesis/synthesis.vN.md` |
| `--verify-prompt` | `VERIFY_PROMPT_VERSION` | `verify/verify.vN.md` |

The `--oracle` blocks are selected by the pipeline itself (newest on disk); they
are not pinned per run today. Both sheet rows below triage the *same stored scan*,
so the comparison is between prompts and nothing else — see `config/harness/`:

```yaml
rows:
  - name: prompt-v5
    stages: [triage]
    env: { TRIAGE_PROMPT_VERSION: "5" }
  - name: prompt-v6
    stages: [triage]
    env: { TRIAGE_PROMPT_VERSION: "6" }
```

## What ends up in the artifact

The **verbatim text**, plus the name, version and filename. A run has to stay
readable after this file is edited, moved or deleted — "prompt v6" means nothing to
a reader who does not have this checkout.
