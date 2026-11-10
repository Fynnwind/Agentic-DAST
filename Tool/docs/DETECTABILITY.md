# Detectability — what counts as a detected vulnerability

This document defines how the tool's performance against real vulnerabilities is
measured. The load-bearing principle, settled 2026-09-29: **detectability is a
*result*, measured from runs — it is never asserted in `cve-markers.yml`.** The
tool measures the two links it can actually observe (**reach** and **observe**) and
reports a per-marker *outcome*; the *why* behind every non-detection — whether the
exploit was delivered, and which structural limit stopped it — is **manual analysis
in the thesis**, not a value the tool derives. For the field mechanics of a marker
see [`TARGETS.md`](TARGETS.md); for the surrounding concepts — blind vs the
`--oracle` ceiling — see [`ARCHITECTURE.md`](ARCHITECTURE.md).

> **Status (2026-10-01): SETTLED and IMPLEMENTED.** The marker files hold facts
> only (identity, one probe, `zap_rules`, `seed`, and `auth`); `ground_truth.py`
> measures `reach`/`observe` per run and derives the outcome; `dast cve` takes run
> ids and prints the two-run ladder. The earlier **asserted** `detection:` block
> (a hand-set reach/deliver/observe/limit/tier) and the live `--probe` mode are
> **removed**. → `DECISIONS.md` §T0.

## What is being measured

Every target is pinned to a version chosen *because* it carries documented,
real-world vulnerabilities — so in principle each marker is a genuine live bug the
tool ought to have a chance at. The honest result is therefore **not a single
fraction**. It is a distribution: for each real vulnerability, did the tool detect
it, at what level of assistance, or did it not — with the reason left to the
write-up.

The guiding principle is **capability, not configuration**. Detectability is what
the tool can do when its capabilities are used correctly — the scanner
authenticates, the fixtures are seeded, out-of-band confirmation is available. A run
that omits a capability (no `--auth`, no `--oob`) is an operator choice, measured as
a *delta*, never a property of the architecture. The one capability different in
kind is **`--oracle` seeding**, because it requires knowing where the CVE is; it is
the line between what the tool discovers on its own and what it can only reach when
pointed at the sink.

## What the marker file holds — facts only

`cve-markers.yml` is **pure ground truth about the vulnerability**, and nothing about
its detectability:

- identity and provenance — `id`, `cve`, `fixed_in`, `fix_pr`, `fix_location`,
  `description`, `cwe`;
- how to exercise it — `probe` (one concrete request) and `signal` (what
  distinguishes vulnerable from fixed);
- how the join reads a scan — `zap_rules` (the plugin ids that would fire if the
  class were detected);
- where to point the scanner under `--oracle` — `seed` (the benign URL(s) that make
  an otherwise-undiscovered sink reachable);
- the session the CVE requires — `auth` (`none`/`user`/`admin`). A fact about the
  vulnerability, not a detectability claim: a run whose `auth_mode` is below it
  records the marker `not-applicable (auth)` rather than a miss (see below).

The `seed` is a **fact** — *where the sink is* — not a detectability claim; it is
oracle knowledge, so it is applied only under `--oracle`, never in a blind run.
There is **no `detection:` block, no tier, no limit, no note** in the marker file:
those would state the result in the input, which is exactly the confusion this design
removes.

## The two measured links

Of the classic reach → deliver → observe chain, the tool can honestly measure only
the first and the last; **`deliver` is dropped** because black-box DAST cannot see
the bytes the sink received, and crafting a guaranteed positive to compare against is
not always possible. So the tool measures, per marker, per run:

- **reach** — did a request the tool issued arrive at the marker's sink? Measured
  from the scan: was the sink route in this run's tree / did a fuzzer target it. The
  earliest tree it appears in classifies it (see the two-run comparison below):
  `blind` · `seeded` (only under `--oracle`) · `none`.
- **observe** — did success produce a signal the tool could see, and on which
  channel? `in-band` (a rule fired strict on the marker's own sink, or verification
  confirmed there) · `oob` (an out-of-band callback landed) · `none` (nothing the
  tool saw).

**`deliver` is not a tool field.** When a marker is *reached but not observed*, the
tool cannot tell apart "delivered but blind", "the transport mangled the exploit",
and "not actually vulnerable at this pin" — all three look identical on the wire.
Distinguishing them is manual analysis in the thesis, and stating whether the
exploit was delivered *is* how the limit gets named (below).

## The measured outcome (single run)

From the two measured links, plus the auth-applicability check, the tool derives one
**descriptive** outcome per marker for **one run** — what that run saw, with no
a-priori judgement baked in. This is what `cve-detection.json` stores:

| outcome | when | meaning |
|---|---|---|
| **detected** | reached **and** observed | this run found it |
| **reached-unconfirmed** | reached but **not** observed | the scanner got there, no signal came back — the thesis says why |
| **unreached** | the sink entered no tree this run built | the scanner never got a request to it — the thesis says why |
| **not-applicable** | the run's `auth_mode` was **below** the marker's `auth` | the run could not exercise the CVE at all — not a miss |

There is deliberately **no `out-of-scope` and no `undetectable` outcome.** Both were
a-priori judgements dressed as measurements, and as tool labels they wrongly imply
"this should not be a marker." A marker DAST cannot in principle exercise (an email
or git sink) simply measures `unreached`; that it is *permanently* out of reach — as
opposed to a scanner miss — is a conclusion you draw and defend in the write-up,
never a flag the tool sets.

**`not-applicable (auth)` is the one exception, and it is applicability, not a
judgement.** A CVE that needs an admin session, assessed on an anonymous run, was
never exercisable — recording it `unreached` would blame the scanner for a run the
operator did not configure for it. The marker's `auth` fact and the run's `auth_mode`
decide it (none < user < admin).

`observe == oob` (an out-of-band callback landed) is a `detected`, like `in-band`
— out-of-band confirmation is a capability, not a downgrade — but which channel it
rode is recorded, because the confirmation path differs.

## blind vs seeded is a two-run comparison

A single run's assessment can only report what *that* run saw. Whether a marker is
`detected-seeded` (found under `--oracle`, missed blind) or `detected-blind` is
computed by **comparing the blind run against the `--oracle` run of the same
target**. So each run's per-marker `reach`/`observe`/`outcome` is single-run
measured and stored; the blind-vs-seeded split — the ladder — is produced on demand
by the comparison, not stored in either file.

`dast cve` is where that lands. Given **two** run ids (one blind, one `--oracle`) it
prints the ladder — `detected-blind` / `detected-seeded` / `reached-unconfirmed` /
`unreached` / `not-applicable` — plus the blind and ceiling rates. Given **one** run
id it re-executes the flipped counterpart (the same scan config with `--oracle`
toggled) and then compares. The ladder is **printed, never persisted**: the analyzer
re-derives it from the two `cve-detection.json` files (derive-on-read, like
`dast costs`).

## The denominators and the result

There is **no single detection rate**. The result is a distribution over the
outcomes, against **one** honest denominator — the total marker set:

- **blind rate** = `detected-blind` / total markers;
- **ceiling rate** = (`detected-blind` + `detected-seeded`) / total markers;
- the **blind→ceiling gap** = the `detected-seeded` markers — what discovery
  (scanning without the answer key) costs, measured;
- the **`reached-unconfirmed` and `unreached` sets** — reported in full, per marker,
  because *why* each real vulnerability was not detected is a result in its own
  right, and it is the material the thesis analyses.

Config-gated markers (a datasource configured, a fixture seeded) are not
special-cased: those are capabilities the run either used or did not, measured as
reach/observe. **Auth is the one gate the tool records**, because a run below a
marker's required session could not exercise the CVE at all — that marker is
`not-applicable (auth)` and drops out of the rates rather than counting as a miss.

**A target whose CVEs span auth modes is a known limitation** (README remark). One
scan runs at a single `--auth`, so a marker needing a higher session stays
`not-applicable (auth)` in both runs of a blind/`--oracle` pair, and the comparison
*warns* that the pair leaves markers uncovered. Fully covering such a target needs a
pair **per auth mode** its markers require.

## The limit vocabulary — a thesis-level classification, not tool output

Every `reached-unconfirmed` and `unreached` marker gets a *reason* in the thesis.
The vocabulary below is a **general, target-independent** starting set the analyst
applies by manual analysis; it is **not** produced or validated by the tool, and it
is **open and non-holistic** — extend it whenever a real case does not fit. Each
entry is defined generally; the worked instances are the corpus's current
applications, not part of the definition.

- **transport-encoding** — the tool's request-building escapes or encodes the
  exploit before it is sent, so the intact payload never reaches the sink. *(Applied:
  WPDM modal-login reflected XSS — every delivery path percent-encodes the
  `</script>` breakout; the probe reflects it raw, the scanner cannot.)*
- **injection-unreached** — the trigger sits at an injection point no configured
  fuzzer targets (a JSON request-body field, a git-remote string, a sink stock code
  exposes no HTTP parameter to). *(Applied: Grafana TestData `.csv` traversal; WP
  core `WP_Query`/`WP_Meta_Query` SQLi; Gitea git-fetch remote.)*
- **blind-no-oob** — no in-band signal **and** no reachable callback channel; success
  leaves no trace the tool can see. *(Applied: Cacti authenticated SNMP-options
  command injection, firing asynchronously in the poller.)*
- **non-http** — the sink or the observable is a channel DAST does not speak (email,
  git, an internal API), so no HTTP request exercises it. *(Applied: Gitea
  display-name email autolink; storage traversal reachable only via internal object
  names.)*
- **semantic-authz** — success is a semantic authorisation outcome with no in-band
  signal; detecting it needs a model of who-may-see-what (multiple accounts, object
  ownership). *(Applied: Gitea issue access-control; WPDM password-lock bypass;
  Grafana teams-API IDOR; WP core object-injection.)*
- **stored-flow** — a store-then-observe flow (a value stored while authenticated,
  rendered on a later view) a session-less scanner neither drives nor observes.
  *(Applied: WP core post-slug stored XSS; Grafana unified-alerting stored XSS.)*
- **upstream-required** — the payload source is an attacker-controlled *upstream*
  response, not any request parameter a scanner fuzzes; a benign fixture cannot
  honestly provide it. *(Applied: Grafana datasource-proxy XSS.)*
- **defended-at-pin** — a documented CVE whose sink is already hardened at the pinned
  version by generic sanitisation, so no request produces the bug and an alert here
  would be a false positive; the formal fix lands in a later minor. *(Applied: WPDM
  inline-login and search-toolbar reflected XSS — `strip_tags`/`esc_attr`/
  `esc_url_raw` at 3.2.33, verified in source.)*

For the thesis this yields a mapping table — marker → measured outcome → the reason
you assign — that is authored in the write-up, drawing on the measured
`reach`/`observe`, each marker's `probe` request run by hand, and source reading.
The tool supplies the measurements; the classification is yours.
