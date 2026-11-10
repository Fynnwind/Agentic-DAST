# `Targets/<name>/` — every field, and what it changes

This is the reference for that directory; for the pipeline the targets feed, see
[`ARCHITECTURE.md`](ARCHITECTURE.md), and for how a marker's detectability is
MEASURED (reach/observe → outcome) rather than asserted — see
[`DETECTABILITY.md`](DETECTABILITY.md).

A target is **data**: one directory plus one `include:` line in
`Targets/persistent.yml`. Adding one edits no Python — the pipeline is
target-agnostic by design, and only two things ever need code (a login mechanism
new in kind, and the seeding script; see the checklist at the end).

**The current targets** — each pinned to a version with a documented CVE; the
authoritative per-target ground truth is each target's `cve-markers.yml`:

| target | pinned version | headline CVE for detection |
|---|---|---|
| `gitea` | 1.16.0 | the HTTP-reachable 1.16.x cluster (open redirect, path traversal, XSS, CSRF, access-control) |
| `wordpress` | 5.8.0 + WP Download Manager 3.2.33 | the WPDM cluster — reflected XSS (ZAP rule 40026) and an unauth SQLi |
| `grafana` | 8.3.0 | CVE-2021-43798 — unauth plugin-asset path traversal, the first DAST-detected-and-confirmed at its own sink |
| `cacti` | 1.2.22 | CVE-2022-46169 — unauth blind RCE, the first confirmed out of band |

```
Targets/<name>/
  target.yml         # the definition — this document
  cve-markers.yml    # ground truth: the documented vulnerabilities of the pinned version
  oracle.md          # the same weaknesses in prose, read ONLY under --oracle
  src/               # its source clone (gitignored) — Noir, ctags and the SAST baseline read it
  env/
    compose.yml      # its container, pulled into the persistent stack
    seed-*.sh        # its accounts and CVE fixtures
    reset.sh         # restore it to the clean seeded state (--reset-target)
```

Three of these are **not** interchangeable and the distinction is load-bearing:
`cve-markers.yml` is the measurement join and is **never shown to a model**;
`oracle.md` is prose about the application and names no ZAP rule id; `target.yml`
is configuration. A target with markers but no oracle simply cannot run under
`--oracle`.

---

## Required

| field | what it is |
|---|---|
| `name` | Must equal the **directory name** — the directory is the target's identity, since it holds the source, the container and the fixtures. A mismatch is an error. |
| `base_url` | Where ZAP and the verification tools reach it: a **container name on `dast-net`**, not `localhost`. They run in their own containers. |
| `source_dir` | Source tree Noir analyses, resolved **inside the target's own directory** (default `src`). Must match the running version — a tree from a different release makes every endpoint claim wrong. |

## Reachability

| field | what it is |
|---|---|
| `path_vars` | Values substituted into route placeholders so a seeded URL is fetchable (`username: thesis`). An unknown placeholder falls back to `"1"`. |
| `form_fillers` | Benign values for form fields, so a reconstructed POST body submits the flagged parameter inside a plausible form. |
| `openapi` | OpenAPI/Swagger specs whose routes seed the tree, for a target whose router Noir cannot parse. See the section below. |

**Reaching a sink no crawler discovers** — WordPress's `?__wpdmxp=1` shortcode
iframe, Grafana's plugin-asset route — is **oracle knowledge** (the surface is
seeded because the CVE's location is known), so it does **not** live in
`target.yml` and is **not** in a blind scan. It lives on the CVE marker (`cve-markers.yml` `seed:`)
and is seeded only by `dast scan <target> --oracle`. See "The `--oracle` ceiling"
below. A blind run's tree is what Noir and the crawlers find on their own; the
gap from the ceiling is what discovery costs.
| `spiders` | Which crawlers suit this application. Keep `traditional` in every list: it produced every recorded coverage number, so dropping it moves that baseline rather than adding to it. |
| `noir_ignore_technologies` | Noir classifications to drop. The framework-blind PHP tagger emits a `php_pure` "endpoint" for every `.php` file — a source path WordPress never serves. A framework-less PHP app, whose files *are* routable, would leave this empty. |
| `scan_headers` | Fixed request headers ZAP adds to **every** request (injected as Replacer rules, like the auth cookie), for a header-gated sink a crawler cannot otherwise reach. Cacti's `remote_agent.php` needs `{X-Forwarded-For: 127.0.0.1}` to pass its poller check — not a login (no session, no credential), a static header the app trusts. **Changes what a scan can reach**, so it is in the run's configuration digest. |

### `openapi` — route discovery from a spec, when Noir can't parse the router

```yaml
openapi:
  - url: "http://target-x:3000/v3/api-docs"   # a spec the target serves
  - file: "openapi/api.yaml"                   # or one committed beside the target
    base_path: "/v1"                           # optional: override the spec's prefix
```

Noir extracts routes by recognising a framework's routing idiom in source. When a
target routes through a framework Noir doesn't model, it extracts nothing useful
— Noir finds **zero** routes in Grafana's `pkg/api`, which uses a custom
`RouteRegister`. An OpenAPI/Swagger document is the
framework-agnostic alternative: its `paths` are literal strings whatever router
serves them. Each entry is a served **`url`** (fetched over `dast-net` at scan
time, carrying the run's session cookie so a spec behind auth is reachable) **or**
a committed **`file`** (resolved inside the target's own directory) — exactly one.

The paths are parsed **here**, into the same seed-request list Noir produces, and
seeded through the same path — not handed to ZAP's own importer — so every URL
added is recorded in the run's artifacts and counted in its metrics
(`seeding.openapi_seeds`), and path parameters are filled from `path_vars` by the
same rule Noir's routes use. A spec that can't be fetched/parsed **warns and is
skipped**, never failing the scan.

**What it does not do:** a spec describes an application's declared **API** — not
static-asset routes, admin file handlers, or anything absent from it. It widens
discovery to the API surface; it is not a way to reach a route nothing declares.
Grafana 8.3 is the limiting case — it ships no spec at all, and its one
DAST-reachable CVE lives on a static-file handler no spec would list — so there
the marker's `--oracle` `seed:` stays the honest lever, and the gap is itself a
result.

## The `--oracle` ceiling (scan) — seeding the documented CVE sinks

```bash
dast scan <target>            # BLIND: Noir + crawlers only — true discovery
dast scan <target> --oracle   # CEILING: also seed the markers' `seed:` sinks
```

A marker in `cve-markers.yml` may carry a `seed:` — the benign URL(s) that make
its sink reachable:

```yaml
- id: grafana-plugin-path-traversal
  seed:
    - "/public/plugins/prometheus/plugin.json"   # the base the traversal escapes
  probe:
    path: "/public/plugins/prometheus/%2e%2e%2f…/etc/passwd"   # the exploit
```

Each seed must land **at that marker's own sink** — its `probe` route (a
query-parameter marker), or under its traversal `seed_base` (a path-payload
marker) — validated when the markers load, so a stray seed fails loudly rather
than silently widening the attack surface.

**Why gated behind `--oracle` and not always-on:** choosing which surface to seed
uses knowledge of where the CVE is, so it is oracle knowledge. A **blind** run
therefore seeds none of them and measures true discovery; an **`--oracle`** run
seeds them and measures detection *given* the scanner is pointed at the known
sinks. `--oracle` is in the scan's configuration digest, so the two never share a
corpus. This is the scan-stage half of the ceiling the LLM stages already take
`--oracle` for (they are *told* the vulnerabilities; here the *scanner* is made to
reach them). A complete ceiling run is `--oracle` on scan **and** on the LLM
stages.

## Authentication

```yaml
auth:
  strategy: form              # built-in CSRF-form login
  login_path: /user/login
  csrf_field: _csrf           # "" if the form has no token
  session_cookie: i_like_gitea
  logged_in_indicator: "Sign Out"   # text present only when authenticated
  logged_in_check_path: ""    # page the login check fetches; "" = app root "/"
  username_field: user_name   # defaults to "username"
  password_field: password
  extra_login_fields: {}      # any additional fixed fields the form needs
  logout_markers: ["/user/logout"]  # URL substrings that end the session; the scan never sends one
  destructive_markers: ["/settings", "POST /admin", "body:drp_action="]  # routes that wreck the account/app
  users:
    - { role: user,  username: dastuser,  password: "..." }
    - { role: admin, username: dastadmin, password: "..." }
```

`strategy` names a function in `auth.STRATEGIES`, of which there are two:

- **`form`** — the CSRF-form case (Gitea, WordPress). GET the login page, read
  the hidden `csrf_field` if one is declared, POST the credentials url-encoded.
- **`json`** — a JSON-API login (Grafana). A single `POST` of a JSON body
  `{"<username_field>": …, "<password_field>": …}` (plus any `extra_login_fields`
  as extra keys) with an `application/json` content type; no CSRF token, no prior
  GET. Grafana's is `POST /login`, session cookie `grafana_session`,
  `username_field: user`.

**A login mechanism that differs in kind again** adds one more small function to
`auth.STRATEGIES` — it is one of the only two things that still need Python. The
field *names* always stay data in `target.yml`, whichever strategy is chosen.

**Login is fail-closed.** A login that returns a cookie is not proof of a
session — apps set one for anonymous visitors too — so after logging in, `auth`
fetches `logged_in_check_path` (the app root `/` when empty) with the harvested
cookie and requires `logged_in_indicator` in the response; if it is absent the
login raises rather than threading a logged-out session into every probe. Set
`logged_in_check_path` only for a target whose root does not carry the indicator
(e.g. a SPA whose root HTML is client-rendered — point it at an authenticated
endpoint instead). The indicator must be absent from every signed-out page:
Cacti's `"Logout"` sat in a script block of its login page too, so its check
passed logged out.

**The scan keeps the session, and checks that it did.** The session is a fixed
injected cookie, so one request to a logout route ends it for the rest of the
scan — Noir seeding Gitea's `POST /user/logout`, the spider following WordPress's
nonce'd admin-bar link. `logout_markers` are literal substrings of such a URL:
seeding drops the routes, ZAP's spider and active scanner exclude them, and a
Replacer rule rewrites them in any other request ZAP sends (the browser spider has
no exclusion list). An authenticated scan of a target that declares none refuses to
start. `destructive_markers` get the same handling: routes a logged-in crawl must not
send because it submits every form it finds, with valid tokens, and follows action
links (account settings, admin jobs, plugin editors, trash links). Two more forms:
`"POST /path"` blocks only a POST to exactly that path (the page itself stays
scanned) and `"body:text"` blocks a request whose body carries `text` (a form's
action field). Every marker is in the configuration digest. Through ZAP the scan then
re-checks `logged_in_indicator` after seeding and after the spider (aborting if the
target answers without it; a check with no answer is retried, then recorded as
unknown), every 5 minutes of the active scan and at the end, recorded as
`session_checks` and `session_held_to_end` in `scan-zap-alerts.json`.

## What the scan CONTAINS

Everything in this group changes what a scan *is*, so each is part of the run's
**configuration digest** and a run carrying one is not comparable with a run that
does not. That is why none of them has a command-line flag: turning one off for a
single run would produce a differently-shaped corpus under a name that says
nothing about it.

### `zap_context.structural_parameters`

Query parameters ZAP should treat as part of a URL's **identity** rather than as
values.

```yaml
zap_context:
  structural_parameters: [action]
```

WordPress funnels ~90 plugin endpoints through one PHP file distinguished only by
`?action=<name>`. Without this, ZAP builds one site-tree node where the
application has ninety and the active scanner attacks one of them — measured, 91
seeded requests collapsed into 15 URLs, and 56 with it. ZAP has **no REST action**
for this (upstream issue #2141, open since 2015), so `zap_context.py` exports the
context, rewrites the URL parser's `struct` list and imports it back.

### `zap_scan` — per-rule active-scan settings

```yaml
zap_scan:
  max_rule_minutes: 10        # -1 = no limit; see the precedence note below
  rules:
    "40026":
      enabled: false
      why: "server-rendered Go; no DOM sink this rule can reach"
    "90019":
      strength: low           # DEFAULT | LOW | MEDIUM | HIGH | INSANE
      threshold: high         # DEFAULT | OFF | LOW | MEDIUM | HIGH
      why: "no template engine takes user input on this target"
```

**What ZAP offers per rule, and what it does not.** Verified against the 2.17.0
daemon: `strength` (how many payloads a rule sends — the request-based limit) and
`threshold` (how much evidence it needs before raising) are settable per plugin
id, and rules can be disabled. There is **no per-rule time limit** in ZAP's API —
`MaxRuleDurationInMins` is one global number — so `max_rule_minutes` moves the
ceiling for *every* rule and no per-rule `max_minutes` is offered.

**Why this exists.** In a representative Gitea scan, 30 of 52 enabled rules ran
inside the 45-minute cap and produced **7 alerts**, two rules produced all of
them, and roughly 1,700 s went to rules that raised nothing (`DomXssScanRule`
302 s, `CommandInjectionScanRule` 284 s, `SstiScanRule` 205 s) — so bounding and
disabling per rule is what keeps a scan inside its budget.

**`why` is required for any rule that changes a default, and it must be about the
application.** Disabling a rule because it raised nothing last run is fitting the
scanner to the answer key — the same mistake as tuning against a stored corpus,
and it makes every detection rate computed over it meaningless. A defensible
exclusion is grounded in what the target *is*: Gitea is Go with no exposed
template engine, so template-injection rules cannot fire; a PostgreSQL-backed app
has no Oracle or MsSQL timing surface.

The loader **warns** about a changed rule with no reason and runs anyway, rather
than failing a scan over a missing sentence.

**Precedence for `max_rule_minutes`**, most specific first:
`--max-rule-minutes` → `SCAN_ZAP_MAX_RULE_MINUTES` → `zap_scan.max_rule_minutes` →
built-in default. The target is **not** the most specific: a harness sheet sets
the env var to hold the number fixed across every row, and a target that
outranked it could quietly make two rows of one experiment incomparable. A sheet
keeps control by setting it and hands control to the targets by omitting it.

### `env/reset.sh` — the clean-state reset (`--reset-target`)

Every target ships an **`env/reset.sh`**. By default a target is **persistent**:
it models a permanent CI/CD staging environment, and the state prior
authenticated scans accumulate in it (content, settings, the scanner's own
footprint) is itself a finding — so a scan does *not* reset it. `--reset-target`
(env `SCAN_RESET_TARGET`) opts in: before the scan, the orchestrator runs that
target's `env/reset.sh`, which restores the target to its clean, freshly-seeded
state so the band a repeat measures is the **scanner's** own nondeterminism, not
accumulation. It is a **structural parameter** — a reset run carries its own
configuration digest and does not group with persistent runs of the same target.

The script is the same contract for every target (snapshot/restore of the
target's bind-mounted `env/data`, stopping every service that writes under it
first, so a live database is never copied mid-write):

```bash
./Targets/<name>/env/reset.sh --snapshot   # ONCE, from a freshly-seeded target:
                                            # captures env/data-snapshot.tar
./Targets/<name>/env/reset.sh              # restore it (what --reset-target runs)
```

The one-time `--snapshot` capture is a prerequisite: with no snapshot the reset
fails fast rather than scan a target whose clean state was never recorded. The
orchestrator raises the same way if a target has no `env/reset.sh` at all, so the
flag is general — a unit test asserts every target ships an executable one.

### `recovery` — self-healing a target that wedges mid-run (optional)

Only a target that deadlocks under sustained scanning needs this, so it is
**opt-in**: a target without a `recovery:` block scans exactly once and is never
auto-restarted. Cacti is the one target that declares it — its CVE-2022-46169 RCE
spawns resident processes that each hold a MariaDB connection and never exit, so
repeated scanning saturates `max_connections`; and its 342-endpoint seed storms
`/JSON/core/action` and drops the connection ~1 in 3, crashing the scan
pre-triage.

```yaml
recovery:
  containers: [target-cacti, target-cacti-db]   # docker restart, in order
```

When a scan of such a target drops the connection (an `httpx` transport error, or
ZAP cannot reach it), the scan stage `docker restart`s these containers, waits for
the target's login page to serve its form again (status 200 carrying the auth
profile's password field — login-readiness, not mere liveness: a wedged DB still
500s the page), and runs the whole scan again under a fresh run id. It is the
inline twin of `config/harness/rerun-cacti-ceiling-driver.sh`, which does the same
restart-and-wait before each ceiling run. **Failure-path only** — it changes
nothing a healthy scan does — so it is **not** in the configuration digest, and
readiness is derived from `auth` (no separate probe field).

## Analysis inputs

### `code_context` — the scoped code extractor

```yaml
code_context:
  scope: [routers/web]        # where this target's handlers live
  languages: [Go]
  kinds: { Go: f }            # ctags kinds to index
```

Unset means the LLM stages get **no handler source** for this target — a stated
limitation, not a silent one. `scope` is what bounds the extractor's expansion:
measured, same-package callees saturate at one hop (39 → 320 → 358 lines)
*because* the calls that would go further leave the indexed tree. Widening it to
the whole repository would trade that bound for a hop limit picked by feel.

### `source_analysis` — the independent SAST/SCA baselines

```yaml
source_analysis:
  semgrep_rulesets: [go, javascript]    # directories of the pinned checkout
```

Read by `dast static-analysis`, which is **not** part of the DAST chain: no
triage, no verification, no model. OSV-Scanner needs no configuration — it finds
the dependency manifests itself.

---

## Adding a target: the checklist

1. `Targets/<name>/target.yml`, plus `env/compose.yml` and its seed scripts.
2. One `include:` line in `Targets/persistent.yml` — `include:` rather than
   several `-f` files, because each target's relative paths then resolve against
   **its own** directory (`./data` means `Targets/<name>/env/data`).
3. **An `env/reset.sh`** (snapshot/restore of the target's `env/data`, stopping
   every service that writes under it first). `--reset-target` runs it, and a
   unit test globs every target and fails if one is missing or not executable —
   add it, never relax the test. Capture its one-time snapshot from a
   freshly-seeded target before the first reset scan (see the `env/reset.sh`
   section above).
4. `cve-markers.yml` — **OPTIONAL.** Ground truth is an add-on evaluation layer,
   not a prerequisite: a target with no markers is fully scannable (scan → triage
   → verify → report), it simply has no detection numbers and `dast cve` no-ops on
   it, the report omitting the ground-truth section. Map markers when a target is
   to be *measured*; each marker holds facts only plus `auth` (the session the CVE
   requires) — detectability is measured per run, not stored
   (see [`DETECTABILITY.md`](DETECTABILITY.md)).
5. `oracle.md` **at the same time**, if the target has markers. Neither is
   generated from the other, and a target with markers but no oracle cannot run
   under `--oracle`.
6. **A `rescan_table` row for every ZAP rule the markers name.** A marker rule the
   table declines makes `dast cve` report that marker undetected at the
   deterministic layer, *silently*. The rescan-table tests glob every target's
   `cve-markers.yml` and fail if one is missing — add the row, never relax the
   test. (A markerless target names no rules, so this is vacuous for it.)
7. Ask whether it needs `structural_parameters`. The answer belongs in
   `target.yml` either way.
8. For any marker whose sink no crawler discovers, give it a `seed:` in
   `cve-markers.yml` (validated to land at that marker's sink). It is seeded
   only under `dast scan --oracle`, so a blind run stays honest.

Only two things ever need Python: a login mechanism new in kind, and the seeding
script (each app creates users its own way). Everything else — the join, triage,
verification, SARIF — is target-agnostic.
