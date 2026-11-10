# Targets — the systems under test, as data

Each target is a self-hosted, deliberately outdated open-source application,
pinned to a version with a documented CVE so detection can be measured against
ground truth. A target is **data**, not code: one directory here plus one
`include:` line in [`persistent.yml`](persistent.yml). The pipeline is
target-agnostic — only a login mechanism new in kind and the seeding script ever
need code.

| target | pinned version | headline CVE for detection |
|---|---|---|
| [`gitea/`](gitea/) | 1.16.0 | the HTTP-reachable 1.16.x cluster (open redirect, path traversal, XSS, CSRF, access-control) |
| [`wordpress/`](wordpress/) | 5.8.0 + WP Download Manager 3.2.33 | the WPDM cluster — reflected XSS and an unauth SQLi |
| [`grafana/`](grafana/) | 8.3.0 | CVE-2021-43798 — unauth plugin-asset path traversal |
| [`cacti/`](cacti/) | 1.2.22 | CVE-2022-46169 — unauth blind RCE, confirmed out of band |

## What a target directory holds

```
<name>/
  target.yml         # the definition (base_url, auth, reachability, scan settings…)
  cve-markers.yml    # ground truth: the documented vulnerabilities of the pinned version
  oracle.md          # the same weaknesses in prose, read only under --oracle
  src/               # its source clone (gitignored) — Noir and the SAST pass read it
  env/               # its compose service, seed scripts and bind mount
```

The full field-by-field reference — every `target.yml` field and what it changes —
is in **[`../Tool/docs/TARGETS.md`](../Tool/docs/TARGETS.md)**.

## Running the targets

```bash
docker compose -f persistent.yml up -d      # bring up all targets as containers
<name>/env/seed*.sh                         # seed each target's accounts and CVE fixtures (idempotent)
```

The `src/` trees and each target's seeded data are gitignored (see
[`.gitignore`](.gitignore)); clone or seed them as each target's `env/` scripts
describe. The tool reaches this directory through `SHARED_TARGETS_DIR` (default
`../Targets` from `Tool/`).
