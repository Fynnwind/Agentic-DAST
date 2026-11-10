#!/usr/bin/env bash
# Seed Grafana with the content a scan needs in order to have a surface at all.
# Idempotent. The Grafana analogue of the Gitea target's seed-repo.sh and the
# WordPress target's seed-content.sh.
#
# Grafana differs from the other two in who creates the admin: the running
# container mints it from GF_SECURITY_ADMIN_USER / GF_SECURITY_ADMIN_PASSWORD in
# env/compose.yml, so there is NO user-creation step here — the credentials the
# pipeline logs in with exist the moment the container is healthy. What this
# script adds is the authenticated *content* an authenticated scan crawls, none
# of which Grafana creates for you on a fresh install:
#
#   * a folder and a dashboard, so /api/search and the /d/<uid>/ dashboard routes
#     return something rather than an empty list;
#   * a datasource, so the /api/datasources and proxy route families exist (the
#     surface CVE-2022-21702's datasource-proxy XSS sits on — not reachable on a
#     default install, but the route should still exist for the scan to see);
#   * a team, so the /api/teams family (CVE-2022-21713's IDOR surface) is not
#     empty.
#
# NOTE none of this makes a marker *detectable* that was not already: the one
# DAST-reachable marker (the plugin-asset traversal, CVE-2021-43798) is
# unauthenticated and needs no fixture — it is listed in cve-markers.yml with
# `dast_reachable: yes` and fires on the anonymous asset route regardless of any
# content seeded here. This script only ensures the authenticated surface the
# other markers live on is non-empty, so a run does not look clean for the wrong
# reason.
#
# Reaches the target the way the pipeline does: a one-shot curl container on
# dast-net, by container name. Usage:  ./targets/grafana/env/seed.sh
set -euo pipefail

GRAFANA_CONTAINER="${GRAFANA_CONTAINER:-target-grafana}"
DAST_NET="${DAST_NET:-dast-net}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
BASE="${GRAFANA_BASE:-http://target-grafana:3000}"
# TEST-ONLY, and the same fixed values compose.yml sets and target.yml logs in
# with. This is a loopback-bound, deliberately-vulnerable local target.
ADMIN_USER="${GRAFANA_ADMIN_USER:-admin}"
ADMIN_PASS="${GRAFANA_ADMIN_PASS:-DastAdminPass123!}"

# One-shot curl on dast-net, basic-auth as admin, JSON in. Prints body; callers
# inspect it. The admin basic-auth path is used for seeding only — the scan's
# own login is the JSON session flow in auth.py.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -u "${ADMIN_USER}:${ADMIN_PASS}" -X "$method"
              -H "Content-Type: application/json")
  [ -n "$body" ] && args+=(--data "$body")
  docker run --rm --network "$DAST_NET" "$CURL_IMAGE" "${args[@]}" "${BASE}${path}"
}

# GET returning the HTTP status only, for existence checks.
status() {
  docker run --rm --network "$DAST_NET" "$CURL_IMAGE" \
    -s -o /dev/null -w '%{http_code}' -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE}$1"
}

require_target_running() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$GRAFANA_CONTAINER"; then
    echo "Grafana container '$GRAFANA_CONTAINER' is not running — bring the " \
         "persistent stack up first (docker compose -f stacks/persistent.yml up -d grafana)" >&2
    exit 1
  fi
  # Wait for the HTTP API to answer (the DB migration on first boot takes a moment).
  for _ in $(seq 1 30); do
    code="$(status /api/health || true)"
    [ "$code" = "200" ] && return 0
    sleep 2
  done
  echo "Grafana did not become healthy in time" >&2
  exit 1
}

require_target_running

# -- datasources -----------------------------------------------------------
# Existence check by name: the create API mints a random uid, so re-running
# without this would pile up duplicates.
#
# THREE datasources, and two of them are load-bearing for the CVE cluster —
# without them the vulnerable code paths are dormant and their markers report
# undetected for a reason that is a fixture omission, not a property of Grafana:
#
#   * dast-prometheus — a plain datasource so /api/datasources and the proxy
#     route family exist and the UI has something to render.
#   * dast-testdata (type `testdata`) — ACTIVATES CVE-2021-43815: the TestData
#     datasource's csv_file scenario reads a caller-supplied path, and at 8.3.0
#     loadCsvFile's filename regex is UNANCHORED (`([\w_]+)\.csv` matched
#     anywhere), so `../../…/x.csv` escapes the testdata dir (fixed 8.3.2). The
#     path is only reachable if this datasource is configured — hence seeded.
#
# dast-prometheus is also a server-access HTTP datasource, so it ALSO activates
# the proxy route family (/api/datasources/proxy/:id/) CVE-2022-21702 sits on —
# no separate datasource is needed for that. NB the proxy XSS itself needs the
# UPSTREAM to serve attacker HTML; a benign upstream makes the route reachable
# but not exploitable, which the marker states honestly.
add_datasource() {  # name, json
  if [ "$(status /api/datasources/name/$1)" = "200" ]; then
    echo "datasource $1 already present"
  else
    api POST /api/datasources "$2" >/dev/null && echo "created datasource $1"
  fi
}
add_datasource dast-prometheus \
  '{"name":"dast-prometheus","type":"prometheus","url":"http://localhost:9090","access":"proxy"}'
add_datasource dast-testdata \
  '{"name":"dast-testdata","type":"testdata","access":"proxy"}'

# -- team ------------------------------------------------------------------
if api GET '/api/teams/search?name=dast-team' | grep -q '"totalCount":0'; then
  api POST /api/teams '{"name":"dast-team"}' >/dev/null
  echo "created team dast-team"
else
  echo "team dast-team already present"
fi

# -- folder + dashboard ----------------------------------------------------
# The dashboard write is overwrite:true, so it is idempotent on its own; the
# folder create is guarded because a second create of the same uid is a 409.
if [ "$(status /api/folders/dastfolder)" = "200" ]; then
  echo "folder dastfolder already present"
else
  api POST /api/folders '{"uid":"dastfolder","title":"DAST Folder"}' >/dev/null
  echo "created folder dastfolder"
fi
api POST /api/dashboards/db \
  '{"dashboard":{"uid":"dastdash","title":"DAST Dashboard","panels":[],"schemaVersion":30},"folderUid":"dastfolder","overwrite":true}' \
  >/dev/null
echo "ensured dashboard dastdash"

# -- a non-admin user (campaign: --auth user) ------------------------------
# The campaign scans every target at none/user/admin (RUN-PLAN decision 3).
# Grafana ships only the admin (minted from GF_SECURITY_ADMIN_*), so seed a
# Viewer the `user` session logs in as. Sign-up is disabled, so a scan cannot
# mint its own — it has to exist here. POST /api/admin/users creates a main-org
# user at the default Viewer role; it authenticates through the same JSON /login
# flow auth.py uses and crawls the authenticated surface at least privilege.
# Idempotent by login (the create 409s/412s on a second run otherwise).
USER_LOGIN="${GRAFANA_USER_LOGIN:-dastviewer}"
USER_PASS="${GRAFANA_USER_PASS:-DastUserPass123!}"
if [ "$(status "/api/users/lookup?loginOrEmail=${USER_LOGIN}")" = "200" ]; then
  echo "user ${USER_LOGIN} already present"
else
  api POST /api/admin/users \
    "{\"name\":\"DAST User\",\"login\":\"${USER_LOGIN}\",\"password\":\"${USER_PASS}\"}" \
    >/dev/null && echo "created user ${USER_LOGIN} (Viewer)"
fi

echo "grafana seed complete"
