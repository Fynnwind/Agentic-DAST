#!/usr/bin/env bash
# Populate the Gitea target with the CONTENT its documented CVEs need, idempotently.
#
# Why this exists
# ---------------
# A DAST scanner can only attack what it can reach, and an empty application is
# unreachable in the ways that matter: `/{user}/{repo}/issues/{index}` 404s when
# no issue exists, so the endpoint is seeded into the site tree but offers the
# active scanner nothing to inject into. Two markers of the Gitea 1.16.0 CVE
# cluster are unreachable by construction without content:
#
#   * missing permission / access-control checks on issues (1.16.6, 1.16.9)
#     — needs issues, and a second account that must NOT see the private ones;
#   * path cleaning in Storage / path traversal (1.16.5)
#     — needs release attachments, i.e. stored files addressed by name.
#
# So the fixture is part of the experiment, not incidental setup: it is scripted,
# versioned and idempotent, it is identical across every configuration compared,
# and it is defined here — in advance, from the CVE list — rather than shaped
# around whatever a scanner happened to find. Running it changes the target's
# state, so scans taken before and after it are NOT comparable; that delta is
# itself worth measuring (site-tree URLs, alerts, distinct rules).
#
# Driven through the Gitea REST API from the pinned curl image on dast-net, the
# same way the orchestrator reaches the target — no host dependencies, and the
# API is the reproducible path (no CSRF, no form scraping).
#
# Usage:  docker compose -f stacks/persistent.yml up -d
#         ./targets/gitea/env/seed-users.sh      # accounts first
#         ./targets/gitea/env/seed-repo.sh       # then content
set -euo pipefail

CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
NETWORK="${DAST_NET:-dast-net}"
BASE="${GITEA_URL:-http://target-gitea:3000}/api/v1"

# TEST-ONLY, fixed and public on purpose (see seed-users.sh): the target is a
# deliberately vulnerable instance bound to loopback.
ADMIN_USER="${GITEA_ADMIN_USER:-dastadmin}"
ADMIN_PASS="${GITEA_ADMIN_PASS:-DastAdminPass123!}"
USER_USER="${GITEA_USER_USER:-dastuser}"

PUBLIC_REPO="dast-public"
PRIVATE_REPO="dast-private"

# One curl call returns body and status together: a fixture that hides the
# server's error message is a fixture you debug by guessing.
call() {
  # call <METHOD> <PATH> [JSON body] -> "<body>\n<status>"
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -w '\n%{http_code}' -X "$method"
              -u "${ADMIN_USER}:${ADMIN_PASS}" -H 'Content-Type: application/json')
  [ -n "$body" ] && args+=(-d "$body")
  docker run --rm --network "$NETWORK" "$CURL_IMAGE" "${args[@]}" "${BASE}${path}" 2>/dev/null
}

status_of() { printf '%s' "$1" | tail -n1; }
body_of()   { printf '%s' "$1" | sed '$d'; }

# Top-level field of a JSON response. Parsed, not pattern-matched: a release
# response carries a nested author.id, and a regex for "id" happily returns that
# one — which is how an upload ended up addressing release 3 instead of 1.
field_of() {
  printf '%s' "$1" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(data, list):
    data = data[0] if data else {}
print(data.get(sys.argv[1], ''))
" "$2" 2>/dev/null
}

# Every step reports created / already-there rather than failing on re-run: the
# fixture has to be reproducible, which means running it twice must be safe.
# Reports created / already-there rather than failing on re-run: the fixture has
# to be reproducible, which means running it twice must be safe. Anything else
# prints the server's own message, so a broken fixture says why.
step() {
  local label="$1" response="$2"
  local code message
  code="$(status_of "$response")"
  message="$(body_of "$response" | head -c 200)"
  case "$code" in
    2*)  echo "  created   $label" ;;
    409) echo "  exists    $label" ;;
    # 422 is Gitea's catch-all: a duplicate *and* a rejected field both land
    # here, so the body decides. Reporting a validation error as "exists" is how
    # a fixture silently stops seeding what the experiment depends on.
    422) case "$message" in
           *already*|*exist*) echo "  exists    $label" ;;
           *) echo "  FAILED    $label (HTTP 422): $message" ;;
         esac ;;
    *)   echo "  FAILED    $label (HTTP $code): $message" ;;
  esac
}

post() { step "$1" "$(call POST "$2" "${3:-}")"; }

# Create only if a probe says it is not already there. Gitea happily accepts a
# second issue with the same title, so a plain POST makes this script *additive*:
# every run would enlarge the fixture, and two scans of "the same" target would
# face different applications. Idempotence is what makes the fixture a constant.
post_once() {
  # post_once <label> <path> <payload> <probe-path> <needle>
  local label="$1" path="$2" payload="$3" probe="$4" needle="$5"
  if body_of "$(call GET "$probe")" | grep -qF "$needle"; then
    echo "  exists    $label"
    return
  fi
  step "$label" "$(call POST "$path" "$payload")"
}

echo "Seeding Gitea content as '${ADMIN_USER}' at ${BASE}"

# -- repositories ----------------------------------------------------------
# auto_init gives a real commit, without which releases, blame and the
# commit/blob routes have nothing to address.
post "repo ${PUBLIC_REPO}" /user/repos \
  "{\"name\":\"${PUBLIC_REPO}\",\"description\":\"public fixture\",\"auto_init\":true,\"private\":false,\"readme\":\"Default\"}"
post "repo ${PRIVATE_REPO} (private)" /user/repos \
  "{\"name\":\"${PRIVATE_REPO}\",\"description\":\"private fixture\",\"auto_init\":true,\"private\":true,\"readme\":\"Default\"}"

# -- issue metadata --------------------------------------------------------
post_once "label bug" "/repos/${ADMIN_USER}/${PUBLIC_REPO}/labels" \
  '{"name":"bug","color":"ee0701","description":"fixture label"}' \
  "/repos/${ADMIN_USER}/${PUBLIC_REPO}/labels" '"name":"bug"'
post_once "milestone v1" "/repos/${ADMIN_USER}/${PUBLIC_REPO}/milestones" \
  '{"title":"v1","description":"fixture milestone"}' \
  "/repos/${ADMIN_USER}/${PUBLIC_REPO}/milestones?state=all" '"title":"v1"' 

# -- issues, in both repos -------------------------------------------------
# The private repo's issues are the access-control surface: dastuser must not be
# able to read them, and the 1.16.6/1.16.9 advisories are about exactly that.
for n in 1 2 3; do
  issue_payload="{\"title\":\"Fixture issue ${n}\",\"body\":\"Body of fixture issue ${n}, linking /${ADMIN_USER}/${PUBLIC_REPO}\"}"
  post_once "issue #${n} in ${PUBLIC_REPO}" "/repos/${ADMIN_USER}/${PUBLIC_REPO}/issues" \
    "$issue_payload" "/repos/${ADMIN_USER}/${PUBLIC_REPO}/issues?state=all" \
    "\"title\":\"Fixture issue ${n}\""
done
post_once "issue #1 in ${PRIVATE_REPO}" "/repos/${ADMIN_USER}/${PRIVATE_REPO}/issues" \
  '{"title":"Private fixture issue","body":"Only the owner should see this."}' \
  "/repos/${ADMIN_USER}/${PRIVATE_REPO}/issues?state=all" '"title":"Private fixture issue"'
post_once "comment on issue #1" "/repos/${ADMIN_USER}/${PUBLIC_REPO}/issues/1/comments" \
  '{"body":"Fixture comment, so the comment routes have a subject."}' \
  "/repos/${ADMIN_USER}/${PUBLIC_REPO}/issues/1/comments" '"body":"Fixture comment' 

# -- a release with an attachment -----------------------------------------
# The attachment is the point: stored files addressed by name are what the
# Storage path-cleaning advisory (1.16.5) concerns.
# target_commitish must be the repo's real default branch — Gitea 1.16 creates
# `master`, not `main`, and a release against a missing branch 404s.
branch="$(body_of "$(call GET "/repos/${ADMIN_USER}/${PUBLIC_REPO}")" \
  | sed -n 's/.*"default_branch":"\([^"]*\)".*/\1/p' | head -1)"
branch="${branch:-master}"
# The payload goes in a variable first. Built inline inside a nested command
# substitution, the braces end up unquoted and bash BRACE-EXPANDS the JSON into
# one argument per comma — which reached Gitea as `"tag_name":"v1.0.0"` and came
# back as an opaque 422.
release_payload="{\"tag_name\":\"v1.0.0\",\"target_commitish\":\"${branch}\",\"name\":\"v1.0.0\",\"body\":\"fixture release\"}"
release_response="$(call POST "/repos/${ADMIN_USER}/${PUBLIC_REPO}/releases" "$release_payload")"
step "release v1.0.0 (on ${branch})" "$release_response"
# Read the id back by tag whether it was just created or already there, so the
# upload cannot address a release that does not exist.
release_id="$(field_of "$(body_of "$(call GET "/repos/${ADMIN_USER}/${PUBLIC_REPO}/releases/tags/v1.0.0")")" id)"
if [ -n "$release_id" ]; then
  if body_of "$(call GET "/repos/${ADMIN_USER}/${PUBLIC_REPO}/releases/${release_id}")" \
       | grep -qF '"name":"fixture-notes.txt"'; then
    echo "  exists    release attachment (release ${release_id})"
  else
  step "release attachment (release ${release_id})" "$(docker run --rm \
    --network "$NETWORK" "$CURL_IMAGE" -s -w '\n%{http_code}' \
    -X POST -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F 'attachment=@/etc/hosts;filename=fixture-notes.txt' \
    "${BASE}/repos/${ADMIN_USER}/${PUBLIC_REPO}/releases/${release_id}/assets?name=fixture-notes.txt" \
    2>/dev/null)"
  fi
else
  echo "  FAILED    release attachment (no release id — is the release there?)"
fi

# -- an organisation and a team -------------------------------------------
post "org dast-org" /orgs '{"username":"dast-org","full_name":"DAST Org"}'
post "team readers" /orgs/dast-org/teams \
  '{"name":"readers","permission":"read","units":["repo.code","repo.issues"]}' 

# -- a display name that exercises the autolink/escaping path -------------
# CVE-2022-* (1.16.5): a display name containing an email address was rendered
# as an autolink. Deliberately planted: this target exists to be vulnerable.
fullname_payload="{\"login_name\":\"${USER_USER}\",\"source_id\":0,\"full_name\":\"Dast User <b>markup</b> dast@example.com\"}"
fullname_response="$(call PATCH "/admin/users/${USER_USER}" "$fullname_payload")"
step "full name on ${USER_USER}" "$fullname_response"

echo "---"
echo "Fixture summary:"
body_of "$(call GET "/repos/search?limit=50")" \
  | tr ',' '\n' | sed -n 's/.*"full_name":"\([^"]*\/[^"]*\)".*/  repo \1/p' | sort -u || true
echo
echo "NOTE: this changes the target's state. Scans taken before and after are"
echo "      not comparable — record which fixture a run used."
