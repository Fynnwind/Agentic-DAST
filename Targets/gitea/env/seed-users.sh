#!/usr/bin/env bash
# Seed the deterministic mock users authenticated DAST needs, idempotently.
#
# Runs the Gitea admin CLI *inside* the running target-gitea container — the
# reproducible path (no HTTP, no CSRF, scriptable), unlike registering through
# the web form. Safe to re-run: an existing user is left as-is.
#
# These are TEST-ONLY credentials for a deliberately-vulnerable local target
# that is bound to loopback (see the compose port bindings). They are meant to
# be fixed and public in the repo so every run authenticates identically — do
# not reuse them anywhere real.
#
# Usage:  stacks/persistent.yml up -d   # target must be running
#         ./targets/seed-users.sh
set -euo pipefail

CONTAINER="${GITEA_CONTAINER:-target-gitea}"

# username : password : admin?  — the fixed test roster.
#   dastuser  — regular account, for the authenticated-but-unprivileged surface
#   dastadmin — admin account, for access-control / admin-only routes
USERS=(
  "dastuser:DastUserPass123!:false"
  "dastadmin:DastAdminPass123!:true"
)

exists() {
  docker exec -u git "$CONTAINER" gitea admin user list 2>/dev/null \
    | awk '{print $2}' | grep -qx "$1"
}

for entry in "${USERS[@]}"; do
  IFS=":" read -r name pass is_admin <<<"$entry"
  if exists "$name"; then
    echo "user '$name' already exists — leaving as-is"
    continue
  fi
  admin_flag=""
  [ "$is_admin" = "true" ] && admin_flag="--admin"
  docker exec -u git "$CONTAINER" gitea admin user create \
    --username "$name" --password "$pass" --email "${name}@example.com" \
    --must-change-password=false $admin_flag
done

echo "---"
docker exec -u git "$CONTAINER" gitea admin user list
