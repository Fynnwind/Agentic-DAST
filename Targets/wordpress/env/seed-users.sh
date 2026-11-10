#!/usr/bin/env bash
# Seed the deterministic mock users authenticated DAST needs, idempotently.
#
# The same fixed roster as the Gitea target, on purpose: the auth-mode
# comparison is a per-target measurement, and it is easier to read across
# targets when `--auth user` means the same kind of account everywhere.
#   dastadmin — administrator; created by `wp core install` in seed-site.sh,
#               so this script only asserts it exists.
#   dastuser  — an unprivileged account. `subscriber` is WordPress's floor and
#               is what the authenticated-but-unprivileged surface should be:
#               anything higher (author, editor) hands the scanner post-editing
#               screens and turns "authenticated user" into "content author",
#               which is a different question from the one this mode asks.
#
# TEST-ONLY credentials for a deliberately-vulnerable, loopback-bound target,
# fixed and public in the repo so every run authenticates identically — do not
# reuse them anywhere real.
#
# Usage:  ./targets/wordpress/env/seed-site.sh   # must have run first
#         ./targets/wordpress/env/seed-users.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_wp.sh"

require_target_running
if ! wp_installed; then
  echo "WordPress is not installed yet — run seed-site.sh first" >&2
  exit 1
fi

# username : password : role  — the fixed test roster.
USERS=(
  "dastuser:DastUserPass123!:subscriber"
  "dastadmin:DastAdminPass123!:administrator"
)

for entry in "${USERS[@]}"; do
  IFS=":" read -r name pass role <<<"$entry"
  if wp user get "$name" --field=ID >/dev/null 2>&1; then
    echo "user '$name' already exists — leaving as-is"
    continue
  fi
  wp user create "$name" "${name}@example.com" \
    --role="$role" --user_pass="$pass" --display_name="$name"
done

echo "---"
wp user list --fields=ID,user_login,roles
