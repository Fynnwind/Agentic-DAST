#!/usr/bin/env bash
# Reset the persistent Gitea target to its clean, freshly-seeded state — what
# `dast scan gitea --reset-target` runs before a scan so the spider sees what
# discovery finds, not the issues/PRs and repo copy prior authenticated scans
# created. Snapshot/restore of the target's bind-mounted state dir (env/data:
# Gitea's SQLite database and repositories).
#
#   ./Targets/gitea/env/reset.sh --snapshot   # once, from a freshly-seeded target
#   ./Targets/gitea/env/reset.sh              # restore it (what the scan calls)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."      # repo root

TARGET=gitea
DATA_DIR="Targets/${TARGET}/env/data"
SNAPSHOT="Targets/${TARGET}/env/data-snapshot.tar"
STACK="Targets/persistent.yml"
SERVICES=(gitea)   # every service that writes under DATA_DIR
READY_URL="http://127.0.0.1:8000/api/v1/version"   # poll until the web answers post-restore

down() { docker compose -f "$STACK" stop "${SERVICES[@]}" >/dev/null; }
up()   { docker compose -f "$STACK" start "${SERVICES[@]}" >/dev/null; }

if [[ "${1:-}" == "--snapshot" ]]; then
  # Take this with the fixture already seeded (seed-users.sh, seed-repo.sh): the
  # snapshot IS the clean state every reset returns to. Stopped first — a SQLite
  # DB copied while being written is not a database.
  echo "==> snapshotting ${DATA_DIR} -> ${SNAPSHOT}"
  down
  tar -cf "$SNAPSHOT" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
  up
  echo "==> $(du -h "$SNAPSHOT" | cut -f1) snapshot written"
  exit 0
fi

if [[ ! -f "$SNAPSHOT" ]]; then
  echo "ERROR: no clean snapshot at ${SNAPSHOT}." >&2
  echo "       Seed the target (env/seed-*.sh), then run" >&2
  echo "       '$0 --snapshot' once. --reset-target restores that snapshot." >&2
  exit 2
fi

echo "==> --reset-target ${TARGET}: restoring the clean seeded snapshot"
down
rm -rf "${DATA_DIR:?}"
tar -xf "$SNAPSHOT" -C "$(dirname "$DATA_DIR")"
up
# Wait for the web to answer before returning — the scan's auth otherwise races
# a target still warming up after the restore.
curl -fsS -o /dev/null --retry 90 --retry-delay 2 --retry-all-errors --max-time 240 "$READY_URL" \
  && echo "==> ${TARGET} web is responding" \
  || { echo "ERROR: ${TARGET} did not become ready at ${READY_URL} after restore" >&2; exit 4; }
echo "==> ${TARGET} restored to clean seeded state"
