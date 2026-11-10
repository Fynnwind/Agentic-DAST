#!/usr/bin/env bash
# Reset the persistent Cacti target to its clean, freshly-seeded state — what
# `dast scan cacti --reset-target` runs before a scan so the spider sees what
# discovery finds, not what prior (authenticated) scans accumulated (devices,
# graphs, poller output). Snapshot/restore of the target's bind-mounted state
# dir (env/data: the MariaDB datadir under db/, plus Cacti's rra/ and log/).
#
#   ./Targets/cacti/env/reset.sh --snapshot   # once, from a freshly-seeded target
#   ./Targets/cacti/env/reset.sh              # restore it (what the scan calls)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."      # repo root

TARGET=cacti
DATA_DIR="Targets/${TARGET}/env/data"
SNAPSHOT="Targets/${TARGET}/env/data-snapshot.tar"
STACK="Targets/persistent.yml"
SERVICES=(cacti cacti-db)   # every service that writes under DATA_DIR
READY_URL="http://127.0.0.1:8003/index.php"   # poll until the web answers post-restore

down() { docker compose -f "$STACK" stop "${SERVICES[@]}" >/dev/null; }
up()   { docker compose -f "$STACK" start "${SERVICES[@]}" >/dev/null; }

if [[ "${1:-}" == "--snapshot" ]]; then
  # Take this with the fixture already seeded (seed.sh): the snapshot IS the
  # clean state every reset returns to. Stopped first — a MariaDB datadir copied
  # while being written is not a database.
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

# A verification tool whose `docker run` client was killed at its timeout leaves
# its container running under dockerd (fixed at the source in mcp/_dispatch_common
# run_container, which now names and force-removes it; swept here too). A straggler
# still fuzzing cacti would re-wedge the target the moment it is restored —
# exhausting its apache workers and the mariadb connection pool, which is what
# timed out the ceiling re-runs' login. Clear any before restoring; belt-and-braces.
strays="$(docker ps -q --filter "name=dast-verify-" 2>/dev/null || true)"
if [[ -n "$strays" ]]; then
  echo "==> sweeping $(echo "$strays" | wc -l | tr -d ' ') stray verify container(s) before restore"
  docker rm -f $strays >/dev/null 2>&1 || true
fi

echo "==> --reset-target ${TARGET}: restoring the clean seeded snapshot"
down
rm -rf "${DATA_DIR:?}"
tar -xf "$SNAPSHOT" -C "$(dirname "$DATA_DIR")"
# The snapshot carries a 363 MB cacti.log from before its capture. Signed in, the log
# viewer (clog.php) renders it for ~2 min holding the session lock, so a spider wave
# sent alongside times out in ZAP; every scan starts from an empty log instead.
: > "${DATA_DIR}/log/cacti.log"
up
# Wait for the web to answer before returning — the scan's auth otherwise races
# a target still coming back up after the restore. (The between-run auth timeouts
# that stalled the block-8 ceiling re-runs were not slow warmup but a straggler
# fuzzer re-saturating cacti's apache workers + mariadb connections — swept above;
# this gate just ensures the restored web answers before the next scan starts.)
curl -fsS -o /dev/null --retry 90 --retry-delay 2 --retry-all-errors --max-time 240 "$READY_URL" \
  && echo "==> ${TARGET} web is responding" \
  || { echo "ERROR: ${TARGET} did not become ready at ${READY_URL} after restore" >&2; exit 4; }
# index.php answers a few seconds before the heavier pages and the just-restored
# MariaDB are fully warm; the scan's first concurrent seed burst otherwise races a
# cold app and times out (the 2026-10-27 ceiling re-run died this way at ~50/343
# seeds). Measured warmup past the gate is ~2-3s (one ~2.5s cold page), so settle a
# short margin — generous against ZAP's concurrent burst — before returning.
sleep 10
echo "==> ${TARGET} restored to clean seeded state"
