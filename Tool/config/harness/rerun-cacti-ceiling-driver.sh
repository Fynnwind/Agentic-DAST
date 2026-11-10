#!/usr/bin/env bash
# One-per-invocation driver for the Cacti --oracle ceiling (rescan freeze rerun-2026-11-03f).
#
#   ./config/harness/rerun-cacti-ceiling-driver.sh [N] [SHEET]   # N runs of SHEET
#     N      number of one-per-invocation ceiling runs   (default 3, the repeats band;
#            G2's admin ceiling, the same sheet, is the band's 4th)
#     SHEET  the ceiling sheet to drive                   (default the admin ceiling)
#   G2's cross-level ceiling drives the none / user / admin sheets, N=1 each.
#   ./config/harness/rerun-cacti-ceiling-driver.sh --restart-only   # recover Cacti only
#
# WHY. The Cacti ceiling verify's nuclei CVE-2022-46169 OOB template genuinely
# RCEs the target: the injected command spawns resident `script_server.php
# realtime` processes that each hold a MariaDB connection and never exit, so the
# fuzzing saturates max_connections and Cacti deadlocks AFTER the scan. A run
# survives its OWN verify, but the next run's reset races a still-wedged target
# and its login times out. So each ceiling run is its own invocation, preceded by
# a full container restart + a login-readiness probe that recovers Cacti to a
# loginable state before the scan's own --reset-target runs. The leak is
# mitigated here, not fixed (NEXT_SESSION §6 / §10).
#
# Prerequisites: run from the Tool/ dir; the persistent targets, the ephemeral
# ZAP job and the OOB stack (docker/oob.yml) are up; config/scanner/secrets.env
# holds the key; the nuclei template volume and zap-plugins-frozen are populated.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."     # Tool/

N="${1:-3}"
SHEET="${2:-config/harness/rerun-cacti-ceiling.yml}"
READY_URL="http://127.0.0.1:8003/index.php"   # Cacti login page (host-published)

restart_and_wait() {
  echo "==> restarting Cacti to clear the RCE connection leak"
  docker restart target-cacti target-cacti-db >/dev/null
  # Login-readiness, not mere liveness: a wedged DB makes index.php 500, so poll
  # until it returns 200 AND carries the login form (`login_password`), which
  # only a healthy, DB-connected Cacti serves.
  local i body
  for i in $(seq 1 90); do
    body="$(curl -fsS --max-time 10 "$READY_URL" 2>/dev/null || true)"
    if printf '%s' "$body" | grep -q 'login_password'; then
      echo "==> Cacti login page is serving (attempt $i)"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: Cacti did not reach a loginable state at $READY_URL" >&2
  return 1
}

# `--restart-only`: recover Cacti and run nothing, so the next sheet's Cacti scan
# does not meet a target the last ceiling run left wedged (scripts/rerun-chain.py).
if [[ "${1:-}" == "--restart-only" ]]; then
  restart_and_wait
  exit
fi

for run in $(seq 1 "$N"); do
  echo "=================== Cacti ceiling run ${run} / ${N} ==================="
  restart_and_wait
  uv run dast harness "$SHEET"
done

echo "==> ${N} Cacti ceiling runs complete; run \`dast cve\` on each new run."
