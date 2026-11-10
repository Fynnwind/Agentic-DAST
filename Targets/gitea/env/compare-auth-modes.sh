#!/usr/bin/env bash
# Run the same pipeline against this target at each authentication mode, from an
# identical starting state, and leave three comparable runs behind.
#
#   ./targets/gitea/env/compare-auth-modes.sh --snapshot        # once, from a seeded target
#   ./targets/gitea/env/compare-auth-modes.sh --minutes 10      # the experiment
#
# WHY THIS IS A SCRIPT AND NOT A HARNESS SHEET. The harness configures runs; it
# cannot restore a container's state between them. The admin scan is the reason
# that matters: it is authenticated as an administrator and the active scanner
# *changes things* — it creates, edits and deletes through the API it is
# attacking. Whatever it leaves behind is then part of the next mode's target,
# so three modes run back to back measure the modes plus an accumulating mess.
# Each mode therefore starts from a restored snapshot of the same seeded state.
#
# WHY ZAP IS RESTARTED TOO. ZAP's site tree is cumulative within a daemon, so a
# reused daemon carries the previous mode's URLs into the next one's coverage
# numbers — and it keeps the previous run's passive-alert cap. A fresh container
# per mode is the only way the site-tree column means anything.
#
# It is a loop over `dast`, and deliberately nothing more: the pipeline itself is
# not re-implemented here, only the state handling that has to happen between
# invocations.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."   # repo root

TARGET=gitea
DATA_DIR="targets/${TARGET}/env/data"
SNAPSHOT="targets/${TARGET}/env/data-snapshot.tar"
TARGET_STACK="stacks/persistent.yml"
JOB_STACK="stacks/ephemeral.yml"
MODES=(none user admin)

MINUTES=45
MAX_PER_RULE=30
DRY_RUN=0

usage() {
  cat <<'EOF'
usage: compare-auth-modes.sh [--snapshot] [--minutes N] [--max-per-rule N] [--dry-run]

  --snapshot        capture the target's CURRENT data directory as the clean
                    state every mode starts from, then exit. Take it with the
                    fixture already seeded (seed-users.sh, seed-repo.sh) — the
                    snapshot IS the experiment's starting condition.
  --minutes N       active-scan cap per mode (default 45). Three modes cost
                    roughly 3 x (N + 3) minutes.
                    DO NOT lower this for a run whose numbers are quoted: the
                    recorded runs that finished naturally needed 33-45 min, and
                    every 10-minute run stopped at its cap with a third of the
                    active-scanner alerts. A shorter cap is for testing the
                    script, not for producing a result.
  --max-per-rule N  verification dispatch cap per ZAP rule (default 30).
  --dry-run         print what each mode would do and stop.

Runs at different caps are not comparable with each other, and none of them is
comparable with a run at a different cap recorded earlier. The cap is printed
into every run's metrics, so this is recorded rather than remembered.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot)      SNAPSHOT_ONLY=1; shift ;;
    --minutes)       MINUTES="$2"; shift 2 ;;
    --max-per-rule)  MAX_PER_RULE="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

target_down() { docker compose -f "$TARGET_STACK" stop "$TARGET" >/dev/null; }
target_up()   { docker compose -f "$TARGET_STACK" start "$TARGET" >/dev/null; }

# -- the snapshot ----------------------------------------------------------

if [[ -n "${SNAPSHOT_ONLY:-}" ]]; then
  echo "==> snapshotting ${DATA_DIR} -> ${SNAPSHOT}"
  # Stopped first: a sqlite database copied while it is being written is not a
  # database, and this one is the entire fixture.
  target_down
  tar -cf "$SNAPSHOT" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
  target_up
  echo "==> $(du -h "$SNAPSHOT" | cut -f1) snapshot written"
  echo "    Every mode will start from exactly this state."
  exit 0
fi

# Refuse rather than start a multi-hour experiment that cannot be made
# comparable: without a snapshot the second and third modes would inherit the
# first's damage, and nothing downstream would show it.
if [[ ! -f "$SNAPSHOT" ]]; then
  echo "ERROR: no snapshot at ${SNAPSHOT}." >&2
  echo "       Seed the target (env/seed-users.sh, env/seed-repo.sh), then run" >&2
  echo "       this script with --snapshot. Without one, each mode would start" >&2
  echo "       from the previous mode's leftovers and the comparison would be" >&2
  echo "       between contaminated states rather than between auth modes." >&2
  exit 2
fi

# -- the experiment --------------------------------------------------------

echo "=============================================================="
echo " auth-mode comparison — target ${TARGET}"
echo "   active-scan cap : ${MINUTES} min per mode"
echo "   verify per-rule : ${MAX_PER_RULE}"
echo "   modes           : ${MODES[*]}"
echo "=============================================================="

for mode in "${MODES[@]}"; do
  echo
  echo "### mode ${mode} — restoring the clean snapshot"
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "    (dry run) restore ${SNAPSHOT}, restart zap, then:"
    echo "    uv run dast scan correlate verify report ${TARGET} \\"
    echo "        --auth ${mode} --no-llm --max-scan-minutes ${MINUTES} \\"
    echo "        --max-per-rule ${MAX_PER_RULE}"
    continue
  fi

  target_down
  rm -rf "$DATA_DIR"
  tar -xf "$SNAPSHOT" -C "$(dirname "$DATA_DIR")"
  target_up

  # A fresh ZAP: the site tree is cumulative and the passive cap is sticky.
  echo "### mode ${mode} — restarting ZAP"
  docker compose -f "$JOB_STACK" --env-file config/scanner/.env up -d --force-recreate zap >/dev/null

  # Wait for both to answer before handing them to the pipeline, rather than
  # letting the first stage fail on a container that was still starting.
  # A connect, not an authenticated call: readiness is "the port answers", and
  # checking it with the API key would mean this script had to hold one.
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null http://127.0.0.1:8000/ && \
       curl -s -o /dev/null --max-time 2 http://127.0.0.1:8080/; then
      break
    fi
    sleep 2
  done

  echo "### mode ${mode} — running the chain"
  # --no-llm keeps this key-free and deterministic: the question here is what
  # authentication does to *detection*, and the LLM arm is a separate variable.
  uv run dast scan correlate verify report "$TARGET" \
      --auth "$mode" --no-llm \
      --max-scan-minutes "$MINUTES" \
      --max-per-rule "$MAX_PER_RULE"
done

echo
echo "=============================================================="
echo " done — three runs, one starting state, one budget"
echo " compare them with:  uv run run-index"
echo "=============================================================="
