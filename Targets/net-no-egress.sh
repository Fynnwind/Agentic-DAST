#!/usr/bin/env bash
# Cut dast-net off from the internet. The targets are deliberately vulnerable, and a
# logged-in scan can make them call out: on 2026-11-04 Gitea's scan-made webhooks sent
# 40,446 POSTs to third-party hosts. Inserts one rule at the top of the Docker VM's
# DOCKER-USER chain that rejects NEW connections entering from dast-net's bridge and
# leaving by any other interface. Traffic between containers and the published
# 127.0.0.1 ports is untouched. The rule lives in Docker Desktop's VM, so a Docker
# restart drops it: run this before every sheet. Idempotent; exits 1 unless a
# connection from dast-net to the outside is refused and a target still answers inside.
#
#   ./Targets/net-no-egress.sh
set -euo pipefail

NET=dast-net
PROBE_OUT="http://1.1.1.1/"                     # any public address; must be refused
PROBE_IN="http://target-gitea:3000/user/login"  # any target on the network; must answer

id="$(docker network inspect "$NET" --format '{{.Id}}')"
br="$(docker network inspect "$NET" --format '{{index .Options "com.docker.network.bridge.name"}}')"
[[ -n "$br" ]] || br="br-${id:0:12}"
rule="-i $br ! -o $br -m conntrack --ctstate NEW -m comment --comment ${NET}-no-egress -j REJECT --reject-with icmp-port-unreachable"

# The VM's own iptables, reached through PID 1's namespaces.
docker run --rm --privileged --pid=host alpine:3.20 nsenter -t 1 -m -u -n -i sh -c \
  "iptables -C DOCKER-USER $rule 2>/dev/null && echo '==> $NET egress block already in place ($br)' \
   || { iptables -I DOCKER-USER 1 $rule && echo '==> $NET egress block inserted ($br)'; }"

probe() {
  docker run --rm --network "$NET" curlimages/curl:8.10.1 -s -o /dev/null -m 8 \
    -w '%{http_code}' "$1" 2>/dev/null || true
}
out="$(probe "$PROBE_OUT")"
in="$(probe "$PROBE_IN")"
echo "==> from $NET: outside ${PROBE_OUT} -> ${out:-000}, inside ${PROBE_IN} -> ${in:-000}"
[[ "${out:-000}" == "000" ]] || { echo "ERROR: $NET still reaches the internet" >&2; exit 1; }
[[ "${in:-000}" != "000" ]] || { echo "ERROR: the target inside $NET did not answer" >&2; exit 1; }
