#!/usr/bin/env bash
# Cacti container entrypoint. Two jobs, then hand off to Apache:
#
#   1. Render include/config.php from the DB_* environment, so no database
#      credential is baked into the image (the same reason config lives in env
#      for every other target). Done every start, idempotently, by copying the
#      shipped config.php.dist and rewriting only the connection + url_path
#      lines — the rest of the dist file (session name, SSL defaults, …) is
#      left as upstream ships it.
#   2. Wait for the database to accept connections, so a fresh `compose up`
#      does not race Apache ahead of MariaDB.
#
# The actual Cacti install (schema load, admin account, the device+graph that
# makes the CVE reachable) is NOT done here — it is the target's seed.sh, run
# once from the host, matching how every other target seeds its scan surface.
set -euo pipefail

CONFIG=/var/www/html/include/config.php
DIST=/var/www/html/include/config.php.dist

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-cacti}"
DB_USER="${DB_USER:-cacti}"
DB_PASS="${DB_PASS:-cacti}"
# Served at the Apache document root, so Cacti's own base path is '/'.
URL_PATH="${URL_PATH:-/}"

render_config() {
  cp "$DIST" "$CONFIG"
  sed -i \
    -e "s#^\$database_default\s*=.*#\$database_default  = '${DB_NAME}';#" \
    -e "s#^\$database_hostname\s*=.*#\$database_hostname = '${DB_HOST}';#" \
    -e "s#^\$database_username\s*=.*#\$database_username = '${DB_USER}';#" \
    -e "s#^\$database_password\s*=.*#\$database_password = '${DB_PASS}';#" \
    -e "s#^\$database_port\s*=.*#\$database_port     = '${DB_PORT}';#" \
    -e "s#^\$url_path\s*=.*#\$url_path = '${URL_PATH}';#" \
    "$CONFIG"
  chown www-data:www-data "$CONFIG"
}

wait_for_db() {
  echo "cacti-entrypoint: waiting for ${DB_HOST}:${DB_PORT} ..."
  for _ in $(seq 1 60); do
    if mysqladmin ping --host="$DB_HOST" --port="$DB_PORT" \
        --user="$DB_USER" --password="$DB_PASS" --silent 2>/dev/null; then
      echo "cacti-entrypoint: database is up."
      return 0
    fi
    sleep 3
  done
  echo "cacti-entrypoint: database did not come up in time; starting anyway." >&2
}

fix_writable_mounts() {
  # `log/` and `rra/` are bind-mounted from the host, so their ownership is the
  # host's (root on a fresh `compose up`), not the image's build-time www-data —
  # and Cacti runs as www-data. Without this the web UI shows "System log file is
  # not available for writing" and the poller cannot write its RRDs. The
  # entrypoint runs as root (Apache drops to www-data itself), so fix it here,
  # every start, after the mount is in place.
  chown -R www-data:www-data /var/www/html/log /var/www/html/rra 2>/dev/null || true
  chmod -R u+rwX /var/www/html/log /var/www/html/rra 2>/dev/null || true
}

render_config
fix_writable_mounts
wait_for_db

exec "$@"
