#!/usr/bin/env bash
# Seed Cacti 1.2.22 into the state a scan needs, idempotently. The Cacti analogue
# of the Grafana target's seed.sh and the WordPress target's seed-site.sh.
#
# Cacti differs from every other target in ONE load-bearing way: its flagship
# CVE is not reachable on a bare install. CVE-2022-46169 (the unauthenticated
# command injection in remote_agent.php) only fires when the device being polled
# has a data source backed by a PHP *script server* data input — the branch in
# poll_for_data() that runs `proc_open('php … script_server.php realtime ' .
# $poller_id)` with the attacker-controlled poller_id. A fresh install's default
# device has only regular-script (popen, action=1) data sources, so the
# vulnerable branch is never entered. This is exactly why vulhub's README makes
# you click through the UI and add a "Device - Uptime" graph by hand. This script
# does that step non-interactively, so the target comes up reproducibly
# exploitable with no manual wizard.
#
# What it does, in order (each step guarded so re-running is safe):
#   1. import the base schema (cacti.sql) if the tables are absent;
#   2. load the MySQL timezone tables and grant the cacti user SELECT on
#      mysql.time_zone_name — Cacti requires both or its date handling breaks;
#   3. run the CLI installer (cli/install_cacti.php) to complete the install:
#      settings, template import, and the default "Local Linux Machine" device;
#   4. add a "Device - Uptime" graph (graph template 42) to that device and
#      rebuild the poller cache — this is what creates the action=2
#      (POLLER_ACTION_SCRIPT_PHP) poller_item at local_data_id 6 that makes
#      CVE-2022-46169 reachable (verified: the injection then fires);
#   5. set the admin password to the fixed test value and clear the
#      force-password-change flag, so an authenticated scan can log in.
#
# Runs against the containers by name via `docker exec` (the install and the CLI
# tools must run *inside* the Cacti container, unlike Grafana's HTTP-only seed).
# Usage, after `docker compose -f stacks/persistent.yml up -d`:
#   ./targets/cacti/env/seed.sh
set -euo pipefail

CACTI_CONTAINER="${CACTI_CONTAINER:-target-cacti}"
DB_CONTAINER="${CACTI_DB_CONTAINER:-target-cacti-db}"
DB_ROOT_PASS="${CACTI_DB_ROOT_PASS:-dast-root}"
DB_NAME="${CACTI_DB_NAME:-cacti}"
DB_USER="${CACTI_DB_USER:-cacti}"
DB_PASS="${CACTI_DB_PASS:-dast-cacti}"
# TEST-ONLY, fixed and public on purpose — a loopback-bound, deliberately
# vulnerable local target. The same value target.yml logs in with, and the same
# convention (DastAdminPass123!) the Grafana target uses.
ADMIN_USER="${CACTI_ADMIN_USER:-admin}"
ADMIN_PASS="${CACTI_ADMIN_PASS:-DastAdminPass123!}"
# Graph template 42 is "Device - Uptime": a PHP-script-server (type_id 5) data
# input, which is the input class that yields an action=2 poller_item.
UPTIME_GRAPH_TEMPLATE="${CACTI_UPTIME_GRAPH_TEMPLATE:-42}"

dbx() { docker exec -i "$DB_CONTAINER" mysql -uroot -p"$DB_ROOT_PASS" "$@"; }
cactiphp() { docker exec -u www-data "$CACTI_CONTAINER" php "/var/www/html/$1" "${@:2}"; }

echo "cacti-seed: waiting for the database ..."
for _ in $(seq 1 40); do
  if docker exec "$DB_CONTAINER" mysqladmin ping -uroot -p"$DB_ROOT_PASS" --silent >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

# -- 1. base schema --------------------------------------------------------
if dbx "$DB_NAME" -N -e "SELECT 1 FROM user_auth LIMIT 1" >/dev/null 2>&1; then
  echo "cacti-seed: schema already present, skipping cacti.sql import."
else
  echo "cacti-seed: importing base schema (cacti.sql) ..."
  docker exec "$CACTI_CONTAINER" bash -c \
    "mysql --host='$DB_CONTAINER' --user='$DB_USER' --password='$DB_PASS' '$DB_NAME' < /var/www/html/cacti.sql"
fi

# -- 2. timezone tables + grant -------------------------------------------
echo "cacti-seed: loading timezone tables and granting SELECT on mysql.time_zone_name ..."
docker exec "$DB_CONTAINER" bash -c \
  "mysql_tzinfo_to_sql /usr/share/zoneinfo 2>/dev/null | mysql -uroot -p'$DB_ROOT_PASS' mysql"
dbx -e "GRANT SELECT ON mysql.time_zone_name TO '$DB_USER'@'%'; FLUSH PRIVILEGES;"

# -- 3. complete the install ----------------------------------------------
if [ "$(dbx "$DB_NAME" -N -e "SELECT COUNT(*) FROM settings WHERE name='install_complete' AND value>0" 2>/dev/null || echo 0)" != "0" ]; then
  echo "cacti-seed: install already complete, skipping installer."
else
  echo "cacti-seed: running CLI installer (this takes ~1-3 min) ..."
  cactiphp cli/install_cacti.php --accept-eula --install
fi

# -- 4. make CVE-2022-46169 reachable: a script-server data source ---------
if [ "$(dbx "$DB_NAME" -N -e "SELECT COUNT(*) FROM poller_item WHERE action=2" 2>/dev/null || echo 0)" != "0" ]; then
  echo "cacti-seed: a script-server (action=2) data source already exists, skipping graph add."
else
  echo "cacti-seed: adding a Device-Uptime graph to make the command-injection sink reachable ..."
  cactiphp cli/add_graphs.php --graph-type=cg \
    --graph-template-id="$UPTIME_GRAPH_TEMPLATE" --host-id=1 --force
  # Rebuild the poller cache so the new data source's action=2 poller_item exists.
  cactiphp cli/rebuild_poller_cache.php -q >/dev/null 2>&1 || true
fi

if [ "$(dbx "$DB_NAME" -N -e "SELECT COUNT(*) FROM poller_item WHERE action=2" 2>/dev/null || echo 0)" != "0" ]; then
  echo "cacti-seed: OK — a POLLER_ACTION_SCRIPT_PHP (action=2) poller_item is present; CVE-2022-46169 is reachable."
else
  echo "cacti-seed: WARNING — no action=2 poller_item; the command-injection sink may not be reachable." >&2
fi

# -- 5. admin password ----------------------------------------------------
echo "cacti-seed: setting the admin password and clearing the change-password flag ..."
HASH="$(docker exec "$CACTI_CONTAINER" php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_DEFAULT);")"
dbx "$DB_NAME" -e \
  "UPDATE user_auth SET password='${HASH}', must_change_password='', password_change='on' WHERE username='${ADMIN_USER}';"

# -- 6. a non-admin user (campaign: --auth user) ---------------------------
# The campaign scans every target at none/user/admin (RUN-PLAN decision 3).
# Cacti ships only the admin and gates its own user administration behind admin,
# so a scan cannot mint a user — it is seeded here. `dastuser` is a DISTINCT
# account (so the `user` session is genuinely not the admin session), granted the
# admin realm set because Cacti exposes no meaningful sub-admin tier for a scan
# surface and the Cacti-user cell serves no marker (RUN-PLAN §5) — it exists only
# for the cross-level tree/alert comparison. Idempotent by username.
USER_NAME="${CACTI_USER_USER:-dastuser}"
USER_PASS_V="${CACTI_USER_PASS:-DastUserPass123!}"
if [ "$(dbx "$DB_NAME" -N -e "SELECT COUNT(*) FROM user_auth WHERE username='${USER_NAME}'" 2>/dev/null || echo 0)" != "0" ]; then
  echo "cacti-seed: user ${USER_NAME} already present"
else
  echo "cacti-seed: creating non-admin user ${USER_NAME} ..."
  UHASH="$(docker exec "$CACTI_CONTAINER" php -r "echo password_hash('${USER_PASS_V}', PASSWORD_DEFAULT);")"
  dbx "$DB_NAME" -e "INSERT INTO user_auth
    (username, password, realm, full_name, email_address, must_change_password,
     password_change, show_tree, show_list, show_preview, graph_settings,
     login_opts, policy_graphs, policy_trees, policy_hosts, policy_graph_templates,
     enabled)
    VALUES ('${USER_NAME}', '${UHASH}', 0, 'DAST User', '', '', 'on', 'on', 'on',
            'on', 'on', 1, 1, 1, 1, 1, 'on');"
  # Copy the admin's realm grants so the user reaches the console ('Logout' is
  # this target's logged_in_indicator) and has a crawlable authenticated surface.
  dbx "$DB_NAME" -e "INSERT INTO user_auth_realm (realm_id, user_id)
    SELECT realm_id, (SELECT id FROM user_auth WHERE username='${USER_NAME}')
    FROM user_auth_realm WHERE user_id=1;"
  echo "cacti-seed: created user ${USER_NAME} / ${USER_PASS_V}"
fi

echo "cacti-seed: done. Admin is ${ADMIN_USER} / ${ADMIN_PASS} at the console."
