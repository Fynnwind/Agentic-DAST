#!/usr/bin/env bash
# Install WordPress and the pinned vulnerable plugin, idempotently. RUN FIRST —
# seed-users.sh and seed-content.sh both need an installed site.
#
# The plugin is installed from a LOCAL zip, verified by SHA-256, and never from
# wordpress.org at seed time. Two reasons, both load-bearing:
#   * the target runs with WP_HTTP_BLOCK_EXTERNAL, so WordPress's own HTTP API
#     cannot fetch anything during a scan — installing from a URL would be the
#     one thing that had to punch through that;
#   * a version pin that re-downloads on every seed is not a pin. The hash is
#     the pin; the URL is only how the file arrives the first time.
#
# The credentials are TEST-ONLY for a deliberately-vulnerable, loopback-bound
# target, fixed and public on purpose so every run reaches the same instance.
#
# Usage:  docker compose -f stacks/persistent.yml up -d
#         ./targets/wordpress/env/seed-site.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_wp.sh"

#: The pinned plugin — see the version table in .claude/CLAUDE.md and the
#: selection record in docs/DECISIONS.md. 59 documented vulnerabilities are live
#: at this version; the marker set is in ../cve-markers.yml.
PLUGIN_SLUG="download-manager"
PLUGIN_VERSION="3.2.33"
PLUGIN_SHA256="4279abe6ac1298ba7d0abec9ee7f3f165511a50a9a722ad7790d0226aa26d8e4"
PLUGIN_ZIP="$SEED_DIR/${PLUGIN_SLUG}.${PLUGIN_VERSION}.zip"
PLUGIN_URL="https://downloads.wordpress.org/plugin/${PLUGIN_SLUG}.${PLUGIN_VERSION}.zip"

SITE_URL="http://target-wordpress"
SITE_TITLE="DAST WordPress Target"
ADMIN_USER="dastadmin"
ADMIN_PASS='DastAdminPass123!'
ADMIN_EMAIL="dastadmin@example.com"

require_target_running

# -- the pinned plugin artifact -------------------------------------------

fetch_plugin() {
  mkdir -p "$SEED_DIR"
  if [ ! -f "$PLUGIN_ZIP" ]; then
    echo "fetching $PLUGIN_SLUG $PLUGIN_VERSION"
    curl -fsSL --max-time 120 -o "$PLUGIN_ZIP.part" "$PLUGIN_URL"
    mv "$PLUGIN_ZIP.part" "$PLUGIN_ZIP"
  fi
  local have
  have="$(shasum -a 256 "$PLUGIN_ZIP" | awk '{print $1}')"
  if [ "$have" != "$PLUGIN_SHA256" ]; then
    echo "PIN VIOLATION: $PLUGIN_ZIP hashes to $have, expected $PLUGIN_SHA256" >&2
    echo "Refusing to seed: the target would not be the pinned one." >&2
    exit 1
  fi
  echo "plugin artifact verified ($PLUGIN_SHA256)"
}

# -- install --------------------------------------------------------------

if wp_installed; then
  echo "WordPress already installed — leaving the site as-is"
else
  echo "installing WordPress"
  wp core install \
    --url="$SITE_URL" --title="$SITE_TITLE" \
    --admin_user="$ADMIN_USER" --admin_password="$ADMIN_PASS" \
    --admin_email="$ADMIN_EMAIL" --skip-email
fi

# Pretty permalinks: the plugin's own routes (/download/<slug>/) only exist
# under a non-default structure, and a rewritten front end is the realistic
# surface. `--hard` writes .htaccess; if Apache is not honouring it the site
# still answers on the ?p= form, which the scan tolerates.
wp rewrite structure '/%postname%/' --hard >/dev/null
wp rewrite flush --hard >/dev/null
echo "permalink structure: $(wp option get permalink_structure)"

fetch_plugin
if wp plugin is-installed "$PLUGIN_SLUG" >/dev/null 2>&1; then
  installed="$(wp plugin get "$PLUGIN_SLUG" --field=version)"
  if [ "$installed" != "$PLUGIN_VERSION" ]; then
    echo "PIN VIOLATION: $PLUGIN_SLUG $installed is installed, expected $PLUGIN_VERSION" >&2
    echo "Remove it (wp plugin delete $PLUGIN_SLUG) and re-run, or reset the" >&2
    echo "bind mount at targets/wordpress/env/data/." >&2
    exit 1
  fi
  echo "$PLUGIN_SLUG $installed already installed"
else
  wp plugin install "/seed/$(basename "$PLUGIN_ZIP")"
fi
wp plugin activate "$PLUGIN_SLUG" >/dev/null
echo "---"
wp plugin list --fields=name,status,version
