#!/usr/bin/env bash
# Seed the CVE fixture: the content the markers in ../cve-markers.yml need in
# order to be *reachable at all*. Idempotent. The WordPress analogue of the
# Gitea target's seed-repo.sh.
#
# This is not decoration. Several of the pinned plugin's documented
# vulnerabilities live in views that only render when the right content exists,
# and a target without them would look clean for the wrong reason:
#
#   * `[wpdm_packages]` renders the package toolbar, whose `skw` search field is
#     echoed into an `<input value="...">` unescaped (fixed upstream in 3.2.60).
#     No page with the shortcode, no sink.
#   * A package whose access list does not contain `guest` makes WPDM render its
#     own login form to anonymous visitors, and that form echoes the raw
#     $_SERVER['REQUEST_URI'] into a hidden field and a JS string literal (fixed
#     in 3.2.53). A site whose packages are all public never shows it.
#   * A published package gives the /download/<slug>/ routes and the ?wpdmdl=
#     download surface something to point at.
#
# The `?__wpdmxp=1&frameid=` sink (fixed in 3.2.43) needs no fixture — it is
# hooked on `wp` and fires on any front-end URL — and is listed here only so the
# next reader does not go looking for the fixture that creates it.
#
# Usage:  ./targets/wordpress/env/seed-site.sh    # must have run first
#         ./targets/wordpress/env/seed-content.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_wp.sh"

require_target_running
if ! wp_installed; then
  echo "WordPress is not installed yet — run seed-site.sh first" >&2
  exit 1
fi

# -- helpers ---------------------------------------------------------------

# Post id for a slug of a given type, empty when absent. `wp post list` with an
# explicit post_status is deliberate: a draft left behind by a failed run would
# otherwise be invisible here and this script would create a duplicate.
post_id() {
  wp post list --post_type="$1" --name="$2" --post_status=any \
    --field=ID --posts_per_page=1 2>/dev/null | tr -d '\r' | head -1
}

ensure_page() {  # slug, title, content
  local id; id="$(post_id page "$1")"
  if [ -n "$id" ]; then
    echo "page '$1' already exists (ID $id)"
  else
    id="$(wp post create --post_type=page --post_status=publish \
      --post_name="$1" --post_title="$2" --post_content="$3" --porcelain | tr -d '\r')"
    echo "page '$1' created (ID $id)"
  fi
  printf '%s' "$id"
}

# -- the download category -------------------------------------------------

if wp term get wpdmcategory demo --by=slug --field=term_id >/dev/null 2>&1; then
  echo "category 'demo' already exists"
else
  wp term create wpdmcategory "Demo" --slug=demo >/dev/null
  echo "category 'demo' created"
fi

# -- the file the packages point at ----------------------------------------
#
# WPDM serves files out of its own upload directory and stores only the
# basename in the __wpdm_files meta, so the file has to exist on disk before a
# download URL means anything. Written through `wp eval` rather than a second
# container so it lands with the same ownership as everything else WP-CLI writes.
wp eval '
  $d = WP_CONTENT_DIR . "/uploads/download-manager-files";
  if (!is_dir($d)) { wp_mkdir_p($d); }
  $f = $d . "/dast-demo.txt";
  if (!file_exists($f)) {
    file_put_contents($f, "DAST target fixture file. Not sensitive.\n");
  }
  echo "package file: " . $f . "\n";
'

# -- the packages ----------------------------------------------------------

seed_package() {  # slug, title, access-role
  local id; id="$(post_id wpdmpro "$1")"
  if [ -n "$id" ]; then
    echo "package '$1' already exists (ID $id)"
  else
    id="$(wp post create --post_type=wpdmpro --post_status=publish \
      --post_name="$1" --post_title="$2" \
      --post_content="Fixture package for the DAST ground-truth markers." \
      --porcelain | tr -d '\r')"
    echo "package '$1' created (ID $id)"
  fi
  wp post term set "$id" wpdmcategory demo >/dev/null
  wp post meta update "$id" __wpdm_files '["dast-demo.txt"]' --format=json >/dev/null
  wp post meta update "$id" __wpdm_access "[\"$3\"]" --format=json >/dev/null
  wp post meta update "$id" __wpdm_link_label "Download" >/dev/null
}

# Public: reachable by an unauthenticated scan, and the one the listing shows.
seed_package dast-public-package "DAST Public Package" guest
# Login-required: `guest` is deliberately absent, which is what makes WPDM
# render its own login form — the sink for the REQUEST_URI reflection.
seed_package dast-locked-package "DAST Locked Package" administrator

# Render the login form inline on a locked package rather than only linking to
# wp-login.php. Without this the REQUEST_URI reflection in the login view is
# never emitted.
wp option update __wpdm_login_form 1 >/dev/null
# Enable the modal login popup. Its view (modal-login-form.php) echoes the raw
# $_SERVER['REQUEST_URI'] into a hidden field and a <script> string, and renders
# site-wide in the footer once this option is on — the sink for the reflected
# XSS fixed in 3.2.53. Off by default, so without this the marker is unreachable
# for a configuration reason rather than a code one.
wp option update __wpdm_modal_login 1 >/dev/null

# -- the shortcode pages ---------------------------------------------------

ensure_page downloads "Downloads" \
  '[wpdm_packages items_per_page="10" order="DESC" toolbar="1"]' >/dev/null
ensure_page download-categories "Download Categories" \
  '[wpdm_category id="demo" toolbar="1"]' >/dev/null
ensure_page member-downloads "Member Downloads" \
  '[wpdm_package id="__LOCKED__"]' >/dev/null
# The MODAL login form, which is a different view from the one a locked package
# renders inline: it is the one that echoes the raw request URI (fixed 3.2.53).
# Without a page carrying this shortcode that sink is never emitted, and the
# marker would look unreachable for the wrong reason.
ensure_page sign-in "Sign In" \
  '[wpdm_login_form][wpdm_modal_login_form]' >/dev/null

# The member-downloads page names the locked package by id, which is only known
# after it is created — patch it in on every run so the fixture is correct even
# if the package was recreated.
locked_id="$(post_id wpdmpro dast-locked-package)"
member_id="$(post_id page member-downloads)"
if [ -n "$locked_id" ] && [ -n "$member_id" ]; then
  wp post update "$member_id" \
    --post_content="[wpdm_package id=\"$locked_id\"]" >/dev/null
  echo "member-downloads page points at package $locked_id"
fi

wp rewrite flush --hard >/dev/null

echo "---"
wp post list --post_type=wpdmpro --fields=ID,post_name,post_status
wp post list --post_type=page --fields=ID,post_name,post_status
