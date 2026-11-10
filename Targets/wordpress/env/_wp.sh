#!/usr/bin/env bash
# Shared WP-CLI plumbing for this target's seed scripts. Sourced, not executed.
#
# WordPress has no admin CLI inside its own image (unlike Gitea, where
# `docker exec target-gitea gitea admin ...` is the reproducible path), so the
# equivalent is a one-shot WP-CLI container — the same `docker run --rm` idiom
# the pipeline uses for Noir and the verification wrappers:
#
#   * `--volumes-from target-wordpress` gives it the running install's files,
#   * `--network dast-net` lets it reach the database by container name,
#   * `-u 33:33` is load-bearing. The Debian-based `wordpress:` image runs as
#     www-data = uid 33; the Alpine-based `wordpress:cli` image's own www-data is
#     uid 82. Left alone, every file WP-CLI writes into the shared volume ends up
#     owned by a user Apache is not, and the failures show up much later as
#     permission errors in unrelated places.
#
# `wp` is passed explicitly as the first argument. The image's entrypoint tries
# to add it for you, but only when `wp help <subcommand>` succeeds inside a
# container that has the target's volumes mounted — which it does not reliably
# do, and the failure surfaces as `exec: core: not found`.

#: Pinned, arm64-native. The PHP version is pinned too, so a rebuilt tag cannot
#: put an interpreter under WP-CLI that core 5.8 does not support.
WP_CLI_IMAGE="${WP_CLI_IMAGE:-wordpress:cli-2.6.0-php7.4}"
WP_CONTAINER="${WP_CONTAINER:-target-wordpress}"
DAST_NET="${DAST_NET:-dast-net}"
SEED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/seed"

# The image's wp-config.php does not hold the database credentials — it calls
# getenv_docker() for each of them on every request, so they exist only in the
# web container's environment. A WP-CLI container that does not carry the same
# four variables silently falls back to the image defaults and fails with
# "can't contact the database server at `mysql`", which reads like a network
# fault and is not one.
_db_env() {
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$WP_CONTAINER" \
    | grep -E '^WORDPRESS_DB_|^WORDPRESS_TABLE_PREFIX='
}

wp() {
  local env_args=()
  local kv
  while IFS= read -r kv; do
    [ -n "$kv" ] && env_args+=(--env "$kv")
  done < <(_db_env)

  docker run --rm --interactive=false \
    --network "$DAST_NET" \
    --volumes-from "$WP_CONTAINER" \
    --volume "$SEED_DIR:/seed:ro" \
    "${env_args[@]}" \
    --user 33:33 \
    "$WP_CLI_IMAGE" wp "$@"
}

# True when WordPress is installed (tables present, siteurl set). Every seed
# script is idempotent and this is how they check.
wp_installed() {
  wp core is-installed >/dev/null 2>&1
}

require_target_running() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$WP_CONTAINER"; then
    echo "target container '$WP_CONTAINER' is not running." >&2
    echo "  docker compose -f stacks/persistent.yml up -d" >&2
    exit 1
  fi
}
