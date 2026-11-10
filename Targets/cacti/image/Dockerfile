# Cacti 1.2.22 — the fourth target, built here rather than pulled.
#
# WHY BUILT, NOT PULLED. There is no official Cacti Docker image, and no image
# of ANY publisher ships an arm64 build of 1.2.22: the vulhub CVE-2022-46169 lab
# (`vulhub/cacti:1.2.22`) and `smcline06/cacti` are amd64-only, and running one
# under emulation on an M3 would break this project's arm64-native invariant and
# make the blind out-of-band callback timing (the whole point of this target)
# unreliable. So Cacti is assembled the same way the ctags index image is: an
# arm64-native base (`php:7.4-apache`, multi-arch) plus a version pinned two ways
# — the source by exact commit, the base by an explicit tag — so `docker build`
# yields the same Cacti on any machine and every later scan runs offline.
#
# Build (arm64, from the repo root):
#     docker build --platform linux/arm64 -t dast-cacti:1.2.22 images/cacti
#
# The vulnerability this target exists for is CVE-2022-46169 (CVSS 9.8):
# unauthenticated OS command injection in remote_agent.php. The auth check is
# bypassed with an X-Forwarded-For header, and the payload rides the `poller_id`
# request var, which poll_for_data() concatenates unfiltered into a proc_open()
# shell command. It is BLIND — no command output comes back in the response — so
# it is the corpus's first target whose flagship CVE can only be *confirmed* out
# of band, via the self-hosted interactsh sink. See targets/cacti/oracle.md and
# cve-markers.yml.

# php:7.4.33-apache-bullseye — the last 7.4 release, arm64-native (arm64/v8), and
# a concrete version tag rather than the floating 7.4-apache. Cacti 1.2.22
# predates PHP 8 support in practice, and this project already runs PHP 7.4 for
# WordPress, so the runtime is consistent across targets.
FROM php:7.4.33-apache-bullseye

# -- system libraries + tools ---------------------------------------------
# Split into build-time -dev headers (for the PHP extensions below) and the
# runtime tools Cacti shells out to: rrdtool (graph storage), net-snmp (device
# polling), and the mariadb client (the seed script drives the DB through
# `docker exec`). git is used once, to fetch the pinned source, then removed.
#
# ping / wget / dnsutils / curl are the ordinary toolset of a network-monitoring
# host — Cacti pings and polls devices — and they are also what a blind-vuln
# scanner's out-of-band payloads invoke (nuclei's cmdi OAST templates call
# nslookup/ping/wget to make the callback). The CVE-2022-46169 command injection
# is real regardless of which binaries exist; whether it can be *confirmed* out
# of band depends on the target having one of them, so a minimal image would make
# the target impossible to confirm for a reason that is about the image, not the
# bug. Installing the realistic toolset keeps the confirmation axis — the whole
# point of this target — measurable.
#
# The apt sources are repointed at snapshot.debian.org at a fixed date. Two
# reasons: bullseye is oldstable and its live security pool prunes older
# point-release binaries, so the mutable deb.debian.org index 404s on the very
# versions it advertises (observed 2026-09-15, arm64); and a frozen snapshot
# makes this apt layer reproducible, the same pin-everything reason the Cacti
# source and PHP base are pinned. The date matches this base image's own build
# snapshot (its sources.list ships these URLs commented out). Check-Valid-Until
# is off because a snapshot's Release file is intentionally stale.
RUN set -eux; \
    printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20221114T000000Z bullseye main' \
      'deb http://snapshot.debian.org/archive/debian-security/20221114T000000Z bullseye-security main' \
      'deb http://snapshot.debian.org/archive/debian/20221114T000000Z bullseye-updates main' \
      > /etc/apt/sources.list; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid; \
    echo 'Acquire::Retries "8";' > /etc/apt/apt.conf.d/99retries; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        git \
        rrdtool \
        snmp \
        libsnmp-dev \
        default-mysql-client \
        iputils-ping \
        wget \
        dnsutils \
        curl \
        libpng-dev \
        libjpeg-dev \
        libfreetype6-dev \
        libgmp-dev \
        libldap2-dev \
        libonig-dev \
        libicu-dev \
        libzip-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# -- PHP extensions Cacti's installer marks mandatory ----------------------
# The mandatory set (lib/utility.php utility_php_verify_extensions) that is not
# already built into the base image: gd, gmp, ldap, mbstring, pdo_mysql, sockets,
# posix, plus the recommended snmp/intl/gettext that a monitoring app genuinely
# uses. ldap needs its libdir pointed at the arch multiarch triplet — `gcc
# -dumpmachine` yields aarch64-linux-gnu on arm64, so the same line is
# arch-correct without hardcoding.
RUN set -eux; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-configure ldap --with-libdir="lib/$(gcc -dumpmachine)"; \
    docker-php-ext-install -j"$(nproc)" \
        gd gmp ldap mbstring mysqli pdo_mysql snmp sockets posix intl gettext zip

# -- Cacti source, pinned to the exact commit of release/1.2.22 ------------
# The tag is resolved to its commit and the build FAILS if that commit ever
# moves — a stronger pin than a GitHub archive tarball, whose checksum is not
# stable. .git is dropped so the image carries only the tree. The same tree is
# what Noir and the SAST baseline read on the host (targets/cacti/src); keep the
# two in step by cloning the host copy from the same tag.
ARG CACTI_COMMIT=a0a8b7d51dcbe1ac0f91788e3579ac8962ba66ad
RUN set -eux; \
    git clone --depth 1 --branch release/1.2.22 https://github.com/Cacti/cacti /var/www/html; \
    cd /var/www/html; \
    test "$(git rev-parse HEAD)" = "${CACTI_COMMIT}"; \
    rm -rf .git; \
    apt-get purge -y --auto-remove git; \
    chown -R www-data:www-data /var/www/html

# Cacti's own PHP requirements (memory_limit, max_execution_time, date.timezone)
# that its installer checks — supplied as a drop-in so the values are explicit
# and versioned, not left to the base image's defaults.
COPY php-cacti.ini /usr/local/etc/php/conf.d/zz-cacti.ini

# Templates include/config.php from the DB_* environment (so no credential is
# baked into the image) and waits for the database before starting Apache.
COPY entrypoint.sh /usr/local/bin/cacti-entrypoint
RUN chmod +x /usr/local/bin/cacti-entrypoint

EXPOSE 80
ENTRYPOINT ["cacti-entrypoint"]
CMD ["apache2-foreground"]
