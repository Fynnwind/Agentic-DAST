"""Seeded-session login (target-agnostic): one login obtains the session cookie, injected into
every ZAP request via a Replacer rule and handed to the verification tools — enough for the
authenticated-vs-unauthenticated coverage delta (its one limit, no re-auth, is immaterial
for a bounded scan).

The login runs as a one-shot container on ``dast-net`` (the Noir/wrapper idiom), so it
reaches the target by the same container name ZAP uses; the CSRF flow (fetch page, read the
hidden field, POST, keep the cookie) is generic, driven from the target's
:class:`~targets.AuthProfile`. It also owns the transport that idiom is built on
(:func:`container_fetch` and its host-side counterpart), which the ground-truth prober and
verify driver reuse. → DECISIONS.md.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, replace

import httpx

from dast_orchestrator.adapters.targets import AuthProfile, AuthUser

#: Pinned, arm64-native. Drives the login flow and every other request this
#: pipeline sends to a target from the host side.
CURL_IMAGE = "curlimages/curl:8.10.1"
DAST_NET = "dast-net"


class AuthError(RuntimeError):
    """Raised when a login attempt cannot produce a session."""


# -- reaching the target the way the scanner does -------------------------


#: The observation a fetch records, whatever the transport: ``(status,
#: location, body)``. Kept as a small tuple so the container transport and the
#: host transport are interchangeable and each caller's record-building is
#: written once.
ProbeResponse = tuple[int, str, str]


def httpx_fetch(method: str, url: str, timeout: float) -> ProbeResponse:
    """Host-side transport: reach a host-published port directly."""
    resp = httpx.request(method, url, timeout=timeout, follow_redirects=False)
    return resp.status_code, resp.headers.get("location", ""), resp.text


def container_fetch(network: str = DAST_NET, image: str = CURL_IMAGE,
                    cookie: str = "", headers: "dict[str, str] | None" = None):
    """Transport that reaches the target by container name on a docker network.

    The host cannot resolve ``target-wordpress`` and — unlike Gitea — WordPress
    canonical-redirects any request whose Host is not its configured site URL, so
    a host-published-port probe of a WordPress URL only ever sees the 301. The
    fix is the same one the scanner and the login flow already use: send the
    request from a one-shot curl container ON ``dast-net``, where the container
    name resolves and the Host matches. ``--path-as-is`` keeps an encoded
    traversal/XSS payload path intact, and redirects are NOT followed (curl's
    default), so a caller's own expected status still means what it says.

    :param cookie: a ``name=value`` session cookie to send. Empty means
        anonymous, which is the right default for a transport whose other
        callers deliberately probe as nobody. **A caller that probes on behalf
        of an authenticated run must pass it**: a status recorded anonymously
        describes a different request than the one it is filed beside, and on a
        login-gated route the difference between ``302`` and ``200`` is the
        whole measurement.

    :param headers: fixed request headers to add to every probe, for a
        header-gated surface a plain request cannot reach — the probe analogue of
        a target's :attr:`~dast_orchestrator.adapters.targets.Target.scan_headers`. Cacti's
        ``remote_agent.php`` needs ``X-Forwarded-For`` to pass its poller check,
        so a probe of that marker without it records a different request than the
        scan issued.

    :returns: a ``(method, url, timeout) -> ProbeResponse`` callable, so the
        transport is chosen once and passed as data.
    """
    #: Splits the body from a trailer curl appends, so status and the redirect
    #: target come back without a second request or an ``-i`` header-parse.
    marker_line = "<<<DAST-PROBE http=%{http_code} loc=%{redirect_url}>>>"
    extra_headers = [
        arg for name, value in (headers or {}).items()
        for arg in ("-H", f"{name}: {value}")
    ]

    def fetch(method: str, url: str, timeout: float) -> ProbeResponse:
        if not shutil.which("docker"):
            raise RuntimeError("docker not on PATH; cannot probe over the network")
        argv = [
            "docker", "run", "--rm", "--network", network, image,
            # --globoff so URL brackets are literal, not curl glob ranges: a
            # marker path like remote_agent.php?local_data_ids[0]=6 otherwise
            # aborts with curl exit 3 before any request is sent.
            "-s", "-g", "--path-as-is", "--max-time", str(int(timeout)),
            "-X", method, "-o", "-", "-w", "\n" + marker_line,
            *(["-H", f"Cookie: {cookie}"] if cookie else []),
            *extra_headers,
            url,
        ]
        proc = subprocess.run(argv, capture_output=True, timeout=timeout + 15)
        if proc.returncode != 0:
            raise RuntimeError(
                f"probe container exited {proc.returncode}: "
                f"{proc.stderr.decode(errors='replace')[:200]}"
            )
        out = proc.stdout.decode(errors="replace")
        head, _, trailer = out.rpartition("<<<DAST-PROBE ")
        status, location = 0, ""
        if trailer:
            for token in trailer.rstrip(">\n").split():
                key, _, value = token.partition("=")
                if key == "http":
                    status = int(value or 0)
                elif key == "loc":
                    location = value
        return status, location, head.rstrip("\n")

    return fetch


@dataclass(frozen=True)
class AuthSession:
    """An authenticated session: the cookies to replay, and how it was obtained."""

    mode: str            #: the auth mode / role, e.g. ``"user"`` or ``"admin"``.
    username: str
    cookie_name: str     #: the PRIMARY session cookie — identity and the success check.
    cookie_value: str
    status: int          #: the login POST status (302 on Gitea success).
    #: The FULL cookie jar the login produced, as a ready ``Cookie`` header
    #: (``a=1; b=2``). Empty falls back to the single primary cookie. This exists
    #: because one cookie is not always enough: WordPress's wp-admin is gated on
    #: the ``wordpress_<hash>`` AUTH cookie, while the front end only needs
    #: ``wordpress_logged_in_`` — replaying just the primary one leaves every
    #: wp-admin page a 302 to login (measured 2026-09-11, the package_ids SQLi).
    #: A real browser replays the whole jar; so do we. Not target-specific: any
    #: multi-cookie session benefits, and single-cookie apps are unaffected.
    cookies: str = ""
    #: Whether the harvested session was CONFIRMED authenticated — the
    #: ``logged_in_indicator`` was observed on a page fetched with it, not merely
    #: that a cookie came back. :func:`login` only ever returns a session with
    #: this true (it raises otherwise), so a caller can record it as proof the
    #: probes were not running logged out.
    authenticated: bool = False

    def cookie_header(self) -> str:
        """The ``Cookie`` header value to inject — the full jar when known."""
        return self.cookies or f"{self.cookie_name}={self.cookie_value}"


def _emit_result(session_cookie: str) -> str:
    """The shell tail both login scripts share: read the primary session cookie
    AND the whole jar, then emit the JSON line the caller parses.

    ``$J`` is the Netscape cookie jar curl wrote, ``$CODE`` the login POST status.
    ``cookie`` is the primary session cookie (identity + success check); ``jar``
    is the full ``Cookie`` header — every cookie the login set, ``#HttpOnly_``
    lines included, comment lines skipped — because one cookie is not always
    enough (wp-admin needs the ``wordpress_<hash>`` AUTH cookie too), and a real
    client replays the whole jar.
    """
    return (
        f'VAL=$(awk \'/{session_cookie}/ {{print $7}}\' "$J" | tail -1); '
        'JAR=$(awk \'$1 ~ /^#HttpOnly_/ || $1 !~ /^#/ '
        '{if (NF>=7) printf "%s=%s; ", $6, $7}\' "$J" | sed \'s/; $//\'); '
        'printf \'{"status":%s,"cookie":"%s","jar":"%s"}\' "$CODE" "$VAL" "$JAR"'
    )


def _login_script(base_url: str, profile: AuthProfile,
                  username: str, password: str) -> str:
    """A self-contained shell flow: GET login page, read CSRF, POST, emit JSON.

    Emits one line ``{"status": <int>, "cookie": "<value>", "jar": "<header>"}``
    on stdout so the caller parses a fixed shape rather than scraping tool
    output. All the target-specific names are substituted in from the profile.
    """
    base = base_url.rstrip("/")
    login = f"{base}{profile.login_path}"
    # The CSRF read and post are conditional on the target declaring a field:
    # WordPress's wp-login.php carries no CSRF token, so an empty csrf_field must
    # not post a bogus ``=<value>`` pair. Gitea sets it and the branch runs.
    if profile.csrf_field:
        # The name attribute's quote style varies by template: Gitea renders
        # name="_csrf" (double), while Cacti's csrf-magic renders
        # name='__csrf_magic' (single). The leading/trailing ``.`` match whatever
        # quote surrounds the field name, and ``[^>]*`` allows other attributes to
        # sit between name and value within the same tag. The value itself is
        # double-quoted in both, so its extraction is unchanged.
        csrf_read = (
            f'CSRF=$(curl -s -c "$J" "{login}" | '
            f'grep -oE \'name=.{profile.csrf_field}.[^>]*value="[^"]+"\' | head -1 | '
            'sed -E \'s/.*value="([^"]+)".*/\\1/\'); '
        )
        csrf_post = f'--data-urlencode "{profile.csrf_field}=$CSRF" '
    else:
        # Still GET the page first — WordPress sets a test cookie there that the
        # POST must return, or the login is rejected as "cookies are blocked".
        csrf_read = f'curl -s -c "$J" "{login}" > /dev/null; '
        csrf_post = ""
    extra_post = "".join(
        f'--data-urlencode "{name}={value}" ' for name, value in profile.extra_login_fields
    )
    return (
        'set -e; J=$(mktemp); '
        # 1. GET the login page, keep cookies (CSRF token and/or test cookie)
        f'{csrf_read}'
        # 2. POST credentials, carrying and updating the cookie jar
        'CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$J" -c "$J" '
        f'{csrf_post}'
        f'--data-urlencode "{profile.username_field}={username}" '
        f'--data-urlencode "{profile.password_field}={password}" '
        f'{extra_post}"{login}"); '
        # 3. emit the primary session cookie and the whole jar
        + _emit_result(profile.session_cookie)
    )


def _json_login_script(base_url: str, profile: AuthProfile,
                       username: str, password: str) -> str:
    """The ``json`` strategy's flow: POST a JSON credential body, emit JSON.

    Grafana's login is a JSON API, not a CSRF-guarded HTML form: a single
    ``POST /login`` of ``{"user": ..., "password": ...}`` with an
    ``application/json`` body returns ``200`` and sets the session cookie, with
    no token to read from a prior GET. So this flow has no page fetch — the one
    the form strategy does only to harvest a CSRF token or a test cookie, both
    absent here.

    The field *names* in the body are still target data
    (:attr:`AuthProfile.username_field` / ``password_field`` — Grafana's are
    ``user``/``password``), and :attr:`AuthProfile.extra_login_fields` are folded
    in as extra JSON keys, so a sibling JSON-login target needs no new code.
    Emits the same ``{"status": <int>, "cookie": "<value>"}`` line the form
    strategy does, so :func:`parse_login_result` reads both identically.
    """
    base = base_url.rstrip("/")
    login = f"{base}{profile.login_path}"
    body: dict[str, str] = {
        profile.username_field: username,
        profile.password_field: password,
    }
    body.update(dict(profile.extra_login_fields))
    # Single-quoted for ``sh``; the values are fixed, public test credentials
    # with no single quote, the same assumption the form script's embedded
    # --data-urlencode values already make.
    payload = json.dumps(body)
    return (
        'set -e; J=$(mktemp); '
        'CODE=$(curl -s -o /dev/null -w "%{http_code}" -c "$J" '
        '-H "Content-Type: application/json" '
        f"--data '{payload}' "
        f'"{login}"); '
        + _emit_result(profile.session_cookie)
    )


def _default_runner(script: str, network: str, timeout: int) -> str:
    """Run the login flow in a pinned curl container on the shared network."""
    if not shutil.which("docker"):
        raise AuthError("docker not on PATH; cannot perform the login flow")
    argv = ["docker", "run", "--rm", "--network", network, CURL_IMAGE,
            "sh", "-c", script]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AuthError(f"login timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise AuthError(
            f"login container exited {proc.returncode}: "
            f"{proc.stderr.decode(errors='replace')[:300]}"
        )
    return proc.stdout.decode(errors="replace")


def parse_login_result(stdout: str) -> tuple[int, str, str]:
    """Extract ``(status, cookie_value, jar)`` from the login flow's JSON line.

    ``jar`` is the full ``Cookie`` header when the script emitted one, else ``""``
    (an older/stubbed result), in which case the caller falls back to the single
    primary cookie.
    """
    stdout = stdout.strip()
    start = stdout.find("{")
    if start == -1:
        raise AuthError(f"login produced no result: {stdout[:200]!r}")
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError as exc:
        raise AuthError(f"login result was not JSON: {stdout[:200]!r}") from exc
    return (int(data.get("status") or 0), str(data.get("cookie") or ""),
            str(data.get("jar") or ""))


def _form_login(base_url: str, profile: AuthProfile, mode: str,
                user: AuthUser, network: str, timeout: int, runner) -> AuthSession:
    """The built-in ``form`` strategy: CSRF-form login (Gitea, WordPress, ...)."""
    script = _login_script(base_url, profile, user.username, user.password)
    status, cookie_value, jar = parse_login_result(runner(script, network, timeout))
    if not cookie_value:
        raise AuthError(
            f"login as {user.username!r} produced no {profile.session_cookie!r} "
            f"cookie (login POST status {status}); check the credentials are seeded "
            "(targets/gitea/seed-users.sh)"
        )
    return AuthSession(
        mode=mode, username=user.username, cookie_name=profile.session_cookie,
        cookie_value=cookie_value, status=status, cookies=jar,
    )


def _json_login(base_url: str, profile: AuthProfile, mode: str,
                user: AuthUser, network: str, timeout: int, runner) -> AuthSession:
    """The built-in ``json`` strategy: JSON-body API login (Grafana, ...)."""
    script = _json_login_script(base_url, profile, user.username, user.password)
    status, cookie_value, jar = parse_login_result(runner(script, network, timeout))
    if not cookie_value:
        raise AuthError(
            f"login as {user.username!r} produced no {profile.session_cookie!r} "
            f"cookie (login POST status {status}); check the credentials are "
            "seeded (targets/grafana/env/seed-users.sh) and that the JSON login "
            "field names match the app"
        )
    return AuthSession(
        mode=mode, username=user.username, cookie_name=profile.session_cookie,
        cookie_value=cookie_value, status=status, cookies=jar,
    )


#: Named login mechanisms a target's ``AuthProfile.strategy`` selects. The
#: ``form`` strategy covers CSRF-form logins (Gitea, WordPress); ``json`` covers
#: a JSON-body API login (Grafana). A target whose login differs in kind again
#: adds one small function here, reusable by any future target of the same shape
#: — the only per-target *code* the design needs.
STRATEGIES = {"form": _form_login, "json": _json_login}


def _confirm_authenticated(session: AuthSession, base_url: str,
                           profile: AuthProfile, network: str, timeout: int,
                           fetch_factory) -> tuple[bool, int, str]:
    """Whether the harvested session is actually logged in.

    A login that returns a cookie is NOT proof of authentication: Gitea,
    WordPress and the rest set a session cookie for anonymous visitors too, so a
    failed or non-authenticating login leaves a perfectly well-formed cookie
    behind. The only honest check is to USE the cookie — fetch a page that
    carries :attr:`~...AuthProfile.logged_in_indicator` only when authenticated
    and look for it. The fetch goes through :func:`container_fetch` so it reaches
    the target the way the scan does (by container name on ``dast-net``, the full
    jar replayed, Host intact for WordPress).

    :returns: ``(authenticated, probe_status, url)`` — the status and url are
        carried out for the caller's error message, so a failure says what was
        fetched and what came back.
    """
    path = profile.logged_in_check_path or "/"
    url = f"{base_url.rstrip('/')}{path}"
    fetch = fetch_factory(network=network, cookie=session.cookie_header())
    status, _location, body = fetch("GET", url, timeout)
    return (profile.logged_in_indicator in body), status, url


def login(base_url: str, profile: AuthProfile, mode: str,
          network: str = DAST_NET, timeout: int = 30, runner=_default_runner,
          fetch_factory=container_fetch) -> AuthSession:
    """Log in as the account for ``mode`` and return a CONFIRMED session to replay.

    Dispatches to the profile's named strategy; the parameters (paths, field and
    cookie names, accounts) are pure data from the target YAML. Before returning,
    the session is confirmed authenticated against the target
    (:func:`_confirm_authenticated`) — the step that makes login **fail-closed**:
    a cookie that does not actually log in raises here rather than silently
    threading an anonymous session into every probe.

    :param mode: ``"user"`` or ``"admin"`` — selects the account on the profile.
    :param runner: the I/O boundary ``(script, network, timeout) -> stdout``,
        injected so the flow is unit-testable without a container.
    :param fetch_factory: the transport builder for the authentication check,
        ``(network, cookie) -> ((method, url, timeout) -> (status, loc, body))``,
        injected for the same reason. Defaults to :func:`container_fetch`.
    :raises AuthError: if the strategy is unknown, the target has no account for
        the mode, the login did not yield a session cookie, or — the new gate —
        the session it yielded is not recognised as authenticated by the target.
    """
    user = profile.user(mode)
    if user is None:
        raise AuthError(
            f"target has no {mode!r} account; known roles: "
            f"{[u.role for u in profile.users]}"
        )
    strategy = STRATEGIES.get(profile.strategy)
    if strategy is None:
        raise AuthError(
            f"unknown auth strategy {profile.strategy!r}; known: {sorted(STRATEGIES)}"
        )
    session = strategy(base_url, profile, mode, user, network, timeout, runner)
    ok, probe_status, url = _confirm_authenticated(
        session, base_url, profile, network, timeout, fetch_factory)
    if not ok:
        raise AuthError(
            f"logged in as {session.username!r} (login POST status "
            f"{session.status}) but the session is NOT authenticated: GET {url} "
            f"returned {probe_status} without {profile.logged_in_indicator!r} in "
            "the body, so the target did not recognise the session cookie and "
            "every probe would run logged out. Check the seeded credentials and "
            "the login flow before trusting an authenticated run."
        )
    return replace(session, authenticated=True)
