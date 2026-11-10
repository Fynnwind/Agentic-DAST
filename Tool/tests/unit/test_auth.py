"""Seeded-session login: the flow logic, with the container as an injected fake.

The one-shot container is the I/O boundary; :func:`auth.login` takes a ``runner``
so the CSRF-then-POST orchestration and the result parsing are tested without
Docker or a live target.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.adapters import auth
from dast_orchestrator.adapters.targets import AuthProfile, AuthUser

PROFILE = AuthProfile(
    login_path="/user/login",
    csrf_field="_csrf",
    session_cookie="i_like_gitea",
    logged_in_indicator="Sign Out",
    users=(
        AuthUser("user", "dastuser", "DastUserPass123!"),
        AuthUser("admin", "dastadmin", "DastAdminPass123!"),
    ),
)

#: A page carrying every target's logged-in indicator, so a strategy test that
#: builds a session passes the authentication gate (:func:`auth.login` now
#: confirms the session) without a container or a live target.
_INDICATORS_BODY = "<html><body>Sign Out Log Out Sign out Logout</body></html>"


def _authed_fetch(network=None, cookie=None, **_kw):
    """A ``fetch_factory`` whose GET returns a logged-in page — the default stub
    for the success-path login tests."""
    def fetch(method, url, timeout):
        return 200, "", _INDICATORS_BODY
    return fetch


def test_parse_login_result_reads_status_cookie_and_jar():
    assert auth.parse_login_result(
        '{"status":302,"cookie":"abc123","jar":"a=1; b=2"}'
    ) == (302, "abc123", "a=1; b=2")
    # an older/stubbed result with no jar field still parses, jar empty
    assert auth.parse_login_result('{"status":302,"cookie":"abc123"}') == (302, "abc123", "")


def test_parse_login_result_tolerates_leading_noise():
    # curl can emit a stray progress char before the JSON blob
    assert auth.parse_login_result('\x1b[2K{"status":302,"cookie":"z"}') == (302, "z", "")


def test_parse_login_result_rejects_garbage():
    with pytest.raises(auth.AuthError):
        auth.parse_login_result("not json at all")


def test_login_builds_session_from_runner():
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        seen["network"] = network
        return '{"status":302,"cookie":"COOKIEVAL"}'

    session = auth.login("http://target-gitea:3000", PROFILE, "admin",
                         runner=fake_runner, fetch_factory=_authed_fetch)
    assert session.mode == "admin" and session.username == "dastadmin"
    assert session.cookie_header() == "i_like_gitea=COOKIEVAL"
    assert session.status == 302
    # the flow targets the right login URL and carries the admin credentials
    assert "/user/login" in seen["script"]
    assert "dastadmin" in seen["script"] and "_csrf" in seen["script"]
    assert seen["network"] == "dast-net"


def test_cookie_header_replays_the_whole_jar_when_present():
    """One cookie is not always enough — wp-admin needs the auth cookie beside
    `wordpress_logged_in_`. When the login emits a full jar, that is what is
    replayed; a single-cookie result falls back to the primary cookie."""
    def full_jar(script, network, timeout):
        return ('{"status":302,"cookie":"WPVAL",'
                '"jar":"wordpress_logged_in_h=WPVAL; wordpress_sec_h=SECVAL"}')

    session = auth.login("http://target-wordpress", WP_PROFILE, "user",
                         runner=full_jar, fetch_factory=_authed_fetch)
    assert session.cookie_header() == (
        "wordpress_logged_in_h=WPVAL; wordpress_sec_h=SECVAL")
    # the primary cookie is still the identity / success check
    assert session.cookie_value == "WPVAL"


def test_login_script_captures_the_full_jar_not_just_one_cookie():
    """The emitted shell reads every cookie from the jar (httponly included),
    so the auth cookie wp-admin needs is not dropped on the floor."""
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        return '{"status":302,"cookie":"V","jar":"a=1"}'

    auth.login("http://target-wordpress", WP_PROFILE, "user", runner=fake_runner, fetch_factory=_authed_fetch)
    assert '"jar":' in seen["script"]          # it emits a jar field
    assert "#HttpOnly_" in seen["script"]        # ...built from httponly lines too


def test_login_unknown_role_errors():
    with pytest.raises(auth.AuthError):
        auth.login("http://t", PROFILE, "root", runner=lambda *a: "{}")


def test_login_without_cookie_errors():
    def no_cookie(script, network, timeout):
        return '{"status":200,"cookie":""}'
    with pytest.raises(auth.AuthError):
        auth.login("http://t", PROFILE, "user", runner=no_cookie)


def test_login_unknown_strategy_errors():
    import dataclasses
    weird = dataclasses.replace(PROFILE, strategy="json-api")
    with pytest.raises(auth.AuthError, match="unknown auth strategy"):
        auth.login("http://t", weird, "user", runner=lambda *a: '{"status":302,"cookie":"x"}')


def test_form_is_the_builtin_strategy():
    assert "form" in auth.STRATEGIES


# -- per-target login field names (WordPress vs Gitea) ---------------------

WP_PROFILE = AuthProfile(
    login_path="/wp-login.php",
    csrf_field="",
    session_cookie="wordpress_logged_in_",
    logged_in_indicator="Log Out",
    users=(AuthUser("user", "dastuser", "DastUserPass123!"),),
    username_field="log",
    password_field="pwd",
    extra_login_fields=(("wp-submit", "Log In"),),
)


def test_login_uses_the_profiles_field_names_and_extras():
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        return '{"status":302,"cookie":"WPVAL"}'

    session = auth.login("http://target-wordpress", WP_PROFILE, "user",
                         runner=fake_runner, fetch_factory=_authed_fetch)
    assert session.cookie_header() == "wordpress_logged_in_=WPVAL"
    # WordPress field names are posted, Gitea's are not
    assert 'log=dastuser' in seen["script"] and 'pwd=DastUserPass123!' in seen["script"]
    assert "user_name=" not in seen["script"]
    assert "wp-submit=Log In" in seen["script"]


def test_empty_csrf_field_posts_no_bogus_pair_but_still_gets_the_page():
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        return '{"status":302,"cookie":"WPVAL"}'

    auth.login("http://target-wordpress", WP_PROFILE, "user", runner=fake_runner, fetch_factory=_authed_fetch)
    # no `=$CSRF` pair, but the GET-first still happens (test cookie)
    assert '="$CSRF"' not in seen["script"] and '=$CSRF' not in seen["script"]
    assert "/wp-login.php" in seen["script"]


# -- the `json` strategy (Grafana) -----------------------------------------

GRAFANA_PROFILE = AuthProfile(
    login_path="/login",
    csrf_field="",
    session_cookie="grafana_session",
    logged_in_indicator="Sign out",
    strategy="json",
    username_field="user",
    password_field="password",
    users=(AuthUser("admin", "admin", "DastAdminPass123!"),),
)


def test_json_is_a_builtin_strategy():
    assert "json" in auth.STRATEGIES


def test_json_login_posts_a_json_body_not_a_form():
    """Grafana's login is a JSON API: a single POST of a JSON credential body,
    no CSRF token to harvest and no prior page fetch."""
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        return '{"status":200,"cookie":"GRAFVAL"}'

    session = auth.login("http://target-grafana:3000", GRAFANA_PROFILE, "admin",
                         runner=fake_runner, fetch_factory=_authed_fetch)
    assert session.cookie_header() == "grafana_session=GRAFVAL"
    assert session.status == 200
    # a JSON body carrying the profile's own field names, sent as application/json
    assert "application/json" in seen["script"]
    assert '"user": "admin"' in seen["script"]
    assert '"password": "DastAdminPass123!"' in seen["script"]
    assert "/login" in seen["script"]
    # it is NOT the form flow: no urlencoded credential pairs, no CSRF read
    assert "--data-urlencode" not in seen["script"]
    assert "CSRF" not in seen["script"]


def test_json_login_folds_in_extra_fields():
    """extra_login_fields become extra JSON keys, so a JSON-login target that
    needs a fixed extra field stays data, not code."""
    import dataclasses
    seen = {}

    def fake_runner(script, network, timeout):
        seen["script"] = script
        return '{"status":200,"cookie":"X"}'

    profile = dataclasses.replace(GRAFANA_PROFILE,
                                  extra_login_fields=(("org", "1"),))
    auth.login("http://target-grafana:3000", profile, "admin", runner=fake_runner, fetch_factory=_authed_fetch)
    assert '"org": "1"' in seen["script"]


def test_json_login_without_cookie_errors():
    def no_cookie(script, network, timeout):
        return '{"status":401,"cookie":""}'
    with pytest.raises(auth.AuthError):
        auth.login("http://t", GRAFANA_PROFILE, "admin", runner=no_cookie)


# -- the fail-closed authentication gate -----------------------------------
# login no longer trusts "a cookie came back": it USES the cookie and checks the
# target renders `logged_in_indicator`. This is the gate that would have caught
# the October campaign's silently-logged-out Gitea corpus.


def test_login_marks_a_confirmed_session_authenticated():
    session = auth.login(
        "http://target-gitea:3000", PROFILE, "user",
        runner=lambda *a: '{"status":302,"cookie":"OK"}',
        fetch_factory=_authed_fetch)
    assert session.authenticated is True


def test_login_fails_closed_when_the_session_is_not_recognised():
    """A cookie came back but the target serves the anonymous page — the exact
    campaign failure. Login must RAISE rather than thread a logged-out session
    into every probe."""
    def logged_out(network=None, cookie=None, **_kw):
        # the sign-in page: the indicator is absent
        return lambda method, url, timeout: (200, "", "<html>Please Sign In</html>")

    with pytest.raises(auth.AuthError, match="is NOT authenticated"):
        auth.login("http://target-gitea:3000", PROFILE, "user",
                   runner=lambda *a: '{"status":200,"cookie":"anon"}',
                   fetch_factory=logged_out)


def test_auth_gate_fetches_the_root_with_the_whole_jar():
    """The check GETs base_url + check-path (root by default), replaying the full
    cookie jar — the multi-cookie session wp-admin needs, not just the primary."""
    seen = {}

    def spy(network=None, cookie=None, **_kw):
        seen["cookie"] = cookie
        def fetch(method, url, timeout):
            seen["method"], seen["url"] = method, url
            return 200, "", _INDICATORS_BODY
        return fetch

    auth.login(
        "http://target-wordpress", WP_PROFILE, "user",
        runner=lambda *a: ('{"status":302,"cookie":"V",'
                           '"jar":"wordpress_logged_in_h=V; wordpress_sec_h=S"}'),
        fetch_factory=spy)
    assert seen["method"] == "GET"
    assert seen["url"] == "http://target-wordpress/"
    assert seen["cookie"] == "wordpress_logged_in_h=V; wordpress_sec_h=S"


def test_auth_gate_honours_logged_in_check_path():
    """A target whose root does not carry the indicator can point the check
    elsewhere via `logged_in_check_path` — data, not code."""
    import dataclasses
    seen = {}
    prof = dataclasses.replace(PROFILE, logged_in_check_path="/api/me")

    def spy(network=None, cookie=None, **_kw):
        def fetch(method, url, timeout):
            seen["url"] = url
            return 200, "", _INDICATORS_BODY
        return fetch

    auth.login("http://target-gitea:3000", prof, "user",
               runner=lambda *a: '{"status":302,"cookie":"OK"}', fetch_factory=spy)
    assert seen["url"] == "http://target-gitea:3000/api/me"
