"""Credential redaction for stored artifacts (NFR-06).

Header values go by name (so an unknown session token is caught too); the
target's seeded passwords go by exact match. The marker is the loud
``==REDACTED==``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from dast_orchestrator.foundation import redaction


def test_placeholder_is_loud():
    assert redaction.PLACEHOLDER == "==REDACTED=="


def test_scrub_blanks_cookie_value_keeping_name_and_crlf():
    raw = "GET / HTTP/1.1\r\nHost: x\r\nCookie: i_like_gitea=abc; _csrf=z\r\n\r\nbody"
    out = redaction.scrub(raw)
    assert "i_like_gitea" not in out
    assert "Cookie: ==REDACTED==" in out
    assert "Host: x" in out                         # a non-auth header is kept
    assert out.count("\r\n") == raw.count("\r\n")   # line endings preserved


def test_scrub_blanks_set_cookie_and_authorization():
    raw = ("HTTP/1.1 200 OK\r\nSet-Cookie: s=secret; Path=/\r\n"
           "Authorization: Bearer tok123\r\n")
    out = redaction.scrub(raw)
    assert "secret" not in out and "tok123" not in out
    assert "Set-Cookie: ==REDACTED==" in out
    assert "Authorization: ==REDACTED==" in out


def test_header_match_is_case_insensitive():
    out = redaction.scrub("cookie: a=b\r\n")
    assert out == "cookie: ==REDACTED==\r\n"


def test_scrub_redacts_url_encoded_password_in_form_body():
    # A verification tool replays the seeded password inside a urlencoded login
    # body and echoes it back, so the stored byte form is percent-encoded
    # (``!`` -> ``%21``). The literal-only pass missed it (NFR-06 leak); both the
    # raw and the encoded form must blank.
    secret = "DastUserPass123!"
    obj = {
        "command": "sqlmap --data 'log=dastuser&pwd=DastUserPass123%21'",
        "stdout_excerpt": "Parameter: pwd\n    value: DastUserPass123%21",
        "raw_body": "log=dastuser&pwd=DastUserPass123!",
    }
    out = redaction.scrub(obj, secrets=[secret])
    blob = json.dumps(out)
    assert "DastUserPass123%21" not in blob          # encoded form caught
    assert "DastUserPass123!" not in blob            # raw form still caught
    assert blob.count("==REDACTED==") >= 3


def test_scrub_replaces_secret_strings_in_nested_structures():
    doc = {"rounds": [{"data": "wpdm_login[pwd]=DastUserPass123!&log=dastuser"}]}
    out = redaction.scrub(doc, ["DastUserPass123!"])
    assert "DastUserPass123!" not in json.dumps(out)
    assert "==REDACTED==" in out["rounds"][0]["data"]
    assert "dastuser" in out["rounds"][0]["data"]   # the username is not a secret
    # the input is not mutated — the live object keeps what it still needs
    assert "DastUserPass123!" in doc["rounds"][0]["data"]


def test_scrub_leaves_innocent_content_untouched():
    doc = {"a": 1, "b": ["x", "no secrets here"], "c": None}
    assert redaction.scrub(doc) == doc


def _target(user_passwords, fillers):
    auth = SimpleNamespace(
        users=[SimpleNamespace(password=p) for p in user_passwords]
    )
    return SimpleNamespace(auth=auth, form_fillers=fillers)


def test_target_secrets_collects_passwords_and_dedupes():
    t = _target(
        ["DastUserPass123!", "DastAdminPass123!"],
        {"password": "Password123!", "user_name": "thesis", "pwd": "DastUserPass123!"},
    )
    secrets = redaction.target_secrets(t)
    assert "DastUserPass123!" in secrets
    assert "DastAdminPass123!" in secrets
    assert "Password123!" in secrets          # a form-filler password field
    assert "thesis" not in secrets            # a non-password field is not a secret
    assert secrets.count("DastUserPass123!") == 1   # deduped across auth + fillers


def test_target_secrets_tolerates_no_auth():
    assert redaction.target_secrets(SimpleNamespace(auth=None, form_fillers={})) == []


def test_scrub_blanks_cookie_inside_a_command_string():
    # The session cookie reaches a verification record as a -H argument, not a
    # standalone header line; the inline match must still catch it.
    cmd = "curl -s -H 'Cookie: i_like_gitea=TOK; _csrf=z' http://target-gitea/x"
    out = redaction.scrub(cmd)
    assert "i_like_gitea" not in out
    assert "Cookie: ==REDACTED==" in out
    assert out.endswith("http://target-gitea/x")     # trailing args are kept


def test_scrub_does_not_match_a_longer_token_tail():
    # "precookie:" must not be treated as a Cookie header.
    assert redaction.scrub("precookie: value\r\n") == "precookie: value\r\n"


def test_scrub_blanks_cookie_in_a_structured_header_dict():
    # A request spec stores headers as JSON: {"Cookie": "a=1; i_like_gitea=TOK"}.
    doc = {"headers": {"Cookie": "lang=en; i_like_gitea=TOK", "Accept": "*/*"}}
    out = redaction.scrub(doc)
    assert out["headers"]["Cookie"] == "==REDACTED=="
    assert out["headers"]["Accept"] == "*/*"          # a benign header is kept


def test_scrub_redacts_cookie_value_by_name_in_a_flag():
    # sqlmap passes the cookie as --cookie <value>, not a Cookie: header.
    cmd = "sqlmap --cookie i_like_gitea=TOK; _csrf=Z --flush-session"
    out = redaction.scrub(cmd, cookie_names=["i_like_gitea", "_csrf"])
    assert "TOK" not in out and "=Z" not in out
    assert "i_like_gitea===REDACTED==" in out
    assert "_csrf===REDACTED==" in out
    assert out.endswith("--flush-session")            # the rest of the command is kept


def test_target_cookie_names():
    t = SimpleNamespace(auth=SimpleNamespace(session_cookie="i_like_gitea", csrf_field="_csrf"))
    assert redaction.target_cookie_names(t) == ["i_like_gitea", "_csrf"]
    assert redaction.target_cookie_names(SimpleNamespace(auth=None)) == []


def test_scrub_redacts_a_prefixed_hashed_cookie_name():
    # WordPress's auth cookie carries a per-install hash: wordpress_logged_in_<hash>.
    body = "--cookie wordpress_logged_in_abc123=THE%7Ctoken%7Cvalue&redirect=/"
    out = redaction.scrub(body, cookie_names=["wordpress_logged_in_"])
    assert "THE%7Ctoken" not in out
    assert "wordpress_logged_in_abc123===REDACTED==" in out
    assert out.endswith("&redirect=/")


def test_target_cookie_names_covers_the_wordpress_family():
    wp = SimpleNamespace(auth=SimpleNamespace(
        session_cookie="wordpress_logged_in_", csrf_field=""))
    names = redaction.target_cookie_names(wp)
    assert "wordpress_logged_in_" in names and "wordpress_" in names
    # the family root redacts the wp-admin auth cookie the config doesn't name
    jar = "wordpress_5db307=dastuser%7Ctoken; wordpress_logged_in_5db307=also%7Csecret"
    out = redaction.scrub(jar, cookie_names=names)
    assert "dastuser%7Ctoken" not in out and "also%7Csecret" not in out
