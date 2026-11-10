"""The logged-out-scan fix: re-login after a reset, and the through-ZAP gate.

Regression tests for the 2026-10-29 defect — three authenticated targets
scanned logged out because ``--reset-target`` ran AFTER login and wiped the
server-side session, while the pre-reset curl confirm still recorded
``auth_authenticated=True``. The fix re-logins on the clean instance
(:func:`pipeline.reauthenticate_on_clean_target`) and verifies ZAP itself is
logged in before scanning (:func:`pipeline.verify_zap_authenticated`).
"""
import pytest

from dast_orchestrator.stages.scan import pipeline


class _Sess:
    def __init__(self, mode="user", username="dastuser"):
        self.mode = mode
        self.username = username


class _Profile:
    logged_in_indicator = "Sign Out"
    logged_in_check_path = "/"


class _FakeZap:
    """A ZAP whose through-ZAP fetch returns a fixed body."""

    def __init__(self, body):
        self._body = body
        self.fetched = []

    def fetch_body(self, url):
        self.fetched.append(url)
        return self._body


def test_verify_passes_when_zap_sees_the_indicator():
    zap = _FakeZap("<html>... Sign Out ...</html>")
    url, indicator = pipeline.verify_zap_authenticated(
        zap, target_url="http://target-gitea:3000",
        auth_profile=_Profile(), auth_session=_Sess())
    assert indicator == "Sign Out"
    assert zap.fetched == ["http://target-gitea:3000/"]


def test_verify_raises_when_zap_is_logged_out():
    zap = _FakeZap("<html> anonymous home, no indicator </html>")
    with pytest.raises(pipeline.ZapError) as exc:
        pipeline.verify_zap_authenticated(
            zap, target_url="http://target-gitea:3000/",
            auth_profile=_Profile(), auth_session=_Sess())
    assert "not logged in" in str(exc.value)


def test_verify_uses_the_profiles_check_path():
    class P(_Profile):
        logged_in_check_path = "/user/settings"

    zap = _FakeZap("Sign Out")
    url, _ = pipeline.verify_zap_authenticated(
        zap, target_url="http://t", auth_profile=P(), auth_session=_Sess())
    assert url == "http://t/user/settings"


def test_reauthenticate_logs_in_against_the_targets_profile(monkeypatch):
    calls = {}

    class _Target:
        auth = _Profile()

    monkeypatch.setattr(pipeline.targets, "get", lambda name: _Target())
    import dast_orchestrator.adapters.auth as auth_mod

    def fake_login(base, profile, mode, **kw):
        calls.update(base=base, profile=profile, mode=mode)
        return _Sess(mode=mode)

    monkeypatch.setattr(auth_mod, "login", fake_login)
    out = pipeline.reauthenticate_on_clean_target("gitea", "http://t", "admin")
    assert calls["base"] == "http://t"
    assert isinstance(calls["profile"], _Profile)
    assert calls["mode"] == "admin"
    assert out.mode == "admin"
