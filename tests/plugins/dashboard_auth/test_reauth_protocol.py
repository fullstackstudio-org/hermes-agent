"""The provider protocol's fresh-authentication surface (passkey self-enrolment).

A provider can be asked to authenticate the person again (``start_login(..., fresh=True)``) and says
whether it can (``supports_reauth``); a :class:`Session` carries ``auth_time``, when the provider
verified that authentication. A provider written before this existed (no ``fresh``, no flag) keeps
working unchanged: the routes pass ``fresh`` only to a provider that declares ``supports_reauth``.
"""

from __future__ import annotations

import urllib.parse

import pytest

import plugins.dashboard_auth.basic as basic_plugin
import plugins.dashboard_auth.drain as drain_plugin
import plugins.dashboard_auth.nous as nous_plugin
import plugins.dashboard_auth.self_hosted as oidc_plugin
from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    Session,
    assert_protocol_compliance,
)
from plugins.dashboard_auth._shared import NonInteractiveMixin, pkce_login_start


def _session(**kw) -> Session:
    base = dict(user_id="u1", email="", display_name="U", org_id="", provider="p", expires_at=1,
                access_token="at-marker", refresh_token="rt-marker")
    base.update(kw)
    return Session(**base)


class _LegacyProvider(DashboardAuthProvider):
    """An external provider as written before re-authentication existed: no ``fresh``, no flag."""

    name = "legacy"
    display_name = "Legacy IdP"

    def start_login(self, *, redirect_uri):
        return LoginStart(redirect_url="https://idp.example/authorize", cookie_payload={})

    def complete_login(self, *, code, state, code_verifier, redirect_uri):
        return _session(provider=self.name)

    def verify_session(self, *, access_token):
        return None

    def refresh_session(self, *, refresh_token):
        return _session(provider=self.name)

    def revoke_session(self, *, refresh_token):
        return None


class TestSessionAuthTime:
    def test_defaults_to_unknown(self):
        assert _session().auth_time == 0

    def test_kept_out_of_repr(self):
        s = _session(auth_time=1759400123)
        assert s.auth_time == 1759400123
        assert "1759400123" not in repr(s)
        assert "auth_time" not in repr(s)


class TestProtocol:
    def test_default_is_no_reauth(self):
        assert DashboardAuthProvider.supports_reauth is False
        assert _LegacyProvider.supports_reauth is False

    def test_legacy_external_provider_without_fresh_is_compliant(self):
        assert assert_protocol_compliance(_LegacyProvider) is None
        # And its old-signature start_login is still callable the way the routes call it today.
        assert _LegacyProvider().start_login(redirect_uri="https://h/auth/callback").redirect_url

    def test_reauth_provider_must_accept_fresh(self):
        class _Claims(_LegacyProvider):
            supports_reauth = True

        with pytest.raises(TypeError, match="fresh"):
            assert_protocol_compliance(_Claims)

    def test_reauth_provider_accepting_fresh_is_compliant(self):
        class _Fresh(_LegacyProvider):
            supports_reauth = True

            def start_login(self, *, redirect_uri, fresh=False):
                return super().start_login(redirect_uri=redirect_uri)

        assert assert_protocol_compliance(_Fresh) is None

    def test_reauth_provider_with_kwargs_start_login_is_compliant(self):
        class _Kw(_LegacyProvider):
            supports_reauth = True

            def start_login(self, *, redirect_uri, **kwargs):
                return super().start_login(redirect_uri=redirect_uri)

        assert assert_protocol_compliance(_Kw) is None

    def test_reauth_without_a_session_is_refused(self):
        class _TokenOnly(_LegacyProvider):
            supports_reauth = True
            supports_session = False

            def start_login(self, *, redirect_uri, fresh=False):
                raise NotImplementedError

        with pytest.raises(TypeError, match="supports_session"):
            assert_protocol_compliance(_TokenOnly)

    def test_password_provider_may_reauth_without_a_redirect(self):
        class _Pw(NonInteractiveMixin, _LegacyProvider):
            supports_password = True
            supports_reauth = True

        assert assert_protocol_compliance(_Pw) is None

    @pytest.mark.parametrize("cls,reauth", [
        (oidc_plugin.SelfHostedOIDCProvider, True),
        (basic_plugin.BasicAuthProvider, True),
        (nous_plugin.NousDashboardAuthProvider, False),
        (drain_plugin.DrainSecretProvider, False),
    ])
    def test_bundled_providers(self, cls, reauth):
        assert assert_protocol_compliance(cls) is None
        assert cls.supports_reauth is reauth

    def test_non_interactive_stub_accepts_fresh(self):
        class _Pw(NonInteractiveMixin, _LegacyProvider):
            pass

        with pytest.raises(NotImplementedError):
            _Pw().start_login(redirect_uri="https://h/auth/callback", fresh=True)


class TestPkceLoginStart:
    _BASE = dict(client_id="cid", scope="openid", redirect_uri="https://h/auth/callback")

    @staticmethod
    def _params(ls: LoginStart) -> dict:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(ls.redirect_url).query))

    def test_without_extra_params_unchanged(self):
        params = self._params(pkce_login_start("https://idp/authorize", **self._BASE))
        assert set(params) == {
            "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
            "code_challenge_method"}

    def test_extra_params_are_appended(self):
        params = self._params(pkce_login_start(
            "https://idp/authorize", **self._BASE, extra_params={"prompt": "login", "max_age": "0"}))
        assert params["prompt"] == "login" and params["max_age"] == "0"
        assert params["client_id"] == "cid" and params["code_challenge_method"] == "S256"

    @pytest.mark.parametrize("key", [
        "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
        "code_challenge_method"])
    def test_extra_params_cannot_replace_a_protocol_param(self, key):
        with pytest.raises(ValueError, match=key):
            pkce_login_start("https://idp/authorize", **self._BASE, extra_params={key: "x"})
