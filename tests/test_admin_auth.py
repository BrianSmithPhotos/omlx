# SPDX-License-Identifier: Apache-2.0
"""Tests for admin authentication and chat page API key injection."""

import asyncio
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

import omlx.server  # noqa: F401 — ensure server module is imported first
import omlx.admin.auth as admin_auth
import omlx.admin.routes as admin_routes


def _mock_global_settings(api_key=None):
    """Create a mock GlobalSettings with the given API key."""
    mock = MagicMock()
    mock.auth.api_key = api_key
    mock.auth.skip_api_key_verification = False
    return mock


def _patch_getter(mock_settings):
    """Replace the module-level _get_global_settings with a lambda returning mock."""
    original = admin_routes._get_global_settings
    admin_routes._get_global_settings = lambda: mock_settings
    return original


def _restore_getter(original):
    """Restore the original _get_global_settings."""
    admin_routes._get_global_settings = original


def _mock_http_request(ip="127.0.0.1", scheme="http"):
    """Create a mock Request with a given client IP and scheme."""
    req = MagicMock()
    req.client.host = ip
    req.url.scheme = scheme
    req.headers.get.return_value = ""
    return req


class TestAutoLogin:
    """Tests for GET /admin/auto-login endpoint (jundot/omlx#924).

    The endpoint now takes a short-lived, single-use token minted by
    POST /admin/api/auto-login-token instead of the raw API key, so the
    key never appears in a URL. See TestAutoLoginTokenEndpoint and
    TestAutoLoginTokenLifecycle for the token-issuance/expiry behavior.
    """

    def setup_method(self):
        admin_auth._auto_login_tokens.clear()

    def teardown_method(self):
        admin_auth._auto_login_tokens.clear()

    def test_auto_login_success_redirects_to_dashboard(self):
        """Valid token should redirect to the specified path with session cookie."""
        token = admin_auth.create_auto_login_token()
        result = asyncio.run(
            admin_routes.auto_login(
                http_request=_mock_http_request(), token=token, redirect="/admin/dashboard"
            )
        )
        assert result.status_code == 302
        assert result.headers["location"] == "/admin/dashboard"
        cookie_header = result.headers.get("set-cookie", "")
        assert "omlx_admin_session" in cookie_header

    def test_auto_login_success_redirects_to_chat(self):
        """Valid token should redirect to chat page."""
        token = admin_auth.create_auto_login_token()
        result = asyncio.run(
            admin_routes.auto_login(
                http_request=_mock_http_request(), token=token, redirect="/admin/chat"
            )
        )
        assert result.status_code == 302
        assert result.headers["location"] == "/admin/chat"

    def test_auto_login_invalid_token_redirects_to_login(self):
        """Unknown token should redirect to login page without session cookie."""
        result = asyncio.run(
            admin_routes.auto_login(
                http_request=_mock_http_request(), token="bogus-token", redirect="/admin/dashboard"
            )
        )
        assert result.status_code == 302
        assert result.headers["location"] == "/admin"
        cookie_header = result.headers.get("set-cookie", "")
        assert "omlx_admin_session" not in cookie_header

    def test_auto_login_empty_token_redirects_to_login(self):
        """Empty token should redirect to login page."""
        result = asyncio.run(
            admin_routes.auto_login(
                http_request=_mock_http_request(), token="", redirect="/admin/dashboard"
            )
        )
        assert result.status_code == 302
        assert result.headers["location"] == "/admin"

    def test_auto_login_token_is_single_use(self):
        """A token can only redeem a session once."""
        token = admin_auth.create_auto_login_token()
        first = asyncio.run(
            admin_routes.auto_login(http_request=_mock_http_request(), token=token)
        )
        assert first.status_code == 302
        assert first.headers["location"] == "/admin/dashboard"

        second = asyncio.run(
            admin_routes.auto_login(http_request=_mock_http_request(), token=token)
        )
        assert second.headers["location"] == "/admin"
        cookie_header = second.headers.get("set-cookie", "")
        assert "omlx_admin_session" not in cookie_header

    def test_auto_login_invalid_redirect_returns_400(self):
        """Redirect path not starting with /admin should return 400."""
        token = admin_auth.create_auto_login_token()
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                admin_routes.auto_login(
                    http_request=_mock_http_request(), token=token, redirect="https://evil.com"
                )
            )
        assert exc_info.value.status_code == 400
        assert "Invalid redirect path" in exc_info.value.detail

    def test_auto_login_redirect_to_admin_root(self):
        """Redirect to /admin (exact match) should be allowed."""
        token = admin_auth.create_auto_login_token()
        result = asyncio.run(
            admin_routes.auto_login(http_request=_mock_http_request(), token=token, redirect="/admin")
        )
        assert result.status_code == 302
        assert result.headers["location"] == "/admin"


class TestAutoLoginTokenEndpoint:
    """Tests for POST /admin/api/auto-login-token (jundot/omlx#924)."""

    def setup_method(self):
        admin_auth._auto_login_tokens.clear()
        admin_auth._failed_login_attempts.clear()

    def teardown_method(self):
        admin_auth._auto_login_tokens.clear()
        admin_auth._failed_login_attempts.clear()

    def test_valid_api_key_returns_redeemable_token(self):
        mock_settings = _mock_global_settings(api_key="test-key")
        original = _patch_getter(mock_settings)
        try:
            request = admin_routes.AutoLoginTokenRequest(api_key="test-key")
            result = asyncio.run(
                admin_routes.create_auto_login_token_endpoint(
                    request, _mock_http_request(ip="10.9.9.1")
                )
            )
            assert "token" in result
            redirect_result = asyncio.run(
                admin_routes.auto_login(
                    http_request=_mock_http_request(), token=result["token"]
                )
            )
            assert redirect_result.status_code == 302
            assert redirect_result.headers["location"] == "/admin/dashboard"
        finally:
            _restore_getter(original)

    def test_invalid_api_key_raises_401(self):
        mock_settings = _mock_global_settings(api_key="correct-key")
        original = _patch_getter(mock_settings)
        try:
            request = admin_routes.AutoLoginTokenRequest(api_key="wrong-key")
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    admin_routes.create_auto_login_token_endpoint(
                        request, _mock_http_request(ip="10.9.9.2")
                    )
                )
            assert exc_info.value.status_code == 401
        finally:
            _restore_getter(original)

    def test_no_server_key_configured_raises_400(self):
        mock_settings = _mock_global_settings(api_key=None)
        original = _patch_getter(mock_settings)
        try:
            request = admin_routes.AutoLoginTokenRequest(api_key="any-key")
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    admin_routes.create_auto_login_token_endpoint(
                        request, _mock_http_request(ip="10.9.9.3")
                    )
                )
            assert exc_info.value.status_code == 400
        finally:
            _restore_getter(original)


class TestAutoLoginTokenLifecycle:
    """Direct tests for create/consume_auto_login_token (jundot/omlx#924)."""

    def setup_method(self):
        admin_auth._auto_login_tokens.clear()

    def teardown_method(self):
        admin_auth._auto_login_tokens.clear()

    def test_consume_returns_true_exactly_once(self):
        token = admin_auth.create_auto_login_token()
        assert admin_auth.consume_auto_login_token(token) is True
        assert admin_auth.consume_auto_login_token(token) is False

    def test_consume_rejects_unknown_token(self):
        assert admin_auth.consume_auto_login_token("does-not-exist") is False

    def test_consume_rejects_empty_token(self):
        assert admin_auth.consume_auto_login_token("") is False

    def test_consume_rejects_expired_token(self):
        token = admin_auth.create_auto_login_token()
        # Force expiry without sleeping.
        admin_auth._auto_login_tokens[token] = time.monotonic() - 1
        assert admin_auth.consume_auto_login_token(token) is False

    def test_create_prunes_expired_entries(self):
        stale = "stale-token"
        admin_auth._auto_login_tokens[stale] = time.monotonic() - 1
        admin_auth.create_auto_login_token()
        assert stale not in admin_auth._auto_login_tokens


class TestLoginPage:
    """Tests for GET /admin login page TemplateResponse signature."""

    def test_login_page_uses_new_template_signature(self):
        """login_page should pass request as first arg to TemplateResponse."""
        mock_settings = _mock_global_settings(api_key="test-key")
        original = _patch_getter(mock_settings)
        try:
            mock_request = MagicMock()
            with patch("omlx.admin.auth.verify_session", return_value=False):
                with patch.object(admin_routes, "templates") as mock_templates:
                    mock_templates.TemplateResponse.return_value = MagicMock()
                    asyncio.run(admin_routes.login_page(request=mock_request))
                    mock_templates.TemplateResponse.assert_called_once_with(
                        mock_request, "login.html", {"api_key_configured": True}
                    )
        finally:
            _restore_getter(original)


class TestDashboardPage:
    """Tests for GET /admin/dashboard TemplateResponse signature."""

    def test_dashboard_page_uses_new_template_signature(self):
        """dashboard_page should pass request as first arg to TemplateResponse."""
        mock_request = MagicMock()
        with patch.object(admin_routes, "templates") as mock_templates:
            mock_templates.TemplateResponse.return_value = MagicMock()
            asyncio.run(
                admin_routes.dashboard_page(request=mock_request, is_admin=True)
            )
            mock_templates.TemplateResponse.assert_called_once_with(
                mock_request, "dashboard.html", {}
            )


class TestChatPageApiKeyInjection:
    """Tests for GET /admin/chat API key template injection."""

    def test_chat_page_passes_api_key_in_context(self):
        """Chat page should include API key in template context."""
        mock_settings = _mock_global_settings(api_key="test-chat-key")
        original = _patch_getter(mock_settings)
        try:
            mock_request = MagicMock()
            with patch.object(admin_routes, "templates") as mock_templates:
                mock_templates.TemplateResponse.return_value = MagicMock()
                asyncio.run(
                    admin_routes.chat_page(request=mock_request, is_admin=True)
                )
                mock_templates.TemplateResponse.assert_called_once_with(
                    mock_request,
                    "chat.html",
                    {"api_key": "test-chat-key"},
                )
        finally:
            _restore_getter(original)

    def test_chat_page_passes_empty_when_no_key(self):
        """Chat page should pass empty string when no API key is configured."""
        mock_settings = _mock_global_settings(api_key=None)
        original = _patch_getter(mock_settings)
        try:
            mock_request = MagicMock()
            with patch.object(admin_routes, "templates") as mock_templates:
                mock_templates.TemplateResponse.return_value = MagicMock()
                asyncio.run(
                    admin_routes.chat_page(request=mock_request, is_admin=True)
                )
                call_args = mock_templates.TemplateResponse.call_args
                context = call_args[0][2]
                assert context["api_key"] == ""
        finally:
            _restore_getter(original)

    def test_chat_page_passes_empty_when_no_settings(self):
        """Chat page should pass empty string when global settings is None."""
        original = admin_routes._get_global_settings
        admin_routes._get_global_settings = lambda: None
        try:
            mock_request = MagicMock()
            with patch.object(admin_routes, "templates") as mock_templates:
                mock_templates.TemplateResponse.return_value = MagicMock()
                asyncio.run(
                    admin_routes.chat_page(request=mock_request, is_admin=True)
                )
                call_args = mock_templates.TemplateResponse.call_args
                context = call_args[0][2]
                assert context["api_key"] == ""
        finally:
            admin_routes._get_global_settings = original


class TestSkipAdminAuth:
    """Tests for skipping admin auth when skip_api_key_verification is enabled."""

    def _mock_gs(self, skip=True, host="127.0.0.1"):
        mock = MagicMock()
        mock.auth.skip_api_key_verification = skip
        mock.server.host = host
        return mock

    def test_require_admin_skipped_on_localhost(self):
        """require_admin should pass when skip_api_key_verification=True."""
        gs = self._mock_gs(skip=True, host="127.0.0.1")
        original = admin_auth._get_global_settings
        admin_auth._get_global_settings = lambda: gs
        try:
            mock_request = MagicMock()
            mock_request.cookies.get.return_value = None  # No session cookie
            result = asyncio.run(admin_auth.require_admin(mock_request))
            assert result is True
        finally:
            admin_auth._get_global_settings = original

    def test_require_admin_skipped_on_any_host(self):
        """require_admin should skip auth when skip_api_key_verification=True regardless of host."""
        gs = self._mock_gs(skip=True, host="0.0.0.0")
        original = admin_auth._get_global_settings
        admin_auth._get_global_settings = lambda: gs
        try:
            mock_request = MagicMock()
            mock_request.cookies.get.return_value = None
            result = asyncio.run(admin_auth.require_admin(mock_request))
            assert result is True
        finally:
            admin_auth._get_global_settings = original

    def test_require_admin_not_skipped_when_disabled(self):
        """require_admin should still require auth when skip_api_key_verification=False."""
        gs = self._mock_gs(skip=False, host="127.0.0.1")
        original = admin_auth._get_global_settings
        admin_auth._get_global_settings = lambda: gs
        try:
            mock_request = MagicMock()
            mock_request.cookies.get.return_value = None
            mock_request.headers.get.return_value = "application/json"
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(admin_auth.require_admin(mock_request))
            assert exc_info.value.status_code == 401
        finally:
            admin_auth._get_global_settings = original

    def test_login_page_redirects_when_skip_enabled(self):
        """Login page should redirect to dashboard when skip is enabled on localhost."""
        gs = MagicMock()
        gs.auth.skip_api_key_verification = True
        gs.auth.api_key = "test-key"
        gs.server.host = "127.0.0.1"
        original = _patch_getter(gs)
        try:
            mock_request = MagicMock()
            with patch("omlx.admin.auth.verify_session", return_value=False):
                result = asyncio.run(admin_routes.login_page(request=mock_request))
                assert result.status_code == 302
                assert result.headers["location"] == "/admin/dashboard"
        finally:
            _restore_getter(original)


class TestInitAuth:
    """Tests for init_auth() persistent secret key initialization."""

    def test_init_auth_sets_serializer(self):
        """init_auth should update the serializer with the provided key."""
        original_serializer = admin_auth._serializer
        try:
            admin_auth.init_auth("test-persistent-secret-key")
            # Create a token with the new serializer
            token = admin_auth.create_session_token()
            assert admin_auth.verify_session_token(token) is True
        finally:
            admin_auth._serializer = original_serializer

    def test_init_auth_env_var_takes_priority(self):
        """OMLX_SECRET_KEY env var should take priority over provided key."""
        original_serializer = admin_auth._serializer
        original_secret = admin_auth.SECRET_KEY
        try:
            with patch.dict("os.environ", {"OMLX_SECRET_KEY": "env-secret-key"}):
                admin_auth.init_auth("settings-secret-key")
                assert admin_auth.SECRET_KEY == "env-secret-key"
        finally:
            admin_auth._serializer = original_serializer
            admin_auth.SECRET_KEY = original_secret

    def test_init_auth_uses_provided_key_when_no_env(self):
        """Should use provided key when no OMLX_SECRET_KEY env var."""
        original_serializer = admin_auth._serializer
        original_secret = admin_auth.SECRET_KEY
        try:
            with patch.dict("os.environ", {}, clear=True):
                # Remove OMLX_SECRET_KEY if it exists
                import os

                os.environ.pop("OMLX_SECRET_KEY", None)
                admin_auth.init_auth("my-persistent-key")
                assert admin_auth.SECRET_KEY == "my-persistent-key"
        finally:
            admin_auth._serializer = original_serializer
            admin_auth.SECRET_KEY = original_secret

    def test_tokens_survive_reinit_with_same_key(self):
        """Tokens created before re-init should still be valid with same key."""
        original_serializer = admin_auth._serializer
        original_secret = admin_auth.SECRET_KEY
        try:
            key = "persistent-key-for-test"
            admin_auth.init_auth(key)
            token = admin_auth.create_session_token()

            # Re-initialize with same key (simulates server restart)
            admin_auth.init_auth(key)
            assert admin_auth.verify_session_token(token) is True
        finally:
            admin_auth._serializer = original_serializer
            admin_auth.SECRET_KEY = original_secret

    def test_tokens_invalid_after_reinit_with_different_key(self):
        """Tokens should be invalid after re-init with a different key."""
        original_serializer = admin_auth._serializer
        original_secret = admin_auth.SECRET_KEY
        try:
            admin_auth.init_auth("key-one")
            token = admin_auth.create_session_token()

            admin_auth.init_auth("key-two")
            assert admin_auth.verify_session_token(token) is False
        finally:
            admin_auth._serializer = original_serializer
            admin_auth.SECRET_KEY = original_secret


class TestRememberMe:
    """Tests for remember me session token functionality."""

    def test_create_token_default_no_remember(self):
        """Default token should not have remember flag."""
        token = admin_auth.create_session_token()
        # Verify it works with default max_age
        assert admin_auth.verify_session_token(token) is True

    def test_create_token_with_remember(self):
        """Token with remember=True should be valid."""
        token = admin_auth.create_session_token(remember=True)
        assert admin_auth.verify_session_token(token) is True

    def test_remember_token_has_extended_max_age(self):
        """Remember token should use 30-day max_age for verification."""
        token = admin_auth.create_session_token(remember=True)
        # Manually load the payload to check the remember flag
        data = admin_auth._serializer.loads(token, max_age=None)
        assert data["remember"] is True
        assert data["admin"] is True

    def test_non_remember_token_payload(self):
        """Non-remember token should have remember=False in payload."""
        token = admin_auth.create_session_token(remember=False)
        data = admin_auth._serializer.loads(token, max_age=None)
        assert data["remember"] is False
        assert data["admin"] is True

    def test_remember_me_max_age_constant(self):
        """REMEMBER_ME_MAX_AGE should be 30 days."""
        assert admin_auth.REMEMBER_ME_MAX_AGE == 2592000  # 30 * 24 * 60 * 60

    def test_session_max_age_constant(self):
        """SESSION_MAX_AGE should be 24 hours."""
        assert admin_auth.SESSION_MAX_AGE == 86400  # 24 * 60 * 60


# =============================================================================
# Update Check
# =============================================================================


def _make_async_return(value):
    """Create a coroutine function that returns the given value."""

    async def _coro(*args, **kwargs):
        return value

    return _coro


class _FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json


class TestCheckUpdate:
    """Tests for update-check version filtering."""

    def setup_method(self):
        admin_routes._update_cache = {}
        admin_routes._update_cache_time = {}
        admin_routes._UPDATE_PREFS_PATH = Path(
            "/tmp/omlx-test-missing-update-prefs.json"
        )

    @pytest.mark.asyncio
    async def test_prerelease_not_shown(self):
        """Dev/pre-release GitHub releases should not trigger update notification."""
        fake_resp = _FakeResponse(
            200,
            [{
                "tag_name": "v99.0.0.dev1",
                "html_url": "https://github.com/jundot/omlx/releases/tag/v99.0.0.dev1",
            }],
        )
        with patch("omlx.admin.routes.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = _make_async_return(fake_resp)
            result = await admin_routes.check_update(is_admin=True)

        assert result["update_available"] is False
        assert result["latest_version"] is None

    @pytest.mark.asyncio
    async def test_stable_version_shown(self):
        """Stable GitHub releases should trigger update notification."""
        fake_resp = _FakeResponse(
            200,
            [{
                "tag_name": "v99.0.0",
                "html_url": "https://github.com/jundot/omlx/releases/tag/v99.0.0",
            }],
        )
        with patch("omlx.admin.routes.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = _make_async_return(fake_resp)
            result = await admin_routes.check_update(is_admin=True)

        assert result["update_available"] is True
        assert result["latest_version"] == "99.0.0"

    @pytest.mark.asyncio
    async def test_rc_not_shown(self):
        """RC releases should not trigger update notification."""
        fake_resp = _FakeResponse(
            200,
            [{
                "tag_name": "v99.0.0rc1",
                "html_url": "https://github.com/jundot/omlx/releases/tag/v99.0.0rc1",
            }],
        )
        with patch("omlx.admin.routes.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = _make_async_return(fake_resp)
            result = await admin_routes.check_update(is_admin=True)

        assert result["update_available"] is False
        assert result["latest_version"] is None


class TestLoginRateLimit:
    """Tests for the failed-login lockout (jundot/omlx#925)."""

    def setup_method(self):
        admin_auth._failed_login_attempts.clear()

    def teardown_method(self):
        admin_auth._failed_login_attempts.clear()

    def test_allows_attempts_below_limit(self):
        for _ in range(admin_auth.LOGIN_ATTEMPT_LIMIT - 1):
            admin_auth.record_failed_login("1.2.3.4")
            admin_auth.check_login_rate_limit("1.2.3.4")  # should not raise

    def test_blocks_once_limit_reached(self):
        for _ in range(admin_auth.LOGIN_ATTEMPT_LIMIT):
            admin_auth.record_failed_login("1.2.3.5")
        with pytest.raises(HTTPException) as exc_info:
            admin_auth.check_login_rate_limit("1.2.3.5")
        assert exc_info.value.status_code == 429

    def test_different_clients_tracked_independently(self):
        for _ in range(admin_auth.LOGIN_ATTEMPT_LIMIT):
            admin_auth.record_failed_login("1.2.3.6")
        admin_auth.check_login_rate_limit("1.2.3.7")  # different IP, should not raise

    def test_clear_login_attempts_resets_lockout(self):
        for _ in range(admin_auth.LOGIN_ATTEMPT_LIMIT):
            admin_auth.record_failed_login("1.2.3.8")
        admin_auth.clear_login_attempts("1.2.3.8")
        admin_auth.check_login_rate_limit("1.2.3.8")  # should not raise

    def test_old_attempts_outside_window_are_dropped(self):
        stale = time.monotonic() - admin_auth.LOGIN_ATTEMPT_WINDOW_SECONDS - 1
        admin_auth._failed_login_attempts["1.2.3.9"] = [stale] * admin_auth.LOGIN_ATTEMPT_LIMIT
        admin_auth.check_login_rate_limit("1.2.3.9")  # should not raise; all stale

    @pytest.mark.asyncio
    async def test_login_endpoint_returns_429_after_repeated_failures(self):
        mock_settings = MagicMock()
        mock_settings.auth.api_key = "correct-key"
        original = admin_routes._get_global_settings
        admin_routes._get_global_settings = lambda: mock_settings
        http_request = MagicMock()
        http_request.client.host = "9.9.9.9"
        try:
            request = admin_routes.LoginRequest(api_key="wrong-key")
            for _ in range(admin_auth.LOGIN_ATTEMPT_LIMIT):
                with pytest.raises(HTTPException) as exc_info:
                    await admin_routes.login(request, http_request, MagicMock())
                assert exc_info.value.status_code == 401

            with pytest.raises(HTTPException) as exc_info:
                await admin_routes.login(request, http_request, MagicMock())
            assert exc_info.value.status_code == 429
        finally:
            admin_routes._get_global_settings = original


class TestSessionCookieSecureFlag:
    """Tests for conditional Secure cookie flag (jundot/omlx#927)."""

    def test_request_is_https_plain_http(self):
        req = _mock_http_request(scheme="http")
        assert admin_auth.request_is_https(req) is False

    def test_request_is_https_direct_tls(self):
        req = _mock_http_request(scheme="https")
        assert admin_auth.request_is_https(req) is True

    def test_request_is_https_behind_proxy_header(self):
        req = _mock_http_request(scheme="http")
        req.headers.get.return_value = "https"
        assert admin_auth.request_is_https(req) is True

    def test_request_is_https_proxy_header_case_insensitive(self):
        req = _mock_http_request(scheme="http")
        req.headers.get.return_value = "HTTPS"
        assert admin_auth.request_is_https(req) is True

    @pytest.mark.asyncio
    async def test_login_cookie_not_secure_over_http(self):
        mock_settings = _mock_global_settings(api_key="main-key")
        original = _patch_getter(mock_settings)
        try:
            request = admin_routes.LoginRequest(api_key="main-key")
            mock_response = MagicMock()
            await admin_routes.login(
                request, _mock_http_request(scheme="http"), mock_response
            )
            assert mock_response.set_cookie.call_args.kwargs["secure"] is False
        finally:
            _restore_getter(original)

    @pytest.mark.asyncio
    async def test_login_cookie_secure_over_https(self):
        mock_settings = _mock_global_settings(api_key="main-key")
        original = _patch_getter(mock_settings)
        try:
            request = admin_routes.LoginRequest(api_key="main-key")
            mock_response = MagicMock()
            await admin_routes.login(
                request, _mock_http_request(scheme="https"), mock_response
            )
            assert mock_response.set_cookie.call_args.kwargs["secure"] is True
        finally:
            _restore_getter(original)
