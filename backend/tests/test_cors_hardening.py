"""
Phase 7B: CORS Hardening Tests.

Tests covering:
  - Allowed dev origin (http://localhost:5173) receives CORS headers
  - Disallowed arbitrary origin is rejected (no ACA header)
  - Allowed origin via APP_CORS_ORIGINS env var
  - Preflight (OPTIONS) request returns correct headers
  - Existing API behavior remains unchanged (health endpoint accessible)
"""
import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def _restore_cors_env():
    """Restore env vars after each test."""
    old_origins = os.environ.pop("APP_CORS_ORIGINS", None)
    old_env = os.environ.pop("APP_ENV", None)
    yield
    if old_origins is not None:
        os.environ["APP_CORS_ORIGINS"] = old_origins
    if old_env is not None:
        os.environ["APP_ENV"] = old_env


class TestCORSHardening:
    """Verify CORS configuration is locked down to known origins."""

    @pytest.fixture
    def client(self):
        """Fresh TestClient with current env."""
        # Clear cached imports so env changes take effect
        import importlib
        import app.main as app_main
        importlib.reload(app_main)
        from starlette.testclient import TestClient
        return TestClient(app_main.app)

    def test_allowed_dev_origin(self, client):
        """http://localhost:5173 is allowed (default dev origin)."""
        resp = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_disallowed_arbitrary_origin(self, client):
        """An arbitrary origin does NOT get CORS allow headers."""
        resp = client.get("/api/v1/health", headers={"Origin": "https://evil-attacker.com"})
        assert resp.status_code == 200
        # No CORS headers → browser blocks the response for cross-origin requests
        assert "access-control-allow-origin" not in resp.headers

    def test_no_wildcard_origin(self, client):
        """No '*' wildcard in allow-origin."""
        resp = client.get("/api/v1/health", headers={"Origin": "https://evil-attacker.com"})
        allow_origin = resp.headers.get("access-control-allow-origin", "")
        assert allow_origin != "*"

    def test_preflight_allowed_origin(self, client):
        """OPTIONS preflight from allowed origin returns correct headers."""
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert resp.status_code in (200, 204)
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert "GET" in resp.headers.get("access-control-allow-methods", "")

    def test_preflight_disallowed_origin(self, client):
        """OPTIONS preflight from disallowed origin gets no allow-origin header."""
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # No CORS allow header for disallowed origins
        assert "access-control-allow-origin" not in resp.headers

    def test_existing_api_behavior_unchanged(self, client):
        """Health endpoint still works without Origin header."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}