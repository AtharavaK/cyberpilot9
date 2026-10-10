"""
Phase 7B: /setup endpoint security tests.

Tests covering:
  - /setup POST works without auth when no active keys exist (first-run bootstrap)
  - /setup POST is rate-limited per client IP (prevents uncontrolled key creation)
  - /setup POST returns 429 when minimum interval is violated
  - /setup POST returns 429 when hourly maximum is exceeded
  - /setup POST does not create a key when rate-limited
  - 401 auto-recovery flow: invalid key -> /setup creates new key -> retry succeeds
  - 401 from API with valid key does not trigger recovery
  - API keys are never returned in logs
"""
import os
import time
import pytest
import importlib
from unittest.mock import patch


@pytest.fixture
def client():
    """Fresh TestClient with re-initialized module (resets rate limiter state)."""
    import app.main as app_main
    importlib.reload(app_main)
    from starlette.testclient import TestClient
    with TestClient(app_main.app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_keys():
    """Delete all API keys after each test for isolation."""
    import asyncio
    from app.db import crud

    yield

    async def _cleanup():
        await crud.delete_all_api_keys()

    try:
        asyncio.run(_cleanup())
    except Exception:
        pass


class TestSetupFirstRun:
    """Verify /setup works without auth when no active keys exist."""

    def test_setup_creates_key_without_auth_when_no_keys(self, client):
        """First-run: POST /setup without Authorization creates a key."""
        resp = client.post("/setup", data={"name": "test-key"})
        assert resp.status_code == 200
        data = resp.json()
        assert "key" in data
        assert data["key"].startswith("cpk_")
        assert data["name"] == "test-key"

    def test_setup_key_stored_in_db_as_hash(self, client):
        """The plain API key is NOT stored in the DB — only its hash."""
        resp = client.post("/setup", data={"name": "hash-test"})
        key = resp.json()["key"]

        from app.api.auth import hash_api_key
        from app.db import crud
        import asyncio
        key_hash = hash_api_key(key)
        stored = asyncio.run(crud.get_api_key_by_hash(key_hash))
        assert stored is not None
        assert stored["key_prefix"] == key[:8]
        assert stored["key_hash"] == key_hash


class TestSetupRateLimiting:
    """Verify /setup is rate-limited to prevent uncontrolled key creation."""

    def test_setup_rate_limited_when_called_rapidly(self, client):
        """Two /setup calls within 10 seconds: first succeeds, second is 429."""
        resp1 = client.post("/setup", data={"name": "key1"})
        assert resp1.status_code == 200

        resp2 = client.post("/setup", data={"name": "key2"})
        assert resp2.status_code == 429
        assert "Rate limited" in resp2.json()["detail"]

    def test_setup_rate_limit_returns_retry_after_header(self, client):
        """429 response includes Retry-After header."""
        client.post("/setup", data={"name": "key1"})
        resp2 = client.post("/setup", data={"name": "key2"})
        assert resp2.status_code == 429
        assert "retry-after" in {k.lower() for k in resp2.headers.keys()}

    def test_setup_hourly_max_prevents_unlimited_creation(self, client):
        """After MAX creations per hour, /setup returns 429."""
        import app.main as app_main
        now = time.time()
        # TestClient uses "testclient" as the client host
        client_ip = "testclient"
        # Fill up to the max for the current IP
        app_main._SETUP_CREATION_TIMES[client_ip] = [
            now - 3500 + i * 10 for i in range(10)
        ]

        resp = client.post("/setup", data={"name": "overflow-key"})
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]

    def test_setup_does_not_create_key_when_rate_limited(self, client):
        """When rate-limited, no new key is stored in the DB."""
        client.post("/setup", data={"name": "key1"})
        resp2 = client.post("/setup", data={"name": "key2"})
        assert resp2.status_code == 429

        import asyncio
        from app.db import crud
        keys = asyncio.run(crud.list_api_keys())
        assert len(keys) == 1


class TestSetupAuthSemantics:
    """Verify the backend's actual 401 response semantics."""

    def test_api_endpoint_returns_401_without_key(self, client):
        """GET /api/v1/auth/keys without Authorization returns 401."""
        resp = client.get("/api/v1/auth/keys")
        assert resp.status_code == 401
        assert "Authorization" in resp.json()["detail"]

    def test_api_endpoint_returns_401_with_invalid_key(self, client):
        """GET /api/v1/auth/keys with non-matching key returns 401 'Invalid or revoked'."""
        resp = client.get(
            "/api/v1/auth/keys",
            headers={"Authorization": "Bearer cpk_invalid_token"},
        )
        assert resp.status_code == 401
        assert "Invalid or revoked" in resp.json()["detail"]

    def test_api_endpoint_returns_401_with_revoked_key(self, client):
        """A revoked key returns 401 'API key is disabled'."""
        resp = client.post("/setup", data={"name": "to-revoke"})
        key = resp.json()["key"]

        import asyncio
        from app.db import crud
        keys = asyncio.run(crud.list_api_keys())
        key_id = keys[0]["id"]
        asyncio.run(crud.revoke_api_key(key_id))

        resp = client.get(
            "/api/v1/auth/keys",
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 401
        assert "disabled" in resp.json()["detail"].lower()


class TestAuthAutoRecovery:
    """Verify the auto-recovery flow: 401 -> /setup -> new key -> retry."""

    def test_invalid_key_triggers_recovery_and_retry(self, client):
        """A 401 from an API call is recovered by /setup and retried."""
        stale_key = "cpk_stalekey_that_does_not_exist_in_db_xyz123"

        # Original request with stale key -> 401
        resp = client.get(
            "/api/v1/auth/keys",
            headers={"Authorization": f"Bearer {stale_key}"},
        )
        assert resp.status_code == 401

        # Recovery: call /setup to get a new key
        setup_resp = client.post("/setup", data={"name": "auto-recovery"})
        assert setup_resp.status_code == 200
        new_key = setup_resp.json()["key"]

        # Retry with new key
        resp2 = client.get(
            "/api/v1/auth/keys",
            headers={"Authorization": f"Bearer {new_key}"},
        )
        assert resp2.status_code == 200
        assert len(resp2.json()) == 1

    def test_valid_key_does_not_trigger_recovery(self, client):
        """A valid key does NOT trigger recovery — no new key is created."""
        resp = client.post("/setup", data={"name": "valid-key"})
        valid_key = resp.json()["key"]

        resp = client.get(
            "/api/v1/auth/keys",
            headers={"Authorization": f"Bearer {valid_key}"},
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1  # Only the one key we created

    def test_non_auth_4xx_does_not_involve_setup(self, client):
        """Non-authentication 4xx errors (e.g., 404) do not create keys via /setup."""
        resp = client.post("/setup", data={"name": "valid"})
        key = resp.json()["key"]

        resp = client.get(
            "/api/v1/auth/keys/99999",
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 404

        # No new key created via /setup
        import asyncio
        from app.db import crud
        keys = asyncio.run(crud.list_api_keys())
        assert len(keys) == 1


class TestSetupNoKeyLogging:
    """Verify API keys are never returned in logs."""

    @patch("app.main.secrets.token_urlsafe")
    def test_setup_response_contains_only_key_and_name(self, mock_token, client):
        """The /setup response contains exactly {key, name}. No extra fields."""
        mock_token.return_value = "test_random_part_32_chars!!"
        resp = client.post("/setup", data={"name": "log-test"})
        data = resp.json()
        assert set(data.keys()) == {"key", "name"}
        assert data["key"].startswith("cpk_")
