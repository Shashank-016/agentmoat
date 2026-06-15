"""Regression tests for optional API-key authentication (Fix 3).

Before this fix, every route on the audit API — including the kill switch —
was reachable by anyone who could route to the process. ``AGENTMOAT_API_KEY``
now gates every router except ``/health`` (kept open for liveness probes).
For backward compatibility, leaving the env var unset keeps the API open
(with a logged warning) so existing deployments don't break on upgrade.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENTMOAT_DB_URL", "sqlite+aiosqlite:///:memory:")
    with TestClient(app) as test_client:
        yield test_client


class TestHealthIsAlwaysOpen:
    def test_health_accessible_without_key_when_key_configured(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_accessible_without_key_when_unconfigured(self, client, monkeypatch):
        monkeypatch.delenv("AGENTMOAT_API_KEY", raising=False)
        response = client.get("/health")
        assert response.status_code == 200


class TestBackwardCompatibilityWhenUnconfigured:
    def test_protected_route_allowed_without_key_when_unconfigured(self, client, monkeypatch):
        monkeypatch.delenv("AGENTMOAT_API_KEY", raising=False)
        response = client.get("/events")
        assert response.status_code == 200


class TestProtectedRoutesWhenKeyConfigured:
    def test_missing_key_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/events")
        assert response.status_code == 401

    def test_wrong_key_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/events", headers={"X-API-Key": "wrong-key"})
        assert response.status_code == 401

    def test_correct_x_api_key_header_is_accepted(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/events", headers={"X-API-Key": "secret-123"})
        assert response.status_code == 200

    def test_correct_bearer_token_is_accepted(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/events", headers={"Authorization": "Bearer secret-123"})
        assert response.status_code == 200

    def test_malformed_bearer_token_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        response = client.get("/events", headers={"Authorization": "Basic secret-123"})
        assert response.status_code == 401

    def test_sessions_route_is_protected(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        assert client.get("/sessions").status_code == 401
        assert client.get("/sessions", headers={"X-API-Key": "secret-123"}).status_code == 200

    def test_control_route_is_protected(self, client, monkeypatch):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        assert client.get("/control/status").status_code == 401
        assert client.get("/control/status", headers={"X-API-Key": "secret-123"}).status_code == 200


class TestKillSwitchMutatingRoutesAreProtected:
    """The high-impact POST kill-switch endpoints must require the API key.

    ``test_control_route_is_protected`` only exercises ``GET /control/status``.
    These are the routes that can actually halt running agents — an
    unauthenticated ``kill-all`` is a denial-of-service against your own
    agents — so assert each mutating route is gated, not just the read route.
    """

    @pytest.fixture(autouse=True)
    def _reset_default_kill_switch(self):
        # These tests hit the real mutating endpoints, which trip the
        # process-wide default KillSwitch singleton. Reset it after each test
        # so a tripped global flag doesn't leak into the rest of the suite.
        from agentmoat.control import get_default_kill_switch

        yield
        get_default_kill_switch().reset()

    @pytest.mark.parametrize(
        "method,path",
        [
            ("post", "/control/kill/session-123"),
            ("post", "/control/kill-all"),
            ("post", "/control/revive/session-123"),
        ],
    )
    def test_mutating_route_rejected_without_key(self, client, monkeypatch, method, path):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        assert getattr(client, method)(path).status_code == 401

    @pytest.mark.parametrize(
        "method,path",
        [
            ("post", "/control/kill/session-123"),
            ("post", "/control/kill-all"),
            ("post", "/control/revive/session-123"),
        ],
    )
    def test_mutating_route_accepted_with_key(self, client, monkeypatch, method, path):
        monkeypatch.setenv("AGENTMOAT_API_KEY", "secret-123")
        resp = getattr(client, method)(path, headers={"X-API-Key": "secret-123"})
        assert resp.status_code == 200
