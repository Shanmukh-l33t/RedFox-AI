"""API authentication: off by default, closed when a token is configured."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from redfox.api import create_app

TOKEN = "test-token-0123456789"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("REDFOX_API_TOKEN", raising=False)
    return TestClient(create_app(home=str(tmp_path / "open")))


@pytest.fixture()
def locked(tmp_path, monkeypatch):
    monkeypatch.setenv("REDFOX_API_TOKEN", TOKEN)
    return TestClient(create_app(home=str(tmp_path / "locked")))


def test_without_a_token_the_api_stays_open_on_loopback(client) -> None:
    assert client.get("/api/engagements").status_code == 200


def test_a_configured_token_is_required(locked) -> None:
    assert locked.get("/api/engagements").status_code == 401
    assert locked.get("/api/engagements", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_the_token_is_accepted_as_bearer_or_header(locked) -> None:
    assert locked.get("/api/engagements",
                      headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert locked.get("/api/engagements",
                      headers={"X-RedFox-Token": TOKEN}).status_code == 200


def test_health_is_also_closed_when_a_token_is_set(locked) -> None:
    # Consistent rule: with a token configured, no /api route answers without it.
    assert locked.get("/api/health").status_code == 401
    assert locked.get("/api/health",
                      headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_the_static_ui_loads_but_its_data_does_not(locked) -> None:
    assert locked.get("/").status_code == 200
    assert locked.get("/api/engagements").status_code == 401


def test_a_mutating_route_is_refused_without_the_token(locked) -> None:
    response = locked.post("/api/kill")
    assert response.status_code == 401
    assert "token" in response.json()["detail"].lower()