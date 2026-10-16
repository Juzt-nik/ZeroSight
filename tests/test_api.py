"""Tests for FastAPI routes."""

from fastapi.testclient import TestClient
from backend.main import app


def test_health_endpoint():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_root_endpoint():
    client = TestClient(app)
    r = client.get("/")
    assert r.status_code == 200
    assert "service" in r.json()