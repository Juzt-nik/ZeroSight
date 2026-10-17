"""API smoke tests and authentication/dual-approval regression tests."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.routes import privacy as privacy_routes
from backend.services.access_control import access_control
from backend.services.audit_service import audit_service
from backend.services.unmasking import UnmaskingService


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_root_endpoint():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "service" in response.json()


def _configure_demo_auth(monkeypatch):
    tokens = {
        "ZEROSIGHT_DEMO_AUTH": "true",
        "ZEROSIGHT_ANALYST_TOKEN": "analyst-demo-token-" + "a" * 40,
        "ZEROSIGHT_SECURITY_OFFICER_1_TOKEN": "officer-one-demo-token-" + "b" * 40,
        "ZEROSIGHT_SECURITY_OFFICER_2_TOKEN": "officer-two-demo-token-" + "c" * 40,
        "ZEROSIGHT_SECURITY_OFFICER_3_TOKEN": "officer-three-demo-token-" + "d" * 40,
        "ZEROSIGHT_AUDITOR_TOKEN": "auditor-demo-token-" + "e" * 40,
        "ZEROSIGHT_ADMIN_TOKEN": "admin-demo-token-" + "f" * 40,
    }
    for name, value in tokens.items():
        monkeypatch.setenv(name, value)

    async def no_op_audit_event(*args, **kwargs):
        return None

    # Keep API tests independent from SQLite initialization and filesystem state.
    monkeypatch.setattr(audit_service, "log_event", no_op_audit_event)
    return tokens


def test_privacy_route_rejects_missing_bearer_token(monkeypatch):
    _configure_demo_auth(monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/privacy/unmask/request",
        json={"vehicle_token": "token-demo", "justification": "Investigation of a safety alert"},
    )
    assert response.status_code == 401


def test_analyst_cannot_spoof_security_officer_in_request_body(monkeypatch):
    tokens = _configure_demo_auth(monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/privacy/unmask/request",
        headers={"Authorization": f"Bearer {tokens['ZEROSIGHT_ANALYST_TOKEN']}"},
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            "requested_by": "sec_officer_1",
        },
    )
    assert response.status_code == 403


def test_api_dual_approval_uses_authenticated_principals_and_discloses_once(monkeypatch):
    tokens = _configure_demo_auth(monkeypatch)
    monkeypatch.setattr(
        privacy_routes,
        "unmask_service",
        UnmaskingService(required_approvers=2, access_control_service=access_control),
    )
    privacy_routes.unmask_service.register_identity("token-demo", "SYNTHETIC-VIN-001")
    client = TestClient(app)

    create_response = client.post(
        "/privacy/unmask/request",
        headers={"Authorization": f"Bearer {tokens['ZEROSIGHT_SECURITY_OFFICER_1_TOKEN']}"},
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            "requested_by": "sec_officer_2",  # Must be ignored; identity comes from Bearer token.
        },
    )
    assert create_response.status_code == 200, create_response.text
    request_id = create_response.json()["request_id"]
    assert privacy_routes.unmask_service.get_request(request_id).requested_by == "sec_officer_1"

    first = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": f"Bearer {tokens['ZEROSIGHT_SECURITY_OFFICER_2_TOKEN']}"},
        json={"request_id": request_id, "approve": True, "approver_user_id": "sec_officer_3"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "requested"

    duplicate = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": f"Bearer {tokens['ZEROSIGHT_SECURITY_OFFICER_2_TOKEN']}"},
        json={"request_id": request_id, "approve": True},
    )
    assert duplicate.status_code == 400

    second = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": f"Bearer {tokens['ZEROSIGHT_SECURITY_OFFICER_3_TOKEN']}"},
        json={"request_id": request_id, "approve": True, "approver_user_id": "admin_1"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "completed"
    assert second.json()["real_identity"] == "SYNTHETIC-VIN-001"
    assert privacy_routes.unmask_service.unmask(request_id, disclosed_by="sec_officer_3") is None
