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
    """Configure demo-mode authentication using auth.py's get_current_user.

    In DEMO_MODE, Authorization: Bearer <user_id>:<role1,role2> is accepted.
    """
    import backend.auth as _auth

    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("AUTH_SECRET", "strong-test-secret-0123456789abcdef")
    monkeypatch.setenv("TOKEN_SECRET", "strong-test-secret-0123456789abcdef")
    # DEMO_MODE is read at module import time; set it directly on the module
    monkeypatch.setattr(_auth, "DEMO_MODE", True)

    async def no_op_audit_event(*args, **kwargs):
        return None

    # Keep API tests independent from SQLite initialization and filesystem state.
    monkeypatch.setattr(audit_service, "log_event", no_op_audit_event)

    # Return (user_id, roles) mappings for constructing bearer tokens
    return {
        "analyst": ("analyst_1", "analyst"),
        "security_officer_1": ("sec_officer_1", "security_officer"),
        "security_officer_2": ("sec_officer_2", "security_officer"),
        "security_officer_3": ("sec_officer_3", "security_officer"),
        "auditor": ("auditor_1", "auditor"),
        "admin": ("admin_1", "admin"),
    }


def _bearer(user_id: str, roles: str) -> str:
    return f"Bearer {user_id}:{roles}"


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
    analyst_id, analyst_roles = tokens["analyst"]
    response = client.post(
        "/privacy/unmask/request",
        headers={"Authorization": _bearer(analyst_id, analyst_roles)},
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            # requested_by in body is ignored; authenticated user is used instead
            "requested_by": "sec_officer_1",
        },
    )
    # Request is denied because analyst lacks privacy:unmask_request permission
    assert response.status_code == 403, response.text


def test_api_dual_approval_uses_authenticated_principals_and_discloses_once(monkeypatch):
    tokens = _configure_demo_auth(monkeypatch)
    monkeypatch.setattr(
        privacy_routes,
        "unmask_service",
        UnmaskingService(required_approvers=2, access_control_service=access_control),
    )
    privacy_routes.unmask_service.register_identity("token-demo", "SYNTHETIC-VIN-001")
    client = TestClient(app)

    officer1_id, officer1_roles = tokens["security_officer_1"]
    officer2_id, officer2_roles = tokens["security_officer_2"]
    officer3_id, officer3_roles = tokens["security_officer_3"]

    create_response = client.post(
        "/privacy/unmask/request",
        headers={"Authorization": _bearer(officer1_id, officer1_roles)},
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            # requested_by in body is ignored; identity comes from Bearer token.
            "requested_by": "sec_officer_2",
        },
    )
    assert create_response.status_code == 200, create_response.text
    request_id = create_response.json()["request_id"]
    assert privacy_routes.unmask_service.get_request(request_id).requested_by == officer1_id

    first = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": _bearer(officer2_id, officer2_roles)},
        json={"request_id": request_id, "approve": True, "approver_user_id": "sec_officer_3"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "requested"

    duplicate = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": _bearer(officer2_id, officer2_roles)},
        json={"request_id": request_id, "approve": True},
    )
    assert duplicate.status_code == 400

    second = client.post(
        "/privacy/unmask/approve",
        headers={"Authorization": _bearer(officer3_id, officer3_roles)},
        json={"request_id": request_id, "approve": True, "approver_user_id": "admin_1"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "completed"
    assert second.json()["real_identity"] == "SYNTHETIC-VIN-001"
    assert privacy_routes.unmask_service.unmask(request_id, disclosed_by=officer1_id) is None
