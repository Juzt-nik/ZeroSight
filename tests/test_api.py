"""API smoke tests and authentication/dual-approval regression tests."""

import backend.auth as backend_auth
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
    """Configure demo-mode authentication and isolate audit writes."""
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv(
        "AUTH_SECRET",
        "strong-test-secret-0123456789abcdef",
    )
    monkeypatch.setenv(
        "TOKEN_SECRET",
        "strong-test-secret-0123456789abcdef",
    )

    # DEMO_MODE is read at module import time, so set it directly as well.
    monkeypatch.setattr(backend_auth, "DEMO_MODE", True)

    async def no_op_audit_event(*args, **kwargs):
        """Prevent tests from depending on SQLite initialization."""
        return None

    monkeypatch.setattr(audit_service, "log_event", no_op_audit_event)

    # Synthetic identities and roles used by the demo authentication flow.
    return {
        "analyst": ("analyst_1", "analyst"),
        "security_officer_1": ("sec_officer_1", "security_officer"),
        "security_officer_2": ("sec_officer_2", "security_officer"),
        "security_officer_3": ("sec_officer_3", "security_officer"),
        "auditor": ("auditor_1", "auditor"),
        "admin": ("admin_1", "admin"),
    }


def _bearer(user_id: str, roles: str) -> str:
    """Build a demo-mode bearer authorization header."""
    return f"Bearer {user_id}:{roles}"


def test_privacy_route_rejects_missing_bearer_token(monkeypatch):
    _configure_demo_auth(monkeypatch)
    client = TestClient(app)

    response = client.post(
        "/privacy/unmask/request",
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
        },
    )

    assert response.status_code == 401


def test_analyst_cannot_spoof_security_officer_in_request_body(monkeypatch):
    tokens = _configure_demo_auth(monkeypatch)
    analyst_id, analyst_roles = tokens["analyst"]
    client = TestClient(app)

    response = client.post(
        "/privacy/unmask/request",
        headers={
            "Authorization": _bearer(analyst_id, analyst_roles),
        },
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            "requested_by": "sec_officer_1",
        },
    )

    # Analysts lack permission to request identity unmasking.
    assert response.status_code == 403, response.text


def test_api_dual_approval_uses_authenticated_principals_and_discloses_once(
    monkeypatch,
):
    tokens = _configure_demo_auth(monkeypatch)

    monkeypatch.setattr(
        privacy_routes,
        "unmask_service",
        UnmaskingService(
            required_approvers=2,
            access_control_service=access_control,
        ),
    )

    privacy_routes.unmask_service.register_identity(
        "token-demo",
        "SYNTHETIC-VIN-001",
    )

    client = TestClient(app)

    officer1_id, officer1_roles = tokens["security_officer_1"]
    officer2_id, officer2_roles = tokens["security_officer_2"]
    officer3_id, officer3_roles = tokens["security_officer_3"]

    # The authenticated principal must determine the requester identity.
    create_response = client.post(
        "/privacy/unmask/request",
        headers={
            "Authorization": _bearer(officer1_id, officer1_roles),
        },
        json={
            "vehicle_token": "token-demo",
            "justification": "Investigation of a safety alert",
            "requested_by": "sec_officer_2",
        },
    )

    assert create_response.status_code == 200, create_response.text

    request_id = create_response.json()["request_id"]

    assert (
        privacy_routes.unmask_service.get_request(request_id).requested_by
        == officer1_id
    )

    # The first security officer approves the request.
    first = client.post(
        "/privacy/unmask/approve",
        headers={
            "Authorization": _bearer(officer2_id, officer2_roles),
        },
        json={
            "request_id": request_id,
            "approve": True,
            "approver_user_id": "sec_officer_3",
        },
    )

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "requested"

    # The same officer cannot approve the same request twice.
    duplicate = client.post(
        "/privacy/unmask/approve",
        headers={
            "Authorization": _bearer(officer2_id, officer2_roles),
        },
        json={
            "request_id": request_id,
            "approve": True,
        },
    )

    assert duplicate.status_code == 400

    # A second, distinct security officer completes the approval.
    second = client.post(
        "/privacy/unmask/approve",
        headers={
            "Authorization": _bearer(officer3_id, officer3_roles),
        },
        json={
            "request_id": request_id,
            "approve": True,
            "approver_user_id": "admin_1",
        },
    )

    assert second.status_code == 200, second.text
    assert second.json()["status"] == "completed"
    assert second.json()["real_identity"] == "SYNTHETIC-VIN-001"

    # The completed request cannot disclose the identity again.
    assert (
        privacy_routes.unmask_service.unmask(
            request_id,
            disclosed_by=officer1_id,
        )
        is None
    )


def test_access_me_resolves_async_auth_dependency(monkeypatch):
    """Verify the async authentication dependency returns a valid user."""
    _configure_demo_auth(monkeypatch)
    client = TestClient(app)

    response = client.get(
        "/access/me",
        headers={
            "Authorization": _bearer(
                "dependency-test-analyst",
                "analyst",
            ),
        },
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["user_id"] == "dependency-test-analyst"
    assert data["roles"] == ["analyst"]
    assert data["is_authenticated"] is True


def test_access_roles_enforces_permissions(monkeypatch):
    """Verify the roles endpoint enforces role-based permissions."""
    _configure_demo_auth(monkeypatch)
    client = TestClient(app)

    # An analyst lacks the access:roles permission.
    denied = client.get(
        "/access/roles",
        headers={
            "Authorization": _bearer(
                "dependency-test-analyst",
                "analyst",
            ),
        },
    )

    assert denied.status_code == 403, denied.text

    # An auditor has the access:roles permission.
    allowed = client.get(
        "/access/roles",
        headers={
            "Authorization": _bearer(
                "dependency-test-auditor",
                "auditor",
            ),
        },
    )

    assert allowed.status_code == 200, allowed.text