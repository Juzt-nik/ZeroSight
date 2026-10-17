"""Tests for privacy, location minimization, and unmasking workflow."""

from datetime import datetime, timedelta, timezone

import os
import pytest

from backend.services.access_control import AccessControlService
from backend.services.tokenization import generate_token
from backend.services.location import coarsen_location
from backend.services.unmasking import (
    COMPLETED,
    EXPIRED,
    REQUESTED,
    UnmaskingService,
)


def _new_unmasking_service() -> UnmaskingService:
    acl = AccessControlService()
    acl.register_user("sec_officer_1", ["security_officer"])
    acl.register_user("sec_officer_2", ["security_officer"])
    acl.register_user("sec_officer_3", ["security_officer"])
    acl.register_user("analyst_1", ["analyst"])
    return UnmaskingService(required_approvers=2, access_control_service=acl)


def _set_strong_token_secret(monkeypatch):
    monkeypatch.setenv("TOKEN_SECRET", "strong-test-secret-0123456789abcdef")
    # TOKEN_SECRET is read at module import time; set it directly on the module
    import backend.services.tokenization as _tok
    monkeypatch.setattr(_tok, "TOKEN_SECRET", "strong-test-secret-0123456789abcdef")


def test_token_generation(monkeypatch):
    _set_strong_token_secret(monkeypatch)
    token, epoch, expires_at = generate_token("VIN-DEMO-12345")
    assert len(token) == 16
    assert isinstance(epoch, int)
    assert expires_at is not None


def test_token_different_vehicles_different_tokens(monkeypatch):
    _set_strong_token_secret(monkeypatch)
    token_a, _, _ = generate_token("VEHICLE-A")
    token_b, _, _ = generate_token("VEHICLE-B")
    assert token_a != token_b


def test_token_same_vehicle_same_token(monkeypatch):
    _set_strong_token_secret(monkeypatch)
    token_a, _, _ = generate_token("VEHICLE-A")
    token_b, _, _ = generate_token("VEHICLE-A")
    assert token_a == token_b


def test_location_coarsen():
    result = coarsen_location(40.7128, -74.0060, minimization_level="coarsen")
    assert result["minimization_applied"] == "coarsen"
    assert result["grid_cell"] is not None
    assert result["original_latitude"] is None


def test_location_withhold():
    result = coarsen_location(40.7128, -74.0060, minimization_level="withhold")
    assert result["minimization_applied"] == "withhold"
    assert result["coarsened_latitude"] is None


def test_unmask_requires_two_distinct_authorized_approvers_and_is_single_use():
    service = _new_unmasking_service()
    service.register_identity("test-token", "REAL-VIN-001")
    record = service.create_request(
        "test-token", "Investigation justification here", "sec_officer_1"
    )
    assert record.status == REQUESTED

    assert service.approve(record.request_id, "sec_officer_2") is True
    assert service.get_request(record.request_id).status == REQUESTED
    assert service.approve(record.request_id, "sec_officer_2") is False
    assert service.approve(record.request_id, "sec_officer_1") is False

    assert service.approve(record.request_id, "sec_officer_3") is True
    record = service.get_request(record.request_id)
    assert record.status == COMPLETED
    assert record.completed_by == "sec_officer_3"

    # Disclosure is tied to the completing officer and consumed after one use.
    assert service.unmask(record.request_id, disclosed_by="sec_officer_2") is None
    assert service.unmask(record.request_id, disclosed_by="sec_officer_3") == "REAL-VIN-001"
    assert service.unmask(record.request_id, disclosed_by="sec_officer_3") is None


def test_unauthorized_user_cannot_approve():
    service = _new_unmasking_service()
    record = service.create_request("token", "Valid investigation purpose", "sec_officer_1")
    assert service.approve(record.request_id, "analyst_1") is False
    assert service.get_request(record.request_id).status == REQUESTED


def test_requester_cannot_approve_own_request():
    service = _new_unmasking_service()
    record = service.create_request("token", "Valid investigation purpose", "sec_officer_1")
    assert service.approve(record.request_id, "sec_officer_1") is False


def test_non_officer_cannot_create_unmask_request():
    service = _new_unmasking_service()
    with pytest.raises(PermissionError):
        service.create_request("token", "Valid investigation purpose", "analyst_1")


def test_expired_request_cannot_be_approved():
    service = _new_unmasking_service()
    record = service.create_request("token", "Valid investigation purpose", "sec_officer_1")
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert service.approve(record.request_id, "sec_officer_2") is False
    assert service.get_request(record.request_id).status == EXPIRED


def test_single_approver_configuration_is_rejected():
    with pytest.raises(ValueError, match="At least two distinct approvers"):
        UnmaskingService(required_approvers=1, access_control_service=AccessControlService())


# --- Phase 2: Token-to-vault registration tests ---


def test_token_registered_in_vault(monkeypatch):
    """Phase 2: generate_token() registers the token→vehicle_id mapping."""
    _set_strong_token_secret(monkeypatch)
    from backend.services import tokenization as _tok

    # Clear vault before test
    _tok._token_vault.clear()

    token, _, _ = _tok.generate_token("VEHICLE-VIN-001")
    assert _tok.get_vehicle_from_token(token) == "VEHICLE-VIN-001"


def test_vault_access_denied_without_permission(monkeypatch):
    """Phase 2: get_vehicle_from_token() denies access without vault:read."""
    _set_strong_token_secret(monkeypatch)
    from backend.services import tokenization as _tok
    from backend.services.access_control import UserContext

    _tok._token_vault.clear()
    token, _, _ = _tok.generate_token("VEHICLE-VIN-002")

    # Analyst has no vault:read permission
    analyst = UserContext(user_id="analyst", roles={"analyst"})
    assert _tok.get_vehicle_from_token(token, requesting_user=analyst) is None


def test_vault_access_granted_with_permission(monkeypatch):
    """Phase 2: get_vehicle_from_token() allows access with vault:read."""
    _set_strong_token_secret(monkeypatch)
    from backend.services import tokenization as _tok
    from backend.services.access_control import UserContext

    _tok._token_vault.clear()
    token, _, _ = _tok.generate_token("VEHICLE-VIN-003")

    # Security officer has vault:read permission
    officer = UserContext(user_id="officer", roles={"security_officer"})
    assert _tok.get_vehicle_from_token(token, requesting_user=officer) == "VEHICLE-VIN-003"


# --- Phase 2: Automatic re-masking tests ---


def test_expired_request_remasks_identity():
    """Phase 2: When a request expires, the identity is removed from the vault."""
    service = _new_unmasking_service()
    service.register_identity("TOKEN-RE-MASK", "REAL-VIN-RE-MASK")
    assert "REAL-VIN-RE-MASK" == service._identity_map.get("TOKEN-RE-MASK")

    record = service.create_request(
        "TOKEN-RE-MASK", "Valid investigation purpose", "sec_officer_1"
    )
    # Force expiry
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    # Accessing the request triggers _expire_if_needed → re-masking
    service.get_request(record.request_id)

    # Identity should be removed from vault after expiry
    assert service._identity_map.get("TOKEN-RE-MASK") is None


def test_re_mask_token_requires_vault_write():
    """Phase 2: re_mask_token() requires vault:write permission."""
    from backend.services.access_control import UserContext

    service = _new_unmasking_service()
    service.register_identity("TOKEN-WRITE", "REAL-VIN-WRITE")

    # Analyst has no vault:write permission
    analyst = UserContext(user_id="analyst", roles={"analyst"})
    assert service.re_mask_token("TOKEN-WRITE", requesting_user=analyst) is False

    # Identity should still be present
    assert service._identity_map.get("TOKEN-WRITE") == "REAL-VIN-WRITE"

    # Security officer has vault:write permission
    officer = UserContext(user_id="officer", roles={"security_officer"})
    assert service.re_mask_token("TOKEN-WRITE", requesting_user=officer) is True

    # Identity should be removed
    assert service._identity_map.get("TOKEN-WRITE") is None


def test_analyst_cannot_retrieve_vin_through_vault(monkeypatch):
    """Phase 2: Analysts cannot retrieve real VINs through the token vault."""
    _set_strong_token_secret(monkeypatch)
    from backend.services import tokenization as _tok
    from backend.services.access_control import UserContext

    _tok._token_vault.clear()
    token, _, _ = _tok.generate_token("VEHICLE-SECRET-VIN")

    # Analyst attempts to look up VIN through vault — must be denied
    analyst = UserContext(user_id="analyst_1", roles={"analyst"})
    result = _tok.get_vehicle_from_token(token, requesting_user=analyst)
    assert result is None, "Analyst must not retrieve VIN through token vault"

    # Verify token exists in vault but analyst can't read it
    assert _tok._token_vault.get(token) == "VEHICLE-SECRET-VIN"
