"""Tests for privacy, location minimization, and unmasking workflow."""

from datetime import datetime, timedelta, timezone

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


def test_token_generation():
    token, epoch, expires_at = generate_token("VIN-DEMO-12345")
    assert len(token) == 16
    assert isinstance(epoch, int)
    assert expires_at is not None


def test_token_different_vehicles_different_tokens():
    token_a, _, _ = generate_token("VEHICLE-A")
    token_b, _, _ = generate_token("VEHICLE-B")
    assert token_a != token_b


def test_token_same_vehicle_same_token():
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
