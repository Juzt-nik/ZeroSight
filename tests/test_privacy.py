"""Tests for privacy module."""

import pytest
from backend.services.tokenization import generate_token, verify_token, is_token_expired
from backend.services.location import coarsen_location
from backend.services.unmasking import UnmaskingService, REQUESTED, COMPLETED


def test_token_generation():
    token, epoch, expires_at = generate_token("VIN-DEMO-12345")
    assert len(token) == 16
    assert isinstance(epoch, int)
    assert expires_at is not None


def test_token_different_vehicles_different_tokens():
    t1, _, _ = generate_token("VEHICLE-A")
    t2, _, _ = generate_token("VEHICLE-B")
    assert t1 != t2


def test_token_same_vehicle_same_token():
    t1, _, _ = generate_token("VEHICLE-A")
    t2, _, _ = generate_token("VEHICLE-A")
    assert t1 == t2


def test_location_coarsen():
    result = coarsen_location(40.7128, -74.0060, minimization_level="coarsen")
    assert result["minimization_applied"] == "coarsen"
    assert result["grid_cell"] is not None
    assert result["original_latitude"] is None


def test_location_withhold():
    result = coarsen_location(40.7128, -74.0060, minimization_level="withhold")
    assert result["minimization_applied"] == "withhold"
    assert result["coarsened_latitude"] is None


def test_unmask_requires_two_approvers():
    service = UnmaskingService(required_approvers=2)
    # Register a fake identity
    service.register_identity("test-token", "REAL-VIN-001")

    record = service.create_request("test-token", "Investigation justification here", "sec_officer_1")
    assert record.status == REQUESTED

    # First approval
    assert service.approve(record.request_id, "sec_officer_2") is True
    record = service.get_request(record.request_id)
    assert record.status == REQUESTED  # still needs 2nd approver

    # Same user cannot approve twice
    assert service.approve(record.request_id, "sec_officer_2") is False

    # Second approver completes
    assert service.approve(record.request_id, "sec_officer_3") is True
    record = service.get_request(record.request_id)
    assert record.status == COMPLETED

    # Unmask should work
    identity = service.unmask(record.request_id)
    assert identity == "REAL-VIN-001"


def test_unmask_requester_cannot_approve_own():
    service = UnmaskingService(required_approvers=2)
    record = service.create_request("tok", "Justification for test", "sec_officer_1")
    # Requester trying to approve their own request
    assert service.approve(record.request_id, "sec_officer_1") is False