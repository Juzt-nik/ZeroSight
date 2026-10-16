"""Tests for access control module."""

from backend.services.access_control import (
    AccessControlService, UserContext,
)


def test_deny_by_default():
    ac = AccessControlService()
    user = UserContext(user_id="u1", roles={"analyst"})
    assert ac.require_permission(user, "audit:verify") is False
    assert ac.require_permission(user, "privacy:unmask_request") is False


def test_analyst_can_detect():
    ac = AccessControlService()
    user = UserContext(user_id="u1", roles={"analyst"})
    assert ac.require_permission(user, "detect:create") is True
    assert ac.require_permission(user, "privacy:tokenize") is True


def test_security_officer_can_unmask():
    ac = AccessControlService()
    user = UserContext(user_id="u1", roles={"security_officer"})
    assert ac.require_permission(user, "privacy:unmask_request") is True


def test_admin_has_all():
    ac = AccessControlService()
    user = UserContext(user_id="u1", roles={"admin"})
    assert ac.require_permission(user, "anything_at_all") is True