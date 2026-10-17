"""Tests for access-control policy boundaries."""

import pytest

from backend.services.access_control import AccessControlService, UserContext


def test_deny_by_default():
    service = AccessControlService()
    analyst = UserContext(user_id="u1", roles={"analyst"})
    assert service.require_permission(analyst, "audit:verify") is False
    assert service.require_permission(analyst, "privacy:unmask_request") is False


def test_analyst_can_detect():
    service = AccessControlService()
    analyst = UserContext(user_id="u1", roles={"analyst"})
    assert service.require_permission(analyst, "detect:create") is True
    assert service.require_permission(analyst, "privacy:tokenize") is True


def test_security_officer_can_request_unmasking():
    service = AccessControlService()
    officer = UserContext(user_id="officer", roles={"security_officer"})
    assert service.require_permission(officer, "privacy:unmask_request") is True
    assert service.require_permission(officer, "privacy:unmask_approve") is True


def test_admin_has_wildcard_permissions_but_not_security_officer_role():
    admin = UserContext(user_id="admin", roles={"admin"})
    assert admin.has_permission("anything_at_all") is True
    assert admin.has_role("security_officer") is False


def test_unknown_roles_are_rejected():
    service = AccessControlService()
    with pytest.raises(ValueError, match="Unknown role"):
        service.register_user("user", ["superuser"])


def test_empty_user_id_is_rejected():
    service = AccessControlService()
    with pytest.raises(ValueError, match="user_id"):
        service.register_user("  ", ["analyst"])


def test_security_officer_has_vault_permissions():
    """Phase 2: security_officer can read/write the identity vault."""
    service = AccessControlService()
    officer = UserContext(user_id="officer", roles={"security_officer"})
    assert service.require_permission(officer, "vault:read") is True
    assert service.require_permission(officer, "vault:write") is True


def test_analyst_denied_vault_permissions():
    """Phase 2: analysts cannot read or write the identity vault."""
    service = AccessControlService()
    analyst = UserContext(user_id="analyst", roles={"analyst"})
    assert service.require_permission(analyst, "vault:read") is False
    assert service.require_permission(analyst, "vault:write") is False


def test_auditor_denied_vault_permissions():
    """Phase 2: auditors cannot read or write the identity vault."""
    service = AccessControlService()
    auditor = UserContext(user_id="auditor", roles={"auditor"})
    assert service.require_permission(auditor, "vault:read") is False
    assert service.require_permission(auditor, "vault:write") is False


def test_admin_has_vault_permissions():
    """Phase 2: admin has wildcard vault permissions."""
    admin = UserContext(user_id="admin", roles={"admin"})
    assert admin.has_permission("vault:read") is True
    assert admin.has_permission("vault:write") is True
