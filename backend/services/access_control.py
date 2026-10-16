"""Role-based access control with deny-by-default.

Roles:
  analyst        - view alerts, run detection, tokenize vehicles
  security_officer - approve/reject unmask requests
  auditor        - view audit logs, verify chain, view anomaly warnings
  admin          - full access (emergency break-glass only)
"""

import logging
from typing import Set, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("vsoc.access_control")

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "analyst": {
        "detect:read",
        "detect:create",
        "privacy:tokenize",
        "privacy:location",
        "audit:read_own",
    },
    "security_officer": {
        "detect:read",
        "privacy:unmask_request",
        "privacy:unmask_approve",
        "audit:read_own",
    },
    "auditor": {
        "audit:read",
        "audit:verify",
        "anomaly:read",
        "access:roles",
    },
    "admin": {
        "*",  # all permissions
    },
}

ROLE_DESCRIPTIONS: Dict[str, str] = {
    "analyst": "Security analyst - detection and alert review",
    "security_officer": "Security officer - unmask approval authority",
    "auditor": "Auditor - audit and compliance review",
    "admin": "Administrator - break-glass emergency access",
}


@dataclass
class UserContext:
    user_id: str
    roles: Set[str] = field(default_factory=set)

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles

    def has_permission(self, permission: str) -> bool:
        if "admin" in self.roles:
            return True
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True
            if "*" in ROLE_PERMISSIONS.get(role, set()):
                return True
        return False


class AccessControlService:
    """Application-level RBAC. Deny-by-default."""

    def __init__(self):
        # In production, integrate with OPA/Keycloak. Here we use inline policy.
        self._users: Dict[str, UserContext] = {}

    def register_user(self, user_id: str, roles: List[str]) -> UserContext:
        ctx = UserContext(user_id=user_id, roles=set(roles))
        self._users[user_id] = ctx
        logger.info("Registered user %s with roles %s", user_id, roles)
        return ctx

    def get_user(self, user_id: str) -> Optional[UserContext]:
        return self._users.get(user_id)

    def require_permission(self, user: UserContext, permission: str) -> bool:
        """Return True if user has permission, False otherwise (deny-by-default)."""
        allowed = user.has_permission(permission)
        if not allowed:
            logger.warning(
                "Access denied: user=%s permission=%s roles=%s",
                user.user_id, permission, user.roles,
            )
        return allowed

    def require_role(self, user: UserContext, role: str) -> bool:
        """Return True if user has the required role."""
        allowed = user.has_role(role)
        if not allowed:
            logger.warning(
                "Access denied: user=%s required_role=%s roles=%s",
                user.user_id, role, user.roles,
            )
        return allowed

    def list_roles(self) -> list[dict]:
        return [
            {"role": r, "description": ROLE_DESCRIPTIONS.get(r, ""), "permissions": sorted(ROLE_PERMISSIONS.get(r, set()))}
            for r in ROLE_PERMISSIONS
        ]


# Default users for demonstration (no real PII)
default_access_control = AccessControlService()
default_access_control.register_user("analyst_1", ["analyst"])
default_access_control.register_user("sec_officer_1", ["security_officer"])
default_access_control.register_user("sec_officer_2", ["security_officer"])
default_access_control.register_user("auditor_1", ["auditor"])
default_access_control.register_user("admin_1", ["admin"])

# Module-level singleton instance (with default users registered)
access_control = default_access_control