"""Role-based access control with deny-by-default behavior.

Demo users are synthetic identities for local development only. Production
identity and role assertions must come from a trusted identity provider.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

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
        "vault:read",
        "vault:write",
    },
    "auditor": {
        "audit:read",
        "audit:verify",
        "anomaly:read",
        "access:roles",
    },
    "admin": {"*"},
}

ROLE_DESCRIPTIONS: Dict[str, str] = {
    "analyst": "Security analyst - detection and alert review",
    "security_officer": "Security officer - unmask approval authority and identity vault access",
    "auditor": "Auditor - audit and compliance review",
    "admin": "Administrator - break-glass emergency access",
}

VALID_ROLES = frozenset(ROLE_PERMISSIONS)


@dataclass
class UserContext:
    user_id: str
    roles: Set[str] = field(default_factory=set)

    def has_role(self, role: str) -> bool:
        """Return true only for an explicitly assigned role.

        An admin's wildcard permissions do not make the admin a security officer
        for dual-control workflows.
        """
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        if "admin" in self.roles:
            return True
        for role in self.roles:
            permissions = ROLE_PERMISSIONS.get(role, set())
            if permission in permissions or "*" in permissions:
                return True
        return False


class AccessControlService:
    """In-process RBAC registry for the prototype; not an identity provider."""

    def __init__(self) -> None:
        self._users: Dict[str, UserContext] = {}

    def register_user(self, user_id: str, roles: List[str]) -> UserContext:
        user_id = user_id.strip()
        if not user_id:
            raise ValueError("user_id must not be empty")
        unknown_roles = set(roles) - VALID_ROLES
        if unknown_roles:
            raise ValueError(f"Unknown role(s): {', '.join(sorted(unknown_roles))}")
        if not roles:
            raise ValueError("At least one role must be assigned")
        context = UserContext(user_id=user_id, roles=set(roles))
        self._users[user_id] = context
        # Do not log credentials, tokens, identities, or other sensitive values.
        logger.info("Registered demo principal %s with roles %s", user_id, sorted(context.roles))
        return context

    def get_user(self, user_id: str) -> Optional[UserContext]:
        return self._users.get(user_id)

    def require_permission(self, user: UserContext, permission: str) -> bool:
        allowed = user.has_permission(permission)
        if not allowed:
            logger.warning(
                "Access denied: user=%s permission=%s roles=%s",
                user.user_id,
                permission,
                sorted(user.roles),
            )
        return allowed

    def require_role(self, user: UserContext, role: str) -> bool:
        allowed = user.has_role(role)
        if not allowed:
            logger.warning(
                "Access denied: user=%s required_role=%s roles=%s",
                user.user_id,
                role,
                sorted(user.roles),
            )
        return allowed

    def list_roles(self) -> list[dict]:
        return [
            {
                "role": role,
                "description": ROLE_DESCRIPTIONS.get(role, ""),
                "permissions": sorted(ROLE_PERMISSIONS.get(role, set())),
            }
            for role in ROLE_PERMISSIONS
        ]


# Synthetic principals used only by the local datathon demo. Authentication is
# supplied separately by per-user Bearer tokens configured in the environment.
default_access_control = AccessControlService()
default_access_control.register_user("analyst_1", ["analyst"])
default_access_control.register_user("sec_officer_1", ["security_officer"])
default_access_control.register_user("sec_officer_2", ["security_officer"])
default_access_control.register_user("sec_officer_3", ["security_officer"])
default_access_control.register_user("auditor_1", ["auditor"])
default_access_control.register_user("admin_1", ["admin"])

access_control = default_access_control
