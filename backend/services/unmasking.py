"""Dual-approval identity-unmasking workflow.

This in-memory store is suitable only for the datathon prototype. A production
implementation should persist state transactionally and protect the identity
mapping separately from ordinary alert processing.
"""

import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Dict, List, Optional

from backend.services.access_control import (
    AccessControlService,
    access_control as default_access_control,
)

logger = logging.getLogger("vsoc.unmasking")

REQUIRED_APPROVERS = int(os.getenv("REQUIRED_APPROVERS", "2"))
REQUEST_TTL_MINUTES = int(os.getenv("UNMASK_REQUEST_TTL_MINUTES", "30"))

REQUESTED = "requested"
APPROVED = "approved"  # Reserved for compatibility with existing imports.
REJECTED = "rejected"
COMPLETED = "completed"
EXPIRED = "expired"


@dataclass
class UnmaskRequestRecord:
    request_id: str
    vehicle_token: str
    justification: str
    requested_by: str
    status: str = REQUESTED
    approvers: List[str] = field(default_factory=list)
    rejections: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
        + timedelta(minutes=REQUEST_TTL_MINUTES)
    )
    real_identity: Optional[str] = None
    completed_at: Optional[datetime] = None
    completed_by: Optional[str] = None
    identity_revealed_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def can_be_approved_by(self, user_id: str) -> bool:
        if self.status != REQUESTED or self.is_expired():
            return False
        if user_id in self.approvers or user_id == self.requested_by:
            return False
        return True

    def approve(self, user_id: str, required_approvers: int) -> bool:
        if not self.can_be_approved_by(user_id):
            return False
        self.approvers.append(user_id)
        if len(set(self.approvers)) >= required_approvers:
            self.status = COMPLETED
            self.completed_at = datetime.now(timezone.utc)
            self.completed_by = user_id
            logger.info(
                "Unmask request %s completed after required approvals",
                self.request_id,
            )
        else:
            logger.info("Unmask request %s received an approval", self.request_id)
        return True

    def reject(self, user_id: str) -> bool:
        if self.status != REQUESTED or self.is_expired():
            return False
        if user_id == self.requested_by or user_id in self.rejections:
            return False
        self.status = REJECTED
        self.rejections.append(user_id)
        logger.info("Unmask request %s rejected", self.request_id)
        return True


class UnmaskingService:
    """Dual-control service with in-process locking and single-use disclosure."""

    def __init__(
        self,
        required_approvers: int = REQUIRED_APPROVERS,
        access_control_service: Optional[AccessControlService] = None,
    ) -> None:
        if required_approvers < 2:
            raise ValueError("At least two distinct approvers are required")
        if REQUEST_TTL_MINUTES < 1:
            raise ValueError("UNMASK_REQUEST_TTL_MINUTES must be at least 1")
        self.required_approvers = required_approvers
        self.access_control = access_control_service or default_access_control
        self._requests: Dict[str, UnmaskRequestRecord] = {}
        # This mapping is isolated from regular request/alert processing.
        self._identity_map: Dict[str, str] = {}
        self._lock = RLock()

    def register_identity(self, vehicle_token: str, real_identity: str) -> None:
        """Register a synthetic/demo identity during trusted provisioning only."""
        if not vehicle_token.strip() or not real_identity.strip():
            raise ValueError("vehicle_token and real_identity must not be empty")
        with self._lock:
            self._identity_map[vehicle_token] = real_identity
        logger.info("Registered an identity mapping for a pseudonymous vehicle token")

    def create_request(
        self, vehicle_token: str, justification: str, requested_by: str
    ) -> UnmaskRequestRecord:
        requester = self.access_control.get_user(requested_by)
        if (
            requester is None
            or not requester.has_role("security_officer")
            or not requester.has_permission("privacy:unmask_request")
        ):
            raise PermissionError("Only an authorized security officer can request unmasking")
        if not vehicle_token or not vehicle_token.strip():
            raise ValueError("vehicle_token must not be empty")
        if not justification or len(justification.strip()) < 10:
            raise ValueError("justification must contain at least 10 non-whitespace characters")

        with self._lock:
            record = UnmaskRequestRecord(
                request_id=str(uuid.uuid4()),
                vehicle_token=vehicle_token.strip(),
                justification=justification.strip(),
                requested_by=requester.user_id,
            )
            self._requests[record.request_id] = record
            logger.info("Created unmask request %s", record.request_id)
            return record

    def _expire_if_needed(self, record: UnmaskRequestRecord) -> None:
        if record.status == REQUESTED and record.is_expired():
            record.status = EXPIRED
            # Phase 2: Automatic re-masking — remove identity from vault on expiry
            # so the real identity cannot be disclosed after the request expires.
            identity = self._identity_map.pop(record.vehicle_token, None)
            if identity is not None:
                logger.info(
                    "Re-masked identity for token %s after request %s expired",
                    record.vehicle_token,
                    record.request_id,
                )

    def get_request(self, request_id: str) -> Optional[UnmaskRequestRecord]:
        with self._lock:
            record = self._requests.get(request_id)
            if record is not None:
                self._expire_if_needed(record)
            return record

    def approve(self, request_id: str, approver_user_id: str) -> bool:
        with self._lock:
            record = self._requests.get(request_id)
            approver = self.access_control.get_user(approver_user_id)
            if (
                record is None
                or approver is None
                or not approver.has_role("security_officer")
                or not approver.has_permission("privacy:unmask_approve")
            ):
                return False
            self._expire_if_needed(record)
            return record.approve(approver.user_id, self.required_approvers)

    def reject(
        self, request_id: str, approver_user_id: str, reason: Optional[str] = None
    ) -> bool:
        # Keep the reason out of logs to avoid accidental disclosure of incident data.
        del reason
        with self._lock:
            record = self._requests.get(request_id)
            approver = self.access_control.get_user(approver_user_id)
            if (
                record is None
                or approver is None
                or not approver.has_role("security_officer")
                or not approver.has_permission("privacy:unmask_approve")
            ):
                return False
            self._expire_if_needed(record)
            return record.reject(approver.user_id)

    def unmask(self, request_id: str, disclosed_by: str) -> Optional[str]:
        """Return identity once, only to the authorized approver completing the request.

        Phase 2: Requires vault:read permission on the disclosed_by user.
        """
        with self._lock:
            record = self._requests.get(request_id)
            approver = self.access_control.get_user(disclosed_by)
            if (
                record is None
                or record.status != COMPLETED
                or record.identity_revealed_at is not None
                or record.completed_by != disclosed_by
                or approver is None
                or not approver.has_role("security_officer")
                or not approver.has_permission("privacy:unmask_approve")
                or not approver.has_permission("vault:read")
            ):
                return None

            identity = self._identity_map.get(record.vehicle_token)
            if identity is None:
                return None
            record.identity_revealed_at = datetime.now(timezone.utc)
            logger.info("Identity disclosure completed for request %s", record.request_id)
            return identity

    def re_mask_token(self, vehicle_token: str, requesting_user=None) -> bool:
        """Explicitly re-mask a vehicle token by removing its identity from the vault.

        Phase 2: Requires vault:write permission on the requesting_user.
        Returns True if an identity was removed, False if none existed.
        """
        if requesting_user is not None:
            if not requesting_user.has_permission("vault:write"):
                return False
        with self._lock:
            identity = self._identity_map.pop(vehicle_token, None)
            if identity is not None:
                logger.info("Re-masked identity for token %s on explicit request", vehicle_token)
                return True
            return False

    def list_requests(self) -> List[UnmaskRequestRecord]:
        with self._lock:
            for record in self._requests.values():
                self._expire_if_needed(record)
            return list(self._requests.values())
