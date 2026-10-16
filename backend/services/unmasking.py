"""Dual-approval identity unmasking workflow.

State machine:
  requested -> approved_by_user_a -> approved_by_user_b -> completed
  or rejected / expired at any point.

Requires REQUIRED_APPROVERS (default 2) distinct security_officer users.
Same user cannot approve twice. Expired requests auto-reject.
"""

import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger("vsoc.unmasking")

REQUIRED_APPROVERS = int(os.getenv("REQUIRED_APPROVERS", "2"))
REQUEST_TTL_MINUTES = int(os.getenv("UNAMASK_REQUEST_TTL_MINUTES", "30"))

REQUESTED = "requested"
APPROVED = "approved"
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
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=REQUEST_TTL_MINUTES)
    )
    real_identity: Optional[str] = None
    completed_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def can_be_approved_by(self, user_id: str) -> bool:
        """Check if a user can approve this request."""
        if self.status != REQUESTED:
            return False
        if self.is_expired():
            return False
        if user_id in self.approvers:
            return False  # Duplicate approval not allowed
        if user_id == self.requested_by:
            return False  # Requester cannot approve their own request
        return True

    def approve(self, user_id: str, required_approvers: int) -> bool:
        """Record an approval. Returns True if request is now complete."""
        if not self.can_be_approved_by(user_id):
            return False
        self.approvers.append(user_id)
        if len(self.approvers) >= required_approvers:
            self.status = COMPLETED
            self.completed_at = datetime.now(timezone.utc)
            logger.info(
                "Unmask request %s completed by %d approvers",
                self.request_id, len(self.approvers),
            )
        else:
            logger.info(
                "Unmask request %s approved by %s (%d/%d)",
                self.request_id, user_id, len(self.approvers), required_approvers,
            )
        return True

    def reject(self, user_id: str, reason: Optional[str] = None) -> bool:
        """Reject a request (any security_officer can reject)."""
        if self.status != REQUESTED:
            return False
        if self.is_expired():
            return False
        self.status = REJECTED
        self.rejections.append(user_id)
        logger.info("Unmask request %s rejected by %s", self.request_id, user_id)
        return True


class UnmaskingService:
    """In-memory unmasking request store (backed by audit log in production)."""

    def __init__(self, required_approvers: int = REQUIRED_APPROVERS):
        self.required_approvers = required_approvers
        self._requests: Dict[str, UnmaskRequestRecord] = {}
        # Identity mapping: token -> real identity (isolated from normal processing)
        self._identity_map: Dict[str, str] = {}

    def register_identity(self, vehicle_token: str, real_identity: str):
        """Register the real identity behind a token. Called only during secure provisioning."""
        self._identity_map[vehicle_token] = real_identity
        logger.info("Registered identity mapping for token %s", vehicle_token)

    def create_request(
        self, vehicle_token: str, justification: str, requested_by: str
    ) -> UnmaskRequestRecord:
        """Create a new unmask request."""
        req_id = str(uuid.uuid4())
        record = UnmaskRequestRecord(
            request_id=req_id,
            vehicle_token=vehicle_token,
            justification=justification,
            requested_by=requested_by,
        )
        self._requests[req_id] = record
        logger.info("Created unmask request %s by %s", req_id, requested_by)
        return record

    def get_request(self, request_id: str) -> Optional[UnmaskRequestRecord]:
        return self._requests.get(request_id)

    def approve(self, request_id: str, approver_user_id: str) -> bool:
        record = self.get_request(request_id)
        if not record:
            return False
        return record.approve(approver_user_id, self.required_approvers)

    def reject(self, request_id: str, approver_user_id: str, reason: Optional[str] = None) -> bool:
        record = self.get_request(request_id)
        if not record:
            return False
        return record.reject(approver_user_id)

    def unmask(self, request_id: str) -> Optional[str]:
        """Return real identity if request is completed. Otherwise None."""
        record = self.get_request(request_id)
        if not record or record.status != COMPLETED:
            return None
        return self._identity_map.get(record.vehicle_token)

    def list_requests(self) -> List[UnmaskRequestRecord]:
        # Clean up expired
        now = datetime.now(timezone.utc)
        for rec in self._requests.values():
            if rec.status == REQUESTED and rec.is_expired():
                rec.status = EXPIRED
        return list(self._requests.values())