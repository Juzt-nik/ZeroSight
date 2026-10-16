"""Schemas for access control module."""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class RoleInfo(BaseModel):
    role: str
    description: str
    permissions: List[str]


class CurrentUser(BaseModel):
    user_id: str
    roles: List[str]
    is_authenticated: bool


class ApprovalRequest(BaseModel):
    request_id: str
    action: str = Field(..., description="e.g. 'unmask_identity'")
    requested_by: str
    required_approvers: int = 2
    approvers: List[str] = []
    status: str = Field(..., description="pending | approved | rejected | expired")
    created_at: datetime
    expires_at: datetime


class ApprovalDecision(BaseModel):
    request_id: str
    approver_user_id: str
    approve: bool
    reason: Optional[str] = None