"""Pydantic schemas for privacy-related API routes."""

from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, Field


class TokenizeRequest(BaseModel):
    vehicle_id: str = Field(..., description="Real vehicle identifier (VIN or internal ID)")
    context: Optional[str] = Field(default=None, description="Optional context for token")


class TokenizeResponse(BaseModel):
    vehicle_token: str = Field(..., description="Pseudonymous token (16 hex chars)")
    rotation_epoch: int = Field(..., description="Key rotation epoch this token belongs to")
    expires_at: Optional[datetime] = None


class LocationCoarsenRequest(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    minimization_level: Optional[Literal["coarsen", "withhold"]] = Field(
        default="coarsen", description="coarsen | withhold; raw location is never returned"
    )


class LocationCoarsenResponse(BaseModel):
    original_latitude: Optional[float] = None
    original_longitude: Optional[float] = None
    coarsened_latitude: Optional[float] = None
    coarsened_longitude: Optional[float] = None
    grid_cell: Optional[str] = None
    minimization_applied: str
    reason: str


class UnmaskRequest(BaseModel):
    # The requester identity comes from the authenticated principal, never the JSON body.
    vehicle_token: str = Field(..., description="Pseudonymous token to unmask")
    justification: str = Field(..., min_length=10, description="Business justification")


class UnmaskResponse(BaseModel):
    request_id: str
    status: str = Field(..., description="requested | approved | rejected | completed | expired")
    vehicle_token: str
    real_identity: Optional[str] = None
    approved_by: list[str] = Field(default_factory=list)
    created_at: datetime
    expires_at: datetime


class UnmaskApproveRequest(BaseModel):
    request_id: str
    # The approver identity comes from the authenticated principal, never the JSON body.
    approve: bool = Field(..., description="true to approve, false to reject")
