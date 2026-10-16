"""Schemas for audit module."""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    actor: str
    outcome: str = Field(..., description="success | failure | denial")
    details: Dict[str, Any] = {}
    timestamp: datetime
    hash: str
    prev_hash: str


class AuditQuery(BaseModel):
    event_type: Optional[str] = None
    actor: Optional[str] = None
    outcome: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class VerifyResult(BaseModel):
    chain_valid: bool
    total_records: int
    verified_records: int
    first_hash: str
    last_hash: str
    tampered_records: list[str] = []
    message: str