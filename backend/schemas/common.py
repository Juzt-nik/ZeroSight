"""Common schemas shared across modules."""

from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime


class ErrorResponse(BaseModel):
    error: str
    status_code: int


class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class PaginatedResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[Any]


class TimestampMixin(BaseModel):
    created_at: Optional[datetime] = None