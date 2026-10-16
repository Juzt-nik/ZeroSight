"""Schemas for anomaly detection module."""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class AnomalyWarning(BaseModel):
    rule_id: str
    rule_name: str
    severity: str = Field(..., description="low | medium | high | critical")
    user_id: str
    description: str
    count: int
    window_minutes: int
    first_occurrence: datetime
    last_occurrence: datetime