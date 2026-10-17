"""Schemas for detection module."""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime


class CANFrame(BaseModel):
    """Single CAN bus frame."""
    timestamp: float = Field(..., description="Unix timestamp")
    arbitration_id: str = Field(..., description="CAN ID in hex, e.g. '0316'")
    dlc: int = Field(..., ge=0, le=15, description="Data length code")
    data_bytes: List[int] = Field(
        ..., min_length=0, max_length=8,
        description="Classical CAN payload bytes (0-255 each)"
    )
    label: Optional[Literal["Normal", "DoS", "Fuzzy", "Gear", "RPM", "R", "T", "A", "G", "F", "D"]] = Field(
        default=None, description="Ground truth label (Normal/DoS/Fuzzy/Gear/RPM)"
    )

    @field_validator("data_bytes")
    @classmethod
    def validate_bytes(cls, v):
        for b in v:
            if b < 0 or b > 255:
                raise ValueError(f"Byte value {b} out of range 0-255")
        return v

    @field_validator("data_bytes")
    @classmethod
    def validate_dlc_matches_payload(cls, v, info):
        dlc = info.data.get("dlc")
        if dlc is not None and len(v) != dlc:
            raise ValueError(f"DLC is {dlc}, but payload contains {len(v)} bytes")
        return v

    @field_validator("arbitration_id")
    @classmethod
    def validate_can_id(cls, v):
        try:
            parsed = int(v, 16)
        except ValueError:
            raise ValueError(f"Invalid CAN arbitration_id: {v}")
        if parsed < 0 or parsed > 0x1FFFFFFF:
            raise ValueError(f"CAN arbitration_id is out of range: {v}")
        return v.lower()


class DetectionRequest(BaseModel):
    """Request to detect a single CAN frame."""
    frame: CANFrame
    vehicle_token: Optional[str] = Field(
        default=None, description="Pseudonymous vehicle token (if known)"
    )


class DetectionResult(BaseModel):
    """Detection result for a single frame."""
    prediction: str = Field(..., description="Predicted class: Normal/DoS/Fuzzy/Gear/RPM")
    confidence: float = Field(..., ge=0.0, le=1.0)
    features: Dict[str, Any]
    model_version: str
    timestamp: datetime
    vehicle_token: Optional[str] = None
    inference_latency_ms: Optional[float] = Field(
        default=None, ge=0,
        description="Server-side predict_window call duration in milliseconds, including any model-lock wait",
    )

    model_config = {"protected_namespaces": ()}


class BatchDetectionRequest(BaseModel):
    """Request to detect multiple CAN frames."""
    frames: List[CANFrame]
    vehicle_token: Optional[str] = None


class WindowDetectionRequest(BaseModel):
    """All CAN frames belonging to one bounded inference window."""
    frames: List[CANFrame] = Field(..., min_length=1, max_length=4096)
    vehicle_token: Optional[str] = None


class BatchDetectionResult(BaseModel):
    results: List[DetectionResult]
    summary: Dict[str, int]


class ModelMetrics(BaseModel):
    """Model evaluation metrics."""
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    per_class: Dict[str, Dict[str, float]]
    confusion_matrix: List[List[int]]
    classes: List[str]
    training_samples: int
    test_samples: int
