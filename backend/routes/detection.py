"""Detection routes: CAN frame inference and model metrics."""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any
from datetime import datetime, timezone

from backend.schemas.detection import (
    CANFrame, DetectionRequest, DetectionResult,
    BatchDetectionRequest, BatchDetectionResult, ModelMetrics,
)
from backend.services.model_service import model_service
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext
from backend.auth import get_current_user
from backend.services.preprocessing import frame_to_dict

router = APIRouter()

# Bump this when the inference feature layout changes.
FEATURE_SCHEMA_VERSION = "can-window-v1"


@router.post("", response_model=DetectionResult)
async def detect_single(
    request: DetectionRequest,
    current_user: UserContext = Depends(get_current_user),
):
    """Detect attack type for a single CAN frame.

    P0-05: Uses window-level feature extractor via predict_window so training
    and serving features are identical.
    """
    if not access_control.require_permission(current_user, "detect:create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for detection",
        )

    if not model_service.is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded",
        )

    frame_dict = frame_to_dict(request.frame)
    prediction, confidence, features_dict = await model_service.predict_window(
        [frame_dict]
    )

    # Log the detection as an audit event if it's an attack
    if prediction != "Normal":
        await audit_service.log_event(
            event_type="attack_alert",
            actor=current_user.user_id,
            outcome="success",
            details={
                "prediction": prediction,
                    "model_version": model_service.model_version,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "confidence": confidence,
                "arbitration_id": request.frame.arbitration_id,
                "vehicle_token": request.vehicle_token,
                "features": features_dict,
            },
        )

    return DetectionResult(
        prediction=prediction,
        confidence=confidence,
        features=features_dict,
        model_version=model_service.model_version,
        timestamp=datetime.now(timezone.utc),
        vehicle_token=request.vehicle_token,
    )


@router.post("/batch", response_model=BatchDetectionResult)
async def detect_batch(
    request: BatchDetectionRequest,
    current_user: UserContext = Depends(get_current_user),
):
    """Detect attack types for multiple CAN frames.

    P0-05: Each frame is evaluated through the shared window-level feature
    extractor for training/serving parity.
    """
    if not access_control.require_permission(current_user, "detect:create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for detection",
        )

    if not model_service.is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded",
        )

    frame_dicts = [frame_to_dict(f) for f in request.frames]
    results = await model_service.predict_batch(frame_dicts)

    detection_results = []
    attack_count = 0
    for i, ((prediction, confidence), frame) in enumerate(zip(results, request.frames)):
        if prediction != "Normal":
            attack_count += 1
            await audit_service.log_event(
                event_type="attack_alert",
                actor=current_user.user_id,
                outcome="success",
                details={
                    "prediction": prediction,
                    "model_version": model_service.model_version,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "confidence": confidence,
                    "arbitration_id": frame.arbitration_id,
                    "vehicle_token": request.vehicle_token,
                    "batch_index": i,
                },
            )
        # Extract window-level features for each frame
        _, _, features_dict = await model_service.predict_window(
            [frame_to_dict(frame)]
        )
        detection_results.append(DetectionResult(
            prediction=prediction,
            confidence=confidence,
            features=features_dict,
            model_version=model_service.model_version,
            timestamp=datetime.now(timezone.utc),
            vehicle_token=request.vehicle_token,
        ))

    summary = {"total": len(detection_results), "attacks": attack_count, "normal": len(detection_results) - attack_count}
    return BatchDetectionResult(results=detection_results, summary=summary)


@router.get("/metrics", response_model=ModelMetrics)
async def get_metrics(
    current_user: UserContext = Depends(get_current_user),
):
    """Get model evaluation metrics."""
    if not access_control.require_permission(current_user, "detect:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view metrics",
        )
    metrics = model_service.get_metrics()
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics not available",
        )
    return metrics