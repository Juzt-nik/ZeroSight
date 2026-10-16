"""Detection routes: CAN frame inference and model metrics."""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any

from backend.schemas.detection import (
    CANFrame, DetectionRequest, DetectionResult,
    BatchDetectionRequest, BatchDetectionResult, ModelMetrics,
)
from backend.services.model_service import model_service
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext
from backend.services.preprocessing import frame_to_dict

router = APIRouter()


def get_current_user() -> UserContext:
    """Dependency: extract current user from request context.
    In production, this would validate JWT/session tokens.
    For demo, we accept a header X-User-Id and X-User-Role.
    """
    # This will be overridden by FastAPI dependency injection in main.py
    # For now, return a default analyst context
    return access_control.get_user("analyst_1") or UserContext(user_id="demo", roles={"analyst"})


@router.post("", response_model=DetectionResult)
async def detect_single(
    request: DetectionRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    """Detect attack type for a single CAN frame."""
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
    prediction, confidence = await model_service.predict(frame_dict)

    # Log the detection as an audit event if it's an attack
    if prediction != "Normal":
        await audit_service.log_event(
            event_type="attack_alert",
            actor=current_user.user_id,
            outcome="success",
            details={
                "prediction": prediction,
                "confidence": confidence,
                "arbitration_id": request.frame.arbitration_id,
                "vehicle_token": request.vehicle_token,
            },
        )

    return DetectionResult(
        prediction=prediction,
        confidence=confidence,
        features=model_service.extract_features(frame_dict).tolist()[0],
        model_version=model_service.model_version,
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        vehicle_token=request.vehicle_token,
    )


@router.post("/batch", response_model=BatchDetectionResult)
async def detect_batch(
    request: BatchDetectionRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    """Detect attack types for multiple CAN frames."""
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
                    "confidence": confidence,
                    "arbitration_id": frame.arbitration_id,
                    "vehicle_token": request.vehicle_token,
                    "batch_index": i,
                },
            )
        detection_results.append(DetectionResult(
            prediction=prediction,
            confidence=confidence,
            features=model_service.extract_features(frame_to_dict(frame)).tolist()[0],
            model_version=model_service.model_version,
            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            vehicle_token=request.vehicle_token,
        ))

    summary = {"total": len(detection_results), "attacks": attack_count, "normal": len(detection_results) - attack_count}
    return BatchDetectionResult(results=detection_results, summary=summary)


@router.get("/metrics", response_model=ModelMetrics)
async def get_metrics(
    current_user: UserContext = Depends(lambda: get_current_user()),
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