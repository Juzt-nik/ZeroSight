"""Anomaly detection routes: access pattern warnings."""

from fastapi import APIRouter, Depends, HTTPException, status

from backend.services.anomaly_detector import anomaly_detector, AccessEvent
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext
from backend.auth import get_current_user

router = APIRouter()


@router.get("/warnings")
async def get_anomaly_warnings(
    current_user: UserContext = Depends(get_current_user),
):
    """Get current access anomaly warnings (auditor only)."""
    if not access_control.require_permission(current_user, "anomaly:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view anomaly warnings",
        )
    warnings = anomaly_detector.detect()
    return {"warnings": warnings, "count": len(warnings)}



@router.post("/record-event")
async def record_access_event(
    user_id: str,
    action: str,
    outcome: str,
    current_user: UserContext = Depends(get_current_user),
):
    """Record an access event for anomaly analysis."""
    if not access_control.require_permission(current_user, "anomaly:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    # A caller cannot record events under another user's identity.
    if user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot record access events for another user",
        )

    anomaly_detector.record(
        user_id=user_id,
        action=action,
        outcome=outcome,
    )

    await audit_service.log_event(
        event_type="access_denied" if outcome == "denial" else "attack_alert",
        actor=current_user.user_id,
        outcome="success",
        details={
            "anomaly_record": {
                "user_id": user_id,
                "action": action,
                "outcome": outcome,
            }
        },
    )

    return {
        "message": "Event recorded",
        "user_id": user_id,
        "action": action,
        "outcome": outcome,
    }
