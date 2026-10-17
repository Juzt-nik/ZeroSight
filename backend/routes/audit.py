"""Audit routes: query events and verify chain integrity."""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional

from backend.schemas.audit import AuditQuery, VerifyResult
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext
from backend.auth import get_current_user

router = APIRouter()


@router.get("/events")
async def get_audit_events(
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    outcome: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: UserContext = Depends(get_current_user),
):
    """Query audit events (auditor only)."""
    if not access_control.require_permission(current_user, "audit:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view audit events",
        )
    events = audit_service.get_events(
        event_type=event_type,
        actor=actor,
        outcome=outcome,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {"total": audit_service.count(), "events": events}


@router.get("/verify", response_model=VerifyResult)
async def verify_audit_chain(
    current_user: UserContext = Depends(get_current_user),
):
    """Verify the integrity of the hash-chained audit log."""
    if not access_control.require_permission(current_user, "audit:verify"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to verify audit chain",
        )
    result = audit_service.verify_chain()

    # Log the verification itself
    await audit_service.log_event(
        event_type="audit_verify",
        actor=current_user.user_id,
        outcome="success" if result["chain_valid"] else "failure",
        details={
            "chain_valid": result["chain_valid"],
            "total_records": result["total_records"],
            "tampered_count": len(result["tampered_records"]),
        },
    )

    return result


@router.get("/checkpoints")
async def get_audit_checkpoints(
    current_user: UserContext = Depends(get_current_user),
):
    """List all signed audit checkpoints (auditor only)."""
    if not access_control.require_permission(current_user, "audit:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view checkpoints",
        )
    checkpoints = audit_service._conn.execute(
        "SELECT sequence, hash, signature, key_id, created_at FROM audit_checkpoints ORDER BY sequence ASC"
    ).fetchall()
    return {
        "total": len(checkpoints),
        "checkpoints": [
            {
                "sequence": r[0],
                "hash": r[1],
                "signature": r[2],
                "key_id": r[3],
                "created_at": r[4],
            }
            for r in checkpoints
        ],
    }


@router.get("/checkpoints/verify")
async def verify_audit_checkpoints(
    current_user: UserContext = Depends(get_current_user),
):
    """Verify all signed audit checkpoint signatures (auditor only)."""
    if not access_control.require_permission(current_user, "audit:verify"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to verify checkpoints",
        )
    result = audit_service.verify_checkpoints()
    return result


@router.post("/verify/tamper")
async def test_tamper_detection(
    current_user: UserContext = Depends(get_current_user),
):
    """Test endpoint: demonstrates tamper detection by modifying a record and verifying."""
    if not access_control.require_permission(current_user, "audit:verify"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    # Get a non-genesis event to tamper with
    events = audit_service.get_events(limit=5, offset=1)
    if not events:
        return {"message": "No events to test tamper detection"}

    target = events[0]
    # Simulate tampering by directly modifying the database
    if audit_service._conn:
        audit_service._conn.execute(
            "UPDATE audit_events SET details = ? WHERE event_id = ?",
            ('{"tampered": true}', target["event_id"]),
        )
        audit_service._conn.commit()

    # Verify chain - should now detect tampering
    result = audit_service.verify_chain()

    await audit_service.log_event(
        event_type="audit_verify",
        actor=current_user.user_id,
        outcome="failure" if not result["chain_valid"] else "success",
        details={"test": "tamper_detection", "chain_valid": result["chain_valid"]},
    )

    return {
        "message": "Tamper detection test completed",
        "tampered_event": target["event_id"],
        "chain_valid": result["chain_valid"],
        "tampered_records": result["tampered_records"],
    }