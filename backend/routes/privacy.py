"""Privacy routes: tokenization, location minimization, unmasking."""

from fastapi import APIRouter, Depends, HTTPException, status

from backend.schemas.privacy import (
    TokenizeRequest, TokenizeResponse,
    LocationCoarsenRequest, LocationCoarsenResponse,
    UnmaskRequest, UnmaskResponse, UnmaskApproveRequest,
)
from backend.services.tokenization import generate_token
from backend.services.location import coarsen_location
from backend.services.unmasking import UnmaskingService
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext

router = APIRouter()

unmask_service = UnmaskingService()


def get_current_user() -> UserContext:
    return access_control.get_user("analyst_1") or UserContext(user_id="demo", roles={"analyst"})


@router.post("/tokenize", response_model=TokenizeResponse)
async def tokenize_vehicle(
    request: TokenizeRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    if not access_control.require_permission(current_user, "privacy:tokenize"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for tokenization",
        )
    token, epoch, expires_at = generate_token(request.vehicle_id, request.context)
    await audit_service.log_event(
        event_type="attack_alert",
        actor=current_user.user_id,
        outcome="success",
        details={"action": "tokenize", "vehicle_token": token},
    )
    return TokenizeResponse(vehicle_token=token, rotation_epoch=epoch, expires_at=expires_at)

@router.post("/location/coarsen", response_model=LocationCoarsenResponse)
async def coarsen_location_endpoint(
    request: LocationCoarsenRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    if not access_control.require_permission(current_user, "privacy:location"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for location coarsening",
        )
    result = coarsen_location(
        request.latitude,
        request.longitude,
        minimization_level=request.minimization_level,
    )
    await audit_service.log_event(
        event_type="attack_alert",
        actor=current_user.user_id,
        outcome="success",
        details={"action": "location_coarsen", "level": result["minimization_applied"]},
    )
    return LocationCoarsenResponse(**result)


@router.post("/unmask/request", response_model=UnmaskResponse)
async def request_unmask(
    request: UnmaskRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    if not access_control.require_role(current_user, "security_officer"):
        await audit_service.log_event(
            event_type="access_denied",
            actor=current_user.user_id,
            outcome="denial",
            details={"action": "unmask_request", "reason": "not_security_officer"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only security officers can request unmasking",
        )
    record = unmask_service.create_request(
        vehicle_token=request.vehicle_token,
        justification=request.justification,
        requested_by=current_user.user_id,
    )
    await audit_service.log_event(
        event_type="unmask_request",
        actor=current_user.user_id,
        outcome="success",
        details={"request_id": record.request_id, "vehicle_token": request.vehicle_token},
    )
    return UnmaskResponse(
        request_id=record.request_id,
        status=record.status,
        vehicle_token=record.vehicle_token,
        real_identity=None,
        approved_by=record.approvers,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )

@router.post("/unmask/approve")
async def approve_unmask(
    request: UnmaskApproveRequest,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    if not access_control.require_role(current_user, "security_officer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only security officers can approve unmasking",
        )
    record = unmask_service.get_request(request.request_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unmask request not found",
        )
    if request.approve:
        success = unmask_service.approve(request.request_id, current_user.user_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot approve this request",
            )
        action = "unmask_approve"
    else:
        success = unmask_service.reject(request.request_id, current_user.user_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reject this request",
            )
        action = "unmask_reject"
    await audit_service.log_event(
        event_type=action,
        actor=current_user.user_id,
        outcome="success",
        details={"request_id": request.request_id, "approve": request.approve},
    )
    updated = unmask_service.get_request(request.request_id)
    if updated.status == "completed":
        real_identity = unmask_service.unmask(request.request_id)
        await audit_service.log_event(
            event_type="unmask_complete",
            actor=current_user.user_id,
            outcome="success",
            details={"request_id": request.request_id},
        )
        return {
            "request_id": request.request_id,
            "status": "completed",
            "real_identity": real_identity,
            "message": "Identity unmasked after dual approval",
        }
    return {
        "request_id": request.request_id,
        "status": updated.status,
        "message": "Approval recorded",
    }


@router.get("/unmask/requests", response_model=list)
async def list_unmask_requests(
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    if not access_control.require_role(current_user, "security_officer") and not access_control.require_role(current_user, "auditor"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    records = unmask_service.list_requests()
    return [
        {
            "request_id": r.request_id,
            "status": r.status,
            "vehicle_token": r.vehicle_token,
            "real_identity": None,
            "approved_by": r.approvers,
            "created_at": r.created_at.isoformat(),
            "expires_at": r.expires_at.isoformat(),
        }
        for r in records
    ]