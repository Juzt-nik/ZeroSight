"""Privacy routes: tokenization, location minimization, and controlled unmasking."""

import hmac
import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status

from backend.schemas.privacy import (
    TokenizeRequest,
    TokenizeResponse,
    LocationCoarsenRequest,
    LocationCoarsenResponse,
    UnmaskRequest,
    UnmaskResponse,
    UnmaskApproveRequest,
)
from backend.services.tokenization import generate_token
from backend.services.location import coarsen_location
from backend.services.unmasking import UnmaskingService, COMPLETED
from backend.services.audit_service import audit_service
from backend.services.access_control import access_control, UserContext

router = APIRouter()
unmask_service = UnmaskingService()

# Synthetic demo principals only. Tokens are supplied through environment
# variables and must be unique, random, and at least 32 characters long.
_DEMO_TOKEN_USERS = (
    ("ZEROSIGHT_ANALYST_TOKEN", "analyst_1"),
    ("ZEROSIGHT_SECURITY_OFFICER_1_TOKEN", "sec_officer_1"),
    ("ZEROSIGHT_SECURITY_OFFICER_2_TOKEN", "sec_officer_2"),
    ("ZEROSIGHT_SECURITY_OFFICER_3_TOKEN", "sec_officer_3"),
    ("ZEROSIGHT_AUDITOR_TOKEN", "auditor_1"),
    ("ZEROSIGHT_ADMIN_TOKEN", "admin_1"),
)


def get_current_user(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> UserContext:
    """Authenticate a local demo Bearer token; production must use an IdP.

    Authentication intentionally fails closed if demo auth is disabled or token
    configuration is missing/weak. Client-supplied user IDs are never trusted.
    """
    demo_enabled = os.getenv("ZEROSIGHT_DEMO_AUTH", "false").strip().lower()
    if demo_enabled not in {"1", "true", "yes"}:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No authentication provider is configured. Enable demo authentication "
                "only for local development, or integrate a trusted identity provider."
            ),
        )

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = token.strip()

    configured_tokens = []
    weak_configuration = False
    for environment_name, user_id in _DEMO_TOKEN_USERS:
        expected = os.getenv(environment_name)
        if not expected:
            continue
        if len(expected) < 32:
            weak_configuration = True
        else:
            configured_tokens.append((expected, user_id))

    if weak_configuration:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Demo Bearer tokens must be at least 32 characters long",
        )
    if not configured_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No demo Bearer tokens are configured",
        )

    matches = [
        user_id
        for expected, user_id in configured_tokens
        if hmac.compare_digest(token, expected)
    ]
    if len(matches) > 1:
        # Duplicate tokens across principals are an authentication misconfiguration.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Duplicate demo tokens are configured; authentication is disabled",
        )
    if not matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = access_control.get_user(matches[0])
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authenticated demo principal is not registered",
        )
    return user


@router.post("/tokenize", response_model=TokenizeResponse)
async def tokenize_vehicle(
    request: TokenizeRequest,
    current_user: UserContext = Depends(get_current_user),
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
    current_user: UserContext = Depends(get_current_user),
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
    current_user: UserContext = Depends(get_current_user),
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
    try:
        record = unmask_service.create_request(
            vehicle_token=request.vehicle_token,
            justification=request.justification,
            requested_by=current_user.user_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await audit_service.log_event(
        event_type="unmask_request",
        actor=current_user.user_id,
        outcome="success",
        details={"request_id": record.request_id, "vehicle_token": record.vehicle_token},
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
    current_user: UserContext = Depends(get_current_user),
):
    if not access_control.require_role(current_user, "security_officer"):
        await audit_service.log_event(
            event_type="access_denied",
            actor=current_user.user_id,
            outcome="denial",
            details={"action": "unmask_approve", "reason": "not_security_officer"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only security officers can approve unmasking",
        )

    record = unmask_service.get_request(request.request_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unmask request not found")

    if request.approve:
        success = unmask_service.approve(request.request_id, current_user.user_id)
        action = "unmask_approve"
    else:
        success = unmask_service.reject(request.request_id, current_user.user_id)
        action = "unmask_reject"

    if not success:
        await audit_service.log_event(
            event_type="access_denied",
            actor=current_user.user_id,
            outcome="denial",
            details={"action": action, "request_id": request.request_id},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot approve or reject this request; it may be expired, consumed, duplicated, or unauthorized",
        )

    await audit_service.log_event(
        event_type=action,
        actor=current_user.user_id,
        outcome="success",
        details={"request_id": request.request_id, "approve": request.approve},
    )
    updated = unmask_service.get_request(request.request_id)
    if updated and updated.status == COMPLETED and updated.completed_by == current_user.user_id:
        real_identity = unmask_service.unmask(request.request_id, disclosed_by=current_user.user_id)
        if real_identity is not None:
            await audit_service.log_event(
                event_type="unmask_complete",
                actor=current_user.user_id,
                outcome="success",
                details={"request_id": request.request_id},
            )
            return {
                "request_id": request.request_id,
                "status": COMPLETED,
                "real_identity": real_identity,
                "message": "Identity disclosed once after dual approval",
            }
        await audit_service.log_event(
            event_type="unmask_complete",
            actor=current_user.user_id,
            outcome="failure",
            details={"request_id": request.request_id, "reason": "identity_not_available_or_already_consumed"},
        )
        return {
            "request_id": request.request_id,
            "status": COMPLETED,
            "real_identity": None,
            "message": "Approvals completed; identity mapping unavailable or disclosure already consumed",
        }

    return {
        "request_id": request.request_id,
        "status": updated.status if updated else "unknown",
        "message": "Approval recorded",
    }


@router.get("/unmask/requests", response_model=list)
async def list_unmask_requests(
    current_user: UserContext = Depends(get_current_user),
):
    if not (
        access_control.require_role(current_user, "security_officer")
        or access_control.require_role(current_user, "auditor")
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    records = unmask_service.list_requests()
    return [
        {
            "request_id": record.request_id,
            "status": record.status,
            "vehicle_token": record.vehicle_token,
            "real_identity": None,
            "approved_by": record.approvers,
            "created_at": record.created_at.isoformat(),
            "expires_at": record.expires_at.isoformat(),
        }
        for record in records
    ]
