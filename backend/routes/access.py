"""Access control routes: roles and authorization."""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from backend.schemas.access import RoleInfo, CurrentUser, ApprovalRequest, ApprovalDecision
from backend.services.access_control import access_control, UserContext, default_access_control
from backend.services.audit_service import audit_service

router = APIRouter()


def get_current_user() -> UserContext:
    return access_control.get_user("analyst_1") or UserContext(user_id="demo", roles={"analyst"})


@router.get("/roles", response_model=List[RoleInfo])
async def list_roles(
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    """List available roles and their permissions."""
    if not access_control.require_permission(current_user, "access:roles"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view roles",
        )
    return access_control.list_roles()


@router.get("/me", response_model=CurrentUser)
async def get_current_user_info(
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    """Get the current user's context."""
    return CurrentUser(
        user_id=current_user.user_id,
        roles=list(current_user.roles),
        is_authenticated=True,
    )


@router.post("/approve")
async def generic_approve(
    decision: ApprovalDecision,
    current_user: UserContext = Depends(lambda: get_current_user()),
):
    """Generic approval endpoint for access control decisions."""
    if not access_control.require_role(current_user, "security_officer"):
        await audit_service.log_event(
            event_type="access_denied",
            actor=current_user.user_id,
            outcome="denial",
            details={"action": "generic_approve", "reason": "not_security_officer"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only security officers can approve",
        )
    await audit_service.log_event(
        event_type="access_denied" if not decision.approve else "attack_alert",
        actor=current_user.user_id,
        outcome="success",
        details={"action": "generic_approve", "request_id": decision.request_id, "approve": decision.approve},
    )
    return {"request_id": decision.request_id, "approved": decision.approve, "by": current_user.user_id}