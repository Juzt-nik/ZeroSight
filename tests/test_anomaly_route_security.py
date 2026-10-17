
"""Security tests for anomaly event recording."""

import asyncio

import pytest
from fastapi import HTTPException

from backend.routes.anomaly import record_access_event
from backend.services.access_control import UserContext


def test_cannot_record_event_for_another_user():
    """An authorized user must not be able to spoof another user's ID."""
    current_user = UserContext(
        user_id="phase3-test-admin",
        roles={"admin"},
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            record_access_event(
                user_id="different-user",
                action="login",
                outcome="denial",
                current_user=current_user,
            )
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == (
        "Cannot record access events for another user"
    )
