import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.routes import detection
from backend.schemas.detection import CANFrame, DetectionRequest
from backend.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_detect_attack_persists_audit_alert(monkeypatch, tmp_path):
    # Use an isolated audit database for this test.
    audit = AuditService()
    audit.db_path = str(tmp_path / "audit.db")
    await audit.initialize()

    monkeypatch.setattr(detection, "audit_service", audit)
    monkeypatch.setattr(
        detection.access_control,
        "require_permission",
        lambda user, permission: True,
    )
    monkeypatch.setattr(
        detection.model_service,
        "is_loaded",
        lambda: True,
    )
    monkeypatch.setattr(
        detection.model_service,
        "predict_window",
        AsyncMock(return_value=("DoS", 0.98, {"frame_count": 1})),
    )

    user = SimpleNamespace(user_id="phase3-test-user")
    request = DetectionRequest(
        frame=CANFrame(
            timestamp=1760000000.0,
            arbitration_id="0316",
            dlc=2,
            data_bytes=[255, 255],
        ),
        vehicle_token="test-vehicle-token",
    )

    result = await detection.detect_single(request, user)

    assert result.prediction == "DoS"

    events = audit.get_events(limit=100, offset=0)
    alert = next(
        (event for event in events if event.get("event_type") == "attack_alert"),
        None,
    )

    assert alert is not None, "Attack detection did not persist an attack_alert"
    assert alert["actor"] == "phase3-test-user"

    details = alert["details"]
    if isinstance(details, str):
        details = json.loads(details)

    assert details["prediction"] == "DoS"
    assert details["arbitration_id"] == "0316"
    assert details["vehicle_token"] == "test-vehicle-token"
    assert details["model_version"] == detection.model_service.model_version
    assert details["feature_schema_version"] == detection.FEATURE_SCHEMA_VERSION
