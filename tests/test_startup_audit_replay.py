from unittest.mock import AsyncMock

import pytest

import backend.main as main_module
from backend.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_startup_replays_persisted_denials_into_anomaly_detector(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "startup-replay.db"

    # Seed a persistent audit log before application startup.
    seed = AuditService()
    seed.db_path = str(db_path)
    await seed.initialize()

    for _ in range(5):
        await seed.log_event(
            event_type="access_denied",
            actor="startup-replay-user",
            outcome="failure",
            details={"action": "login"},
        )

    if seed._conn:
        seed._conn.close()
        seed._conn = None

    previous_db_path = main_module.audit_service.db_path
    try:
        monkeypatch.setenv("AUDIT_DB_PATH", str(db_path))
        monkeypatch.setattr(
            main_module, "validate_startup_config", lambda: None
        )
        monkeypatch.setattr(
            main_module.model_service, "initialize", AsyncMock()
        )

        async with main_module.lifespan(main_module.app):
            warnings = main_module.anomaly_detector.detect()
            assert any(
                "ANOM-001" in str(warning) for warning in warnings
            ), f"Persisted denials did not trigger ANOM-001: {warnings}"
    finally:
        conn = main_module.audit_service._conn
        if conn:
            conn.close()
        main_module.audit_service._conn = None
        main_module.audit_service.db_path = previous_db_path
        main_module.anomaly_detector.clear()
