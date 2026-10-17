
"""Integration tests for audit-event-driven anomaly monitoring."""

import asyncio

import backend.services.audit_service as audit_module
from backend.services.audit_service import AuditService
from backend.services.anomaly_detector import AnomalyDetector


def test_audit_denials_feed_anomaly_detector(tmp_path, monkeypatch):
    """Five persisted denials from one actor should trigger ANOM-001."""
    monkeypatch.setattr(audit_module, "CHECKPOINT_INTERVAL", 100)
    monkeypatch.setattr(
        audit_module,
        "CHECKPOINT_KEY_PATH",
        str(tmp_path / "checkpoint_key.pem"),
    )

    detector = AnomalyDetector()
    service = AuditService(
        db_path=str(tmp_path / "audit_anomaly.db")
    )
    service.set_event_listener(detector.record_audit_event)

    try:
        asyncio.run(service.initialize())

        for _ in range(5):
            asyncio.run(
                service.log_event(
                    event_type="access_denied",
                    actor="trusted-user",
                    outcome="denial",
                    details={"action": "login"},
                )
            )

        warnings = detector.detect()
        denial_warning = next(
            (
                warning
                for warning in warnings
                if warning["rule_id"] == "ANOM-001"
            ),
            None,
        )

        assert denial_warning is not None
        assert denial_warning["user_id"] == "trusted-user"
        assert denial_warning["count"] == 5

    finally:
        if service._conn is not None:
            service._conn.close()


def test_successful_audit_events_do_not_trigger_denial_warning(
    tmp_path, monkeypatch
):
    """Successful approvals must not be counted as denied requests."""
    monkeypatch.setattr(audit_module, "CHECKPOINT_INTERVAL", 100)
    monkeypatch.setattr(
        audit_module,
        "CHECKPOINT_KEY_PATH",
        str(tmp_path / "checkpoint_key_success.pem"),
    )

    detector = AnomalyDetector()
    service = AuditService(
        db_path=str(tmp_path / "audit_success.db")
    )
    service.set_event_listener(detector.record_audit_event)

    try:
        asyncio.run(service.initialize())

        for _ in range(5):
            asyncio.run(
                service.log_event(
                    event_type="access_approve",
                    actor="trusted-user",
                    outcome="success",
                    details={"action": "approve"},
                )
            )

        warnings = detector.detect()

        assert not any(
            warning["rule_id"] == "ANOM-001"
            for warning in warnings
        )

    finally:
        if service._conn is not None:
            service._conn.close()
