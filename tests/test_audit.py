"""Tests for audit module."""

import asyncio
import pytest
from backend.services.audit_service import AuditService


def test_audit_chain_integrity(tmp_path):
    db_path = str(tmp_path / "test_audit.db")
    service = AuditService(db_path=db_path)
    asyncio.run(service.initialize())

    asyncio.run(service.log_event(event_type="attack_alert", actor="a1", outcome="success"))
    asyncio.run(service.log_event(event_type="access_denied", actor="a2", outcome="denial"))

    result = service.verify_chain()
    assert result["chain_valid"] is True
    assert result["total_records"] >= 3  # genesis + 2 events


def test_audit_tamper_detection(tmp_path):
    db_path = str(tmp_path / "test_audit2.db")
    service = AuditService(db_path=db_path)
    asyncio.run(service.initialize())

    asyncio.run(service.log_event(event_type="attack_alert", actor="a1", outcome="success"))

    # Tamper with a record directly in the DB
    events = service.get_events(limit=5, offset=1)
    if events:
        service._conn.execute(
            "UPDATE audit_events SET details = ? WHERE event_id = ?",
            ('{"tampered": true}', events[0]["event_id"]),
        )
        service._conn.commit()

    result = service.verify_chain()
    assert result["chain_valid"] is False
    assert len(result["tampered_records"]) > 0