"""Tests for audit-chain and signed-checkpoint integrity."""

import asyncio

import backend.services.audit_service as audit_module
from backend.services.audit_service import AuditService


def test_audit_chain_integrity(tmp_path):
    db_path = str(tmp_path / "test_audit.db")
    service = AuditService(db_path=db_path)
    asyncio.run(service.initialize())

    asyncio.run(
        service.log_event(
            event_type="attack_alert",
            actor="a1",
            outcome="success",
        )
    )
    asyncio.run(
        service.log_event(
            event_type="access_denied",
            actor="a2",
            outcome="denial",
        )
    )

    result = service.verify_chain()

    assert result["chain_valid"] is True
    assert result["total_records"] >= 3  # Genesis + 2 events


def test_audit_tamper_detection(tmp_path):
    db_path = str(tmp_path / "test_audit2.db")
    service = AuditService(db_path=db_path)
    asyncio.run(service.initialize())

    asyncio.run(
        service.log_event(
            event_type="attack_alert",
            actor="a1",
            outcome="success",
        )
    )

    # Tamper with a non-genesis record directly in the database.
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


def _create_checkpointed_service(tmp_path, monkeypatch):
    """Create a temporary audit log with a checkpoint at sequence 2."""
    monkeypatch.setattr(audit_module, "CHECKPOINT_INTERVAL", 2)
    monkeypatch.setattr(
        audit_module,
        "CHECKPOINT_KEY_PATH",
        str(tmp_path / "test_checkpoint_key.pem"),
    )

    service = AuditService(
        db_path=str(tmp_path / "checkpoint_audit.db")
    )
    asyncio.run(service.initialize())  # Genesis occupies sequence 1.

    asyncio.run(
        service.log_event(
            event_type="attack_alert",
            actor="checkpoint-test",
            outcome="success",
        )
    )  # Sequence 2 creates a checkpoint.

    return service


def test_valid_checkpoint_passes_verification(tmp_path, monkeypatch):
    service = _create_checkpointed_service(tmp_path, monkeypatch)

    result = service.verify_checkpoints()

    assert result["checkpoints_valid"] is True
    assert result["total_checkpoints"] == 1
    assert result["verified_checkpoints"] == 1
    assert result["failed_checkpoints"] == []


def test_checkpoint_detects_modified_audit_hash(tmp_path, monkeypatch):
    service = _create_checkpointed_service(tmp_path, monkeypatch)

    # Alter the event hash after the checkpoint was signed.
    service._conn.execute(
        "UPDATE audit_events SET hash = ? WHERE sequence = ?",
        ("f" * 64, 2),
    )
    service._conn.commit()

    result = service.verify_checkpoints()

    assert result["checkpoints_valid"] is False
    assert any(
        "checkpoint hash does not match audit event" in failure
        for failure in result["failed_checkpoints"]
    )


def test_checkpoint_verification_detects_missing_checkpoint(
    tmp_path,
    monkeypatch,
):
    service = _create_checkpointed_service(tmp_path, monkeypatch)

    service._conn.execute(
        "DELETE FROM audit_checkpoints WHERE sequence = ?",
        (2,),
    )
    service._conn.commit()

    result = service.verify_checkpoints()

    assert result["checkpoints_valid"] is False
    assert any(
        "required checkpoint missing" in failure
        for failure in result["failed_checkpoints"]
    )