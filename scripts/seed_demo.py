"""Seed synthetic demo data for immediate demonstration."""

import asyncio
import json
from pathlib import Path
from backend.services.audit_service import audit_service


async def main():
    await audit_service.initialize()
    await audit_service.log_event(
        event_type="system_startup",
        actor="demo",
        outcome="success",
        details={"demo": True},
    )
    await audit_service.log_event(
        event_type="attack_alert",
        actor="analyst_1",
        outcome="success",
        details={"prediction": "DoS", "confidence": 0.95, "vehicle_token": "a1b2c3d4e5f6a7b8"},
    )
    await audit_service.log_event(
        event_type="access_denied",
        actor="analyst_1",
        outcome="denial",
        details={"action": "unmask_request", "reason": "not_security_officer"},
    )
    print("Demo data seeded. Audit events:", audit_service.count())


if __name__ == "__main__":
    asyncio.run(main())