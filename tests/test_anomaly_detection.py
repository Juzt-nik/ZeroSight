"""Tests for anomaly detection module."""

from backend.services.anomaly_detector import AnomalyDetector
from datetime import datetime, timezone, timedelta


def test_repeated_denials_flagged():
    detector = AnomalyDetector()
    now = datetime.now(timezone.utc)
    # Manually inject events
    for i in range(6):
        detector._events.append(
            type("E", (), {
                "user_id": "user1", "action": "login", "outcome": "denial",
                "timestamp": now - timedelta(minutes=i), "details": {},
            })()
        )
    warnings = detector.detect()
    assert any(w["rule_id"] == "ANOM-001" for w in warnings)


def test_no_false_positive():
    detector = AnomalyDetector()
    now = datetime.now(timezone.utc)
    detector._events.append(
        type("E", (), {
            "user_id": "user1", "action": "login", "outcome": "success",
            "timestamp": now, "details": {},
        })()
    )
    warnings = detector.detect()
    assert len(warnings) == 0