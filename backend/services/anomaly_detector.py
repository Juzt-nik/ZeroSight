"""Access anomaly detection with explainable threshold rules.

These are simple, auditable thresholds - NOT AI. They flag suspicious patterns
such as repeated denials, excessive unmask attempts, off-hours access, etc.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("vsoc.anomaly")

# Rule thresholds
MAX_DENIED_PER_WINDOW = 5
DENIED_WINDOW_MINUTES = 10
MAX_UNMASK_ATTEMPTS = 2
UNMASK_WINDOW_MINUTES = 60
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18
MAX_ALERT_VIEWS = 100
ALERT_VIEW_WINDOW_MINUTES = 10


@dataclass
class AccessEvent:
    user_id: str
    action: str
    outcome: str  # success | denial
    timestamp: datetime
    details: Dict[str, Any]


class AnomalyDetector:
    """Stateful anomaly detector over recent access events."""

    def __init__(self):
        self._events: List[AccessEvent] = []

    def record(self, user_id: str, action: str, outcome: str, details: Optional[Dict[str, Any]] = None):
        """Record an access event for anomaly analysis."""
        self._events.append(
            AccessEvent(
                user_id=user_id,
                action=action,
                outcome=outcome,
                timestamp=datetime.now(timezone.utc),
                details=details or {},
            )
        )
        # Keep only last 10000 events
        if len(self._events) > 10000:
            self._events = self._events[-10000:]

    def _window_events(self, user_id: str, action: str, minutes: int) -> List[AccessEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return [
            e for e in self._events
            if e.user_id == user_id and e.action == action and e.timestamp >= cutoff
        ]

    def detect(self) -> List[Dict[str, Any]]:
        """Run all anomaly rules and return warnings."""
        warnings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        # Group events by user
        users = set(e.user_id for e in self._events)

        for user_id in users:
            user_events = [e for e in self._events if e.user_id == user_id]

            # Rule 1: Repeated denied requests
            denied = [e for e in user_events if e.outcome == "denial"]
            recent_denied = [
                e for e in denied
                if e.timestamp >= now - timedelta(minutes=DENIED_WINDOW_MINUTES)
            ]
            if len(recent_denied) >= MAX_DENIED_PER_WINDOW:
                warnings.append({
                    "rule_id": "ANOM-001",
                    "rule_name": "Repeated denied requests",
                    "severity": "high",
                    "user_id": user_id,
                    "description": (
                        f"{len(recent_denied)} denied requests in "
                        f"{DENIED_WINDOW_MINUTES} minutes (threshold: {MAX_DENIED_PER_WINDOW})"
                    ),
                    "count": len(recent_denied),
                    "window_minutes": DENIED_WINDOW_MINUTES,
                    "first_occurrence": min(e.timestamp for e in recent_denied).isoformat(),
                    "last_occurrence": max(e.timestamp for e in recent_denied).isoformat(),
                })

            # Rule 2: Excessive unmask attempts
            unmask_attempts = [
                e for e in user_events
                if e.action == "unmask_request"
                and e.timestamp >= now - timedelta(minutes=UNMASK_WINDOW_MINUTES)
            ]
            if len(unmask_attempts) >= MAX_UNMASK_ATTEMPTS:
                warnings.append({
                    "rule_id": "ANOM-002",
                    "rule_name": "Excessive unmask attempts",
                    "severity": "critical",
                    "user_id": user_id,
                    "description": (
                        f"{len(unmask_attempts)} unmask requests in "
                        f"{UNMASK_WINDOW_MINUTES} minutes (threshold: {MAX_UNMASK_ATTEMPTS})"
                    ),
                    "count": len(unmask_attempts),
                    "window_minutes": UNMASK_WINDOW_MINUTES,
                    "first_occurrence": min(e.timestamp for e in unmask_attempts).isoformat(),
                    "last_occurrence": max(e.timestamp for e in unmask_attempts).isoformat(),
                })

            # Rule 3: Off-hours access
            off_hours = [
                e for e in user_events
                if not (BUSINESS_HOURS_START <= e.timestamp.hour < BUSINESS_HOURS_END)
            ]
            if len(off_hours) >= 3:
                warnings.append({
                    "rule_id": "ANOM-003",
                    "rule_name": "Off-hours access",
                    "severity": "medium",
                    "user_id": user_id,
                    "description": (
                        f"{len(off_hours)} access events outside "
                        f"{BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00"
                    ),
                    "count": len(off_hours),
                    "window_minutes": 0,
                    "first_occurrence": min(e.timestamp for e in off_hours).isoformat(),
                    "last_occurrence": max(e.timestamp for e in off_hours).isoformat(),
                })

        return warnings


# Module-level singleton instance
anomaly_detector = AnomalyDetector()