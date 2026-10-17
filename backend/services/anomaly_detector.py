"""Rule-based anomaly detection for access and audit events.

This detector intentionally uses small, explainable threshold rules rather than
claiming to be an AI model. Persisted audit events can be passed to
``record_audit_event`` so access anomalies are derived from server-recorded
activity. Event history is kept in memory and should be replayed from the audit
store during application startup.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger("vsoc.anomaly")


# ---------------------------------------------------------------------------
# Rule configuration
# ---------------------------------------------------------------------------

MAX_DENIED_PER_WINDOW = 5
DENIED_WINDOW_MINUTES = 10
MAX_UNMASK_ATTEMPTS = 2
UNMASK_WINDOW_MINUTES = 60
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18

MAX_RECORDED_EVENTS = 10000


@dataclass
class AccessEvent:
    """One normalized access/security event used by the detector."""

    user_id: str
    action: str
    outcome: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


class AnomalyDetector:
    """Detect suspicious patterns using transparent threshold rules."""

    def __init__(self) -> None:
        self._events: List[AccessEvent] = []

    def clear(self) -> None:
        """Clear in-memory events before replaying the persisted audit log."""
        self._events.clear()

    def record_audit_event(self, event: Dict[str, Any]) -> None:
        """Normalize a persisted audit-service event for anomaly detection.

        The actor comes from the server-created audit record rather than from a
        user ID claimed in its details. Events created by the manual anomaly
        simulation endpoint are skipped here because that endpoint records
        them directly, which prevents double counting.
        """
        relevant_types = {
            "access_denied",
            "unmask_request",
            "unmask_complete",
            "access_approve",
            "access_deny",
            "attack_alert",
            "audit_verify",
        }

        event_type = event.get("event_type")
        if event_type not in relevant_types:
            return

        details = event.get("details")
        if not isinstance(details, dict):
            details = {}

        # The simulation endpoint records its event directly. Avoid counting
        # its corresponding audit record a second time through the listener.
        if "anomaly_record" in details:
            return

        actor = event.get("actor")
        if not isinstance(actor, str) or not actor.strip():
            return
        if actor in {"system", "unknown"}:
            return

        outcome = event.get("outcome")
        if not isinstance(outcome, str) or not outcome.strip():
            return

        raw_timestamp = event.get("timestamp")
        try:
            if isinstance(raw_timestamp, datetime):
                event_timestamp = raw_timestamp
            elif isinstance(raw_timestamp, str):
                event_timestamp = datetime.fromisoformat(
                    raw_timestamp.replace("Z", "+00:00")
                )
            else:
                raise ValueError("Missing audit timestamp")
        except (TypeError, ValueError):
            logger.warning(
                "Skipping audit event with invalid timestamp: %s",
                event.get("event_id"),
            )
            return

        if event_timestamp.tzinfo is None:
            event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
        else:
            event_timestamp = event_timestamp.astimezone(timezone.utc)

        action = event_type
        if event_type in {"access_denied", "attack_alert"}:
            recorded_action = details.get("action")
            if isinstance(recorded_action, str) and recorded_action.strip():
                action = recorded_action

        self.record(
            user_id=actor,
            action=action,
            outcome=outcome,
            details=details,
            timestamp=event_timestamp,
        )

    def record(
        self,
        user_id: str,
        action: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Record an event, optionally preserving its source timestamp.

        Naive timestamps are interpreted as UTC so comparisons do not mix
        timezone-aware and timezone-naive datetime instances.
        """
        event_time = timestamp or datetime.now(timezone.utc)
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        else:
            event_time = event_time.astimezone(timezone.utc)

        self._events.append(
            AccessEvent(
                user_id=user_id,
                action=action,
                outcome=outcome,
                timestamp=event_time,
                details=details if isinstance(details, dict) else {},
            )
        )

        if len(self._events) > MAX_RECORDED_EVENTS:
            self._events = self._events[-MAX_RECORDED_EVENTS:]

    def detect(self) -> List[Dict[str, Any]]:
        """Return active warnings from the events currently in memory."""
        now = datetime.now(timezone.utc)
        warnings: List[Dict[str, Any]] = []

        # ANOM-001: repeated denied requests in a short window.
        denied_cutoff = now - timedelta(minutes=DENIED_WINDOW_MINUTES)
        denied_by_user: Dict[str, List[AccessEvent]] = {}
        for event in self._events:
            if (
                event.timestamp >= denied_cutoff
                and event.timestamp <= now
                and event.outcome.lower() in {"denial", "denied"}
            ):
                denied_by_user.setdefault(event.user_id, []).append(event)

        for user_id, events in denied_by_user.items():
            count = len(events)
            if count >= MAX_DENIED_PER_WINDOW:
                warnings.append(
                    {
                        "rule_id": "ANOM-001",
                        "severity": "high",
                        "user_id": user_id,
                        "count": count,
                        "window_minutes": DENIED_WINDOW_MINUTES,
                        "message": (
                            f"User {user_id} had {count} denied access attempts "
                            f"within {DENIED_WINDOW_MINUTES} minutes"
                        ),
                    }
                )

        # ANOM-002: repeated unmask requests in a one-hour window.
        unmask_cutoff = now - timedelta(minutes=UNMASK_WINDOW_MINUTES)
        unmask_by_user: Dict[str, List[AccessEvent]] = {}
        for event in self._events:
            if (
                event.timestamp >= unmask_cutoff
                and event.timestamp <= now
                and event.action == "unmask_request"
            ):
                unmask_by_user.setdefault(event.user_id, []).append(event)

        for user_id, events in unmask_by_user.items():
            count = len(events)
            if count >= MAX_UNMASK_ATTEMPTS:
                warnings.append(
                    {
                        "rule_id": "ANOM-002",
                        "severity": "medium",
                        "user_id": user_id,
                        "count": count,
                        "window_minutes": UNMASK_WINDOW_MINUTES,
                        "message": (
                            f"User {user_id} made {count} unmask requests "
                            f"within {UNMASK_WINDOW_MINUTES} minutes"
                        ),
                    }
                )

        # ANOM-003: repeated activity outside configured business hours.
        # Source timestamps are normalized to UTC; these hours therefore refer
        # to UTC until a deployment-specific timezone policy is configured.
        off_hours_by_user: Dict[str, List[AccessEvent]] = {}
        for event in self._events:
            hour = event.timestamp.hour
            outside_business_hours = not (
                BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END
            )
            if outside_business_hours:
                off_hours_by_user.setdefault(event.user_id, []).append(event)

        for user_id, events in off_hours_by_user.items():
            count = len(events)
            if count >= 3:
                warnings.append(
                    {
                        "rule_id": "ANOM-003",
                        "severity": "low",
                        "user_id": user_id,
                        "count": count,
                        "message": (
                            f"User {user_id} had {count} events outside "
                            "configured business hours"
                        ),
                    }
                )

        return warnings


# Module-level detector shared by application routes and the audit listener.
anomaly_detector = AnomalyDetector()
