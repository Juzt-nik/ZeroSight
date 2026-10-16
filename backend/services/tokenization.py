"""Pseudonymous vehicle tokenization with key rotation.

Tokens are HMAC-SHA256(vehicle_id, rotation_key) truncated to 16 hex chars.
Rotation keys change every configured interval (default 24h).
Old tokens cannot be reversed without the historical key.
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

logger = logging.getLogger("vsoc.tokenization")

TOKEN_ROTATION_INTERVAL_HOURS = int(os.getenv("TOKEN_ROTATION_INTERVAL_HOURS", "24"))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-me-token-secret")


def _current_rotation_epoch() -> int:
    """Return the current rotation epoch number based on interval."""
    now = datetime.now(timezone.utc)
    epoch_start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    delta_hours = (now - epoch_start).total_seconds() / 3600.0
    return int(delta_hours // TOKEN_ROTATION_INTERVAL_HOURS)


def _key_for_epoch(epoch: int) -> bytes:
    """Derive a per-epoch key from the master secret."""
    return hmac.new(
        TOKEN_SECRET.encode("utf-8"),
        str(epoch).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def generate_token(vehicle_id: str, context: Optional[str] = None) -> Tuple[str, int, datetime]:
    """Generate a pseudonymous token for a vehicle.

    Returns (token, rotation_epoch, expires_at).
    """
    epoch = _current_rotation_epoch()
    key = _key_for_epoch(epoch)

    message = vehicle_id.encode("utf-8")
    if context:
        message += b"|" + context.encode("utf-8")

    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    token = digest[:16]  # 16 hex chars = 64 bits

    # Expires at end of current rotation epoch
    now = datetime.now(timezone.utc)
    epoch_start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    hours_since = (now - epoch_start).total_seconds() / 3600.0
    current_epoch_start_hour = int(hours_since // TOKEN_ROTATION_INTERVAL_HOURS) * TOKEN_ROTATION_INTERVAL_HOURS
    expires_at = epoch_start + timedelta(hours=current_epoch_start_hour + TOKEN_ROTATION_INTERVAL_HOURS)

    logger.info("Generated token for vehicle (epoch=%d)", epoch)
    return token, epoch, expires_at


def verify_token(token: str, vehicle_id: str, epoch: int) -> bool:
    """Verify that a token matches a vehicle for a given epoch."""
    expected_token, _, _ = generate_token(vehicle_id)
    # Regenerate for the specific epoch
    key = _key_for_epoch(epoch)
    message = vehicle_id.encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    expected = digest[:16]
    return hmac.compare_digest(token, expected)


def is_token_expired(expires_at: datetime) -> bool:
    """Check if a token's rotation epoch has expired."""
    return datetime.now(timezone.utc) > expires_at