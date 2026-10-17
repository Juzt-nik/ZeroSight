"""Pseudonymous vehicle tokenization with key rotation.

Tokens are HMAC-SHA256(vehicle_id, rotation_key) truncated to 16 hex chars.
Rotation keys change every configured interval (default 24h).
Old tokens cannot be reversed without the historical key.

P0-04: Tokens are generated inside the trusted pipeline from a verified
vehicle identity. The TOKEN_SECRET must not be a known default outside
demo mode; startup validation in backend/auth.py enforces this.
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

logger = logging.getLogger("vsoc.tokenization")

TOKEN_ROTATION_INTERVAL_HOURS = int(os.getenv("TOKEN_ROTATION_INTERVAL_HOURS", "24"))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "")

# Known unsafe defaults
_UNSAFE_DEFAULTS = {"change-me-token-secret", "change-me", "secret", "development"}

# Restricted token-to-identity vault (Phase 2: token creation → vault registration)
# Maps token string -> vehicle_id. Only accessible via get_vehicle_from_token()
# which enforces vault:read permission. Populated by generate_token().
_token_vault: dict = {}
_token_vault_lock = None  # type: ignore
try:
    from threading import RLock

    _token_vault_lock = RLock()
except ImportError:
    _token_vault_lock = None


def _is_unsafe_default(secret: str) -> bool:
    return secret in _UNSAFE_DEFAULTS or not secret or len(secret) < 16


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
    if not TOKEN_SECRET or _is_unsafe_default(TOKEN_SECRET):
        raise RuntimeError(
            "TOKEN_SECRET must be set to a strong value before generating tokens. "
            "Do not use the development default."
        )
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

    # Register token→vehicle_id mapping in the restricted vault (Phase 2)
    if _token_vault_lock is not None:
        with _token_vault_lock:
            _token_vault[token] = vehicle_id
    else:
        _token_vault[token] = vehicle_id

    return token, epoch, expires_at


def register_token_mapping(token: str, vehicle_id: str) -> None:
    """Manually register a token→vehicle_id mapping in the restricted vault.

    Used during trusted provisioning or when tokens are created outside
    generate_token(). Enforces that the mapping is stored in the isolated vault.
    """
    if not token or not vehicle_id:
        raise ValueError("token and vehicle_id must not be empty")
    if _token_vault_lock is not None:
        with _token_vault_lock:
            _token_vault[token] = vehicle_id
    else:
        _token_vault[token] = vehicle_id


def get_vehicle_from_token(token: str, requesting_user=None) -> Optional[str]:
    """Look up a vehicle_id from a token in the restricted vault.

    Phase 2: Vault access is restricted. If requesting_user is provided,
    it must have vault:read permission. Analysts and auditors are denied.
    """
    if requesting_user is not None:
        from backend.services.access_control import access_control

        if not access_control.require_permission(requesting_user, "vault:read"):
            return None

    if _token_vault_lock is not None:
        with _token_vault_lock:
            return _token_vault.get(token)
    return _token_vault.get(token)


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