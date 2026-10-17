"""Server-side authentication for protected API callers.

Validates bearer tokens (JWT or opaque demo tokens) and derives user ID and
roles only from server-side trusted sources. Client-supplied role headers or
body role fields are never authoritative.

In demo mode (DEMO_MODE=true), a simple bearer token of the form
"Bearer <user_id>:<role>" is accepted without signature verification so the
dashboard and CLI can exercise the full workflow. Outside demo mode, a valid
JWT signed with AUTH_SECRET is required and missing/weak configuration causes
startup failure.
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

try:
    import jwt
except ImportError:  # pragma: no cover - PyJWT optional in minimal installs
    jwt = None  # type: ignore

from backend.services.access_control import access_control, UserContext

logger = logging.getLogger("vsoc.auth")

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")
AUTH_SECRET = os.getenv("AUTH_SECRET", "")
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-me-token-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Known unsafe defaults that must never be used outside demo mode.
_UNSAFE_DEFAULTS = {"change-me-token-secret", "change-me", "secret", "development"}


def _is_unsafe_default(secret: str) -> bool:
    return secret in _UNSAFE_DEFAULTS or not secret or len(secret) < 16


def validate_startup_config() -> None:
    """Validate security-critical configuration at startup.

    Raises RuntimeError outside demo mode if required secrets are missing or
    unsafe defaults are detected.
    """
    if DEMO_MODE:
        logger.warning(
            "DEMO_MODE is enabled. Unsafe defaults and unauthenticated bearer "
            "tokens are permitted for demonstration only."
        )
        return

    if not AUTH_SECRET or _is_unsafe_default(AUTH_SECRET):
        raise RuntimeError(
            "AUTH_SECRET must be set to a strong value outside demo mode. "
            "Do not use the development default."
        )

    if _is_unsafe_default(TOKEN_SECRET):
        raise RuntimeError(
            "TOKEN_SECRET must be set to a strong value outside demo mode. "
            "Do not use the development default 'change-me-token-secret'."
        )

    logger.info("Authentication configuration validated (demo_mode=%s)", DEMO_MODE)


from fastapi import Header, HTTPException, status  # noqa: E402
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # noqa: E402

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> UserContext:
    """Authenticate the caller and return a server-derived UserContext.

    Demo mode: accepts ``Authorization: Bearer <user_id>:<role1,role2>``.
    Production mode: validates a signed JWT.

    Missing, invalid, or expired credentials raise 401. Client-supplied role
    headers (e.g. X-User-Role) are ignored entirely.
    """
    if DEMO_MODE:
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = parts[1]
        if ":" in token:
            user_id, roles_str = token.split(":", 1)
            roles = [r.strip() for r in roles_str.split(",") if r.strip()]
        else:
            # Bare token treated as user id with analyst role by default
            user_id = token
            roles = ["analyst"]
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Register on demand so role lookups work across route modules
        existing = access_control.get_user(user_id)
        if existing is None:
            access_control.register_user(user_id, roles)
        ctx = access_control.get_user(user_id)
        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to resolve user context",
            )
        return ctx

    # Production path: JWT validation
    if jwt is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="JWT authentication not available",
        )
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1]
    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    roles = payload.get("roles", [])
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )
    existing = access_control.get_user(user_id)
    if existing is None:
        access_control.register_user(user_id, roles)
    ctx = access_control.get_user(user_id)
    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unable to resolve user context",
        )
    return ctx


def create_access_token(user_id: str, roles: list[str]) -> str:
    """Create a signed JWT access token.

    Only used outside demo mode. Inside demo mode callers may use the simple
    bearer format accepted by ``get_current_user``.
    """
    if jwt is None:
        raise RuntimeError("PyJWT is required to create access tokens")
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "roles": list(roles),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, AUTH_SECRET, algorithm=ALGORITHM)