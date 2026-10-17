"""FastAPI application entry point.

Wires together all route modules and services.
Starts model loading and audit service on application lifespan.
"""

import os
import logging
import platform
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.auth import validate_startup_config, get_current_user
from backend.routes import detection, privacy, access, audit, anomaly
from backend.services.model_service import model_service, ModelService
from backend.services.audit_service import audit_service, AuditService
from backend.services.access_control import access_control, AccessControlService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vsoc")

# Module-level service singletons (initialized in lifespan; never reassigned)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup, cleanup on shutdown."""
    logger.info("Starting privacy-native vSOC backend...")

    # Log target-platform evidence (Phase 4: LinuxONE verification)
    try:
        mem_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        mem_gb = round(mem_bytes / (1024 ** 3), 2)
    except (AttributeError, OSError):
        mem_gb = None
    logger.info(
        "Platform: %s %s | arch=%s | python=%s | mem_gb=%s | cpus=%s",
        platform.system(),
        platform.release(),
        platform.machine(),
        platform.python_version(),
        mem_gb,
        os.cpu_count(),
    )

    # Validate security-critical configuration before initializing services
    validate_startup_config()

    # Initialize audit service (hash-chained SQLite log) — mutate singleton, never reassign
    audit_db_path = os.getenv("AUDIT_DB_PATH", "./data/audit.db")
    audit_service.db_path = audit_db_path
    await audit_service.initialize()
    logger.info("Audit service initialized at %s", audit_db_path)

    # Initialize access control — mutate singleton, never reassign
    access_control._users.clear()
    access_control.__init__()
    logger.info("Access control service initialized")

    # Initialize model service (load trained model or fail safely — no dummy fallback)
    model_dir = os.getenv("MODEL_DIR", "./models")
    dataset_dir = os.getenv("DATASET_DIR", "./data/raw")
    model_service.model_dir = Path(model_dir)
    model_service.dataset_dir = Path(dataset_dir)
    await model_service.initialize()
    logger.info("Model service initialized (model_loaded=%s)", model_service.is_loaded())

    # Log startup event
    await audit_service.log_event(
        event_type="system_startup",
        actor="system",
        outcome="success",
        details={"component": "backend", "version": "0.1.0"},
    )

    yield

    logger.info("Shutting down privacy-native vSOC backend...")
    await audit_service.log_event(
        event_type="system_shutdown",
        actor="system",
        outcome="success",
        details={},
    )


app = FastAPI(
    title="Privacy-Native vSOC for Connected Vehicles",
    description=(
        "CAN-bus attack detection with privacy-preserving vehicle identities, "
        "location minimization, dual-approval unmasking, and tamper-evident audit."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — explicit allowlist; no wildcard origins in production
_cors_origins = os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:8501,http://127.0.0.1:8501",
)
_allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() in (
    "1",
    "true",
    "yes",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",") if o.strip()],
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


@app.get("/health", tags=["system"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "privacy-native-vsoc",
        "version": "0.1.0",
        "model_loaded": model_service is not None and model_service.is_loaded(),
        "audit_initialized": audit_service is not None,
    }


@app.get("/", tags=["system"])
async def root():
    return {
        "service": "privacy-native-vsoc",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }


# Include route modules
app.include_router(detection.router, prefix="/detect", tags=["detection"])
app.include_router(privacy.router, prefix="/privacy", tags=["privacy"])
app.include_router(access.router, prefix="/access", tags=["access"])
app.include_router(audit.router, prefix="/audit", tags=["audit"])
app.include_router(anomaly.router, prefix="/anomaly", tags=["anomaly"])


# Global exception handler for clean error responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    await audit_service.log_event(
        event_type="api_error",
        actor="unknown",
        outcome="failure",
        details={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.detail,
        },
    ) if audit_service else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )