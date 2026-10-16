"""FastAPI application entry point.

Wires together all route modules and services.
Starts model loading and audit service on application lifespan.
"""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.routes import detection, privacy, access, audit, anomaly
from backend.services.model_service import model_service, ModelService
from backend.services.audit_service import audit_service, AuditService
from backend.services.access_control import access_control, AccessControlService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vsoc")

# Global service instances (initialized in lifespan, imported as singletons)
# model_service, audit_service, access_control are imported above as module-level singletons


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup, cleanup on shutdown."""
    global model_service, audit_service, access_control

    logger.info("Starting privacy-native vSOC backend...")

    # Initialize audit service (hash-chained SQLite log)
    audit_db_path = os.getenv("AUDIT_DB_PATH", "./data/audit.db")
    # Rebind with correct db_path if different from default
    if audit_db_path != "./data/audit.db":
        audit_service = AuditService(db_path=audit_db_path)
    await audit_service.initialize()
    logger.info("Audit service initialized at %s", audit_db_path)

    # Initialize access control
    access_control = AccessControlService()
    logger.info("Access control service initialized")

    # Initialize model service (load trained model or train baseline)
    model_dir = os.getenv("MODEL_DIR", "./models")
    dataset_dir = os.getenv("DATASET_DIR", "./data/raw")
    if model_dir != "./models" or dataset_dir != "./data/raw":
        model_service = ModelService(model_dir=model_dir, dataset_dir=dataset_dir)
    await model_service.initialize()
    logger.info("Model service initialized")

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

# CORS (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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