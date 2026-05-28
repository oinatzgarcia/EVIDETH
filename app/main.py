from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
from app.config import settings
from app.db.session import engine
from app.db import models
from app.api.v1 import auth, cameras, verification, users, stats, logs
from app.middleware.logging_middleware import LoggingMiddleware
from app.core.logger import log
from app.core.telemetry import setup_telemetry
import logging

logger = logging.getLogger(__name__)


# ── Lifespan ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application Insights — antes de cualquier log de startup
    setup_telemetry()

    try:
        models.Base.metadata.create_all(bind=engine)
        log.info("DB tables verified/created")
    except Exception as e:
        logger.warning(f"DB not ready at startup (will retry on first request): {e}")
    yield
    try:
        engine.dispose()
        log.info("DB engine disposed")
    except Exception as e:
        logger.debug(f"engine.dispose() skipped during shutdown: {e}")


# ── App ────────────────────────────────────────────────
app = FastAPI(
    title="EVIDETH API",
    description="Forensic Video Integrity Verification System",
    version="2.0.0",
    lifespan=lifespan,
)

# ── Middleware (orden: primero logging, luego CORS) ────────────
app.add_middleware(LoggingMiddleware)

# ── CORS ────────────────────────────────────────────────
_raw_origins = getattr(settings, "CORS_ORIGINS", "")
_extra_origins = (
    [o.strip() for o in _raw_origins.split(",") if o.strip()] if _raw_origins else []
)

allow_origins = list(
    set(
        [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3000",
        ]
        + _extra_origins
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(cameras.router, prefix="/api/v1")
app.include_router(verification.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")
app.include_router(logs.router, prefix="/api/v1")


# ── Health check ──────────────────────────────────────
@app.get("/api/v1/health", tags=["Health"])
def health():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/health", include_in_schema=False)
def health_root():
    return {"status": "healthy"}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/frontend/pages/login/login.html", status_code=302)


# ── Static files — AL FINAL para no enmascarar rutas API ─────
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")
