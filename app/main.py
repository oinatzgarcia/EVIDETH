from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.db.session import engine
from app.db import models
from app.api.v1 import auth, cameras, verification, users, stats, logs


# ── Lifespan ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    yield
    engine.dispose()


# ── App ────────────────────────────────────────────
app = FastAPI(
    title="EVIDETH API",
    description="Forensic Video Integrity Verification System",
    version="2.0.0",
    lifespan=lifespan
)


# ── CORS ──────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────
app.include_router(auth.router,         prefix="/api/v1")
app.include_router(users.router,        prefix="/api/v1")
app.include_router(cameras.router,      prefix="/api/v1")
app.include_router(verification.router, prefix="/api/v1")
app.include_router(stats.router,        prefix="/api/v1")
app.include_router(logs.router,         prefix="/api/v1")


# ── Endpoints base ────────────────────────────────
@app.get("/")
def root():
    return {"status": "online", "system": "EVIDETH v2.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}
