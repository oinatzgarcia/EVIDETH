from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
from app.config import settings
from app.db.session import engine
from app.db import models
from app.api.v1 import auth, cameras, verification, users, stats, logs


# ── Lifespan ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    yield
    engine.dispose()


# ── App ──────────────────────────────────────────────────
app = FastAPI(
    title="EVIDETH API",
    description="Forensic Video Integrity Verification System",
    version="2.0.0",
    lifespan=lifespan
)


# ── CORS ──────────────────────────────────────────────────
# Incluye los puertos del start script:
#   8000 → FastAPI (backend)
#   8080 → python -m http.server (frontend estático en desarrollo)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",   # por si se usa un bundler en el futuro
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ────────────────────────────────────────────────
app.include_router(auth.router,         prefix="/api/v1")
app.include_router(users.router,        prefix="/api/v1")
app.include_router(cameras.router,      prefix="/api/v1")
app.include_router(verification.router, prefix="/api/v1")
app.include_router(stats.router,        prefix="/api/v1")
app.include_router(logs.router,         prefix="/api/v1")


# ── Endpoints base ───────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    """
    Redirige la raíz del servidor al frontend de login.
    Esto permite que al abrir http://localhost:8000/ se muestre
    directamente la página de autenticación.
    """
    return RedirectResponse(url="/frontend/pages/login/login.html", status_code=302)


@app.get("/health")
def health():
    return {"status": "healthy"}


# ── Static files — debe ir AL FINAL para no enmascarar rutas API ──
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")
