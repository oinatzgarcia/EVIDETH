from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager
from app.db.session import engine
from app.db import models
from app.api.v1 import auth, cameras, verification, users, stats, logs


# ── Lifespan ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    yield


# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="EVIDETH API",
    description="Sistema de verificación de integridad de vídeo forense",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files ──────────────────────────────────────────────
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except RuntimeError:
    pass

# ── Routers ───────────────────────────────────────────────────
app.include_router(auth.router,         prefix="/api/v1")
app.include_router(cameras.router,      prefix="/api/v1")
app.include_router(verification.router, prefix="/api/v1")
app.include_router(users.router,        prefix="/api/v1")
app.include_router(stats.router,        prefix="/api/v1")
app.include_router(logs.router,         prefix="/api/v1")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")
