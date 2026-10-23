from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.api.simulator import router as simulator_router
from backend.app.api.celesto import router as celesto_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.actions import router as actions_router
from backend.app.api.emails import router as emails_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite tables on startup
    await init_db()
    yield

app = FastAPI(
    title="MailGuard API",
    description="Security-First AI Communication Gatekeeper with Celesto Sandbox Quarantine",
    version="0.1.0",
    lifespan=lifespan
)

# Enable CORS strictly for local development origins (no wildcard fallback)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(simulator_router, prefix="/api")
app.include_router(celesto_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(actions_router, prefix="/api")
app.include_router(emails_router, prefix="/api")

@app.get("/")
async def root():
    return {
        "name": "MailGuard API",
        "version": "0.1.0",
        "status": "online",
        "active_provider_mode": settings.SANDBOX_PROVIDER_MODE,
        "docs_url": "/docs"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}
