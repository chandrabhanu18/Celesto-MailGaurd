from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.api.simulator import router as simulator_router
from backend.app.api.celesto import router as celesto_router

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

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(simulator_router, prefix="/api")
app.include_router(celesto_router, prefix="/api")

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
