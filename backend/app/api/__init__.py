"""MailGuard API Endpoints."""
from backend.app.api.celesto import router as celesto_router
from backend.app.api.simulator import router as simulator_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.actions import router as actions_router

__all__ = ["celesto_router", "simulator_router", "analysis_router", "actions_router"]
