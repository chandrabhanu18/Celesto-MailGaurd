"""Database layer for MailGuard."""
from backend.app.db.database import Base, engine, AsyncSessionLocal, init_db, get_db
from backend.app.db.models import (
    EmailRecord,
    CelestoTelemetryRecord,
    LLMAnalysisRecord,
    ActionProposalRecord,
    RunRecord,
)

__all__ = [
    "Base",
    "engine",
    "AsyncSessionLocal",
    "init_db",
    "get_db",
    "EmailRecord",
    "CelestoTelemetryRecord",
    "LLMAnalysisRecord",
    "ActionProposalRecord",
    "RunRecord",
]
