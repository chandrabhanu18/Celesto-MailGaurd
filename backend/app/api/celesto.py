import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.db.database import get_db
from backend.app.db.models import CelestoTelemetryRecord, EmailRecord
from backend.app.services.provider_factory import get_sandbox_provider

router = APIRouter(prefix="/celesto", tags=["Celesto Telemetry & Status"])

@router.get("/status")
async def get_celesto_status():
    """Returns the live status of the active Celesto provider (Real vs Demo Fallback)."""
    provider = get_sandbox_provider()
    health = await provider.health_check()
    return health

@router.get("/telemetry")
async def list_telemetry(
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Retrieve historical Celesto sandbox execution telemetry records."""
    stmt = (
        select(CelestoTelemetryRecord, EmailRecord.subject, EmailRecord.static_risk_label)
        .join(EmailRecord, CelestoTelemetryRecord.email_id == EmailRecord.id)
        .order_by(desc(CelestoTelemetryRecord.created_at))
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.all()

    telemetry_list = []
    for tele, subject, risk_label in rows:
        try:
            indicators = json.loads(tele.indicators_json)
        except Exception:
            indicators = []

        telemetry_list.append({
            "id": tele.id,
            "email_id": tele.email_id,
            "email_subject": subject,
            "static_risk_label": risk_label,
            "provider_mode": tele.provider_mode,
            "sandbox_id": tele.sandbox_id,
            "network_mode": tele.network_mode,
            "execution_time_ms": tele.execution_time_ms,
            "exit_code": tele.exit_code,
            "indicators": indicators,
            "error_message": tele.error_message,
            "created_at": tele.created_at.isoformat() if tele.created_at else None
        })

    return telemetry_list
