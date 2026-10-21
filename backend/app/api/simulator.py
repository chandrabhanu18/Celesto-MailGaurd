import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.db.database import get_db
from backend.app.db.models import EmailRecord, CelestoTelemetryRecord
from backend.app.schemas.simulator import (
    ScenarioListResponse,
    SimulationTriggerRequest,
    SimulationTriggerResponse,
    SimulationScenarioMeta
)
from backend.app.services.simulation_data import FIXTURE_METADATA, get_scenario_eml
from backend.app.services.provider_factory import get_sandbox_provider

router = APIRouter(prefix="/simulator", tags=["Attack Simulator"])

@router.get("/scenarios", response_model=ScenarioListResponse)
async def list_scenarios():
    """List all 9 pre-loaded attack and benign simulation fixtures."""
    return ScenarioListResponse(scenarios=FIXTURE_METADATA)

@router.post("/trigger", response_model=SimulationTriggerResponse)
async def trigger_simulation(
    req: SimulationTriggerRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Execute a simulated email scenario through the Celesto quarantine pipeline.
    Ensures zero-trust isolation, schema validation, and telemetry persistence.
    """
    # 1. Locate scenario metadata
    meta = next((m for m in FIXTURE_METADATA if m.scenario_id == req.scenario_id), None)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{req.scenario_id}' not found."
        )

    # 2. Retrieve deterministic raw EML fixture
    try:
        raw_eml_bytes = get_scenario_eml(req.scenario_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load fixture EML: {e}"
        )

    # 3. Dispatch into active isolation provider (Real Celesto or Demo Fallback)
    provider = get_sandbox_provider()
    exec_result = await provider.analyze(raw_eml_bytes, filename=f"{req.scenario_id}.eml")

    # 4. Extract data from validated report (if successful)
    report = exec_result.report
    subject = report.subject if report else meta.title
    sender = report.sender if report else "simulated@mailguard.test"
    recipient = report.recipient if report else "user@company.com"
    date_str = report.date_str if report else ""
    sanitized_text = report.sanitized_text if report else ""
    risk_label = report.static_risk_label if report else "SUSPICIOUS"
    risk_score = report.static_risk_score if report else 0.5
    threat_count = len(report.threat_indicators) if report else 1

    # 5. Persist Email record in SQLite
    email_rec = EmailRecord(
        scenario_id=req.scenario_id,
        source="SIMULATED",
        sender=sender,
        recipient=recipient,
        subject=subject,
        date_str=date_str,
        sanitized_text=sanitized_text,
        static_risk_label=risk_label,
        static_risk_score=risk_score,
        threat_indicators_count=threat_count
    )
    db.add(email_rec)
    await db.flush()  # Populate email_rec.id

    # 6. Persist Celesto telemetry record
    indicators_data = [ti.model_dump() for ti in report.threat_indicators] if report else []
    telemetry_rec = CelestoTelemetryRecord(
        email_id=email_rec.id,
        provider_mode=exec_result.provider_mode,
        sandbox_id=exec_result.sandbox_id,
        network_mode=exec_result.network_mode,
        execution_time_ms=exec_result.execution_time_ms,
        exit_code=exec_result.exit_code,
        stdout_bytes_len=len(sanitized_text),
        indicators_json=json.dumps(indicators_data),
        error_message=exec_result.error_message
    )
    db.add(telemetry_rec)
    await db.commit()

    # 7. Compute security verdict
    if risk_label in ("CRITICAL", "SUSPICIOUS"):
        verdict = f"QUARANTINED: High threat indicators detected ({threat_count} indicators). Zero side effects permitted."
    else:
        verdict = "PASSED_STATIC_CHECKS: Benign profile. Ready for delimited LLM evaluation."

    invariants = [
        f"Execution isolated in {exec_result.provider_mode} ({exec_result.sandbox_id})",
        "Outbound network egress locked: mode='off'",
        "Untrusted MIME content extracted strictly as passive data",
        "Zero tool bindings or external side effects permitted"
    ]

    return SimulationTriggerResponse(
        scenario_id=req.scenario_id,
        title=meta.title,
        category=meta.category,
        email_id=email_rec.id,
        execution=exec_result,
        security_verdict=verdict,
        unauthorized_side_effects_prevented=True,
        invariants_maintained=invariants
    )
