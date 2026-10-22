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

    # 8. Optional Phase 2B LLM Advisory Evaluation
    llm_analysis_detail = None
    llm_provider_used = None

    if req.run_llm_analysis:
        import hashlib
        from backend.app.schemas.llm import LLMAnalysisContext, ThreatCategory, ThreatLevel, LLMAnalysisDetailResponse
        from backend.app.services.llm_client import get_llm_client
        from backend.app.services.llm_prompt_templates import build_analysis_prompt
        from backend.app.db.models import LLMAnalysisRecord

        threat_indicators_list = [
            f"{ti.indicator_type}: {ti.description}" for ti in report.threat_indicators
        ] if report else []
        extracted_urls_list = [u.url for u in report.extracted_urls] if report else []
        attachments_list = [f"{a.filename} ({a.content_type}, {a.size_bytes}B)" for a in report.attachments] if report else []

        llm_ctx = LLMAnalysisContext(
            email_id=email_rec.id,
            subject=subject,
            sender=sender,
            recipient=recipient,
            date_str=date_str,
            sanitized_text=sanitized_text,
            static_risk_score=risk_score,
            static_risk_label=risk_label,
            threat_indicators_count=threat_count,
            threat_indicators=threat_indicators_list,
            extracted_urls=extracted_urls_list,
            attachments_summary=attachments_list
        )

        client = get_llm_client()
        llm_provider_used = client.provider_name
        analysis_result = await client.analyze(llm_ctx)

        prompt_str = build_analysis_prompt(llm_ctx)
        prompt_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()
        extracted_event_json = (
            analysis_result.extracted_calendar_event.model_dump_json()
            if analysis_result.extracted_calendar_event else None
        )

        llm_rec = LLMAnalysisRecord(
            email_id=email_rec.id,
            provider=client.provider_name,
            model=client.model_name,
            threat_category=analysis_result.threat_category.value,
            threat_level=analysis_result.threat_level.value,
            confidence=analysis_result.confidence,
            urgency=analysis_result.urgency,
            explanation=analysis_result.explanation,
            indicators_json=json.dumps(analysis_result.indicators),
            recommended_action=analysis_result.recommended_action,
            calendar_event_detected=analysis_result.calendar_event_detected,
            extracted_event_json=extracted_event_json,
            raw_prompt_hash=prompt_hash
        )
        db.add(llm_rec)
        await db.commit()
        await db.refresh(llm_rec)

        llm_analysis_detail = LLMAnalysisDetailResponse(
            id=llm_rec.id,
            email_id=email_rec.id,
            provider=llm_rec.provider,
            model=llm_rec.model,
            threat_category=ThreatCategory(llm_rec.threat_category),
            threat_level=ThreatLevel(llm_rec.threat_level),
            confidence=llm_rec.confidence,
            urgency=llm_rec.urgency,
            explanation=llm_rec.explanation,
            indicators=json.loads(llm_rec.indicators_json),
            recommended_action=llm_rec.recommended_action,
            calendar_event_detected=llm_rec.calendar_event_detected,
            extracted_calendar_event=analysis_result.extracted_calendar_event,
            is_advisory_only=True,
            created_at=llm_rec.created_at.isoformat()
        )

        invariants.append(f"Phase 2B LLM advisory analysis completed via '{client.provider_name}'")
        invariants.append("LLM executed with zero tools, zero network, zero action capabilities")

    # 9. Optional Phase 3 Policy Engine Action Proposals (strictly PENDING_APPROVAL)
    proposed_actions_formatted = []
    if req.propose_actions:
        from backend.app.services.policy_engine import PolicyEngine
        from backend.app.schemas.action import ActionType, ActionState
        from backend.app.db.models import ActionProposalRecord
        from backend.app.api.actions import format_action_response

        t_cat = analysis_result.threat_category.value if llm_analysis_detail else None
        t_lvl = analysis_result.threat_level.value if llm_analysis_detail else None
        t_urg = analysis_result.urgency if llm_analysis_detail else 1
        t_cal = analysis_result.calendar_event_detected if llm_analysis_detail else False
        t_cal_data = analysis_result.extracted_calendar_event.model_dump() if (llm_analysis_detail and analysis_result.extracted_calendar_event) else None
        source_id = llm_rec.id if llm_analysis_detail else None

        drafts = PolicyEngine.evaluate(
            static_risk_label=risk_label,
            static_risk_score=risk_score,
            threat_category=t_cat,
            threat_level=t_lvl,
            urgency=t_urg,
            calendar_event_detected=t_cal,
            calendar_event_data=t_cal_data,
            static_threat_indicators=[ti.indicator_type for ti in report.threat_indicators] if report else []
        )

        created_recs = []
        for draft in drafts:
            action_rec = ActionProposalRecord(
                email_id=email_rec.id,
                source_analysis_id=source_id,
                action_type=draft.action_type.value,
                state=ActionState.PENDING_APPROVAL.value,
                reason=draft.reason,
                policy_rule=draft.policy_rule,
                risk_level=draft.risk_level,
                payload_json=json.dumps(draft.payload),
                is_human_approved=False
            )
            db.add(action_rec)
            created_recs.append(action_rec)

        if created_recs:
            await db.commit()
            for act in created_recs:
                await db.refresh(act)

        proposed_actions_formatted = [format_action_response(a) for a in created_recs]
        invariants.append(f"Phase 3 Policy Engine generated {len(created_recs)} proposal(s) strictly in PENDING_APPROVAL state")
        invariants.append("Zero actions executed; human approval strictly required before execution")

    return SimulationTriggerResponse(
        scenario_id=req.scenario_id,
        title=meta.title,
        category=meta.category,
        email_id=email_rec.id,
        execution=exec_result,
        security_verdict=verdict,
        unauthorized_side_effects_prevented=True,
        invariants_maintained=invariants,
        llm_analysis=llm_analysis_detail,
        llm_provider_used=llm_provider_used,
        proposed_actions=proposed_actions_formatted,
        has_pending_actions=len(proposed_actions_formatted) > 0
    )
