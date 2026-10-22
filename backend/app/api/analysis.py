import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.db.database import get_db
from backend.app.db.models import EmailRecord, CelestoTelemetryRecord, LLMAnalysisRecord
from backend.app.schemas.llm import (
    LLMAnalysisContext,
    LLMAnalysisResult,
    LLMAnalysisDetailResponse,
    ExtractedCalendarEvent,
    ThreatCategory,
    ThreatLevel,
)
from backend.app.services.llm_client import get_llm_client, LLMError
from backend.app.services.llm_prompt_templates import build_analysis_prompt

router = APIRouter(prefix="/analysis", tags=["LLM Security Analysis"])

@router.post("/{email_id}", response_model=LLMAnalysisDetailResponse)
async def analyze_email(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger advisory LLM security analysis and urgency/calendar classification
    on a quarantined email with completed Phase 2A static inspection.
    Security Invariant: Advisory only, zero tool capabilities, zero side effects.
    """
    # 1. Retrieve the email record
    stmt = select(EmailRecord).where(EmailRecord.id == email_id)
    result = await db.execute(stmt)
    email_rec = result.scalar_one_or_none()
    if not email_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID '{email_id}' not found."
        )

    # 2. Retrieve Phase 2A telemetry record to gather verified static indicators
    tel_stmt = select(CelestoTelemetryRecord).where(CelestoTelemetryRecord.email_id == email_id).order_by(desc(CelestoTelemetryRecord.created_at))
    tel_res = await db.execute(tel_stmt)
    telemetry_rec = tel_res.scalars().first()

    threat_indicators = []
    if telemetry_rec and telemetry_rec.indicators_json:
        try:
            parsed_inds = json.loads(telemetry_rec.indicators_json)
            threat_indicators = [
                f"{ind.get('indicator_type')}: {ind.get('description')}"
                for ind in parsed_inds if isinstance(ind, dict)
            ]
        except Exception:
            pass

    # 3. Construct validated analysis context (strictly excludes unvalidated raw sandbox dumps)
    context = LLMAnalysisContext(
        email_id=email_rec.id,
        subject=email_rec.subject,
        sender=email_rec.sender,
        recipient=email_rec.recipient,
        date_str=email_rec.date_str,
        sanitized_text=email_rec.sanitized_text,
        static_risk_score=email_rec.static_risk_score,
        static_risk_label=email_rec.static_risk_label,
        threat_indicators_count=email_rec.threat_indicators_count,
        threat_indicators=threat_indicators
    )

    # 4. Invoke the configured LLM provider
    client = get_llm_client()
    try:
        analysis_result: LLMAnalysisResult = await client.analyze(context)
    except LLMError as le:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM analysis failed: {le}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error during LLM analysis: {e}"
        )

    # 5. Persist audit record in SQLite (stores audit hashes, zero secrets)
    prompt_str = build_analysis_prompt(context)
    prompt_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()

    extracted_event_data = (
        analysis_result.extracted_calendar_event.model_dump_json()
        if analysis_result.extracted_calendar_event
        else None
    )

    analysis_rec = LLMAnalysisRecord(
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
        extracted_event_json=extracted_event_data,
        raw_prompt_hash=prompt_hash
    )
    db.add(analysis_rec)
    await db.commit()
    await db.refresh(analysis_rec)

    # 6. Format API response
    return LLMAnalysisDetailResponse(
        id=analysis_rec.id,
        email_id=email_rec.id,
        provider=analysis_rec.provider,
        model=analysis_rec.model,
        threat_category=ThreatCategory(analysis_rec.threat_category),
        threat_level=ThreatLevel(analysis_rec.threat_level),
        confidence=analysis_rec.confidence,
        urgency=analysis_rec.urgency,
        explanation=analysis_rec.explanation,
        indicators=json.loads(analysis_rec.indicators_json),
        recommended_action=analysis_rec.recommended_action,
        calendar_event_detected=analysis_rec.calendar_event_detected,
        extracted_calendar_event=analysis_result.extracted_calendar_event,
        is_advisory_only=True,
        created_at=analysis_rec.created_at.isoformat()
    )

@router.get("/{email_id}", response_model=LLMAnalysisDetailResponse)
async def get_email_analysis(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve the latest persisted LLM analysis for a given email ID.
    """
    stmt = (
        select(LLMAnalysisRecord)
        .where(LLMAnalysisRecord.email_id == email_id)
        .order_by(desc(LLMAnalysisRecord.created_at))
    )
    res = await db.execute(stmt)
    analysis_rec = res.scalars().first()

    if not analysis_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No LLM analysis found for email ID '{email_id}'."
        )

    extracted_event = None
    if analysis_rec.extracted_event_json:
        try:
            extracted_event = ExtractedCalendarEvent.model_validate_json(analysis_rec.extracted_event_json)
        except Exception:
            pass

    return LLMAnalysisDetailResponse(
        id=analysis_rec.id,
        email_id=analysis_rec.email_id,
        provider=analysis_rec.provider,
        model=analysis_rec.model,
        threat_category=ThreatCategory(analysis_rec.threat_category),
        threat_level=ThreatLevel(analysis_rec.threat_level),
        confidence=analysis_rec.confidence,
        urgency=analysis_rec.urgency,
        explanation=analysis_rec.explanation,
        indicators=json.loads(analysis_rec.indicators_json),
        recommended_action=analysis_rec.recommended_action,
        calendar_event_detected=analysis_rec.calendar_event_detected,
        extracted_calendar_event=extracted_event,
        is_advisory_only=True,
        created_at=analysis_rec.created_at.isoformat()
    )
