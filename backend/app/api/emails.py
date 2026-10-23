import json
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from backend.app.db.database import get_db
from backend.app.db.models import EmailRecord, CelestoTelemetryRecord, LLMAnalysisRecord, ActionProposalRecord
from backend.app.schemas.email import (
    EmailListResponse,
    EmailListItem,
    EmailDetailResponse,
    StaticInspectionDetail,
    TelemetrySummary,
)
from backend.app.schemas.llm import (
    LLMAnalysisDetailResponse,
    ExtractedCalendarEvent,
    ThreatCategory,
    ThreatLevel,
)
from backend.app.schemas.action import ActionState
from backend.app.api.actions import format_action_response

router = APIRouter(prefix="/emails", tags=["Emails & Triage Queue"])

def format_llm_analysis(rec: LLMAnalysisRecord) -> LLMAnalysisDetailResponse:
    extracted_event = None
    if rec.extracted_event_json:
        try:
            extracted_event = ExtractedCalendarEvent.model_validate_json(rec.extracted_event_json)
        except Exception:
            pass

    indicators = []
    if rec.indicators_json:
        try:
            indicators = json.loads(rec.indicators_json)
        except Exception:
            pass

    return LLMAnalysisDetailResponse(
        id=rec.id,
        email_id=rec.email_id,
        provider=rec.provider,
        model=rec.model,
        threat_category=ThreatCategory(rec.threat_category),
        threat_level=ThreatLevel(rec.threat_level),
        confidence=rec.confidence,
        urgency=rec.urgency,
        explanation=rec.explanation,
        indicators=indicators,
        recommended_action=rec.recommended_action,
        calendar_event_detected=rec.calendar_event_detected,
        extracted_calendar_event=extracted_event,
        is_advisory_only=True,
        created_at=rec.created_at.isoformat() if rec.created_at else "",
    )

@router.get("", response_model=EmailListResponse)
async def list_emails(
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """
    Read-only endpoint listing processed emails with summarized threat,
    urgency, analysis, and action gating state.
    """
    stmt = (
        select(EmailRecord)
        .options(
            selectinload(EmailRecord.analyses),
            selectinload(EmailRecord.actions)
        )
        .order_by(desc(EmailRecord.created_at))
        .limit(limit)
    )
    result = await db.execute(stmt)
    records = result.scalars().all()

    items: List[EmailListItem] = []
    for email in records:
        latest_analysis = email.analyses[-1] if email.analyses else None
        actions = email.actions or []

        has_analysis = latest_analysis is not None
        pending_count = sum(1 for a in actions if a.state == ActionState.PENDING_APPROVAL.value)
        is_quarantined = any(
            a.action_type == "QUARANTINE_EMAIL" and a.state in (ActionState.APPROVED.value, ActionState.EXECUTED.value)
            for a in actions
        )

        primary_action = actions[0] if actions else None

        items.append(EmailListItem(
            id=email.id,
            scenario_id=email.scenario_id,
            source=email.source,
            sender=email.sender,
            recipient=email.recipient,
            subject=email.subject,
            date_str=email.date_str,
            created_at=email.created_at.isoformat() if email.created_at else "",
            static_risk_label=email.static_risk_label,
            static_risk_score=email.static_risk_score,
            threat_indicators_count=email.threat_indicators_count,
            has_analysis=has_analysis,
            threat_category=latest_analysis.threat_category if latest_analysis else None,
            threat_level=latest_analysis.threat_level if latest_analysis else None,
            urgency=latest_analysis.urgency if latest_analysis else None,
            confidence=latest_analysis.confidence if latest_analysis else None,
            recommended_action=latest_analysis.recommended_action if latest_analysis else None,
            calendar_event_detected=latest_analysis.calendar_event_detected if latest_analysis else False,
            total_actions_count=len(actions),
            pending_approval_count=pending_count,
            primary_action_type=primary_action.action_type if primary_action else None,
            primary_action_state=primary_action.state if primary_action else None,
            is_quarantined=is_quarantined,
        ))

    return EmailListResponse(emails=items, total=len(items))

@router.get("/{email_id}", response_model=EmailDetailResponse)
async def get_email_detail(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Read-only endpoint retrieving comprehensive investigation data:
    - Email metadata and sanitized text
    - Phase 2A static indicators & telemetry
    - Phase 2B advisory LLM analysis
    - Phase 3 deterministic action proposals and execution status
    """
    stmt = (
        select(EmailRecord)
        .options(
            selectinload(EmailRecord.telemetry),
            selectinload(EmailRecord.analyses),
            selectinload(EmailRecord.actions)
        )
        .where(EmailRecord.id == email_id)
    )
    res = await db.execute(stmt)
    email = res.scalar_one_or_none()

    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID '{email_id}' not found."
        )

    # 1. Telemetry & Static Inspection
    tele_rec = email.telemetry[-1] if email.telemetry else None
    telemetry_summary = None
    indicators: List[Dict[str, Any]] = []

    if tele_rec:
        if tele_rec.indicators_json:
            try:
                indicators = json.loads(tele_rec.indicators_json)
            except Exception:
                pass

        telemetry_summary = TelemetrySummary(
            id=tele_rec.id,
            provider_mode=tele_rec.provider_mode,
            sandbox_id=tele_rec.sandbox_id,
            network_mode=tele_rec.network_mode,
            execution_time_ms=tele_rec.execution_time_ms,
            exit_code=tele_rec.exit_code,
            indicators=indicators,
            error_message=tele_rec.error_message,
            created_at=tele_rec.created_at.isoformat() if tele_rec.created_at else None,
        )

    # Extract high-level boolean static flags
    has_prompt_injection = any("PROMPT_INJECTION" in str(i).upper() or "SYSTEM_OVERRIDE" in str(i).upper() for i in indicators)
    has_homoglyph = any("HOMOGLYPH" in str(i).upper() or "TYPOSQUATTING" in str(i).upper() for i in indicators)
    has_ip = any("IP_URL" in str(i).upper() or "RAW IP" in str(i).upper() for i in indicators)
    has_zero_width = any("HIDDEN_UNICODE" in str(i).upper() or "ZERO-WIDTH" in str(i).upper() for i in indicators)

    static_inspection = StaticInspectionDetail(
        static_risk_label=email.static_risk_label,
        static_risk_score=email.static_risk_score,
        threat_indicators_count=email.threat_indicators_count,
        threat_indicators=indicators,
        extracted_urls=[],
        has_html=False,
        has_prompt_injection=has_prompt_injection,
        has_suspicious_homoglyph=has_homoglyph,
        has_ip_url=has_ip,
        has_zero_width_chars=has_zero_width,
        analysis_duration_ms=tele_rec.execution_time_ms if tele_rec else 0,
    )

    # 2. Advisory LLM Analysis
    latest_analysis = None
    if email.analyses:
        latest_analysis = format_llm_analysis(email.analyses[-1])

    # 3. Action Proposals
    actions_formatted = [format_action_response(a) for a in (email.actions or [])]

    return EmailDetailResponse(
        id=email.id,
        scenario_id=email.scenario_id,
        source=email.source,
        sender=email.sender,
        recipient=email.recipient,
        subject=email.subject,
        date_str=email.date_str,
        sanitized_text=email.sanitized_text,
        created_at=email.created_at.isoformat() if email.created_at else "",
        static_inspection=static_inspection,
        telemetry=telemetry_summary,
        latest_analysis=latest_analysis,
        actions=actions_formatted,
    )
