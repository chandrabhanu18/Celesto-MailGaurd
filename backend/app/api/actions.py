import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.db.database import get_db
from backend.app.db.models import EmailRecord, LLMAnalysisRecord, CelestoTelemetryRecord, ActionProposalRecord
from backend.app.schemas.action import (
    ActionType,
    ActionState,
    ActionProposalResponse,
    ActionApproveRequest,
    ActionRejectRequest,
    ActionExecutionResponse,
    ActionListResponse,
)
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.approval_service import (
    HumanApprovalService,
    ActionNotFoundError,
    InvalidStateTransitionError,
)
from backend.app.services.action_executor import (
    ActionExecutor,
    ActionAuthorizationError,
    ActionExecutionError,
)

router = APIRouter(prefix="/actions", tags=["Policy Engine & Human Approval"])

def format_action_response(action: ActionProposalRecord) -> ActionProposalResponse:
    payload = {}
    if action.payload_json:
        try:
            payload = json.loads(action.payload_json)
        except Exception:
            pass

    exec_res = None
    if action.execution_result_json:
        try:
            exec_res = json.loads(action.execution_result_json)
        except Exception:
            pass

    return ActionProposalResponse(
        id=action.id,
        email_id=action.email_id,
        source_analysis_id=action.source_analysis_id,
        action_type=ActionType(action.action_type),
        state=ActionState(action.state),
        reason=action.reason,
        policy_rule=action.policy_rule,
        risk_level=action.risk_level,
        payload=payload,
        rejection_reason=action.rejection_reason,
        execution_result=exec_res,
        is_human_approved=action.is_human_approved,
        created_at=action.created_at.isoformat(),
        approved_at=action.approved_at.isoformat() if action.approved_at else None,
        rejected_at=action.rejected_at.isoformat() if action.rejected_at else None,
        executed_at=action.executed_at.isoformat() if action.executed_at else None,
    )

@router.get("", response_model=ActionListResponse)
async def list_actions(
    email_id: Optional[str] = Query(None, description="Filter by email ID"),
    state: Optional[ActionState] = Query(None, description="Filter by state"),
    db: AsyncSession = Depends(get_db)
):
    """List all action proposals with optional filtering."""
    stmt = select(ActionProposalRecord).order_by(desc(ActionProposalRecord.created_at))
    if email_id:
        stmt = stmt.where(ActionProposalRecord.email_id == email_id)
    if state:
        stmt = stmt.where(ActionProposalRecord.state == state.value)

    res = await db.execute(stmt)
    records = res.scalars().all()
    actions = [format_action_response(r) for r in records]
    return ActionListResponse(actions=actions, total=len(actions))

@router.get("/{action_id}", response_model=ActionProposalResponse)
async def get_action(
    action_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve details and audit history for a single action proposal."""
    try:
        action = await HumanApprovalService.get_action(db, action_id)
        return format_action_response(action)
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

@router.post("/propose/{email_id}", response_model=List[ActionProposalResponse])
async def propose_actions_for_email(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Evaluate Phase 2A and Phase 2B records through the deterministic Policy Engine
    to generate Action Proposals in PENDING_APPROVAL state.
    """
    # 1. Retrieve EmailRecord
    stmt = select(EmailRecord).where(EmailRecord.id == email_id)
    res = await db.execute(stmt)
    email_rec = res.scalar_one_or_none()
    if not email_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID '{email_id}' not found."
        )

    # 2. Retrieve latest LLMAnalysisRecord (if available)
    analysis_stmt = (
        select(LLMAnalysisRecord)
        .where(LLMAnalysisRecord.email_id == email_id)
        .order_by(desc(LLMAnalysisRecord.created_at))
    )
    analysis_res = await db.execute(analysis_stmt)
    analysis_rec = analysis_res.scalars().first()

    # 3. Retrieve telemetry for static indicators
    tel_stmt = (
        select(CelestoTelemetryRecord)
        .where(CelestoTelemetryRecord.email_id == email_id)
        .order_by(desc(CelestoTelemetryRecord.created_at))
    )
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

    # Extract event data if available
    calendar_event_data = None
    calendar_detected = False
    threat_category = None
    threat_level = None
    urgency = 1

    if analysis_rec:
        threat_category = analysis_rec.threat_category
        threat_level = analysis_rec.threat_level
        urgency = analysis_rec.urgency
        calendar_detected = analysis_rec.calendar_event_detected
        if analysis_rec.extracted_event_json:
            try:
                calendar_event_data = json.loads(analysis_rec.extracted_event_json)
            except Exception:
                pass

    # 4. Invoke Policy Engine
    drafts = PolicyEngine.evaluate(
        static_risk_label=email_rec.static_risk_label,
        static_risk_score=email_rec.static_risk_score,
        threat_category=threat_category,
        threat_level=threat_level,
        urgency=urgency,
        calendar_event_detected=calendar_detected,
        calendar_event_data=calendar_event_data,
        static_threat_indicators=threat_indicators
    )

    created_actions = []
    for draft in drafts:
        action_rec = ActionProposalRecord(
            email_id=email_rec.id,
            source_analysis_id=analysis_rec.id if analysis_rec else None,
            action_type=draft.action_type.value,
            state=ActionState.PENDING_APPROVAL.value,
            reason=draft.reason,
            policy_rule=draft.policy_rule,
            risk_level=draft.risk_level,
            payload_json=json.dumps(draft.payload),
            is_human_approved=False
        )
        db.add(action_rec)
        created_actions.append(action_rec)

    if created_actions:
        await db.commit()
        for act in created_actions:
            await db.refresh(act)

    return [format_action_response(a) for a in created_actions]

@router.post("/{action_id}/approve", response_model=ActionProposalResponse)
async def approve_action(
    action_id: str,
    req: ActionApproveRequest = ActionApproveRequest(),
    db: AsyncSession = Depends(get_db)
):
    """
    Transition action from PENDING_APPROVAL -> APPROVED.
    Requires explicit human decision.
    """
    try:
        action = await HumanApprovalService.approve_action(db, action_id, notes=req.notes)
        return format_action_response(action)
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.post("/{action_id}/reject", response_model=ActionProposalResponse)
async def reject_action(
    action_id: str,
    req: ActionRejectRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Transition action from PENDING_APPROVAL -> REJECTED.
    Mandatory reason required. REJECTED is a terminal state.
    """
    try:
        action = await HumanApprovalService.reject_action(db, action_id, reason=req.reason)
        return format_action_response(action)
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

@router.post("/{action_id}/execute", response_model=ActionExecutionResponse)
async def execute_action(
    action_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Execute an action proposal.
    STRICTLY requires state == APPROVED.
    PENDING_APPROVAL actions are rejected with HTTP 403 Forbidden.
    REJECTED/EXECUTED/FAILED actions are rejected.
    """
    try:
        action = await ActionExecutor.execute(db, action_id)
        exec_res = json.loads(action.execution_result_json) if action.execution_result_json else {}
        return ActionExecutionResponse(
            action_id=action.id,
            action_type=ActionType(action.action_type),
            state=ActionState(action.state),
            executed_at=action.executed_at.isoformat() if action.executed_at else "",
            is_simulated=True,
            execution_result=exec_res
        )
    except ActionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ActionAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ActionExecutionError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
