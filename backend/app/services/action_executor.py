"""
Action Executor for MailGuard.
Simulates execution of APPROVED actions.
CRITICAL INVARIANTS:
1. ONLY actions in APPROVED state can be executed.
2. PENDING_APPROVAL cannot execute.
3. REJECTED cannot execute.
4. EXECUTED actions cannot execute again (idempotency / replay protection).
5. All execution is strictly simulated; zero connection to external Gmail/Calendar/Social APIs.
"""

import json
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.db.models import ActionProposalRecord, utc_now
from backend.app.schemas.action import ActionState, ActionType
from backend.app.services.approval_service import ActionError, ActionNotFoundError

class ActionAuthorizationError(ActionError):
    """Raised when execution is attempted on an unauthorized action."""
    pass

class ActionExecutionError(ActionError):
    """Raised when simulated action execution fails."""
    pass

class ActionExecutor:
    """Executes human-approved actions via safe simulated drivers."""

    @staticmethod
    async def execute(db: AsyncSession, action_id: str) -> ActionProposalRecord:
        """
        Execute an action.
        Strictly requires action.state == APPROVED.
        """
        stmt = select(ActionProposalRecord).where(ActionProposalRecord.id == action_id)
        result = await db.execute(stmt)
        action = result.scalar_one_or_none()

        if not action:
            raise ActionNotFoundError(f"Action proposal '{action_id}' not found.")

        # Hard authorization gating:
        if action.state == ActionState.PENDING_APPROVAL.value:
            raise ActionAuthorizationError(
                f"Unauthorized: Action '{action_id}' is in PENDING_APPROVAL state. Human approval is strictly required before execution."
            )

        if action.state == ActionState.REJECTED.value:
            raise ActionAuthorizationError(
                f"Unauthorized: Action '{action_id}' is in REJECTED state (terminal). Cannot execute rejected proposals."
            )

        if action.state == ActionState.EXECUTED.value:
            raise ActionAuthorizationError(
                f"Unauthorized: Action '{action_id}' has already been EXECUTED. Replay/duplicate execution is prohibited."
            )

        if action.state == ActionState.FAILED.value:
            raise ActionAuthorizationError(
                f"Unauthorized: Action '{action_id}' is in FAILED state. Cannot re-execute failed proposals directly."
            )

        if action.state != ActionState.APPROVED.value:
            raise ActionAuthorizationError(
                f"Unauthorized: Action '{action_id}' is in unexpected state '{action.state}'. Only APPROVED actions can execute."
            )

        # Dispatch safe simulated execution
        try:
            payload = json.loads(action.payload_json) if action.payload_json else {}
        except Exception:
            payload = {}

        try:
            simulated_result = ActionExecutor._run_simulated_driver(action.action_type, payload, action.email_id)
            
            # Transition: APPROVED -> EXECUTED
            action.state = ActionState.EXECUTED.value
            action.executed_at = utc_now()
            action.execution_result_json = json.dumps(simulated_result)
            await db.commit()
            await db.refresh(action)
            return action

        except Exception as e:
            # Transition: APPROVED -> FAILED
            action.state = ActionState.FAILED.value
            action.executed_at = utc_now()
            action.execution_result_json = json.dumps({
                "error": str(e),
                "is_simulated": True,
                "status": "FAILED"
            })
            await db.commit()
            await db.refresh(action)
            raise ActionExecutionError(f"Simulated execution failed: {e}")

    @staticmethod
    def _run_simulated_driver(action_type: str, payload: Dict[str, Any], email_id: str) -> Dict[str, Any]:
        """
        Pure safe simulated execution. Zero external side effects.
        """
        base_meta = {
            "is_simulated": True,
            "executor": "safe_simulated_executor",
            "email_id": email_id,
            "status": "SUCCESS"
        }

        if action_type == ActionType.QUARANTINE_EMAIL.value:
            return {
                **base_meta,
                "driver": "simulated_quarantine_vault",
                "action_applied": "EMAIL_MOVED_TO_QUARANTINE_FOLDER",
                "mailbox_status": "ISOLATED",
                "risk_score_mitigated": payload.get("static_risk_score", 0.0)
            }

        elif action_type == ActionType.FLAG_EMAIL.value:
            return {
                **base_meta,
                "driver": "simulated_mailbox_tagger",
                "action_applied": "HIGH_PRIORITY_FLAG_ADDED",
                "urgency_level": payload.get("urgency", 5)
            }

        elif action_type == ActionType.CREATE_CALENDAR_EVENT.value:
            event_data = payload.get("event_data", {})
            return {
                **base_meta,
                "driver": "simulated_calendar_draft_scheduler",
                "action_applied": "CALENDAR_EVENT_DRAFTED",
                "event_title": event_data.get("title", "Draft Event"),
                "event_date": event_data.get("date"),
                "event_time": event_data.get("start_time"),
                "note": "Event created in simulated draft calendar only. No live Google Calendar API invoked."
            }

        elif action_type == ActionType.GENERATE_REPLY.value:
            return {
                **base_meta,
                "driver": "simulated_reply_drafter",
                "action_applied": "DRAFT_REPLY_SAVED",
                "note": "Simulated reply draft saved. No email sent."
            }

        elif action_type == ActionType.PUBLISH_SOCIAL_CONTENT.value:
            return {
                **base_meta,
                "driver": "simulated_social_sandbox",
                "action_applied": "SOCIAL_DRAFT_STAGED",
                "note": "Simulated social post staged. No external social networks reached."
            }

        else:
            return {
                **base_meta,
                "driver": "simulated_generic_driver",
                "action_applied": f"UNKNOWN_ACTION_{action_type}"
            }
