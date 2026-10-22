"""
Human Approval Service for MailGuard.
Enforces deterministic state transitions for Action Proposals.
CRITICAL INVARIANTS:
1. PENDING_APPROVAL -> APPROVED (Explicit human approval only)
2. PENDING_APPROVAL -> REJECTED (Explicit human rejection with mandatory reason)
3. No other transitions are permitted through this service.
4. REJECTED actions are terminal.
5. EXECUTED actions cannot be re-approved or re-rejected.
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.db.models import ActionProposalRecord, utc_now
from backend.app.schemas.action import ActionState

class ActionError(Exception):
    """Base exception for action operations."""
    pass

class ActionNotFoundError(ActionError):
    """Raised when the specified action proposal is not found."""
    pass

class InvalidStateTransitionError(ActionError):
    """Raised when an illegal action state transition is attempted."""
    pass

class HumanApprovalService:
    """Service governing human authorization transitions."""

    @staticmethod
    async def get_action(db: AsyncSession, action_id: str) -> ActionProposalRecord:
        stmt = select(ActionProposalRecord).where(ActionProposalRecord.id == action_id)
        result = await db.execute(stmt)
        action = result.scalar_one_or_none()
        if not action:
            raise ActionNotFoundError(f"Action proposal '{action_id}' not found.")
        return action

    @staticmethod
    async def approve_action(
        db: AsyncSession,
        action_id: str,
        notes: Optional[str] = None
    ) -> ActionProposalRecord:
        """
        Transition an action from PENDING_APPROVAL -> APPROVED.
        Requires explicit human authorization.
        """
        action = await HumanApprovalService.get_action(db, action_id)

        # Enforce deterministic state machine rules
        if action.state == ActionState.APPROVED.value:
            # Idempotent or already approved
            return action

        if action.state == ActionState.REJECTED.value:
            raise InvalidStateTransitionError(
                f"Cannot approve action '{action_id}'. Current state is REJECTED (terminal state)."
            )

        if action.state in (ActionState.EXECUTED.value, ActionState.FAILED.value):
            raise InvalidStateTransitionError(
                f"Cannot approve action '{action_id}'. Current state is {action.state}."
            )

        if action.state != ActionState.PENDING_APPROVAL.value:
            raise InvalidStateTransitionError(
                f"Illegal transition: Cannot transition action '{action_id}' from '{action.state}' to APPROVED."
            )

        # Transition: PENDING_APPROVAL -> APPROVED
        action.state = ActionState.APPROVED.value
        action.is_human_approved = True
        action.approved_at = utc_now()
        await db.commit()
        await db.refresh(action)
        return action

    @staticmethod
    async def reject_action(
        db: AsyncSession,
        action_id: str,
        reason: str
    ) -> ActionProposalRecord:
        """
        Transition an action from PENDING_APPROVAL -> REJECTED.
        Mandatory rejection reason required for auditability.
        """
        if not reason or not reason.strip():
            raise ValueError("Rejection reason must be provided.")

        action = await HumanApprovalService.get_action(db, action_id)

        if action.state == ActionState.REJECTED.value:
            # Already rejected
            return action

        if action.state == ActionState.EXECUTED.value:
            raise InvalidStateTransitionError(
                f"Cannot reject action '{action_id}'. Action has already been EXECUTED."
            )

        if action.state != ActionState.PENDING_APPROVAL.value:
            raise InvalidStateTransitionError(
                f"Illegal transition: Cannot transition action '{action_id}' from '{action.state}' to REJECTED. Only PENDING_APPROVAL actions can be rejected."
            )

        # Transition: PENDING_APPROVAL -> REJECTED
        action.state = ActionState.REJECTED.value
        action.rejection_reason = reason.strip()
        action.rejected_at = utc_now()
        await db.commit()
        await db.refresh(action)
        return action
