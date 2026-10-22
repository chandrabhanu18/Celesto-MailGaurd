from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class ActionType(str, Enum):
    QUARANTINE_EMAIL = "QUARANTINE_EMAIL"
    FLAG_EMAIL = "FLAG_EMAIL"
    CREATE_CALENDAR_EVENT = "CREATE_CALENDAR_EVENT"
    GENERATE_REPLY = "GENERATE_REPLY"
    PUBLISH_SOCIAL_CONTENT = "PUBLISH_SOCIAL_CONTENT"

class ActionState(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"

class ActionProposalResponse(BaseModel):
    """Structured proposal representation with full audit trail."""
    id: str
    email_id: str
    source_analysis_id: Optional[str] = None
    action_type: ActionType
    state: ActionState
    reason: str
    policy_rule: str
    risk_level: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    rejection_reason: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None
    is_human_approved: bool = False
    created_at: str
    approved_at: Optional[str] = None
    rejected_at: Optional[str] = None
    executed_at: Optional[str] = None

class ActionApproveRequest(BaseModel):
    """Optional human decision notes when approving."""
    notes: Optional[str] = None

class ActionRejectRequest(BaseModel):
    """Mandatory reason when rejecting an action."""
    reason: str = Field(min_length=1, description="Reason for rejection")

class ActionExecutionResponse(BaseModel):
    """Response returned after executing an APPROVED action."""
    action_id: str
    action_type: ActionType
    state: ActionState
    executed_at: str
    is_simulated: bool = True
    execution_result: Dict[str, Any]

class ActionListResponse(BaseModel):
    actions: List[ActionProposalResponse]
    total: int
