from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.app.schemas.llm import LLMAnalysisDetailResponse
from backend.app.schemas.action import ActionProposalResponse

class StaticInspectionDetail(BaseModel):
    static_risk_label: str
    static_risk_score: float
    threat_indicators_count: int
    threat_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    has_html: bool = False
    has_prompt_injection: bool = False
    has_suspicious_homoglyph: bool = False
    has_ip_url: bool = False
    has_zero_width_chars: bool = False
    analysis_duration_ms: int = 0

class EmailListItem(BaseModel):
    id: str
    scenario_id: Optional[str] = None
    source: str = "SIMULATED"
    sender: str
    recipient: str
    subject: str
    date_str: str
    created_at: str
    static_risk_label: str
    static_risk_score: float
    threat_indicators_count: int
    # AI Advisory Analysis summary (if available)
    has_analysis: bool = False
    threat_category: Optional[str] = None
    threat_level: Optional[str] = None
    urgency: Optional[int] = None
    confidence: Optional[float] = None
    recommended_action: Optional[str] = None
    calendar_event_detected: bool = False
    # Action gating summary
    total_actions_count: int = 0
    pending_approval_count: int = 0
    primary_action_type: Optional[str] = None
    primary_action_state: Optional[str] = None
    is_quarantined: bool = False

class EmailListResponse(BaseModel):
    emails: List[EmailListItem]
    total: int

class TelemetrySummary(BaseModel):
    id: str
    provider_mode: str
    sandbox_id: str
    network_mode: str
    execution_time_ms: int
    exit_code: int
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
    created_at: Optional[str] = None

class EmailDetailResponse(BaseModel):
    id: str
    scenario_id: Optional[str] = None
    source: str = "SIMULATED"
    sender: str
    recipient: str
    subject: str
    date_str: str
    sanitized_text: str
    created_at: str
    static_inspection: StaticInspectionDetail
    telemetry: Optional[TelemetrySummary] = None
    latest_analysis: Optional[LLMAnalysisDetailResponse] = None
    actions: List[ActionProposalResponse] = Field(default_factory=list)
