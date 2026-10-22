from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, model_validator

class ThreatCategory(str, Enum):
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    MALWARE = "MALWARE"
    SCAM = "SCAM"
    SUSPICIOUS = "SUSPICIOUS"
    OTHER = "OTHER"

class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ExtractedCalendarEvent(BaseModel):
    title: str = Field(description="Event title or summary")
    date: str = Field(description="Event date, e.g. YYYY-MM-DD or recognized date")
    start_time: Optional[str] = Field(default=None, description="Start time, e.g. HH:MM or 2:00 PM")
    end_time: Optional[str] = Field(default=None, description="End time if specified")
    timezone: Optional[str] = Field(default=None, description="Timezone if specified")
    location: Optional[str] = Field(default=None, description="Physical location or meeting URL")
    description: Optional[str] = Field(default=None, description="Event agenda or notes")

class LLMAnalysisResult(BaseModel):
    """
    Structured, strictly validated LLM analysis result.
    The LLM output is parsed into this schema and verified for semantic integrity.
    """
    threat_category: ThreatCategory
    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    urgency: int = Field(ge=1, le=5, description="Urgency score from 1 (lowest) to 5 (critical)")
    explanation: str = Field(description="Human-readable advisory rationale")
    indicators: List[str] = Field(default_factory=list, description="Identified threat or urgency signals")
    recommended_action: str = Field(description="Advisory recommendation, e.g. ALLOW, REVIEW, QUARANTINE")
    calendar_event_detected: bool = Field(default=False, description="True if actionable calendar event detected")
    extracted_calendar_event: Optional[ExtractedCalendarEvent] = Field(
        default=None,
        description="Extracted event details if calendar_event_detected is True"
    )

    @model_validator(mode="after")
    def validate_calendar_consistency(self):
        if not self.calendar_event_detected:
            # Enforce that if no event detected, extracted_calendar_event must be None
            if self.extracted_calendar_event is not None:
                raise ValueError("extracted_calendar_event must be null when calendar_event_detected is false.")
        else:
            # If calendar_event_detected is True, event metadata must be provided
            if self.extracted_calendar_event is None:
                raise ValueError("extracted_calendar_event must be provided when calendar_event_detected is true.")
        return self

class LLMAnalysisContext(BaseModel):
    """
    Normalized, validated Phase 2A context passed to the LLM.
    Strictly forbids raw sandbox stdout/stderr string dumps.
    """
    email_id: str
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    date_str: str = ""
    sanitized_text: str = ""
    static_risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    static_risk_label: str = "SAFE"
    threat_indicators_count: int = 0
    threat_indicators: List[str] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    attachments_summary: List[str] = Field(default_factory=list)

class LLMAnalysisDetailResponse(BaseModel):
    """API response model for audit and client consumption."""
    id: str
    email_id: str
    provider: str
    model: str
    threat_category: ThreatCategory
    threat_level: ThreatLevel
    confidence: float
    urgency: int
    explanation: str
    indicators: List[str]
    recommended_action: str
    calendar_event_detected: bool
    extracted_calendar_event: Optional[ExtractedCalendarEvent] = None
    is_advisory_only: bool = True
    created_at: str
