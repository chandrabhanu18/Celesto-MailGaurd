import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from backend.app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scenario_id = Column(String(64), nullable=True, index=True)
    source = Column(String(32), default="SIMULATED", nullable=False)
    sender = Column(String(255), default="", nullable=False)
    recipient = Column(String(255), default="", nullable=False)
    subject = Column(String(512), default="", nullable=False)
    date_str = Column(String(64), default="", nullable=False)
    sanitized_text = Column(Text, default="", nullable=False)
    static_risk_label = Column(String(32), default="SAFE", nullable=False)
    static_risk_score = Column(Float, default=0.0, nullable=False)
    threat_indicators_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    telemetry = relationship("CelestoTelemetryRecord", back_populates="email", cascade="all, delete-orphan")
    analyses = relationship("LLMAnalysisRecord", back_populates="email", cascade="all, delete-orphan")
    actions = relationship("ActionProposalRecord", back_populates="email", cascade="all, delete-orphan")

class CelestoTelemetryRecord(Base):
    __tablename__ = "celesto_telemetry"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, index=True)
    provider_mode = Column(String(32), nullable=False)  # "REAL_CELESTO" | "DEMO_FALLBACK"
    sandbox_id = Column(String(128), nullable=False)
    network_mode = Column(String(32), default="off", nullable=False)
    execution_time_ms = Column(Integer, default=0, nullable=False)
    exit_code = Column(Integer, default=0, nullable=False)
    stdout_bytes_len = Column(Integer, default=0, nullable=False)
    indicators_json = Column(Text, default="[]", nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    email = relationship("EmailRecord", back_populates="telemetry")

class LLMAnalysisRecord(Base):
    """
    Advisory security & urgency analysis persisted for auditing.
    Stores structured classification and optional calendar events.
    Does NOT store sensitive credentials or unvalidated raw model outputs.
    """
    __tablename__ = "llm_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, index=True)
    provider = Column(String(32), nullable=False)  # "mock" | "ollama"
    model = Column(String(64), nullable=False)
    threat_category = Column(String(32), nullable=False)
    threat_level = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)
    urgency = Column(Integer, nullable=False)
    explanation = Column(Text, default="", nullable=False)
    indicators_json = Column(Text, default="[]", nullable=False)
    recommended_action = Column(String(64), nullable=False)
    calendar_event_detected = Column(Boolean, default=False, nullable=False)
    extracted_event_json = Column(Text, nullable=True)
    raw_prompt_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    email = relationship("EmailRecord", back_populates="analyses")
    actions = relationship("ActionProposalRecord", back_populates="analysis")

class ActionProposalRecord(Base):
    """
    Deterministic Action Proposal Record.
    Created exclusively by the deterministic Policy Engine.
    All actions begin in PENDING_APPROVAL and require explicit human authorization.
    """
    __tablename__ = "action_proposals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, index=True)
    source_analysis_id = Column(String(36), ForeignKey("llm_analyses.id"), nullable=True, index=True)
    action_type = Column(String(64), nullable=False)
    state = Column(String(32), default="PENDING_APPROVAL", nullable=False)
    reason = Column(Text, nullable=False)
    policy_rule = Column(String(64), nullable=False)
    risk_level = Column(String(32), default="LOW", nullable=False)
    payload_json = Column(Text, default="{}", nullable=False)
    rejection_reason = Column(Text, nullable=True)
    execution_result_json = Column(Text, nullable=True)
    is_human_approved = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)

    email = relationship("EmailRecord", back_populates="actions")
    analysis = relationship("LLMAnalysisRecord", back_populates="actions")
