import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey
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
