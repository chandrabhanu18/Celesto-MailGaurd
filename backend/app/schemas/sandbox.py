from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ExtractedURL(BaseModel):
    url: str
    domain: str
    is_ip_address: bool = False
    is_suspicious_homoglyph: bool = False
    is_known_suspicious_tld: bool = False
    risk_notes: Optional[str] = None

class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    entropy: float = Field(ge=0.0, le=8.0, description="Shannon entropy")
    is_executable_or_script: bool = False
    is_archive: bool = False
    archive_traversal_risk: bool = False
    suspicious_notes: Optional[str] = None

class ThreatIndicator(BaseModel):
    indicator_type: str  # e.g., "PROMPT_INJECTION", "PHISHING_URL", "HOMOGLYPH", "HIGH_ENTROPY", "MALICIOUS_INSTRUCTION"
    severity: str        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    matched_pattern: Optional[str] = None

class PromptInjectionSignal(BaseModel):
    pattern_type: str    # e.g., "SYSTEM_OVERRIDE", "INSTRUCTION_RESET", "EXFILTRATION_TRIGGER", "HIDDEN_UNICODE"
    confidence: float = Field(ge=0.0, le=1.0)
    matched_snippet: str
    description: str

class SandboxAnalysisReport(BaseModel):
    """Structured, untrusted output produced strictly by inspector.py inside the sandbox."""
    status: str = "success"
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    date_str: str = ""
    has_html: bool = False
    sanitized_text: str = ""
    extracted_urls: List[ExtractedURL] = Field(default_factory=list)
    attachments: List[AttachmentMeta] = Field(default_factory=list)
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list)
    prompt_injection_signals: List[PromptInjectionSignal] = Field(default_factory=list)
    static_risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    static_risk_label: str = "SAFE"  # SAFE, LOW, MEDIUM, SUSPICIOUS, CRITICAL
    analysis_duration_ms: int = 0

class SandboxExecutionResult(BaseModel):
    """Execution container returned by CelestoSandboxProvider."""
    provider_mode: str  # "REAL_CELESTO" | "DEMO_FALLBACK"
    sandbox_id: str
    network_mode: str = "off"
    execution_time_ms: int
    exit_code: int
    report: Optional[SandboxAnalysisReport] = None
    error_message: Optional[str] = None
    is_quarantine_breach_detected: bool = False
