"""
Pluggable LLM interface adapter for MailGuard.
Provides MockLLM (zero-credential deterministic offline evaluation)
and OllamaLLM (local micro-agent HTTP evaluation).
Strictly enforces:
- Zero tool execution
- LLM output treated as untrusted data
- Pydantic schema validation & size limits
"""

import re
import json
import httpx
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import ValidationError

from backend.app.config import settings
from backend.app.schemas.llm import (
    ThreatCategory,
    ThreatLevel,
    ExtractedCalendarEvent,
    LLMAnalysisResult,
    LLMAnalysisContext,
)
from backend.app.services.llm_prompt_templates import (
    SYSTEM_SECURITY_PROMPT,
    build_analysis_prompt,
)

class LLMError(Exception):
    """Base error for LLM evaluation failures."""
    pass

class LLMProviderError(LLMError):
    """Raised when an external LLM service is offline or unreachable."""
    pass

class LLMOutputValidationError(LLMError):
    """Raised when the LLM produces malformed or invalid output."""
    pass

class BaseLLMClient(ABC):
    """Abstract contract for pluggable LLM security evaluators."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g. 'mock', 'ollama')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the model utilized."""
        pass

    @abstractmethod
    async def analyze(self, context: LLMAnalysisContext) -> LLMAnalysisResult:
        """
        Evaluate normalized Phase 2A context and return a validated LLMAnalysisResult.
        Must never execute actions or call external tools.
        """
        pass

class MockLLM(BaseLLMClient):
    """
    Deterministic offline evaluator for zero-credential test suites and local demos.
    Never misrepresents itself as real AI inference.
    """

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock-deterministic-v1"

    async def analyze(self, context: LLMAnalysisContext) -> LLMAnalysisResult:
        text_lower = (context.sanitized_text + " " + context.subject).lower()

        # 1. Prompt Injection Detection
        injection_triggers = [
            "ignore all previous instructions",
            "ignore prior instructions",
            "ignore previous directives",
            "system override",
            "developer mode",
            "send this email to",
            "forward all emails to",
            "exfiltrate",
            "[system]",
            "[admin]",
            "dan mode",
            "reveal your api key",
            "reveal secret"
        ]
        has_injection = any(trigger in text_lower for trigger in injection_triggers) or any(
            "PROMPT_INJECTION" in str(ind).upper() or "SYSTEM_OVERRIDE" in str(ind).upper()
            for ind in context.threat_indicators
        )

        if has_injection:
            return LLMAnalysisResult(
                threat_category=ThreatCategory.PROMPT_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.99,
                urgency=5,
                explanation="Adversarial prompt injection attempt detected aiming to override gatekeeper directives.",
                indicators=["Directive override attempt", "Adversarial instruction fencing bypass attempt"],
                recommended_action="QUARANTINE",
                calendar_event_detected=False,
                extracted_calendar_event=None
            )

        # 2. Phishing Detection
        phishing_triggers = [
            "paypa1", "suspicious homoglyph", "verify your account", "urgent account suspension",
            "update payment", "banking credentials", "click here to restore access"
        ]
        has_phishing = any(trigger in text_lower for trigger in phishing_triggers) or any(
            "PHISHING" in str(ind).upper() or "HOMOGLYPH" in str(ind).upper()
            for ind in context.threat_indicators
        ) or context.static_risk_label in ("CRITICAL", "SUSPICIOUS")

        if has_phishing:
            return LLMAnalysisResult(
                threat_category=ThreatCategory.PHISHING,
                threat_level=ThreatLevel.HIGH,
                confidence=0.95,
                urgency=4,
                explanation="Phishing / credential harvesting attack detected with deceptive links or high static risk score.",
                indicators=["Deceptive URL pattern", "Credential harvesting call-to-action"],
                recommended_action="QUARANTINE",
                calendar_event_detected=False,
                extracted_calendar_event=None
            )

        # 3. Calendar Event Extraction (e.g. Interview, Assessment, Scheduled Meeting)
        calendar_triggers = ["interview", "assessment", "calendar", "meeting", "sync", "google meet", "zoom.us", "scheduled for"]
        has_calendar = any(trigger in text_lower for trigger in calendar_triggers)

        if has_calendar:
            title = context.subject if context.subject else "Scheduled Meeting"
            # Extract basic meeting info deterministically
            start_time = "14:00"
            date = "2026-10-25"
            location = "Google Meet" if "meet" in text_lower else "Conference Call"
            
            # Simple heuristic regex for time if present
            time_match = re.search(r"(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)", context.sanitized_text)
            if time_match:
                start_time = time_match.group(1)

            date_match = re.search(r"(tomorrow|\d{4}-\d{2}-\d{2}|october\s+\d{1,2}|november\s+\d{1,2})", text_lower)
            if date_match:
                date = date_match.group(1).title()

            event = ExtractedCalendarEvent(
                title=title,
                date=date,
                start_time=start_time,
                end_time=None,
                timezone="UTC",
                location=location,
                description=f"Extracted from email: '{context.subject}'"
            )
            return LLMAnalysisResult(
                threat_category=ThreatCategory.BENIGN,
                threat_level=ThreatLevel.SAFE,
                confidence=0.92,
                urgency=3 if "interview" in text_lower or "assessment" in text_lower else 2,
                explanation="Legitimate meeting schedule or calendar invitation detected.",
                indicators=["Calendar invite pattern", "Benign correspondence"],
                recommended_action="ALLOW",
                calendar_event_detected=True,
                extracted_calendar_event=event
            )

        # 4. Urgent Legitimate Email
        urgent_triggers = ["urgent", "asap", "deadline", "immediate attention", "critical server alert"]
        if any(trigger in text_lower for trigger in urgent_triggers):
            return LLMAnalysisResult(
                threat_category=ThreatCategory.BENIGN,
                threat_level=ThreatLevel.LOW,
                confidence=0.90,
                urgency=5,
                explanation="High-urgency legitimate correspondence requiring timely user awareness.",
                indicators=["High urgency keywords", "No security anomalies"],
                recommended_action="ALLOW",
                calendar_event_detected=False,
                extracted_calendar_event=None
            )

        # 5. Routine Benign Email (e.g. Newsletter, regular updates)
        return LLMAnalysisResult(
            threat_category=ThreatCategory.BENIGN,
            threat_level=ThreatLevel.SAFE,
            confidence=0.90,
            urgency=1,
            explanation="Routine benign correspondence. No security threats or calendar events detected.",
            indicators=["Standard benign communication"],
            recommended_action="ALLOW",
            calendar_event_detected=False,
            extracted_calendar_event=None
        )

class OllamaLLM(BaseLLMClient):
    """
    Ollama HTTP adapter connecting to a locally hosted Ollama instance (e.g. llama3.2).
    Enforces strict zero-tool isolation, output limits, and Pydantic validation.
    """

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self._base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self._model = model or settings.OLLAMA_MODEL

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    async def analyze(self, context: LLMAnalysisContext) -> LLMAnalysisResult:
        endpoint = f"{self._base_url}/api/generate"
        prompt = build_analysis_prompt(context)

        payload = {
            "model": self._model,
            "system": SYSTEM_SECURITY_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0  # Deterministic analysis
            }
        }

        try:
            async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code != 200:
                    raise LLMProviderError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}")
                raw_bytes = resp.content
        except httpx.ConnectError as ce:
            raise LLMProviderError(f"Ollama server is unreachable at {self._base_url}: {ce}")
        except httpx.TimeoutException:
            raise LLMProviderError(f"Ollama request timed out after {settings.LLM_TIMEOUT_SECONDS}s")
        except httpx.RequestError as re:
            raise LLMProviderError(f"Ollama network error: {re}")

        # Enforce size limit on raw output
        if len(raw_bytes) > settings.MAX_LLM_OUTPUT_BYTES:
            raise LLMOutputValidationError(
                f"LLM output exceeded size limit ({len(raw_bytes)} > {settings.MAX_LLM_OUTPUT_BYTES} bytes)"
            )

        try:
            outer_data = resp.json()
            raw_response_text = outer_data.get("response", "").strip()
        except Exception as e:
            raise LLMOutputValidationError(f"Failed to parse Ollama JSON wrapper: {e}")

        # Strip accidental markdown fencing
        cleaned_text = raw_response_text
        if cleaned_text.startswith("```"):
            cleaned_text = re.sub(r"^```(?:json)?\s*", "", cleaned_text)
            cleaned_text = re.sub(r"\s*```$", "", cleaned_text)
        cleaned_text = cleaned_text.strip()

        # Parse JSON
        try:
            parsed_json = json.loads(cleaned_text)
        except json.JSONDecodeError as jde:
            raise LLMOutputValidationError(f"LLM produced malformed JSON: {jde}. Raw text: {cleaned_text[:200]}")

        # Validate against strict Pydantic schema
        try:
            validated_result = LLMAnalysisResult.model_validate(parsed_json)
            return validated_result
        except ValidationError as ve:
            raise LLMOutputValidationError(f"LLM JSON failed schema validation: {ve}")

def get_llm_client() -> BaseLLMClient:
    """Factory returning configured LLM client."""
    provider = settings.LLM_PROVIDER.lower()
    if provider == "mock":
        return MockLLM()
    elif provider == "ollama":
        return OllamaLLM()
    else:
        raise ValueError(f"Unsupported LLM provider '{settings.LLM_PROVIDER}'. Supported: 'mock', 'ollama'.")
