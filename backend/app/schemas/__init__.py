"""Pydantic schemas for MailGuard."""
from backend.app.schemas.sandbox import (
    SandboxAnalysisReport,
    SandboxExecutionResult,
    ThreatIndicator,
    PromptInjectionSignal,
    ExtractedURL,
    AttachmentMeta,
)
from backend.app.schemas.simulator import (
    SimulationScenarioMeta,
    ScenarioListResponse,
    SimulationTriggerRequest,
    SimulationTriggerResponse,
)
from backend.app.schemas.llm import (
    ThreatCategory,
    ThreatLevel,
    ExtractedCalendarEvent,
    LLMAnalysisResult,
    LLMAnalysisContext,
    LLMAnalysisDetailResponse,
)
from backend.app.schemas.action import (
    ActionType,
    ActionState,
    ActionProposalResponse,
    ActionApproveRequest,
    ActionRejectRequest,
    ActionExecutionResponse,
    ActionListResponse,
)

__all__ = [
    "SandboxAnalysisReport",
    "SandboxExecutionResult",
    "ThreatIndicator",
    "PromptInjectionSignal",
    "ExtractedURL",
    "AttachmentMeta",
    "SimulationScenarioMeta",
    "ScenarioListResponse",
    "SimulationTriggerRequest",
    "SimulationTriggerResponse",
    "ThreatCategory",
    "ThreatLevel",
    "ExtractedCalendarEvent",
    "LLMAnalysisResult",
    "LLMAnalysisContext",
    "LLMAnalysisDetailResponse",
    "ActionType",
    "ActionState",
    "ActionProposalResponse",
    "ActionApproveRequest",
    "ActionRejectRequest",
    "ActionExecutionResponse",
    "ActionListResponse",
]
