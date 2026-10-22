from typing import List, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.sandbox import SandboxExecutionResult
from backend.app.schemas.llm import LLMAnalysisDetailResponse
from backend.app.schemas.action import ActionProposalResponse

class SimulationScenarioMeta(BaseModel):
    scenario_id: str
    title: str
    category: str
    description: str
    expected_risk: str
    attack_type: Optional[str] = None

class SimulationTriggerRequest(BaseModel):
    scenario_id: str
    run_llm_analysis: bool = False
    propose_actions: bool = False

class SimulationTriggerResponse(BaseModel):
    scenario_id: str
    title: str
    category: str
    email_id: str
    execution: SandboxExecutionResult
    security_verdict: str
    unauthorized_side_effects_prevented: bool = True
    invariants_maintained: List[str]
    llm_analysis: Optional[LLMAnalysisDetailResponse] = None
    llm_provider_used: Optional[str] = None
    proposed_actions: List[ActionProposalResponse] = Field(default_factory=list)
    has_pending_actions: bool = False

class ScenarioListResponse(BaseModel):
    scenarios: List[SimulationScenarioMeta]
