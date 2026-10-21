from typing import List, Optional
from pydantic import BaseModel
from backend.app.schemas.sandbox import SandboxExecutionResult

class SimulationScenarioMeta(BaseModel):
    scenario_id: str
    title: str
    category: str
    description: str
    expected_risk: str
    attack_type: Optional[str] = None

class SimulationTriggerRequest(BaseModel):
    scenario_id: str

class SimulationTriggerResponse(BaseModel):
    scenario_id: str
    title: str
    category: str
    email_id: str
    execution: SandboxExecutionResult
    security_verdict: str
    unauthorized_side_effects_prevented: bool = True
    invariants_maintained: List[str]

class ScenarioListResponse(BaseModel):
    scenarios: List[SimulationScenarioMeta]
