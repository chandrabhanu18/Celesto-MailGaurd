import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

VALID_STATES = {"created", "ready", "running", "succeeded", "failed", "deleted"}
SANDBOX_NAME_REGEX = re.compile(r"^sbx-[a-z0-9]{8,}$")

class RunCreate(BaseModel):
    run_id: str = Field(..., min_length=1, description="Unique run identifier")
    sandbox_name: str = Field(..., description="Matches sbx- and 8 or more lowercase letters or digits")
    problem_id: str = Field(..., min_length=1, description="Identifier of the evaluated problem")
    state: str = Field(..., description="Run lifecycle state")
    execution_target: str = Field(..., description="Must equal 'celesto_sandbox'")

class RunResponse(BaseModel):
    run_id: str
    sandbox_name: str
    problem_id: str
    state: str
    execution_target: str
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
