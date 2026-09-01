"""FastAPI Pydantic Schemas for PayGuard REST API."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class ScreenRequest(BaseModel):
    text: str = Field(..., description="Message text or retrieved content to screen")
    input_type: str = Field("direct_input", description="Type of input: direct_input, tool_output, retrieved_content")
    session_id: Optional[str] = Field(None, description="Optional session tracking ID")
    use_llm: bool = Field(False, description="Whether to trigger LLM semantic reasoning layer")
    block_threshold: float = Field(0.7, ge=0.0, le=1.0)
    flag_threshold: float = Field(0.4, ge=0.0, le=1.0)

class ScreenResponse(BaseModel):
    verdict: str = Field(..., description="Verdict: allow, block, flag_for_human")
    confidence: float = Field(..., description="Risk confidence score (0.0 to 1.0)")
    reason: str = Field(..., description="Human-readable decision rationale")
    layer: str = Field(..., description="Screening layer responsible for decision")
    heuristic_triggers: List[str] = Field(default_factory=list)

class ActionScreenRequest(BaseModel):
    tool_name: str = Field(..., description="Name of tool being called (e.g. issue_refund, apply_discount)")
    tool_args: Dict[str, Any] = Field(..., description="Arguments passed to the tool")
    session_id: Optional[str] = Field(None, description="Active session ID for anomaly velocity tracking")

class ActionScreenResponse(BaseModel):
    verdict: str
    confidence: float
    reason: str
    policy_violations: List[str] = Field(default_factory=list)

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class ProcessRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Customer message to process through the complete firewall")
    use_llm: bool = Field(False, description="Whether to use the semantic analysis layer")
    block_threshold: float = Field(0.7, ge=0.0, le=1.0)
    flag_threshold: float = Field(0.4, ge=0.0, le=1.0)


class ProcessResponse(BaseModel):
    verdict: str
    confidence: float
    reason: str
    layer: str
    agent_response: str = ""
    tool_calls_made: List[Dict[str, Any]] = Field(default_factory=list)
    tool_calls_blocked: List[Dict[str, Any]] = Field(default_factory=list)
    input_screening: Optional[Dict[str, Any]] = None
    action_screenings: List[Dict[str, Any]] = Field(default_factory=list)
    session_id: str
    timestamp: str


class RedTeamRunRequest(BaseModel):
    """Configuration for one deterministic red-team challenge run."""
    use_llm: bool = Field(False, description="Whether to add the semantic analysis layer")
    block_threshold: float = Field(0.7, ge=0.0, le=1.0)
    flag_threshold: float = Field(0.4, ge=0.0, le=1.0)


class RedTeamCaseResult(BaseModel):
    case_id: str
    category: str
    payload: str
    expected_verdict: str
    verdict: str
    confidence: float
    reason: str
    layer: str
    heuristic_triggers: List[str] = Field(default_factory=list)
    simulated_exposure_inr: int = Field(0, ge=0)
    passed: bool


class RedTeamRunResponse(BaseModel):
    total: int
    blocked: int
    flagged: int
    allowed: int
    block_rate: float
    passed: int
    potential_exposure_inr: int = Field(0, ge=0)
    prevented_exposure_inr: int = Field(0, ge=0)
    escaped_exposure_inr: int = Field(0, ge=0)
    unsafe_gateway_actions_executed: int = Field(0, ge=0)
    cases: List[RedTeamCaseResult]


class ResetResponse(BaseModel):
    status: str
    session_id: str
