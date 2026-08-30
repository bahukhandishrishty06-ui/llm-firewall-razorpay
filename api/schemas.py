"""FastAPI Pydantic Schemas for PayGuard REST API."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class ScreenRequest(BaseModel):
    text: str = Field(..., description="Message text or retrieved content to screen")
    input_type: str = Field("direct_input", description="Type of input: direct_input, tool_output, retrieved_content")
    session_id: Optional[str] = Field(None, description="Optional session tracking ID")
    use_llm: bool = Field(False, description="Whether to trigger LLM semantic reasoning layer")

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
