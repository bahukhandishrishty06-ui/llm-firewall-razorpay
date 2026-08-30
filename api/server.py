"""PayGuard REST API Service."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import os

from api.schemas import ScreenRequest, ScreenResponse, ActionScreenRequest, ActionScreenResponse, HealthResponse
from firewall.input_screener import screen_input
from firewall.action_screener import screen_action
from firewall.firewall import PayGuardFirewall

app = FastAPI(
    title="PayGuard API",
    description="Real-time LLM Firewall REST API for Payment and Agentic-Commerce contexts",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall_instance = PayGuardFirewall(use_llm=False)

@app.get("/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/v1/screen/input", response_model=ScreenResponse)
def screen_input_endpoint(req: ScreenRequest):
    try:
        res = screen_input(
            text=req.text,
            input_type=req.input_type,
            session_id=req.session_id,
            force_llm=req.use_llm
        )
        return {
            "verdict": res.verdict,
            "confidence": res.confidence,
            "reason": res.reason,
            "layer": res.layer,
            "heuristic_triggers": res.heuristic_triggers
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/screen/action", response_model=ActionScreenResponse)
def screen_action_endpoint(req: ActionScreenRequest):
    try:
        res = screen_action(
            tool_name=req.tool_name,
            tool_args=req.tool_args,
            session_id=req.session_id,
            use_llm=False
        )
        return {
            "verdict": res.verdict,
            "confidence": res.confidence,
            "reason": res.reason,
            "policy_violations": res.policy_violations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
