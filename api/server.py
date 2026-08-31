"""PayGuard REST API service for the React inspector."""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from typing import Any
import json
import os

from api.schemas import (
    ActionScreenRequest,
    ActionScreenResponse,
    HealthResponse,
    ProcessRequest,
    ProcessResponse,
    ResetResponse,
    ScreenRequest,
    ScreenResponse,
)
from firewall.input_screener import screen_input
from firewall.action_screener import screen_action
from firewall.firewall import PayGuardFirewall
from agent.tools import seed_test_orders
from database import get_audit_log, get_firewall_decisions

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
seed_test_orders()


def _validate_thresholds(block_threshold: float, flag_threshold: float) -> None:
    if flag_threshold > block_threshold:
        raise HTTPException(
            status_code=422,
            detail="Flag threshold must be less than or equal to the block threshold.",
        )

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
        _validate_thresholds(req.block_threshold, req.flag_threshold)
        res = screen_input(
            text=req.text,
            input_type=req.input_type,
            session_id=req.session_id,
            force_llm=req.use_llm,
            block_threshold=req.block_threshold,
            flag_threshold=req.flag_threshold,
            use_llm=req.use_llm,
        )
        return {
            "verdict": res.verdict,
            "confidence": res.confidence,
            "reason": res.reason,
            "layer": res.layer,
            "heuristic_triggers": res.heuristic_triggers
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
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


@app.post("/v1/firewall/process", response_model=ProcessResponse)
def process_message_endpoint(req: ProcessRequest):
    """Run a message through the complete Layer 1 → agent → Layer 2 pipeline."""
    try:
        _validate_thresholds(req.block_threshold, req.flag_threshold)
        firewall_instance.use_llm = req.use_llm
        firewall_instance.block_threshold = req.block_threshold
        firewall_instance.flag_threshold = req.flag_threshold
        return firewall_instance.process_message(req.text.strip()).to_dict()
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/session/reset", response_model=ResetResponse)
def reset_session_endpoint():
    firewall_instance.new_session()
    return {"status": "reset", "session_id": firewall_instance.session_id}


@app.get("/v1/audit/decisions", response_model=list[dict[str, Any]])
def firewall_decisions_endpoint(limit: int = Query(40, ge=1, le=200)):
    return get_firewall_decisions(limit=limit)


@app.get("/v1/audit/actions", response_model=list[dict[str, Any]])
def audit_actions_endpoint(limit: int = Query(40, ge=1, le=200)):
    return get_audit_log(limit=limit)


@app.get("/v1/evaluation/results", response_model=dict[str, Any])
def evaluation_results_endpoint():
    results_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "evaluation",
        "results",
        "evaluation_results.json",
    )
    if not os.path.exists(results_path):
        raise HTTPException(status_code=404, detail="Evaluation results have not been generated.")
    with open(results_path, "r", encoding="utf-8") as results_file:
        return json.load(results_file)
