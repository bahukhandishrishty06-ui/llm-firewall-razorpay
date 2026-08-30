"""High-Risk Security Alert Dispatcher.

Dispatches security event notifications (Slack, Discord, generic webhook)
when high-confidence prompt injections or unauthorized financial actions are intercepted.
"""
import os
import json
import httpx
from datetime import datetime, timezone

WEBHOOK_URL = os.getenv("PAYGUARD_ALERT_WEBHOOK_URL", "")

def dispatch_security_alert(event_type: str, details: dict) -> bool:
    """
    Dispatch security event payload to configured webhook sink.
    Returns True if dispatched successfully (or simulated if no URL configured).
    """
    payload = {
        "source": "PayGuard LLM Firewall",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "details": details
    }

    if not WEBHOOK_URL:
        # Simulation mode: log to stderr/stdout
        print(f"📢 [SIMULATED ALERT] {event_type.upper()}: {json.dumps(details)}")
        return True

    try:
        with httpx.Client(timeout=3.0) as client:
            response = client.post(WEBHOOK_URL, json=payload)
            return response.status_code in (200, 201, 204)
    except Exception as e:
        print(f"⚠️ Failed to dispatch alert webhook: {e}")
        return False
