"""Unit tests for Security Alert Dispatcher."""
import pytest
from firewall.notifications import dispatch_security_alert

def test_dispatch_simulation():
    success = dispatch_security_alert("attack_blocked", {
        "user_input": "Ignore rules",
        "confidence": 0.95,
        "layer": "input_screener"
    })
    assert success is True
