"""Unit tests for Layer 2 Action Screener Policy and Anomaly Engine."""
import pytest
from firewall.action_screener import screen_action, check_policy_rules, check_anomalies, reset_session
from agent.tools import seed_test_orders
from database import record_verified_refund_evidence

@pytest.fixture(autouse=True)
def setup_data():
    seed_test_orders()
    reset_session("test_sess_action")

def test_refund_without_proof_is_blocked():
    res = screen_action("issue_refund", {"order_id": "ORD_001", "amount": 2500}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "block"
    assert any("verified evidence" in v for v in res.policy_violations)
    assert any("authenticated customer" in v for v in res.policy_violations)


def test_refund_with_verified_evidence_and_identity_is_allowed():
    record_verified_refund_evidence("EV-TEST-ORD-003", "ORD_003", "CUST_103", "test-reviewer")
    res = screen_action(
        "issue_refund",
        {"order_id": "ORD_003", "amount": 500, "evidence_id": "EV-TEST-ORD-003"},
        session_id="test_sess_action",
        use_llm=False,
        authenticated_customer_id="CUST_103",
    )
    assert res.verdict == "allow"
    assert len(res.policy_violations) == 0

def test_refund_exceeds_max_limit():
    res = screen_action("issue_refund", {"order_id": "ORD_001", "amount": 50000}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "block"
    assert any("exceeds maximum limit" in v for v in res.policy_violations)

def test_refund_exceeds_30_days():
    # ORD_004 is 45 days old
    res = screen_action("issue_refund", {"order_id": "ORD_004", "amount": 1000}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "block"
    assert any("exceeds 30-day" in v for v in res.policy_violations)

def test_discount_within_policy():
    # ORD_001 is loyalty
    res = screen_action("apply_discount", {"order_id": "ORD_001", "percent": 15}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "allow"

def test_discount_exceeds_max_percent():
    res = screen_action("apply_discount", {"order_id": "ORD_001", "percent": 50}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "block"
    assert any("exceeds maximum limit" in v for v in res.policy_violations)

def test_discount_non_loyalty():
    # ORD_002 is not loyalty
    res = screen_action("apply_discount", {"order_id": "ORD_002", "percent": 10}, session_id="test_sess_action", use_llm=False)
    assert res.verdict in ("block", "flag_for_human")
    assert any("not a loyalty member" in v for v in res.policy_violations)

def test_negative_refund_amount_blocked():
    res = screen_action("issue_refund", {"order_id": "ORD_001", "amount": -500}, session_id="test_sess_action", use_llm=False)
    assert res.verdict == "block"
    assert any("Negative refund" in v for v in res.policy_violations)

def test_anomaly_multiple_refunds_velocity():
    screen_action("issue_refund", {"order_id": "ORD_001", "amount": 500}, session_id="velocity_sess", use_llm=False)
    screen_action("issue_refund", {"order_id": "ORD_003", "amount": 500}, session_id="velocity_sess", use_llm=False)
    res = screen_action("issue_refund", {"order_id": "ORD_005", "amount": 500}, session_id="velocity_sess", use_llm=False)
    assert any("Multiple refunds in session" in v for v in res.policy_violations)
