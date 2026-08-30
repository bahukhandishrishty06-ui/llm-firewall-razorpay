"""Unit tests for Agent Tools and SQLite Database."""
import pytest
from agent.tools import check_order, issue_refund, apply_discount, seed_test_orders
from database import get_order, get_audit_log

@pytest.fixture(autouse=True)
def setup_orders():
    seed_test_orders()

def test_check_order_valid():
    res = check_order("ORD_001")
    assert res["success"] is True
    assert res["order_id"] == "ORD_001"
    assert res["amount"] == 2500.0

def test_check_order_nonexistent():
    res = check_order("NON_EXISTENT_999")
    assert res["success"] is False
    assert "error" in res

def test_issue_refund_simulated():
    res = issue_refund("ORD_001", 500)
    assert res["success"] is True
    assert res["amount"] == 500

def test_apply_discount():
    res = apply_discount("ORD_003", 10)
    assert res["success"] is True
    assert res["percent"] == 10
    assert res["new_amount"] == 1350.0

def test_audit_logging():
    check_order("ORD_001", session_id="test_sess_1")
    logs = get_audit_log(session_id="test_sess_1")
    assert len(logs) > 0
    assert logs[0]["action"] == "check_order"
