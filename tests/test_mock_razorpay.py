"""Unit tests for Mock Razorpay Client Fixture."""
import pytest
from agent.mock_razorpay import MockRazorpayClient

def test_mock_razorpay_order_flow():
    client = MockRazorpayClient()
    order = client.order.create({"amount": 10000, "currency": "INR"})
    assert order["id"].startswith("order_")
    assert order["amount"] == 10000

    fetched = client.order.fetch(order["id"])
    assert fetched["id"] == order["id"]

    payments = client.order.fetch_payments(order["id"])
    assert len(payments["items"]) > 0

    pay_id = payments["items"][0]["id"]
    refund = client.payment.refund(pay_id, {"amount": 5000})
    assert refund["status"] == "processed"
    assert refund["amount"] == 5000
