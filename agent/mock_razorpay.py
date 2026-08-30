"""Mock Razorpay Client and Test Fixtures.

Provides offline testing capabilities and payment entity generators
mimicking official Razorpay test-mode SDK objects without requiring live network access.
"""
import uuid
import time
from typing import Dict, Any, Optional

class MockRazorpayPayment:
    def __init__(self):
        self.refunds = {}

    def refund(self, payment_id: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        amount = data.get("amount", 1000) if data else 1000
        refund_id = f"rfnd_mock_{uuid.uuid4().hex[:12]}"
        record = {
            "id": refund_id,
            "entity": "refund",
            "amount": amount,
            "currency": "INR",
            "payment_id": payment_id,
            "status": "processed",
            "created_at": int(time.time())
        }
        self.refunds[refund_id] = record
        return record

class MockRazorpayOrder:
    def __init__(self):
        self.orders = {}

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        order_id = f"order_{uuid.uuid4().hex[:14]}"
        record = {
            "id": order_id,
            "entity": "order",
            "amount": data.get("amount", 50000),
            "amount_paid": data.get("amount", 50000),
            "currency": data.get("currency", "INR"),
            "receipt": data.get("receipt", f"rcpt_{uuid.uuid4().hex[:8]}"),
            "status": "paid",
            "created_at": int(time.time())
        }
        self.orders[order_id] = record
        return record

    def fetch(self, order_id: str) -> Dict[str, Any]:
        if order_id in self.orders:
            return self.orders[order_id]
        return {
            "id": order_id,
            "entity": "order",
            "amount": 250000,
            "amount_paid": 250000,
            "currency": "INR",
            "status": "paid",
            "created_at": int(time.time()) - 86400 * 2
        }

    def fetch_payments(self, order_id: str) -> Dict[str, Any]:
        return {
            "entity": "collection",
            "count": 1,
            "items": [
                {
                    "id": f"pay_{uuid.uuid4().hex[:14]}",
                    "entity": "payment",
                    "amount": 250000,
                    "currency": "INR",
                    "status": "captured",
                    "order_id": order_id
                }
            ]
        }

class MockRazorpayClient:
    """Mock client replicating razorpay.Client interface."""
    def __init__(self, auth=None):
        self.order = MockRazorpayOrder()
        self.payment = MockRazorpayPayment()
