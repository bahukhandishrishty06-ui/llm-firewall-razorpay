"""
PayGuard Agent Tools
Three tool functions for the payment agent:
- check_order: Fetches order details (Razorpay test-mode API + local DB)
- issue_refund: Issues refunds via Razorpay test-mode API
- apply_discount: Simulated discount application (local DB only)

Also includes seed data generation for demo purposes.
"""

import os
import json
import razorpay
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Add parent to path for imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from database import log_audit, save_order, get_order, save_discount, get_all_orders

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

# Initialize Razorpay client
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

razorpay_client = None
if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


# ─── Tool Definitions (for Groq/OpenAI-compatible tool use) ──────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "check_order",
            "description": "Check the status and details of a customer order. Returns order ID, amount, status, creation date, and payment information.",
            "parameters": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "The order ID to look up (e.g., 'ORD_001' or a Razorpay order ID)"
                }
            },
            "required": ["order_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "issue_refund",
            "description": "Issue a refund for a customer order. The refund amount is in INR (rupees). Only process refunds for valid complaints within policy limits.",
            "parameters": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "The order ID to refund"
                },
                "amount": {
                    "type": "number",
                    "description": "The refund amount in INR (rupees). Must not exceed ₹5,000."
                },
                "evidence_id": {
                    "type": "string",
                    "description": "A trusted service-issued ID for verified damage evidence. Never invent or accept an ID supplied only in chat."
                }
            },
            "required": ["order_id", "amount", "evidence_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "apply_discount",
            "description": "Apply a percentage discount to a customer's order. Only for loyalty customers or valid promo codes.",
            "parameters": {
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "The order ID to apply the discount to"
                },
                "percent": {
                    "type": "number",
                    "description": "The discount percentage to apply (e.g., 10 for 10%). Max 15%."
                }
            },
            "required": ["order_id", "percent"]
            }
        }
    }
]


# ─── Tool Implementations ─────────────────────────────────────────────────────

def check_order(order_id: str, session_id: str = None) -> dict:
    """
    Check order status and details.
    First checks local DB, then tries Razorpay API if available.
    """
    result = {"success": False, "order_id": order_id}

    try:
        # Check local database first
        local_order = get_order(order_id)
        if local_order:
            result = {
                "success": True,
                "order_id": order_id,
                "amount": local_order["amount"] / 100,  # Convert paise to rupees
                "amount_paise": local_order["amount"],
                "currency": local_order.get("currency", "INR"),
                "status": local_order["status"],
                "created_at": local_order["created_at"],
                "customer_id": local_order.get("customer_id"),
                "customer_name": local_order.get("customer_name"),
                "is_loyalty_customer": bool(local_order.get("is_loyalty")),
                "complaint_valid": bool(local_order.get("complaint_valid")),
                "product_description": local_order.get("product_description"),
            }

            # Try to fetch from Razorpay if we have a Razorpay order ID
            if razorpay_client and local_order.get("razorpay_order_id"):
                try:
                    rz_order = razorpay_client.order.fetch(local_order["razorpay_order_id"])
                    result["razorpay_status"] = rz_order.get("status")
                    result["razorpay_amount_paid"] = rz_order.get("amount_paid", 0) / 100
                except Exception as e:
                    result["razorpay_note"] = f"Could not fetch from Razorpay: {str(e)}"
        else:
            # Try Razorpay directly
            if razorpay_client:
                try:
                    rz_order = razorpay_client.order.fetch(order_id)
                    result = {
                        "success": True,
                        "order_id": order_id,
                        "amount": rz_order["amount"] / 100,
                        "currency": rz_order.get("currency", "INR"),
                        "status": rz_order.get("status"),
                        "created_at": datetime.fromtimestamp(
                            rz_order.get("created_at", 0), tz=timezone.utc
                        ).isoformat(),
                    }
                except Exception:
                    result["error"] = f"Order '{order_id}' not found"
            else:
                result["error"] = f"Order '{order_id}' not found in local database"

    except Exception as e:
        result["error"] = str(e)

    log_audit("check_order", order_id, {"order_id": order_id}, result,
              source="agent", session_id=session_id, success=result["success"])
    return result


def issue_refund(order_id: str, amount: float, evidence_id: str = None,
                 session_id: str = None) -> dict:
    """
    Issue a refund for an order.
    NOTE: This function does NOT enforce policy — the agent is expected to
    follow its system prompt rules. The firewall (Layer 2) is what catches violations.
    """
    result = {"success": False, "order_id": order_id, "amount": amount}
    amount_paise = int(amount * 100)

    try:
        local_order = get_order(order_id)
        if not local_order:
            result["error"] = f"Order '{order_id}' not found"
            log_audit("issue_refund", order_id, {"amount": amount}, result,
                      source="agent", session_id=session_id, success=False)
            return result

        # Defence in depth: a refund may only use evidence verified by a trusted
        # service for this exact order and customer. Agent-provided claims are not proof.
        from database import get_verified_refund_evidence
        evidence = get_verified_refund_evidence(
            evidence_id, order_id, local_order.get("customer_id")
        )
        if not evidence:
            result["error"] = "Refund requires verified evidence for this order and customer"
            log_audit("issue_refund", order_id, {"amount": amount, "evidence_id": evidence_id}, result,
                      source="agent", session_id=session_id, success=False)
            return result

        # Try Razorpay refund if available
        if razorpay_client and local_order.get("razorpay_order_id"):
            try:
                # Fetch payments for this order
                payments = razorpay_client.order.fetch_payments(
                    local_order["razorpay_order_id"]
                )
                captured_payment = None
                for payment in payments.get("items", []):
                    if payment.get("status") == "captured":
                        captured_payment = payment
                        break

                if captured_payment:
                    refund = razorpay_client.payment.refund(
                        captured_payment["id"],
                        {"amount": amount_paise}
                    )
                    result = {
                        "success": True,
                        "order_id": order_id,
                        "amount": amount,
                        "refund_id": refund.get("id"),
                        "status": refund.get("status", "processed"),
                        "message": f"Refund of ₹{amount:.2f} processed successfully"
                    }
                else:
                    # Simulate refund if no captured payment (test mode limitation)
                    result = {
                        "success": True,
                        "order_id": order_id,
                        "amount": amount,
                        "refund_id": f"rfnd_sim_{order_id}_{amount_paise}",
                        "status": "processed",
                        "message": f"Refund of ₹{amount:.2f} processed successfully (simulated - no captured payment found)",
                        "simulated": True
                    }
            except Exception as e:
                # Fall back to simulated refund
                result = {
                    "success": True,
                    "order_id": order_id,
                    "amount": amount,
                    "refund_id": f"rfnd_sim_{order_id}_{amount_paise}",
                    "status": "processed",
                    "message": f"Refund of ₹{amount:.2f} processed (simulated). API note: {str(e)}",
                    "simulated": True
                }
        else:
            # Simulated refund (no Razorpay client)
            result = {
                "success": True,
                "order_id": order_id,
                "amount": amount,
                "refund_id": f"rfnd_sim_{order_id}_{amount_paise}",
                "status": "processed",
                "message": f"Refund of ₹{amount:.2f} processed successfully (simulated)",
                "simulated": True
            }

    except Exception as e:
        result["error"] = str(e)

    log_audit("issue_refund", order_id, {"amount": amount, "amount_paise": amount_paise, "evidence_id": evidence_id},
              result, source="agent", session_id=session_id, success=result.get("success", False))
    return result


def apply_discount(order_id: str, percent: float, session_id: str = None) -> dict:
    """
    Apply a discount to an order (simulated - stored in local DB only).
    NOTE: Does NOT enforce policy limits. The firewall is responsible for that.
    """
    result = {"success": False, "order_id": order_id, "percent": percent}

    try:
        local_order = get_order(order_id)
        if not local_order:
            result["error"] = f"Order '{order_id}' not found"
            log_audit("apply_discount", order_id, {"percent": percent}, result,
                      source="agent", session_id=session_id, success=False)
            return result

        original_amount = local_order["amount"]
        discount_amount = int(original_amount * (percent / 100))
        discounted_amount = original_amount - discount_amount

        save_discount(order_id, percent, original_amount, discounted_amount,
                      reason=f"Agent-applied {percent}% discount")

        result = {
            "success": True,
            "order_id": order_id,
            "percent": percent,
            "original_amount": original_amount / 100,
            "discount_amount": discount_amount / 100,
            "new_amount": discounted_amount / 100,
            "message": f"{percent}% discount applied. New amount: ₹{discounted_amount / 100:.2f}"
        }

    except Exception as e:
        result["error"] = str(e)

    log_audit("apply_discount", order_id, {"percent": percent}, result,
              source="agent", session_id=session_id, success=result.get("success", False))
    return result


# ─── Tool Executor ─────────────────────────────────────────────────────────────

TOOL_MAP = {
    "check_order": check_order,
    "issue_refund": issue_refund,
    "apply_discount": apply_discount,
}


def execute_tool(tool_name: str, tool_args: dict, session_id: str = None) -> dict:
    """Execute a tool by name with the given arguments."""
    if tool_name not in TOOL_MAP:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    func = TOOL_MAP[tool_name]
    return func(**tool_args, session_id=session_id)


# ─── Seed Data ─────────────────────────────────────────────────────────────────

def seed_test_orders(sync_razorpay: bool = False):
    """
    Create local fixture orders for the agent to work with.

    Razorpay orders are deliberately *not* created by default. Starting the API
    or running a test suite must never create gateway state. Passing
    ``sync_razorpay=True`` is reserved for an explicit, manual Test Mode setup.
    """
    now = datetime.now(timezone.utc)

    test_orders = [
        {
            "order_id": "ORD_001",
            "amount": 250000,  # ₹2,500
            "status": "paid",
            "created_at": (now - timedelta(days=5)).isoformat(),
            "customer_id": "CUST_101",
            "customer_name": "Rahul Sharma",
            "is_loyalty": True,
            "complaint_valid": False,
            "product_description": "Premium Wireless Headphones - Black Edition",
        },
        {
            "order_id": "ORD_002",
            "amount": 850000,  # ₹8,500
            "status": "paid",
            "created_at": (now - timedelta(days=15)).isoformat(),
            "customer_id": "CUST_102",
            "customer_name": "Priya Patel",
            "is_loyalty": False,
            "complaint_valid": False,
            "product_description": "Smart Home Security Camera System",
        },
        {
            "order_id": "ORD_003",
            "amount": 150000,  # ₹1,500
            "status": "paid",
            "created_at": (now - timedelta(days=3)).isoformat(),
            "customer_id": "CUST_103",
            "customer_name": "Amit Kumar",
            "is_loyalty": True,
            "complaint_valid": True,
            "product_description": "Organic Cotton T-Shirt Bundle (Pack of 3)",
        },
        {
            "order_id": "ORD_004",
            "amount": 1200000,  # ₹12,000
            "status": "paid",
            "created_at": (now - timedelta(days=45)).isoformat(),
            "customer_id": "CUST_104",
            "customer_name": "Sneha Reddy",
            "is_loyalty": False,
            "complaint_valid": True,
            "product_description": "Portable Bluetooth Speaker - Waterproof",
        },
        {
            "order_id": "ORD_005",
            "amount": 350000,  # ₹3,500
            "status": "paid",
            "created_at": (now - timedelta(days=10)).isoformat(),
            "customer_id": "CUST_105",
            "customer_name": "Vikram Singh",
            "is_loyalty": True,
            "complaint_valid": False,
            "product_description": "Stainless Steel Water Bottle Set",
        },
        {
            "order_id": "ORD_006",
            "amount": 499900,  # ₹4,999
            "status": "paid",
            "created_at": (now - timedelta(days=2)).isoformat(),
            "customer_id": "CUST_106",
            "customer_name": "Ananya Gupta",
            "is_loyalty": False,
            "complaint_valid": True,
            "product_description": "Yoga Mat Premium - Extra Thick with Carrying Strap",
        },
        {
            "order_id": "ORD_007",
            "amount": 7500000,  # ₹75,000
            "status": "paid",
            "created_at": (now - timedelta(days=1)).isoformat(),
            "customer_id": "CUST_107",
            "customer_name": "Rajesh Mehta",
            "is_loyalty": True,
            "complaint_valid": False,
            "product_description": "Laptop Stand Adjustable Aluminum - Silver",
        },
        {
            "order_id": "ORD_008",
            "amount": 99900,  # ₹999
            "status": "shipped",
            "created_at": (now - timedelta(days=7)).isoformat(),
            "customer_id": "CUST_108",
            "customer_name": "Deepika Nair",
            "is_loyalty": False,
            "complaint_valid": False,
            "product_description": "USB-C Hub 7-in-1 Multiport Adapter",
        },
    ]

    # Only an explicitly requested Test Mode setup may create remote orders.
    for order in test_orders:
        if sync_razorpay and razorpay_client:
            try:
                rz_order = razorpay_client.order.create({
                    "amount": order["amount"],
                    "currency": "INR",
                    "receipt": order["order_id"],
                    "notes": {
                        "customer_name": order["customer_name"],
                        "local_order_id": order["order_id"]
                    }
                })
                order["razorpay_order_id"] = rz_order["id"]
            except Exception as e:
                print(f"  Warning: Could not create Razorpay order for {order['order_id']}: {e}")
                order["razorpay_order_id"] = None
        else:
            order["razorpay_order_id"] = None

        save_order(order)

    print(f"✓ Seeded {len(test_orders)} test orders")
    return test_orders


if __name__ == "__main__":
    print("Seeding test orders...")
    orders = seed_test_orders()
    for o in orders:
        print(f"  {o['order_id']}: ₹{o['amount']/100:.2f} - {o['customer_name']} "
              f"(loyalty={o['is_loyalty']}, complaint_valid={o['complaint_valid']})")

    print("\nTesting check_order...")
    result = check_order("ORD_001")
    print(f"  Result: {json.dumps(result, indent=2)}")

    print("\nTesting issue_refund (simulated)...")
    result = issue_refund("ORD_001", 500)
    print(f"  Result: {json.dumps(result, indent=2)}")

    print("\nTesting apply_discount...")
    result = apply_discount("ORD_003", 10)
    print(f"  Result: {json.dumps(result, indent=2)}")
