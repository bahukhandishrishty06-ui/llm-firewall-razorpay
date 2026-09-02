"""
PayGuard Database Module
Handles SQLite database initialization and operations for audit logging,
order tracking, and firewall decision storage.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "payguard.db")


def get_db_path():
    """Get the database path, creating the directory if needed."""
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)
    return DB_PATH


@contextmanager
def get_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize the database schema."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                razorpay_order_id TEXT,
                amount INTEGER,
                currency TEXT DEFAULT 'INR',
                status TEXT DEFAULT 'created',
                created_at TEXT,
                customer_id TEXT,
                customer_name TEXT,
                is_loyalty BOOLEAN DEFAULT 0,
                complaint_valid BOOLEAN DEFAULT 0,
                product_description TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                action TEXT NOT NULL,
                order_id TEXT,
                parameters TEXT,
                result TEXT,
                source TEXT,
                success BOOLEAN DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS firewall_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                input_text TEXT,
                input_type TEXT,
                layer TEXT,
                verdict TEXT NOT NULL,
                confidence REAL,
                reason TEXT,
                details TEXT,
                tool_call TEXT,
                tool_args TEXT
            );

            CREATE TABLE IF NOT EXISTS discounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT,
                percent REAL,
                original_amount INTEGER,
                discounted_amount INTEGER,
                applied_at TEXT,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS verified_refund_evidence (
                evidence_id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                customer_id TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                verified_by TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('verified', 'rejected'))
            );

            CREATE TABLE IF NOT EXISTS payment_sessions (
                local_order_id TEXT PRIMARY KEY,
                razorpay_order_id TEXT NOT NULL UNIQUE,
                razorpay_payment_id TEXT UNIQUE,
                amount_paise INTEGER NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('created', 'captured', 'failed')),
                created_at TEXT NOT NULL,
                verified_at TEXT
            );

            CREATE TABLE IF NOT EXISTS refund_requests (
                request_id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                customer_id TEXT NOT NULL,
                razorpay_payment_id TEXT NOT NULL,
                amount_paise INTEGER NOT NULL,
                evidence_summary TEXT NOT NULL,
                evidence_id TEXT,
                status TEXT NOT NULL CHECK (status IN ('pending_review', 'approved', 'rejected', 'executing', 'gateway_error', 'executed')),
                reviewer TEXT,
                review_note TEXT,
                idempotency_key TEXT NOT NULL UNIQUE,
                razorpay_refund_id TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                executed_at TEXT
            );
        """)


def log_audit(action: str, order_id: str = None, parameters: dict = None,
              result: dict = None, source: str = "agent", session_id: str = None,
              success: bool = True):
    """Log an action to the audit trail."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO audit_log (timestamp, session_id, action, order_id, parameters, result, source, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                session_id,
                action,
                order_id,
                json.dumps(parameters) if parameters else None,
                json.dumps(result) if result else None,
                source,
                success,
            )
        )


def log_firewall_decision(session_id: str, input_text: str, input_type: str,
                          layer: str, verdict: str, confidence: float,
                          reason: str, details: dict = None,
                          tool_call: str = None, tool_args: dict = None):
    """Log a firewall decision."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO firewall_decisions
               (timestamp, session_id, input_text, input_type, layer, verdict, confidence, reason, details, tool_call, tool_args)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                session_id,
                input_text,
                input_type,
                layer,
                verdict,
                confidence,
                reason,
                json.dumps(details) if details else None,
                tool_call,
                json.dumps(tool_args) if tool_args else None,
            )
        )


def get_order(order_id: str) -> dict | None:
    """Fetch an order from the local database."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
        if row:
            return dict(row)
    return None


def record_verified_refund_evidence(evidence_id: str, order_id: str,
                                    customer_id: str, verified_by: str) -> None:
    """Record evidence accepted by a trusted, out-of-band verification service.

    This function is deliberately not exposed as an agent tool or public API. A
    customer message must never be able to mark its own refund evidence verified.
    """
    with get_connection() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO verified_refund_evidence
               (evidence_id, order_id, customer_id, verified_at, verified_by, status)
               VALUES (?, ?, ?, ?, ?, 'verified')""",
            (evidence_id, order_id, customer_id,
             datetime.now(timezone.utc).isoformat(), verified_by),
        )


def get_verified_refund_evidence(evidence_id: str, order_id: str,
                                 customer_id: str) -> dict | None:
    """Return verified evidence only when it belongs to this order and customer."""
    if not evidence_id or not customer_id:
        return None
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM verified_refund_evidence
               WHERE evidence_id = ? AND order_id = ? AND customer_id = ?
                 AND status = 'verified'""",
            (evidence_id, order_id, customer_id),
        ).fetchone()
        return dict(row) if row else None


def create_payment_session(local_order_id: str, razorpay_order_id: str,
                           amount_paise: int) -> dict:
    """Persist a server-created Razorpay Test Mode order before Checkout opens."""
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO payment_sessions
               (local_order_id, razorpay_order_id, amount_paise, status, created_at)
               VALUES (?, ?, ?, 'created', ?)""",
            (local_order_id, razorpay_order_id, amount_paise, now),
        )
    return get_payment_session(local_order_id)


def get_payment_session(local_order_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM payment_sessions WHERE local_order_id = ?", (local_order_id,)
        ).fetchone()
        return dict(row) if row else None


def mark_payment_captured(local_order_id: str, razorpay_payment_id: str) -> dict:
    with get_connection() as conn:
        conn.execute(
            """UPDATE payment_sessions
               SET razorpay_payment_id = ?, status = 'captured', verified_at = ?
               WHERE local_order_id = ?""",
            (razorpay_payment_id, datetime.now(timezone.utc).isoformat(), local_order_id),
        )
    return get_payment_session(local_order_id)


def create_refund_request(request_id: str, order_id: str, customer_id: str,
                          razorpay_payment_id: str, amount_paise: int,
                          evidence_summary: str, idempotency_key: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO refund_requests
               (request_id, order_id, customer_id, razorpay_payment_id, amount_paise,
                evidence_summary, status, idempotency_key, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'pending_review', ?, ?)""",
            (request_id, order_id, customer_id, razorpay_payment_id, amount_paise,
             evidence_summary, idempotency_key, now),
        )
    return get_refund_request(request_id)


def get_refund_request(request_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM refund_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return dict(row) if row else None


def review_refund_request(request_id: str, approved: bool, reviewer: str,
                          review_note: str, evidence_id: str = None) -> dict | None:
    """Apply a demo reviewer decision; production should require real staff auth."""
    status = "approved" if approved else "rejected"
    with get_connection() as conn:
        updated = conn.execute(
            """UPDATE refund_requests
               SET status = ?, reviewer = ?, review_note = ?, evidence_id = ?, reviewed_at = ?
               WHERE request_id = ? AND status = 'pending_review'""",
            (status, reviewer, review_note, evidence_id,
             datetime.now(timezone.utc).isoformat(), request_id),
        ).rowcount
    return get_refund_request(request_id) if updated else None


def claim_refund_execution(request_id: str) -> dict | None:
    """Atomically claim an approved request before it can reach the gateway."""
    with get_connection() as conn:
        updated = conn.execute(
            """UPDATE refund_requests SET status = 'executing'
               WHERE request_id = ? AND status IN ('approved', 'gateway_error')""",
            (request_id,),
        ).rowcount
    return get_refund_request(request_id) if updated else None


def mark_refund_executed(request_id: str, razorpay_refund_id: str) -> dict:
    with get_connection() as conn:
        conn.execute(
            """UPDATE refund_requests
               SET status = 'executed', razorpay_refund_id = ?, executed_at = ?
               WHERE request_id = ?""",
            (razorpay_refund_id, datetime.now(timezone.utc).isoformat(), request_id),
        )
    return get_refund_request(request_id)


def mark_refund_gateway_error(request_id: str) -> dict:
    with get_connection() as conn:
        conn.execute(
            "UPDATE refund_requests SET status = 'gateway_error' WHERE request_id = ?",
            (request_id,),
        )
    return get_refund_request(request_id)


def mark_order_complaint_valid(order_id: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE orders SET complaint_valid = 1 WHERE order_id = ?", (order_id,))


def get_executed_refund_total(payment_id: str) -> int:
    with get_connection() as conn:
        row = conn.execute(
            """SELECT COALESCE(SUM(amount_paise), 0) AS total FROM refund_requests
               WHERE razorpay_payment_id = ? AND status = 'executed'""",
            (payment_id,),
        ).fetchone()
        return int(row["total"])


def get_reserved_refund_total(payment_id: str) -> int:
    """Return value already committed to non-rejected refund requests.

    This prevents two requests for the same captured payment from each passing a
    check that considers only completed refunds.
    """
    with get_connection() as conn:
        row = conn.execute(
            """SELECT COALESCE(SUM(amount_paise), 0) AS total FROM refund_requests
               WHERE razorpay_payment_id = ?
                 AND status IN ('pending_review', 'approved', 'executing', 'gateway_error', 'executed')""",
            (payment_id,),
        ).fetchone()
        return int(row["total"])


def get_all_orders() -> list[dict]:
    """Fetch all orders from the local database."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]


def save_order(order_data: dict):
    """Save or update an order in the local database."""
    with get_connection() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO orders
               (order_id, razorpay_order_id, amount, currency, status, created_at,
                customer_id, customer_name, is_loyalty, complaint_valid, product_description, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                order_data.get("order_id"),
                order_data.get("razorpay_order_id"),
                order_data.get("amount"),
                order_data.get("currency", "INR"),
                order_data.get("status", "created"),
                order_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                order_data.get("customer_id"),
                order_data.get("customer_name"),
                order_data.get("is_loyalty", False),
                order_data.get("complaint_valid", False),
                order_data.get("product_description"),
                order_data.get("notes"),
            )
        )


def save_discount(order_id: str, percent: float, original_amount: int,
                   discounted_amount: int, reason: str = None):
    """Log a discount application."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO discounts (order_id, percent, original_amount, discounted_amount, applied_at, reason)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (order_id, percent, original_amount, discounted_amount,
             datetime.now(timezone.utc).isoformat(), reason)
        )


def get_firewall_decisions(session_id: str = None, limit: int = 100) -> list[dict]:
    """Fetch firewall decisions, optionally filtered by session."""
    with get_connection() as conn:
        if session_id:
            rows = conn.execute(
                "SELECT * FROM firewall_decisions WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                (session_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM firewall_decisions ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(row) for row in rows]


def get_audit_log(session_id: str = None, limit: int = 100) -> list[dict]:
    """Fetch audit log entries."""
    with get_connection() as conn:
        if session_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                (session_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(row) for row in rows]


# Initialize on import
init_db()
