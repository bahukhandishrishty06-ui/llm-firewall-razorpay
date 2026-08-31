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
