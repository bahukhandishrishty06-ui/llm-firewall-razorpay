"""Structured JSON Logging Framework for PayGuard.

Provides JSON-formatted audit logs with correlation IDs, latency tracking,
and security event metadata for enterprise compliance and SIEM integration.
"""
import logging
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "trace_id"):
            log_obj["trace_id"] = record.trace_id
        if hasattr(record, "event_type"):
            log_obj["event_type"] = record.event_type
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_obj.update(record.extra_data)
        return json.dumps(log_obj)

def get_security_logger(name: str = "payguard.security") -> logging.Logger:
    """Returns a configured structured security logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

def generate_trace_id() -> str:
    """Generates a unique 16-character trace identifier."""
    return f"trc_{uuid.uuid4().hex[:12]}"

security_logger = get_security_logger()
