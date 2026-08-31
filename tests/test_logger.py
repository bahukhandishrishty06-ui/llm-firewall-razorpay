"""Unit tests for Structured JSON Logging."""
import logging
import json
from firewall.logger import JSONFormatter, generate_trace_id, get_security_logger

def test_generate_trace_id():
    tid = generate_trace_id()
    assert tid.startswith("trc_")
    assert len(tid) == 16

def test_json_formatter():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.WARNING,
        pathname="test.py",
        lineno=10,
        msg="Test warning message",
        args=(),
        exc_info=None
    )
    record.trace_id = "trc_12345"
    record.event_type = "injection_attempt"
    record.extra_data = {"score": 0.95}

    formatted = formatter.format(record)
    data = json.loads(formatted)
    assert data["level"] == "WARNING"
    assert data["message"] == "Test warning message"
    assert data["trace_id"] == "trc_12345"
    assert data["event_type"] == "injection_attempt"
    assert data["score"] == 0.95
