"""Unit tests for Metrics Telemetry Endpoint."""
from fastapi.testclient import TestClient
from api.server import app
from api.metrics import metrics_collector

client = TestClient(app)

def test_telemetry_metrics_collector():
    metrics_collector.record_request("/v1/screen/input", is_blocked=True, latency_ms=1.5)
    stats = metrics_collector.get_stats()
    assert stats["total_requests"] >= 1
    assert stats["total_blocked"] >= 1
    assert stats["average_latency_ms"] > 0

def test_telemetry_endpoint():
    res = client.get("/v1/telemetry/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "uptime_seconds" in data
    assert "total_requests" in data
    assert "block_rate" in data
