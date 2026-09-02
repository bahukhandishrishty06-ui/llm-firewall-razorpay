"""Tests for the PayGuard benchmark runner."""
from scripts.benchmark_firewall import run_benchmark


def test_benchmark_runner_executes_and_returns_valid_metrics():
    results = run_benchmark(iterations=5)
    assert "input_screening" in results
    assert "action_screening" in results
    assert "detection" in results

    inp = results["input_screening"]
    act = results["action_screening"]
    det = results["detection"]

    assert inp["total_calls"] == 5 * 8
    assert act["total_calls"] == 5 * 5
    assert inp["p50_ms"] >= 0
    assert act["p50_ms"] >= 0
    assert inp["throughput_qps"] > 0
    assert act["throughput_qps"] > 0
    assert 0.0 <= det["attack_block_rate"] <= 1.0
    assert 0.0 <= det["benign_pass_rate"] <= 1.0
