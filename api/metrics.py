"""Telemetry and Performance Metrics Collector for PayGuard API."""
import time
from collections import defaultdict
from typing import Dict, Any

class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()
        self.request_counts = defaultdict(int)
        self.blocked_counts = defaultdict(int)
        self.latencies = []

    def record_request(self, endpoint: str, is_blocked: bool = False, latency_ms: float = 0.0):
        self.request_counts[endpoint] += 1
        if is_blocked:
            self.blocked_counts[endpoint] += 1
        if latency_ms > 0:
            self.latencies.append(latency_ms)
            if len(self.latencies) > 1000:
                self.latencies.pop(0)

    def get_stats(self) -> Dict[str, Any]:
        uptime = round(time.time() - self.start_time, 1)
        total_reqs = sum(self.request_counts.values())
        total_blocked = sum(self.blocked_counts.values())
        avg_latency = round(sum(self.latencies) / len(self.latencies), 3) if self.latencies else 0.0

        return {
            "uptime_seconds": uptime,
            "total_requests": total_reqs,
            "total_blocked": total_blocked,
            "block_rate": round(total_blocked / total_reqs, 4) if total_reqs > 0 else 0.0,
            "average_latency_ms": avg_latency,
            "requests_by_endpoint": dict(self.request_counts),
        }

metrics_collector = MetricsCollector()
