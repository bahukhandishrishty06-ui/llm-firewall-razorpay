"""In-Memory Sliding Window Rate Limiter for PayGuard.

Throttles abuse attempts, brute-force injection probes, and multi-turn manipulation
by tracking request velocities per session / customer identifier.
"""
import time
from collections import defaultdict, deque
from typing import Tuple

class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 15, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)

    def is_allowed(self, identifier: str) -> Tuple[bool, int, float]:
        """
        Check if an identifier has exceeded the request threshold.
        Returns:
            (allowed: bool, remaining_requests: int, reset_after_seconds: float)
        """
        now = time.time()
        window_start = now - self.window_seconds
        queue = self.history[identifier]

        # Evict timestamps outside sliding window
        while queue and queue[0] < window_start:
            queue.popleft()

        if len(queue) >= self.max_requests:
            oldest = queue[0]
            retry_after = round(self.window_seconds - (now - oldest), 1)
            return False, 0, max(0.1, retry_after)

        queue.append(now)
        remaining = self.max_requests - len(queue)
        return True, remaining, 0.0

    def reset(self, identifier: str = None):
        if identifier:
            if identifier in self.history:
                del self.history[identifier]
        else:
            self.history.clear()

global_rate_limiter = SlidingWindowRateLimiter(max_requests=20, window_seconds=60.0)
