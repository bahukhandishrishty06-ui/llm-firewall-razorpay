"""Unit tests for Sliding Window Rate Limiter."""
import pytest
import time
from firewall.rate_limiter import SlidingWindowRateLimiter

def test_rate_limiter_allows_under_limit():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=2.0)
    allowed, rem, _ = limiter.is_allowed("user_1")
    assert allowed is True
    assert rem == 2

def test_rate_limiter_blocks_over_limit():
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=2.0)
    limiter.is_allowed("user_2")
    limiter.is_allowed("user_2")
    allowed, rem, retry = limiter.is_allowed("user_2")
    assert allowed is False
    assert rem == 0
    assert retry > 0

def test_rate_limiter_resets():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=1.0)
    limiter.is_allowed("user_3")
    limiter.reset("user_3")
    allowed, _, _ = limiter.is_allowed("user_3")
    assert allowed is True
