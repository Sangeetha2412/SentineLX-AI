"""
SentinelX - Input validation & simple in-memory rate limiting.
"""

import re
import time
from collections import defaultdict, deque

EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def is_strong_enough_for_signup(password: str) -> bool:
    """Minimum bar to create an account (separate from the strength analyzer)."""
    return bool(password) and len(password) >= 8


def sanitize_target(value: str) -> str:
    """Strip dangerous characters from a hostname/domain/URL input."""
    if not value:
        return ""
    value = value.strip()
    value = re.sub(r"[;&|`$<>]", "", value)
    return value[:255]


class RateLimiter:
    """Very small in-memory sliding-window rate limiter, keyed by identifier."""

    def __init__(self, max_calls: int = 30, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_calls:
            return False
        q.append(now)
        return True


global_rate_limiter = RateLimiter(max_calls=30, window_seconds=60)
