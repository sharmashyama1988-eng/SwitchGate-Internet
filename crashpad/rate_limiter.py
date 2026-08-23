"""
CrashPad - Security & Rate Limiting (Token Bucket, Leaky Bucket)
Protects internal databases, hardware adapters, and endpoints from request spam flooding.
"""
import time
import threading
from typing import Dict, Any, Optional

class TokenBucketRateLimiter:
    """
    Token Bucket Algorithm:
    - Maintains a bucket with maximum `capacity` tokens.
    - Refills at `refill_rate` tokens per second.
    - Allows short bursts up to `capacity`, but limits sustained request rates.
    """
    def __init__(self, capacity: float = 10.0, refill_rate: float = 2.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = threading.Lock()

    def acquire(self, tokens_required: float = 1.0) -> bool:
        """Attempts to consume tokens. Returns True if granted, False if rate-limited."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now

            # Refill tokens
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))

            if self.tokens >= tokens_required:
                self.tokens -= tokens_required
                return True
            return False

class LeakyBucketRateLimiter:
    """
    Leaky Bucket Algorithm:
    - Empties/leaks water at a strict, constant `leak_rate` per second.
    - If total water exceeds `capacity`, new incoming drops overflow and are rejected.
    - Enforces a steady, smooth outbound flow to downstream databases.
    """
    def __init__(self, capacity: float = 20.0, leak_rate: float = 5.0):
        self.capacity = capacity
        self.leak_rate = leak_rate
        self.water = 0.0
        self.last_leak = time.time()
        self._lock = threading.Lock()

    def add_drop(self, amount: float = 1.0) -> bool:
        """Attempts to add request drops into the bucket. Returns True if accepted, False if overflow."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_leak
            self.last_leak = now

            # Leak water
            self.water = max(0.0, self.water - (elapsed * self.leak_rate))

            if self.water + amount <= self.capacity:
                self.water += amount
                return True
            return False
