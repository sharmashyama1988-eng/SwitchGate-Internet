"""
CrashPad - Network & API Resilience (Exponential Backoff, Jitter, Circuit Breaker)
Prevents cascading server crashes, thundering herd floods, and infinite retry loops.
"""
import time
import random
import asyncio
import functools
import threading
from typing import Callable, Any, Optional, Dict, Type, Tuple, List
from enum import Enum

class CircuitState(Enum):
    CLOSED = "CLOSED"       # Normal operation, traffic flows freely
    OPEN = "OPEN"           # Tripped due to failures, requests fail fast immediately
    HALF_OPEN = "HALF_OPEN" # Testing server health with single test requests

class JitterStrategy(Enum):
    NONE = "none"
    FULL = "full"                 # Uniform random between 0 and exponential backoff
    EQUAL = "equal"               # Half deterministic + half random
    DECORRELATED = "decorrelated" # Sleep between base and 3x previous delay

class ExponentialBackoff:
    """Calculates exponential backoff delay with jitter to prevent herd collisions."""
    def __init__(
        self,
        base_delay: float = 0.5,
        max_delay: float = 30.0,
        factor: float = 2.0,
        jitter: JitterStrategy = JitterStrategy.FULL
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.factor = factor
        self.jitter = jitter
        self.prev_delay = base_delay

    def calculate_delay(self, attempt: int) -> float:
        """Returns the calculated sleep duration in seconds for a given retry attempt index (0-based)."""
        temp_delay = min(self.max_delay, self.base_delay * (self.factor ** attempt))
        
        if self.jitter == JitterStrategy.FULL:
            delay = random.uniform(0, temp_delay)
        elif self.jitter == JitterStrategy.EQUAL:
            half = temp_delay / 2.0
            delay = half + random.uniform(0, half)
        elif self.jitter == JitterStrategy.DECORRELATED:
            delay = min(self.max_delay, random.uniform(self.base_delay, self.prev_delay * 3.0))
            self.prev_delay = delay
        else:
            delay = temp_delay

        return round(delay, 4)

class CircuitBreakerOpenException(Exception):
    """Raised when request is blocked because Circuit Breaker is in OPEN state."""
    pass

class CircuitBreaker:
    """
    Circuit Breaker Pattern:
    - CLOSED: Normal execution. Counts consecutive failures.
    - OPEN: If failures >= failure_threshold, trips to OPEN for `cooldown_seconds`.
    - HALF-OPEN: After cooldown, allows `half_open_success_threshold` test calls to verify recovery.
    """
    def __init__(
        self,
        name: str = "DefaultCircuit",
        failure_threshold: int = 5,
        cooldown_seconds: float = 10.0,
        half_open_success_threshold: int = 2,
        expected_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.half_open_success_threshold = half_open_success_threshold
        self.expected_exceptions = expected_exceptions

        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.success_count: int = 0
        self.last_state_change: float = time.time()
        self._lock = threading.Lock()

    def get_state(self) -> CircuitState:
        with self._lock:
            if self.state == CircuitState.OPEN:
                if time.time() - self.last_state_change >= self.cooldown_seconds:
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    self.last_state_change = time.time()
            return self.state

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        """Executes function protected by the circuit breaker."""
        current_state = self.get_state()
        if current_state == CircuitState.OPEN:
            raise CircuitBreakerOpenException(f"Circuit '{self.name}' is OPEN. Requests blocked for cooldown.")

        try:
            result = fn(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as e:
            self._on_failure()
            raise e

    async def call_async(self, coro_fn: Callable, *args, **kwargs) -> Any:
        """Asynchronous execution protected by circuit breaker."""
        current_state = self.get_state()
        if current_state == CircuitState.OPEN:
            raise CircuitBreakerOpenException(f"Circuit '{self.name}' is OPEN. Async requests blocked.")

        try:
            result = await coro_fn(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as e:
            self._on_failure()
            raise e

    def _on_success(self):
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.half_open_success_threshold:
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    self.last_state_change = time.time()
            elif self.state == CircuitState.CLOSED:
                self.failure_count = 0

    def _on_failure(self):
        with self._lock:
            self.failure_count += 1
            if self.state == CircuitState.HALF_OPEN or self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = time.time()

def circuit_breaker(name: str = "Circuit", failure_threshold: int = 5, cooldown_seconds: float = 10.0):
    cb = CircuitBreaker(name=name, failure_threshold=failure_threshold, cooldown_seconds=cooldown_seconds)
    def decorator(fn: Callable):
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                return await cb.call_async(fn, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                return cb.call(fn, *args, **kwargs)
            return sync_wrapper
    return decorator
