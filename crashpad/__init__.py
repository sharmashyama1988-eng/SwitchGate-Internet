"""
SwitchGate CrashPad - Enterprise Resiliency & Crash Prevention Suite v2.0
Provides 7 core algorithmic pillars for zero-crash, high-concurrency systems:

1. UI & Input Control: Throttle, Debounce, Single-Task / Single-Flight
2. Network & API Resilience: Exponential Backoff, Jitter, Circuit Breaker
3. Memory & Resource Management: LRU Cache, Object Pooling, Lazy Paginator
4. State & Background Handling: State Restoration Snapshot, Heartbeat Ping
5. Concurrency & Queue: Producer-Consumer FIFO Queue, Mutex / Semaphore
6. Error & Fallback Grace: Global Exception Guardian, Graceful Degradation
7. Security & Rate Limiting: Token Bucket, Leaky Bucket
"""

from .input_control import Throttle, Debounce, SingleTaskRunner, throttle, debounce
from .network_resilience import ExponentialBackoff, JitterStrategy, CircuitBreaker, circuit_breaker
from .memory_management import LRUCache, ObjectPool, LazyPaginator
from .state_management import StateRestorationManager, HeartbeatMonitor
from .concurrency_queue import AsyncProducerConsumerQueue, MutexLock, TaskQueue
from .error_guardian import GlobalExceptionGuardian, GracefulDegradation, safe_fallback
from .rate_limiter import TokenBucketRateLimiter, LeakyBucketRateLimiter

__all__ = [
    "Throttle",
    "Debounce",
    "SingleTaskRunner",
    "throttle",
    "debounce",
    "ExponentialBackoff",
    "JitterStrategy",
    "CircuitBreaker",
    "circuit_breaker",
    "LRUCache",
    "ObjectPool",
    "LazyPaginator",
    "StateRestorationManager",
    "HeartbeatMonitor",
    "AsyncProducerConsumerQueue",
    "MutexLock",
    "TaskQueue",
    "GlobalExceptionGuardian",
    "GracefulDegradation",
    "safe_fallback",
    "TokenBucketRateLimiter",
    "LeakyBucketRateLimiter",
]
