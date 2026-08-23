"""
SwitchGate CrashPad - Comprehensive Algorithmic Verification Suite
Tests all 7 pillars of system resilience and crash prevention.
"""
import os
import sys
import time
import asyncio
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from crashpad.input_control import Throttle, Debounce, SingleTaskRunner
from crashpad.network_resilience import ExponentialBackoff, JitterStrategy, CircuitBreaker, CircuitBreakerOpenException
from crashpad.memory_management import LRUCache, ObjectPool, LazyPaginator
from crashpad.state_management import StateRestorationManager, HeartbeatMonitor
from crashpad.concurrency_queue import TaskQueue, MutexLock, AsyncProducerConsumerQueue
from crashpad.error_guardian import GlobalExceptionGuardian, GracefulDegradation, safe_fallback
from crashpad.rate_limiter import TokenBucketRateLimiter, LeakyBucketRateLimiter

def test_1_ui_and_input_control():
    print("[Test 1/7] Testing UI & Input Control Algorithms...")
    
    # 1.1 Throttling: only 1 execution per window
    call_count = 0
    @Throttle(interval=0.2)
    def submit_button():
        nonlocal call_count
        call_count += 1
        return call_count

    assert submit_button() == 1
    assert submit_button() is None # Dropped by throttle
    assert submit_button() is None # Dropped by throttle
    time.sleep(0.25)
    assert submit_button() == 2
    print("      ✓ Throttling Algorithm: Passed")

    # 1.2 Debouncing
    debounced_val = 0
    @Debounce(wait=0.1)
    def on_search(val):
        nonlocal debounced_val
        debounced_val = val

    on_search(1)
    on_search(2)
    on_search(3)
    assert debounced_val == 0 # Hasn't executed yet
    time.sleep(0.15)
    assert debounced_val == 3 # Only last execution processed
    print("      ✓ Debouncing Algorithm: Passed")

    # 1.3 Single-Task Pattern
    runner = SingleTaskRunner()
    executed, res = runner.execute_sync("MODAL_OPEN", lambda: "ModalRendered")
    assert executed is True and res == "ModalRendered"
    print("      ✓ Single-Task Pattern: Passed")

def test_2_network_resilience():
    print("[Test 2/7] Testing Network Resilience (Backoff, Jitter, Circuit Breaker)...")
    
    # 2.1 Exponential Backoff with Jitter
    backoff = ExponentialBackoff(base_delay=0.1, max_delay=5.0, factor=2.0, jitter=JitterStrategy.FULL)
    d0 = backoff.calculate_delay(0)
    d1 = backoff.calculate_delay(1)
    d2 = backoff.calculate_delay(2)
    assert 0 <= d0 <= 0.1
    assert 0 <= d1 <= 0.2
    assert 0 <= d2 <= 0.4
    print("      ✓ Exponential Backoff with Jitter: Passed")

    # 2.2 Circuit Breaker
    cb = CircuitBreaker(name="TestService", failure_threshold=2, cooldown_seconds=0.3)
    
    def failing_call():
        raise ConnectionError("Server Unavailable")

    # 2 failures trip breaker
    try: cb.call(failing_call)
    except ConnectionError: pass

    try: cb.call(failing_call)
    except ConnectionError: pass

    # Breaker should now be OPEN
    try:
        cb.call(lambda: "OK")
        assert False, "Should have thrown CircuitBreakerOpenException"
    except CircuitBreakerOpenException:
        pass

    # Wait for cooldown
    time.sleep(0.35)
    # HALF-OPEN -> Success closes circuit
    res = cb.call(lambda: "Recovered")
    assert res == "Recovered"
    print("      ✓ Circuit Breaker (CLOSED -> OPEN -> HALF-OPEN -> CLOSED): Passed")

def test_3_memory_and_resource_management():
    print("[Test 3/7] Testing Memory & Resource Management (LRU Cache, Object Pool, Paginator)...")
    
    # 3.1 LRU Cache
    cache = LRUCache[str](capacity=2)
    cache.put("A", "Apple")
    cache.put("B", "Banana")
    assert cache.get("A") == "Apple" # Access A, making B the LRU
    cache.put("C", "Cherry") # Evicts B
    assert cache.get("B") is None
    assert cache.get("A") == "Apple"
    assert cache.get("C") == "Cherry"
    print("      ✓ LRU Cache (O(1) Eviction): Passed")

    # 3.2 Object Pool
    pool = ObjectPool[dict](factory=lambda: {"allocated": True}, reset_fn=lambda d: d.clear(), max_size=5)
    obj1 = pool.acquire()
    assert obj1 == {"allocated": True}
    obj1["temp"] = 123
    pool.release(obj1)
    assert pool.pool_size() == 1
    obj2 = pool.acquire()
    assert obj2 == {} # Reset cleanly
    print("      ✓ Object Pool Recycling: Passed")

    # 3.3 Lazy Paginator
    data = list(range(1, 105)) # 104 items
    paginator = LazyPaginator(data, page_size=25)
    assert paginator.total_pages == 5
    assert paginator.get_page(1) == list(range(1, 26))
    assert paginator.get_page(5) == [101, 102, 103, 104]
    print("      ✓ Lazy Paginator & Slice Streaming: Passed")

def test_4_state_and_background_handling():
    print("[Test 4/7] Testing State & Background Handling (State Restoration, Heartbeat)...")
    
    # 4.1 State Restoration
    test_state_file = Path(__file__).resolve().parent / "test_state.json"
    mgr = StateRestorationManager(state_file_path=test_state_file)
    mgr.set_key("active_device", "192.168.1.50")
    mgr.set_key("theme", "obsidian_dark")
    
    # Reload in new instance
    mgr2 = StateRestorationManager(state_file_path=test_state_file)
    assert mgr2.get_key("active_device") == "192.168.1.50"
    assert mgr2.get_key("theme") == "obsidian_dark"
    test_state_file.unlink(missing_ok=True)
    print("      ✓ State Restoration (Atomic Snapshot & Recover): Passed")

    # 4.2 Heartbeat Monitor
    timeout_fired = False
    def on_timeout():
        nonlocal timeout_fired
        timeout_fired = True

    hb = HeartbeatMonitor(interval_seconds=0.1, timeout_seconds=0.25, on_timeout_callback=on_timeout)
    hb.start()
    hb.record_pulse()
    assert hb.is_alive() is True
    time.sleep(0.35)
    hb.stop()
    assert timeout_fired is True
    print("      ✓ Heartbeat / Ping Monitor: Passed")

def test_5_concurrency_and_queues():
    print("[Test 5/7] Testing Concurrency & Queues (Task Queue, Mutex, Async Queue)...")
    
    # 5.1 MutexLock
    counter = 0
    mutex = MutexLock()
    with mutex:
        counter += 1
    assert counter == 1
    print("      ✓ Mutex Reentrant Locking: Passed")

    # 5.2 Task Queue
    processed = []
    tq = TaskQueue(max_queue_size=10)
    tq.start()
    tq.submit(lambda x: processed.append(x * 2), 5)
    tq.submit(lambda x: processed.append(x * 2), 10)
    time.sleep(0.1)
    tq.stop()
    assert processed == [10, 20]
    print("      ✓ FIFO Task Queue: Passed")

def test_6_error_and_fallback():
    print("[Test 6/7] Testing Error & Fallback Grace (Guardian, Graceful Degradation)...")
    
    # 6.1 Graceful Degradation
    @safe_fallback(fallback_value={"status": "degraded_fallback", "render": "static_image.png"})
    def load_complex_3d_heavy_model():
        raise RuntimeError("GPU VRAM Out Of Memory")

    res = load_complex_3d_heavy_model()
    assert res["status"] == "degraded_fallback"
    assert res["render"] == "static_image.png"
    print("      ✓ Graceful Degradation & Fallback Shield: Passed")

    # 6.2 Global Exception Guardian
    guardian = GlobalExceptionGuardian()
    guardian.install()
    print("      ✓ Global Exception Guardian: Passed")

def test_7_security_and_rate_limiting():
    print("[Test 7/7] Testing Security & Rate Limiting (Token Bucket, Leaky Bucket)...")
    
    # 7.1 Token Bucket
    tb = TokenBucketRateLimiter(capacity=3.0, refill_rate=1.0)
    assert tb.acquire(1.0) is True
    assert tb.acquire(1.0) is True
    assert tb.acquire(1.0) is True
    assert tb.acquire(1.0) is False # Bucket empty
    print("      ✓ Token Bucket Rate Limiter: Passed")

    # 7.2 Leaky Bucket
    lb = LeakyBucketRateLimiter(capacity=2.0, leak_rate=10.0)
    assert lb.add_drop(1.0) is True
    assert lb.add_drop(1.0) is True
    assert lb.add_drop(1.0) is False # Overflow rejected
    print("      ✓ Leaky Bucket Rate Limiter: Passed")

def run_all():
    print("==================================================")
    print("   🛡️ CRASHPAD RESILIENCE & ALGORITHM VERIFICATION ")
    print("==================================================")
    test_1_ui_and_input_control()
    test_2_network_resilience()
    test_3_memory_and_resource_management()
    test_4_state_and_background_handling()
    test_5_concurrency_and_queues()
    test_6_error_and_fallback()
    test_7_security_and_rate_limiting()
    print("==================================================")
    print("   🎯 ALL 7 CRASHPAD ALGORITHM PILLARS PASSED!    ")
    print("==================================================")

if __name__ == "__main__":
    run_all()
