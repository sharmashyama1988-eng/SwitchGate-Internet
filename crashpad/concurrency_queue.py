"""
CrashPad - Data Synchronization & Concurrency (Producer-Consumer Queue, Mutex / Locking)
Eliminates race conditions, thread deadlock freezes, and DB corruption.
"""
import queue
import asyncio
import threading
from typing import Callable, Any, Optional, List, Generic, TypeVar

T = TypeVar('T')

class TaskQueue:
    """Thread-safe FIFO Task Queue with worker thread processing."""
    def __init__(self, max_queue_size: int = 1000):
        self._q: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.is_running = False
        self._worker: Optional[threading.Thread] = None

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="CrashPad-TaskQueue")
        self._worker.start()

    def stop(self):
        self.is_running = False
        self._q.put(None) # Sentinel to unblock

    def submit(self, fn: Callable, *args, **kwargs) -> bool:
        """Pushes work item to the queue. Returns False if queue is full."""
        try:
            self._q.put_nowait((fn, args, kwargs))
            return True
        except queue.Full:
            return False

    def size(self) -> int:
        return self._q.qsize()

    def _worker_loop(self):
        while self.is_running:
            try:
                item = self._q.get(timeout=1.0)
                if item is None:
                    break
                fn, args, kwargs = item
                try:
                    fn(*args, **kwargs)
                except Exception as e:
                    print(f"[CrashPad TaskQueue Error] {e}")
                finally:
                    self._q.task_done()
            except queue.Empty:
                continue

class AsyncProducerConsumerQueue(Generic[T]):
    """
    Async Producer-Consumer Pattern:
    Buffers async events/tasks into an asyncio.Queue, allowing steady sequential consumption
    without spiking system RAM or creating race conditions.
    """
    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._queue: Optional[asyncio.Queue] = None

    def _ensure_queue(self):
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=self.max_size)

    async def produce(self, item: T) -> bool:
        self._ensure_queue()
        try:
            await self._queue.put(item)
            return True
        except Exception:
            return False

    async def consume(self) -> T:
        self._ensure_queue()
        return await self._queue.get()

    def qsize(self) -> int:
        if self._queue is None:
            return 0
        return self._queue.qsize()

class MutexLock:
    """Re-entrant Mutex wrapper for thread-safe critical sections."""
    def __init__(self):
        self._rlock = threading.RLock()

    def __enter__(self):
        self._rlock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._rlock.release()
