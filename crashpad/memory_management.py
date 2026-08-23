"""
CrashPad - Memory & Resource Management (LRU Cache, Object Pooling, Lazy Paginator)
Prevents Out-Of-Memory (OOM) crashes, GC allocation spikes, and heavy RAM bloat.
"""
import threading
from typing import Dict, Any, Optional, Callable, List, Generic, TypeVar, Iterator

T = TypeVar('T')

class _LRUNode:
    __slots__ = ('key', 'value', 'prev', 'next')
    def __init__(self, key: Any, value: Any):
        self.key = key
        self.value = value
        self.prev: Optional['_LRUNode'] = None
        self.next: Optional['_LRUNode'] = None

class LRUCache(Generic[T]):
    """
    Least Recently Used (LRU) Cache:
    O(1) Get and Put operations using Hash Map + Doubly Linked List.
    When capacity is reached, automatically evicts the oldest unaccessed item.
    """
    def __init__(self, capacity: int = 1000):
        if capacity <= 0:
            raise ValueError("Capacity must be > 0")
        self.capacity = capacity
        self._map: Dict[Any, _LRUNode] = {}
        self._head = _LRUNode(None, None) # Dummy head (Most Recently Used)
        self._tail = _LRUNode(None, None) # Dummy tail (Least Recently Used)
        self._head.next = self._tail
        self._tail.prev = self._head
        self._lock = threading.Lock()

    def get(self, key: Any, default: Optional[T] = None) -> Optional[T]:
        with self._lock:
            if key not in self._map:
                return default
            node = self._map[key]
            self._move_to_head(node)
            return node.value

    def put(self, key: Any, value: T) -> None:
        with self._lock:
            if key in self._map:
                node = self._map[key]
                node.value = value
                self._move_to_head(node)
            else:
                if len(self._map) >= self.capacity:
                    self._evict_lru()
                new_node = _LRUNode(key, value)
                self._map[key] = new_node
                self._add_to_head(new_node)

    def size(self) -> int:
        with self._lock:
            return len(self._map)

    def clear(self) -> None:
        with self._lock:
            self._map.clear()
            self._head.next = self._tail
            self._tail.prev = self._head

    def _add_to_head(self, node: _LRUNode):
        node.next = self._head.next
        node.prev = self._head
        self._head.next.prev = node
        self._head.next = node

    def _remove_node(self, node: _LRUNode):
        node.prev.next = node.next
        node.next.prev = node.prev

    def _move_to_head(self, node: _LRUNode):
        self._remove_node(node)
        self._add_to_head(node)

    def _evict_lru(self):
        lru_node = self._tail.prev
        if lru_node != self._head:
            self._remove_node(lru_node)
            self._map.pop(lru_node.key, None)

class ObjectPool(Generic[T]):
    """
    Object Pooling Pattern:
    Recycles pre-allocated objects (e.g. buffers, socket instances, byte arrays)
    to eliminate garbage collector pressure and high CPU churn.
    """
    def __init__(self, factory: Callable[[], T], reset_fn: Optional[Callable[[T], None]] = None, max_size: int = 100):
        self.factory = factory
        self.reset_fn = reset_fn
        self.max_size = max_size
        self._pool: List[T] = []
        self._lock = threading.Lock()

    def acquire(self) -> T:
        with self._lock:
            if self._pool:
                return self._pool.pop()
        return self.factory()

    def release(self, obj: T) -> None:
        if self.reset_fn:
            try:
                self.reset_fn(obj)
            except Exception:
                pass

        with self._lock:
            if len(self._pool) < self.max_size:
                self._pool.append(obj)

    def pool_size(self) -> int:
        with self._lock:
            return len(self._pool)

class LazyPaginator:
    """
    Lazy Loading / Paging:
    Streams data in fixed slices / pages rather than loading thousands of items into RAM.
    """
    def __init__(self, data_source: List[Any], page_size: int = 50):
        self.data_source = data_source
        self.page_size = page_size
        self.total_items = len(data_source)
        self.total_pages = (self.total_items + page_size - 1) // page_size if page_size > 0 else 1

    def get_page(self, page_number: int) -> List[Any]:
        """Returns 1-indexed page of data."""
        if page_number < 1 or page_number > self.total_pages:
            return []
        start_idx = (page_number - 1) * self.page_size
        end_idx = min(start_idx + self.page_size, self.total_items)
        return self.data_source[start_idx:end_idx]

    def iterate_pages(self) -> Iterator[List[Any]]:
        for p in range(1, self.total_pages + 1):
            yield self.get_page(p)
