#!/usr/bin/env python3
"""
RedVector AI - Cache, Process-Pool, Resource-Monitoring and Telemetry Primitives

This module is RedVector's own implementation of the caching and process-
management building blocks used by ``redvector_server.py``. It replaces the
single-purpose "AdvancedCache" / "ProcessPool" / "EnhancedProcessManager" /
"ResourceMonitor" / "PerformanceDashboard" classes that server module used to
define inline with a small set of independently-testable, composable pieces:

- ``TTLCache``            bounded, thread-safe key/value cache with TTL expiry
- ``ManagedProcessPool``  on-demand bounded-concurrency async task execution
- ``ProcessRegistry``     a tracked table of external OS processes
                          (start/pause/resume/terminate/cleanup)
- ``SystemResourceMonitor`` CPU/memory/disk/network sampling, nothing else
- ``PerformanceTelemetry``  execution/timing/error metric aggregation

Design goals (see the RedVector Independence Remediation Plan, Phase 1 item 7):
  * composition over monolithic "manager" classes - each class here has one
    job and knows nothing about the others.
  * no persistent "sleep-and-poll" background threads. Expiry is swept lazily
    on access, resource usage is sampled on demand, and task execution is
    gated by a counting bound rather than a fixed pool of idle worker threads
    pulling off a shared queue.
  * every class is plain Python (stdlib + psutil only) and can be constructed
    and unit-tested in isolation, with no Flask/app/global state involved.

``redvector_server.py`` adapts its existing public class names
(``AdvancedCache``, ``RedVectorCache``, ``ProcessPool``, ``ProcessManager``,
``ResourceMonitor``, ``PerformanceDashboard``, ``PerformanceMonitor``,
``EnhancedProcessManager``) onto these primitives via thin compatibility
wrappers so every existing caller, route and test keeps working unchanged.
"""

from __future__ import annotations

import heapq
import itertools
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard runtime dependency
    psutil = None


# ============================================================================
# TTLCache
# ============================================================================

@dataclass
class CacheCounters:
    """Plain counters for a TTLCache instance; no behavior of its own."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
        }


class TTLCache:
    """
    Bounded, thread-safe cache with per-entry expiry.

    Unlike a cache that scans every entry on a timer to find expired ones,
    this cache tracks expirations with a min-heap keyed by expiry time and
    only pays for cleanup when ``get``/``set``/``stats`` are actually called
    ("lazy sweeping"). Capacity eviction is independent of TTL eviction and
    uses plain insertion order (oldest entry first).

    Thread-safe: every public method holds a single internal lock for the
    duration of its work.
    """

    _MISSING = object()

    def __init__(self, capacity: int = 1000, default_ttl_seconds: float = 3600.0):
        if capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds must be positive")

        self.capacity = capacity
        self.default_ttl_seconds = default_ttl_seconds

        # key -> (value, expires_at, generation)
        self._entries: Dict[Any, tuple] = {}
        # heap of (expires_at, generation, key) - may contain stale tombstones
        self._expiry_heap: List[tuple] = []
        # list of (generation, key) in insertion order - may also contain
        # stale tombstones for keys that were overwritten or deleted
        self._insertion_order: List[tuple] = []
        self._generation = itertools.count()
        self._counters = CacheCounters()
        self._lock = threading.RLock()

    def get(self, key: Any, default: Any = None) -> Any:
        """Return the cached value for ``key``, or ``default`` on miss/expiry."""
        with self._lock:
            self._sweep_expired_locked()
            entry = self._entries.get(key, self._MISSING)
            if entry is self._MISSING:
                self._counters.misses += 1
                return default

            value, expires_at, _generation = entry
            if expires_at <= time.monotonic():
                del self._entries[key]
                self._counters.misses += 1
                self._counters.expirations += 1
                return default

            self._counters.hits += 1
            return value

    def set(self, key: Any, value: Any, ttl_seconds: Optional[float] = None) -> None:
        """Store ``value`` under ``key``, evicting the oldest entry if full."""
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        with self._lock:
            self._sweep_expired_locked()

            if key in self._entries:
                del self._entries[key]

            while len(self._entries) >= self.capacity:
                if not self._evict_one_oldest_locked():
                    break  # nothing left to evict; capacity <= 0 handled in __init__

            generation = next(self._generation)
            expires_at = time.monotonic() + ttl
            self._entries[key] = (value, expires_at, generation)
            heapq.heappush(self._expiry_heap, (expires_at, generation, key))
            self._insertion_order.append((generation, key))

    def delete(self, key: Any) -> bool:
        """Remove ``key`` if present. Returns whether it was present."""
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def clear(self) -> None:
        """Drop every entry and reset hit/miss/eviction counters."""
        with self._lock:
            self._entries.clear()
            self._expiry_heap.clear()
            self._insertion_order.clear()
            self._counters = CacheCounters()

    def reset_counters(self, hits: int = 0, misses: int = 0, evictions: int = 0, expirations: int = 0) -> None:
        """Set counters to specific values without touching stored entries."""
        with self._lock:
            self._counters = CacheCounters(hits=hits, misses=misses, evictions=evictions, expirations=expirations)

    def __len__(self) -> int:
        with self._lock:
            self._sweep_expired_locked()
            return len(self._entries)

    def __contains__(self, key: Any) -> bool:
        return self.get(key, self._MISSING) is not self._MISSING

    def stats(self) -> Dict[str, Any]:
        """Hit/miss/eviction counters plus current size and capacity."""
        with self._lock:
            self._sweep_expired_locked()
            total = self._counters.hits + self._counters.misses
            hit_rate_percent = (self._counters.hits / total * 100.0) if total else 0.0
            return {
                "size": len(self._entries),
                "capacity": self.capacity,
                "hit_rate_percent": hit_rate_percent,
                **self._counters.as_dict(),
            }

    # -- internal helpers; caller must hold self._lock --

    def _sweep_expired_locked(self) -> None:
        now = time.monotonic()
        while self._expiry_heap and self._expiry_heap[0][0] <= now:
            expires_at, generation, key = heapq.heappop(self._expiry_heap)
            current = self._entries.get(key)
            if current is not None and current[2] == generation:
                del self._entries[key]
                self._counters.expirations += 1
            # else: tombstone for an already-overwritten/deleted key, discard

    def _evict_one_oldest_locked(self) -> bool:
        while self._insertion_order:
            generation, key = self._insertion_order.pop(0)
            current = self._entries.get(key)
            if current is not None and current[2] == generation:
                del self._entries[key]
                self._counters.evictions += 1
                return True
            # else: stale tombstone, keep looking
        return False


# ============================================================================
# ManagedProcessPool - bounded-concurrency async task execution
# ============================================================================

@dataclass
class TaskRecord:
    status: str  # "running" | "completed" | "failed"
    result: Any = None
    error: Optional[str] = None
    execution_seconds: float = 0.0
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None


class ManagedProcessPool:
    """
    Runs callables asynchronously under a bounded concurrency limit.

    This intentionally does not model a fixed set of idle worker threads
    pulling tasks off a shared queue (the classic thread-pool-plus-monitor
    design). Instead, each submitted task gets its own short-lived daemon
    thread, gated by a counting bound (``_slots``) so that no more than
    ``current_limit`` tasks run at once. Scaling up/down just adjusts that
    bound; there is nothing to "start" or "stop" at scale time, and there is
    no separate monitor thread deciding when to scale - callers decide that
    explicitly via ``scale_to``/``scale_by``.
    """

    def __init__(self, min_concurrency: int = 2, max_concurrency: int = 20):
        if min_concurrency < 1 or max_concurrency < min_concurrency:
            raise ValueError("require 1 <= min_concurrency <= max_concurrency")

        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self._current_limit = min_concurrency

        self._gate = threading.Condition()
        self._in_flight = 0
        self._queued = 0

        self._tasks: Dict[str, TaskRecord] = {}
        self._tasks_lock = threading.Lock()

        self._completed_count = 0
        self._failed_count = 0
        self._total_execution_seconds = 0.0
        self._metrics_lock = threading.Lock()

    def submit(self, task_id: str, func: Callable, *args, **kwargs) -> str:
        """Schedule ``func(*args, **kwargs)`` to run and return immediately."""
        with self._tasks_lock:
            self._tasks[task_id] = TaskRecord(status="running")
        with self._gate:
            self._queued += 1

        worker = threading.Thread(
            target=self._run, args=(task_id, func, args, kwargs), daemon=True
        )
        worker.start()
        return task_id

    def _run(self, task_id: str, func: Callable, args: tuple, kwargs: dict) -> None:
        with self._gate:
            while self._in_flight >= self._current_limit:
                self._gate.wait()
            self._in_flight += 1
            self._queued -= 1

        start = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start
            with self._tasks_lock:
                self._tasks[task_id] = TaskRecord(
                    status="completed", result=result,
                    execution_seconds=elapsed, finished_at=time.time(),
                )
            with self._metrics_lock:
                self._completed_count += 1
                self._total_execution_seconds += elapsed
        except Exception as exc:  # noqa: BLE001 - task errors are data, not a crash
            elapsed = time.time() - start
            with self._tasks_lock:
                self._tasks[task_id] = TaskRecord(
                    status="failed", error=str(exc),
                    execution_seconds=elapsed, finished_at=time.time(),
                )
            with self._metrics_lock:
                self._failed_count += 1
        finally:
            with self._gate:
                self._in_flight -= 1
                self._gate.notify()

    def get_result(self, task_id: str) -> Optional[TaskRecord]:
        with self._tasks_lock:
            return self._tasks.get(task_id)

    def record_external_result(self, task_id: str, result: Any, execution_seconds: float = 0.0) -> None:
        """Register a result computed outside the pool (e.g. a cache hit)."""
        with self._tasks_lock:
            self._tasks[task_id] = TaskRecord(
                status="completed", result=result,
                execution_seconds=execution_seconds, finished_at=time.time(),
            )

    def scale_to(self, concurrency: int) -> int:
        """Set the concurrency bound, clamped to [min_concurrency, max_concurrency]."""
        with self._gate:
            self._current_limit = max(self.min_concurrency, min(self.max_concurrency, concurrency))
            self._gate.notify_all()
            return self._current_limit

    def scale_by(self, delta: int) -> int:
        with self._gate:
            return self.scale_to(self._current_limit + delta)

    @property
    def current_limit(self) -> int:
        with self._gate:
            return self._current_limit

    def stats(self) -> Dict[str, Any]:
        with self._gate:
            in_flight, queued, limit = self._in_flight, self._queued, self._current_limit
        with self._metrics_lock:
            completed, failed, total_seconds = (
                self._completed_count, self._failed_count, self._total_execution_seconds
            )
        avg_seconds = (total_seconds / completed) if completed else 0.0
        return {
            "in_flight": in_flight,
            "queued": queued,
            "concurrency_limit": limit,
            "min_concurrency": self.min_concurrency,
            "max_concurrency": self.max_concurrency,
            "tasks_completed": completed,
            "tasks_failed": failed,
            "avg_task_seconds": avg_seconds,
        }


# ============================================================================
# ProcessRegistry - tracked table of externally-spawned OS processes
# ============================================================================

@dataclass
class TrackedProcess:
    pid: int
    command: str
    handle: Any  # subprocess.Popen-like object exposing poll()/terminate()/kill()
    status: str = "running"
    started_at: float = field(default_factory=time.time)
    progress: float = 0.0
    last_output: str = ""
    bytes_processed: int = 0
    runtime: float = 0.0
    eta: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "command": self.command,
            "process": self.handle,
            "start_time": self.started_at,
            "status": self.status,
            "progress": self.progress,
            "last_output": self.last_output,
            "bytes_processed": self.bytes_processed,
            "runtime": self.runtime,
            "eta": self.eta,
        }


class ProcessRegistry:
    """
    Tracks externally-spawned OS processes by pid so they can be listed,
    inspected, paused/resumed and terminated from an HTTP API.

    This holds no execution logic of its own - callers register a process
    they already started (``track``) and this class is purely bookkeeping
    plus the pause/resume/terminate OS calls.
    """

    def __init__(self):
        self._processes: Dict[int, TrackedProcess] = {}
        self._lock = threading.Lock()

    def track(self, pid: int, command: str, handle: Any) -> None:
        with self._lock:
            self._processes[pid] = TrackedProcess(pid=pid, command=command, handle=handle)

    def update_progress(self, pid: int, progress: float, last_output: str = "", bytes_processed: int = 0) -> None:
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                return
            proc.progress = progress
            proc.last_output = last_output
            proc.bytes_processed = bytes_processed
            proc.runtime = time.time() - proc.started_at
            proc.eta = (proc.runtime / progress) * (1.0 - progress) if progress > 0 else 0.0

    def get(self, pid: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            proc = self._processes.get(pid)
            return proc.as_dict() if proc else None

    def list_all(self) -> Dict[int, Dict[str, Any]]:
        with self._lock:
            return {pid: proc.as_dict() for pid, proc in self._processes.items()}

    def forget(self, pid: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            proc = self._processes.pop(pid, None)
            return proc.as_dict() if proc else None

    def terminate(self, pid: int, grace_seconds: float = 1.0) -> bool:
        """Terminate a tracked process. Returns False (without changing its
        status) if the process is not tracked or has already exited - only
        an actual live-process termination counts as success."""
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                return False
            handle = proc.handle
            try:
                if handle is not None and handle.poll() is None:
                    handle.terminate()
                    time.sleep(grace_seconds)
                    if handle.poll() is None:
                        handle.kill()
                    proc.status = "terminated"
                    return True
                return False
            except Exception:
                return False

    def terminate_gracefully(self, pid: int, timeout_seconds: float = 30.0) -> bool:
        """Like ``terminate``, but waits up to ``timeout_seconds`` for a clean exit
        before force-killing, and reports which of the two happened via status."""
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                return False
            handle = proc.handle
        try:
            handle.terminate()
            try:
                handle.wait(timeout=timeout_seconds)
                with self._lock:
                    proc.status = "terminated_gracefully"
            except Exception:
                handle.kill()
                with self._lock:
                    proc.status = "force_killed"
            return True
        except Exception:
            return False

    def pause(self, pid: int) -> bool:
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                return False
            handle = proc.handle
            try:
                if handle is not None and handle.poll() is None:
                    _suspend_pid(pid)
                    proc.status = "paused"
                    return True
            except Exception:
                return False
            return False

    def resume(self, pid: int) -> bool:
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                return False
            handle = proc.handle
            try:
                if handle is not None and handle.poll() is None:
                    _resume_pid(pid)
                    proc.status = "running"
                    return True
            except Exception:
                return False
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._processes)


def _suspend_pid(pid: int) -> None:
    if os.name == "nt":
        if psutil is None:
            raise RuntimeError("psutil is required to suspend a process on Windows")
        psutil.Process(pid).suspend()
    else:
        import signal
        os.kill(pid, signal.SIGSTOP)


def _resume_pid(pid: int) -> None:
    if os.name == "nt":
        if psutil is None:
            raise RuntimeError("psutil is required to resume a process on Windows")
        psutil.Process(pid).resume()
    else:
        import signal
        os.kill(pid, signal.SIGCONT)


# ============================================================================
# SystemResourceMonitor - CPU/memory/disk/network sampling only
# ============================================================================

class SystemResourceMonitor:
    """
    Reads current OS resource usage. Holds a short rolling history so callers
    can ask for a trend without re-sampling, but does not run any background
    thread, auto-scale anything, or execute processes itself - sampling only
    happens when a caller asks for it.
    """

    _EMPTY_USAGE = {
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "memory_available_gb": 0.0,
        "disk_percent": 0.0,
        "disk_free_gb": 0.0,
        "network_bytes_sent": 0,
        "network_bytes_recv": 0,
        "timestamp": 0.0,
    }

    def __init__(self, history_length: int = 100, sample_interval_seconds: float = 1.0):
        self.history_length = history_length
        self.sample_interval_seconds = sample_interval_seconds
        self._history: List[Dict[str, float]] = []
        self._lock = threading.Lock()

    def sample(self) -> Dict[str, float]:
        """Take and record one resource-usage measurement."""
        if psutil is None:
            usage = dict(self._EMPTY_USAGE)
            usage["timestamp"] = time.time()
            return usage

        try:
            cpu_percent = psutil.cpu_percent(interval=self.sample_interval_seconds)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(os.path.abspath(os.sep))
            network = psutil.net_io_counters()

            usage = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024 ** 3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 ** 3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time(),
            }
        except Exception:
            usage = dict(self._EMPTY_USAGE)
            usage["timestamp"] = time.time()

        with self._lock:
            self._history.append(usage)
            if len(self._history) > self.history_length:
                self._history.pop(0)

        return usage

    def sample_process(self, pid: int) -> Dict[str, Any]:
        """Resource usage for one specific process, or {} if it can't be read."""
        if psutil is None:
            return {}
        try:
            process = psutil.Process(pid)
            return {
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "memory_rss_mb": process.memory_info().rss / (1024 ** 2),
                "num_threads": process.num_threads(),
                "status": process.status(),
            }
        except Exception:
            return {}

    def trend(self, recent_count: int = 10) -> Dict[str, Any]:
        """Average CPU/memory over the last ``recent_count`` recorded samples."""
        with self._lock:
            history = list(self._history)

        if len(history) < 2:
            return {}

        recent = history[-recent_count:]
        return {
            "cpu_avg": sum(u["cpu_percent"] for u in recent) / len(recent),
            "memory_avg": sum(u["memory_percent"] for u in recent) / len(recent),
            "sample_count": len(history),
        }


# ============================================================================
# PerformanceTelemetry - timing/count/error metric aggregation only
# ============================================================================

class IntervalScheduler:
    """Runs a callback on a fixed interval, on its own daemon thread, until
    stopped - a reusable primitive for "do X periodically in the
    background" instead of a bare ``while True: time.sleep(N)`` loop
    written inline wherever that's needed.

    Waiting on a ``threading.Event`` (rather than ``time.sleep``) means
    ``stop()`` interrupts the wait immediately instead of only being
    noticed on the loop's next wake-up, and a callback that raises is
    logged-and-swallowed by the caller-supplied `on_error` rather than
    silently killing the loop.
    """

    def __init__(
        self,
        interval_seconds: float,
        callback: Callable[[], None],
        name: str = "interval-scheduler",
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        self.interval_seconds = interval_seconds
        self._callback = callback
        self._on_error = on_error
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._started = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background thread. Safe to call more than once -
        only the first call has any effect."""
        with self._lock:
            if self._started:
                return
            self._started = True
            self._thread.start()

    def stop(self) -> None:
        """Signal the loop to exit. The thread may still be finishing its
        current callback when this returns; it will not run another."""
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._started and not self._stop_event.is_set()

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self._callback()
            except Exception as exc:  # noqa: BLE001 - one bad tick must not kill the loop
                if self._on_error is not None:
                    try:
                        self._on_error(exc)
                    except Exception:
                        pass


@dataclass
class ExecutionRecord:
    label: str
    success: bool
    execution_seconds: float
    return_code: int
    recorded_at: float = field(default_factory=time.time)


class PerformanceTelemetry:
    """
    Aggregates "how did recent work go" metrics (success rate, timings) and
    a bounded history of recent system-resource samples, for a dashboard to
    render. It has no opinion about *what* produced those numbers - callers
    feed it execution outcomes and resource samples.
    """

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._executions: List[ExecutionRecord] = []
        self._resource_samples: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_execution(self, label: str, success: bool, execution_seconds: float, return_code: int = -1) -> None:
        with self._lock:
            self._executions.append(ExecutionRecord(
                label=label[:100], success=success,
                execution_seconds=execution_seconds, return_code=return_code,
            ))
            if len(self._executions) > self.max_history:
                self._executions.pop(0)

    def record_resource_sample(self, usage: Dict[str, Any]) -> None:
        with self._lock:
            self._resource_samples.append(usage)
            if len(self._resource_samples) > self.max_history:
                self._resource_samples.pop(0)

    def summary(self, recent_count: int = 100) -> Dict[str, Any]:
        with self._lock:
            total_recorded = len(self._executions)
            if total_recorded == 0:
                return {"executions": 0}

            recent = self._executions[-recent_count:]
            resource_sample_count = len(self._resource_samples)

        successes = sum(1 for e in recent if e.success)
        avg_seconds = sum(e.execution_seconds for e in recent) / len(recent)

        return {
            "total_executions": total_recorded,
            "recent_executions": len(recent),
            "success_rate": (successes / len(recent) * 100.0) if recent else 0.0,
            "avg_execution_time": avg_seconds,
            "system_metrics_count": resource_sample_count,
        }
