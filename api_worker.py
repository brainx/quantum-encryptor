"""Bounded background execution for one admitted cryptographic request."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import Any, Callable, TypeVar

Result = TypeVar("Result")


class CryptoWorker:
    """Own one worker thread and admit one request until its work and response finish."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="crypto-worker")
        self._lock = Lock()
        self._closed = False
        self._lease: CryptoLease | None = None

    def acquire(self) -> CryptoLease | None:
        """Admit immediately, returning None while busy or shutting down."""
        with self._lock:
            if self._closed or self._lease is not None:
                return None
            self._lease = CryptoLease(self)
            return self._lease

    def _release_if_finished(self, lease: CryptoLease) -> None:
        # Call only while holding _lock; callbacks can run on the worker thread.
        if self._lease is lease and lease._closed and lease._pending == 0:
            self._lease = None

    def close(self) -> None:
        """Stop admission, cancel queued work, and wait for executing work to finish."""
        with self._lock:
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=True)


class CryptoLease:
    """Keep admission until the request closes and all submitted functions finish."""

    def __init__(self, worker: CryptoWorker) -> None:
        self._worker = worker
        self._closed = False
        self._pending = 0

    async def run(self, function: Callable[..., Result], *args: Any) -> Result:
        """Run a synchronous function without blocking the request's event loop."""
        worker = self._worker
        with worker._lock:
            if self._closed or worker._closed:
                raise RuntimeError("The cryptographic worker or request has closed.")
            self._pending += 1
            try:
                future = worker._executor.submit(function, *args)
            except BaseException:
                self._pending -= 1
                worker._release_if_finished(self)
                raise

        # A cancelled asyncio wrapper may leave its thread running. Only the
        # underlying concurrent future can mark that work as finished.
        future.add_done_callback(self._work_finished)
        return await asyncio.wrap_future(future)

    def _work_finished(self, _future: Future[Any]) -> None:
        with self._worker._lock:
            self._pending -= 1
            self._worker._release_if_finished(self)

    def close(self) -> None:
        """Mark request/response cleanup complete without abandoning running work."""
        with self._worker._lock:
            self._closed = True
            self._worker._release_if_finished(self)
