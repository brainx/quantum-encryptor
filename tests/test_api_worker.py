import asyncio
import threading

import pytest

from api_worker import CryptoWorker


async def _acquire_when_ready(worker):
    async def poll():
        while True:
            lease = worker.acquire()
            if lease is not None:
                return lease
            await asyncio.sleep(0.001)

    return await asyncio.wait_for(poll(), timeout=2)


def test_admission_is_exclusive_and_independent_for_each_worker():
    first_worker = CryptoWorker()
    second_worker = CryptoWorker()
    try:
        first = first_worker.acquire()
        second = second_worker.acquire()
        assert first is not None
        assert second is not None
        assert first_worker.acquire() is None
        first.close()
        replacement = first_worker.acquire()
        assert replacement is not None
        first.close()
        assert first_worker.acquire() is None
        replacement.close()
        second.close()
    finally:
        first_worker.close()
        second_worker.close()


def test_work_runs_off_event_loop_and_admission_lasts_until_request_closes():
    async def scenario():
        worker = CryptoWorker()
        try:
            lease = worker.acquire()
            assert lease is not None
            assert await lease.run(threading.get_ident) != threading.get_ident()
            assert await lease.run(bytes.join, b"-", [b"first", b"second"]) == b"first-second"
            assert worker.acquire() is None
            lease.close()
            with pytest.raises(RuntimeError):
                await lease.run(lambda: None)
            replacement = worker.acquire()
            assert replacement is not None
            replacement.close()
        finally:
            worker.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel_queued", [False, True])
def test_cancelled_request_holds_admission_until_running_worker_finishes(cancel_queued):
    async def scenario():
        worker = CryptoWorker()
        unblock = threading.Event()
        started = asyncio.Event()
        loop = asyncio.get_running_loop()

        def blocked_operation():
            loop.call_soon_threadsafe(started.set)
            assert unblock.wait(timeout=3)
            return b"completed"

        try:
            lease = worker.acquire()
            assert lease is not None
            running = asyncio.create_task(lease.run(blocked_operation))
            await asyncio.wait_for(started.wait(), timeout=2)
            if cancel_queued:
                queued = asyncio.create_task(lease.run(lambda: pytest.fail("cancelled queued work must not run")))
                await asyncio.sleep(0)
                queued.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await queued
            running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await running
            lease.close()
            lease.close()
            assert worker.acquire() is None
            unblock.set()
            replacement = await _acquire_when_ready(worker)
            assert await replacement.run(lambda: b"next") == b"next"
            replacement.close()
        finally:
            unblock.set()
            worker.close()

    asyncio.run(scenario())


def test_callable_failure_propagates_and_request_close_restores_admission():
    def fail():
        raise ValueError("operation failed")

    async def scenario():
        worker = CryptoWorker()
        try:
            lease = worker.acquire()
            assert lease is not None
            with pytest.raises(ValueError, match="operation failed"):
                await lease.run(fail)
            assert worker.acquire() is None
            lease.close()
            replacement = worker.acquire()
            assert replacement is not None
            replacement.close()
        finally:
            worker.close()

    asyncio.run(scenario())


def test_submit_failure_does_not_leak_admission(monkeypatch):
    def fail_submit(*_args, **_kwargs):
        raise RuntimeError("executor unavailable")

    async def scenario():
        worker = CryptoWorker()
        try:
            lease = worker.acquire()
            assert lease is not None
            with monkeypatch.context() as context:
                context.setattr(worker._executor, "submit", fail_submit)
                with pytest.raises(RuntimeError, match="executor unavailable"):
                    await lease.run(lambda: None)
            lease.close()
            replacement = worker.acquire()
            assert replacement is not None
            assert await replacement.run(lambda: "recovered") == "recovered"
            replacement.close()
        finally:
            worker.close()

    asyncio.run(scenario())


def test_shutdown_stops_admission_and_waits_for_running_work(monkeypatch):
    async def scenario():
        worker = CryptoWorker()
        unblock = threading.Event()
        started = asyncio.Event()
        shutting_down = asyncio.Event()
        loop = asyncio.get_running_loop()
        original_shutdown = worker._executor.shutdown

        def tracked_shutdown(*args, **kwargs):
            loop.call_soon_threadsafe(shutting_down.set)
            return original_shutdown(*args, **kwargs)

        def blocked_operation():
            loop.call_soon_threadsafe(started.set)
            assert unblock.wait(timeout=3)
            return "finished"

        monkeypatch.setattr(worker._executor, "shutdown", tracked_shutdown)
        try:
            lease = worker.acquire()
            assert lease is not None
            operation = asyncio.create_task(lease.run(blocked_operation))
            await asyncio.wait_for(started.wait(), timeout=2)
            shutdown = asyncio.create_task(asyncio.to_thread(worker.close))
            await asyncio.wait_for(shutting_down.wait(), timeout=2)
            assert not shutdown.done()
            assert worker.acquire() is None
            with pytest.raises(RuntimeError):
                await lease.run(lambda: None)
            unblock.set()
            assert await asyncio.wait_for(operation, timeout=2) == "finished"
            await asyncio.wait_for(shutdown, timeout=2)
            lease.close()
            assert worker.acquire() is None
        finally:
            unblock.set()
            worker.close()

    asyncio.run(scenario())
