import asyncio
import io
import os
import threading
import time

import pytest

import api_jobs as jobs
from api_worker import CryptoWorker


async def chunks(*values):
    for value in values:
        yield value


@pytest.mark.parametrize(
    "mode,size,code",
    [
        ("other", 1, "invalid_job"),
        ("encrypt", -1, "invalid_job"),
        ("encrypt", True, "invalid_job"),
        ("encrypt", jobs.cfg.MAX_STREAM_FILE_BYTES + 1, "file_too_large"),
        ("decrypt", jobs.encrypted_limit() + 1, "file_too_large"),
    ],
)
def test_reservation_rejects_invalid_input_without_taking_admission(mode, size, code):
    worker = CryptoWorker()
    store = jobs.JobStore(worker)
    try:
        with pytest.raises(jobs.JobError) as error:
            store.reserve(mode, "file", size)
        assert error.value.code == code
        lease = worker.acquire()
        assert lease is not None
        lease.close()
    finally:
        worker.close()


def test_reservation_checks_disk_and_releases_lease_after_tempfile_failure(monkeypatch):
    worker = CryptoWorker()
    store = jobs.JobStore(worker)
    try:
        with monkeypatch.context() as context:
            context.setattr(jobs.shutil, "disk_usage", lambda _: type("Disk", (), {"free": 0})())
            with pytest.raises(jobs.JobError, match="disk space"):
                store.reserve("encrypt", "file", 1)
        with monkeypatch.context() as context:

            def fail(**_kwargs):
                raise OSError("synthetic disk failure")

            context.setattr(jobs.tempfile, "TemporaryFile", fail)
            with pytest.raises(OSError):
                store.reserve("encrypt", "file", 1)
        assert store.job is None
        lease = worker.acquire()
        assert lease is not None
        lease.close()
    finally:
        worker.close()


@pytest.mark.parametrize("payload,code", [(b"short", "incomplete_upload"), (b"too much data", "file_too_large")])
def test_upload_must_match_reservation_and_failure_releases_files(payload, code):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = store.reserve("encrypt", "file", 8)
            file = job.input
            assert file is not None
            if os.name == "posix":
                assert os.fstat(file.fileno()).st_mode & 0o777 == 0o600
                assert os.fstat(file.fileno()).st_nlink == 0
            with pytest.raises(jobs.JobError) as error:
                await store.upload(job, chunks(payload))
            assert error.value.code == code
            assert file.closed and job.state == "failed"
            with pytest.raises(jobs.JobError, match="existing"):
                store.reserve("encrypt", "other", 1)
            store.cancel(job, discard=True)
            assert store.job is None
        finally:
            await store.close()

    asyncio.run(scenario())


def test_owned_write_waits_through_repeated_cancellation():
    async def scenario():
        started = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()
        file = io.BytesIO()

        def write():
            loop.call_soon_threadsafe(started.set)
            assert release.wait(3)
            file.write(b"finished")

        task = asyncio.create_task(jobs.finish_io(write))
        try:
            await asyncio.wait_for(started.wait(), 2)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and not file.closed
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert file.getvalue() == b"finished"
        finally:
            release.set()
            file.close()

    asyncio.run(scenario())


def test_short_upload_writes_are_completed_and_zero_progress_is_an_error():
    class ShortWriter(io.BytesIO):
        def write(self, data):
            return super().write(data[:2])

    output = ShortWriter()
    jobs.write_all(output, b"complete")
    assert output.getvalue() == b"complete"
    with pytest.raises(OSError):
        jobs.write_all(type("Stalled", (), {"write": lambda *_: 0})(), b"x")


def test_running_cancellation_waits_for_worker_before_closing_owned_files(monkeypatch):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        started = asyncio.Event()
        release = threading.Event()
        loop = asyncio.get_running_loop()
        job = store.reserve("decrypt", "file.pqc", 1)
        source = job.input

        def blocked_process(active, *_args):
            active.output = jobs.tempfile.TemporaryFile(mode="w+b")
            active.result = {"filename": "file", "bytes": 1}
            loop.call_soon_threadsafe(started.set)
            assert release.wait(3)
            assert not source.closed
            assert not active.output.closed
            active.output.write(b"x")

        monkeypatch.setattr(store, "_process", blocked_process)
        try:
            await store.upload(job, chunks(b"x"))
            store.start(job, "pem", "password", "file")
            await asyncio.wait_for(started.wait(), 2)
            assert "result" not in job.snapshot()
            store.cancel(job, discard=True)
            assert job.state == "cancelling" and not source.closed
            assert store.worker.acquire() is None
            job.task.cancel()
            await asyncio.sleep(0)
            job.task.cancel()
            await asyncio.sleep(0)
            assert not job.task.done() and not source.closed
            release.set()
            await asyncio.wait_for(job.task, 2)
            assert source.closed and job.output is None and store.job is None
        finally:
            release.set()
            await store.close()

    asyncio.run(scenario())


def test_failed_authentication_never_exposes_download_or_internal_error(monkeypatch):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())

        def fail(*_args):
            raise jobs.core.AuthenticationFailedError("private details")

        monkeypatch.setattr(store, "_process", fail)
        try:
            job = store.reserve("decrypt", "file", 1)
            await store.upload(job, chunks(b"x"))
            store.start(job, "pem", "password", "file")
            await job.task
            snapshot = job.snapshot()
            assert snapshot["state"] == "failed"
            assert snapshot["error"]["code"] == "operation_failed"
            assert "private details" not in str(snapshot)
            assert job.input is None and job.output is None
            with pytest.raises(jobs.JobError, match="authenticated"):
                store.begin_download(job)
        finally:
            await store.close()

    asyncio.run(scenario())


def test_download_clear_waits_for_reader_and_removes_expired_result(monkeypatch):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())

        def complete(active, *_args):
            active.output = jobs.tempfile.TemporaryFile(mode="w+b")
            active.output.write(b"result")
            active.result = {"filename": "file", "bytes": 6}

        monkeypatch.setattr(store, "_process", complete)
        try:
            job = store.reserve("decrypt", "file", 1)
            await store.upload(job, chunks(b"x"))
            store.start(job, "pem", "password", "file")
            await job.task
            assert job.snapshot()["result"]["bytes"] == 6
            output = job.output
            store.begin_download(job)
            with pytest.raises(jobs.JobError, match="already active"):
                store.begin_download(job)
            reader = store.download(job)
            assert await anext(reader) == b"result"
            store.cancel(job, discard=True)
            assert not output.closed and store.job is job
            with pytest.raises(jobs.JobError) as error:
                store.get(job.id)
            assert error.value.status == 410
            await reader.aclose()
            store.finish_download(job)
            assert output.closed and store.job is None
        finally:
            await store.close()

    asyncio.run(scenario())


def test_expiration_closes_anonymous_storage_and_restores_admission():
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = store.reserve("encrypt", "file", 0)
            file = job.input
            job.deadline = time.monotonic() - 1
            with pytest.raises(jobs.JobError) as error:
                store.get(job.id)
            assert error.value.status == 410
            assert file.closed and store.job is None
            replacement = store.reserve("encrypt", "file", 0)
            await store.upload(replacement, chunks(b""))
            assert replacement.state == "ready"
        finally:
            await store.close()
        assert replacement.input is None

    asyncio.run(scenario())


class CloseFailure(io.BytesIO):
    def close(self):
        super().close()
        raise OSError("synthetic private storage detail")


@pytest.mark.parametrize("failures", [{"input"}, {"output"}, {"input", "output"}])
def test_close_failure_still_closes_other_file_and_releases_admission(failures):
    async def scenario():
        worker = CryptoWorker()
        store = jobs.JobStore(worker)
        try:
            job = store.reserve("decrypt", "file", 0)
            job.input.close()
            job.input = source = CloseFailure() if "input" in failures else io.BytesIO()
            job.output = output = CloseFailure() if "output" in failures else io.BytesIO(b"private output")
            with pytest.raises(OSError):
                job.close_files()
            assert source.closed and output.closed
            assert job.input is None and job.output is None
            assert job.state == "failed"
            assert job.error["code"] == "storage_failed"
            assert "synthetic private storage detail" not in str(job.snapshot())
            lease = worker.acquire()
            assert lease is not None
            lease.close()
        finally:
            await store.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("shutdown", [False, True])
def test_cancel_or_shutdown_finishes_cleanup_after_close_failure(shutdown):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = store.reserve("decrypt", "file", 0)
            job.input.close()
            job.input = source = CloseFailure()
            job.output = output = io.BytesIO()
            with pytest.raises(OSError):
                if shutdown:
                    await store.close()
                else:
                    store.cancel(job, discard=True)
            assert source.closed and output.closed
            assert store.job is None
            if shutdown:
                assert store.worker.acquire() is None
            else:
                lease = store.worker.acquire()
                assert lease is not None
                lease.close()
        finally:
            await store.close()

    asyncio.run(scenario())


def test_input_close_failure_discards_completed_result_and_reports_storage_failure(monkeypatch):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        source = CloseFailure()
        output = io.BytesIO(b"authenticated output")

        def complete(job, *_args):
            job.output = output
            job.result = {"filename": "file", "bytes": len(b"authenticated output")}

        monkeypatch.setattr(store, "_process", complete)
        try:
            job = store.reserve("decrypt", "file", 1)
            job.input.close()
            job.input = source
            await store.upload(job, chunks(b"x"))
            store.start(job, "pem", "password", "file")
            await job.task
            assert source.closed and output.closed
            assert job.input is None and job.output is None
            snapshot = job.snapshot()
            assert snapshot["state"] == "failed"
            assert snapshot["error"]["code"] == "storage_failed"
            assert "result" not in snapshot and "verification" not in snapshot
            assert "synthetic private storage detail" not in str(snapshot)
            with pytest.raises(jobs.JobError, match="authenticated"):
                store.begin_download(job)
            lease = store.worker.acquire()
            assert lease is not None
            lease.close()
        finally:
            await store.close()

    asyncio.run(scenario())
