"""One bounded large-file job with private, automatically unlinked temporary files."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import logging
import secrets
import shutil
import tempfile
from threading import Event, RLock
import time
from typing import Any, BinaryIO, Callable

from starlette.concurrency import run_in_threadpool

from api_worker import CryptoLease, CryptoWorker, finish_owned
from crypto_config import cfg
import crypto_core as core
import crypto_stream as stream

RESULT_TTL_SECONDS = 15 * 60
logger = logging.getLogger(__name__)


class JobError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def encrypted_limit() -> int:
    return stream.encrypted_size_limit()


async def finish_io(operation: Callable[..., Any], *args: Any) -> Any:
    """Keep the file alive until its thread finishes even if the request is cancelled."""
    future = asyncio.get_running_loop().run_in_executor(None, operation, *args)
    return await finish_owned(future, lambda: None)


def write_all(file: BinaryIO, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = file.write(remaining)
        if not isinstance(written, int) or not 0 < written <= len(remaining):
            raise OSError("Temporary storage did not accept the upload.")
        remaining = remaining[written:]


class FileJob:
    def __init__(self, mode: str, filename: str, size: int, lease: CryptoLease, ttl: int) -> None:
        self.id = secrets.token_hex(16)
        self.mode = mode
        self.filename = filename
        self.size = size
        self.lease = lease
        self.state = "awaiting_upload"
        self.phase = "uploading"
        self.processed = 0
        self.total = size
        self.expires_at = time.time() + ttl
        self.deadline = time.monotonic() + ttl
        self.cancel = Event()
        self.input: BinaryIO | None = tempfile.TemporaryFile(mode="w+b", buffering=0)
        self.output: BinaryIO | None = None
        self.result: dict[str, Any] | None = None
        self.verification: dict[str, Any] | None = None
        self.error: dict[str, str] | None = None
        self.task: asyncio.Task[None] | None = None
        self.upload_task: asyncio.Task[Any] | None = None
        self.download_task: asyncio.Task[Any] | None = None
        self.downloading = False
        self.download_finished = asyncio.Event()
        self.download_finished.set()
        self.discard = False
        self.lock = RLock()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            result: dict[str, Any] = {
                "id": self.id,
                "mode": self.mode,
                "state": self.state,
                "phase": self.phase,
                "processedBytes": self.processed,
                "totalBytes": self.total,
                "expiresAt": datetime.fromtimestamp(self.expires_at, timezone.utc).isoformat(),
            }
            if self.state == "complete" and self.result is not None:
                result["result"] = dict(self.result)
            if self.state == "complete" and self.verification is not None:
                result["verification"] = dict(self.verification)
            if self.error is not None:
                result["error"] = dict(self.error)
            return result

    def progress(self, phase: str, processed: int, total: int) -> None:
        with self.lock:
            self.phase, self.processed, self.total = phase, processed, total

    def close_files(self, *, keep_output: bool = False) -> None:
        """Release every owned handle and admission even if a close reports an I/O error."""
        first_error: OSError | None = None
        try:
            for name in ("input", "output"):
                if name == "output" and keep_output and first_error is None:
                    continue
                file = getattr(self, name)
                setattr(self, name, None)
                if file is not None:
                    try:
                        file.close()
                    except OSError as exc:
                        if first_error is None:
                            first_error = exc
        finally:
            self.lease.close()
        if first_error is not None:
            self.state = "failed"
            self.result = self.verification = None
            self.error = {
                "code": "storage_failed",
                "message": "Temporary storage failed. Check free disk space and try again.",
            }
            raise first_error


class JobStore:
    """Reserve disk/admission before upload; retain at most one job until clear or expiry."""

    def __init__(self, worker: CryptoWorker, ttl: int = RESULT_TTL_SECONDS) -> None:
        self.worker = worker
        self.ttl = ttl
        self.job: FileJob | None = None
        self.closed = False

    def reserve(self, mode: str, filename: str, size: int) -> FileJob:
        if mode not in {"encrypt", "decrypt", "verify"} or type(size) is not int or size < 0:
            raise JobError(400, "invalid_job", "Choose a supported operation and file size.")
        limit = cfg.MAX_STREAM_FILE_BYTES if mode == "encrypt" else encrypted_limit()
        if size > limit:
            raise JobError(413, "file_too_large", "This file exceeds the large-file limit.")
        if self.closed or self.job is not None:
            raise JobError(429, "server_busy", "Clear the existing large-file job before starting another.")
        # Includes input, decryption snapshot, output, header allowance, and a safety margin.
        if shutil.disk_usage(tempfile.gettempdir()).free < size * 3 + 64 * 1024 * 1024:
            raise JobError(507, "insufficient_storage", "Not enough temporary disk space for this file.")
        lease = self.worker.acquire()
        if lease is None:
            raise JobError(429, "server_busy", "A cryptographic operation is already running. Try again shortly.")
        try:
            job = FileJob(mode, filename, size, lease, self.ttl)
        except BaseException:
            lease.close()
            raise
        self.job = job
        return job

    def get(self, identifier: str) -> FileJob:
        job = self.job
        if job is None or not secrets.compare_digest(job.id, identifier) or job.discard:
            raise JobError(410, "job_expired", "The temporary job has expired or was cleared. Run the operation again.")
        if time.monotonic() >= job.deadline:
            self.cancel(job, discard=True)
            raise JobError(410, "job_expired", "The temporary job has expired. Run the operation again.")
        return job

    def cancel(self, job: FileJob, *, discard: bool = False) -> None:
        job.cancel.set()
        job.discard = job.discard or discard
        with job.lock:
            if job.state in {"running", "cancelling", "uploading"}:
                job.state = "cancelling"
                if job.upload_task is not None:
                    job.upload_task.cancel()
            elif job.downloading:
                # A client can stall in ASGI flow control after the iterator yielded.
                # Interrupt the response so its finally owns closing the iterator/file.
                if job.download_task is not None and job.download_task is not asyncio.current_task():
                    job.download_task.cancel()
            elif not job.downloading:
                job.state = "cancelled"
                job.result = None
                job.verification = None
                try:
                    job.close_files()
                finally:
                    self._discard_if_finished(job)

    def _discard_if_finished(self, job: FileJob) -> None:
        if job.discard and not job.downloading and job.state not in {"running", "cancelling", "uploading"}:
            try:
                job.close_files()
            finally:
                if self.job is job:
                    self.job = None

    async def upload(self, job: FileJob, chunks: Any) -> None:
        if job.state != "awaiting_upload":
            raise JobError(409, "invalid_job_state", "This job cannot accept another upload.")
        job.state = "uploading"
        job.upload_task = asyncio.current_task()
        count = 0
        try:
            async for chunk in chunks:
                if job.cancel.is_set():
                    raise stream.OperationCancelled()
                count += len(chunk)
                if count > job.size:
                    raise JobError(413, "file_too_large", "Upload exceeds its reserved size.")
                if job.input is None:
                    raise RuntimeError("Upload storage is unavailable.")
                for offset in range(0, len(chunk), cfg.STREAM_CHUNK_BYTES):
                    await finish_io(write_all, job.input, chunk[offset : offset + cfg.STREAM_CHUNK_BYTES])
                job.progress("uploading", count, job.size)
            if count != job.size:
                raise JobError(400, "incomplete_upload", "Upload size does not match the selected file.")
            if job.cancel.is_set():
                raise stream.OperationCancelled()
            if job.input is None:
                raise RuntimeError("Input storage is unavailable.")
            await finish_io(job.input.seek, 0)
            job.state = "ready"
        except BaseException:
            job.state = "cancelled" if job.cancel.is_set() else "failed"
            job.error = {"code": "upload_failed", "message": "The upload did not finish. Clear the job and try again."}
            try:
                job.close_files()
            finally:
                self._discard_if_finished(job)
            raise
        finally:
            job.upload_task = None

    def start(self, job: FileJob, pem: str, password: str, output_filename: str) -> None:
        if job.state != "ready":
            raise JobError(409, "invalid_job_state", "Upload a complete file before starting this job.")
        job.state = "running"
        job.phase = "preparing"
        job.processed = 0
        job.task = asyncio.create_task(self._execute(job, pem, password, output_filename))

    def _process(self, job: FileJob, pem: str, password: str, output_filename: str) -> None:
        if job.cancel.is_set():
            raise stream.OperationCancelled()
        info = core.inspect_key_pem_strict(pem)
        expected_type = "public" if job.mode == "encrypt" else "private"
        if info.get("key_type") != expected_type:
            raise JobError(400, "invalid_key", "Choose the appropriate supported key for this operation.")
        raw, algorithm, key_type = core.load_key_pem(pem, password if expected_type == "private" else None)
        if raw is None or algorithm is None or key_type != expected_type:
            raise JobError(400, "private_key_failed", "Could not unlock the private key. Check its password and file.")
        try:
            if job.input is None:
                raise RuntimeError("Input storage is unavailable.")
            if job.mode == "verify":
                metadata = stream.verify_stream(
                    job.input, raw, expected_kem_alg=algorithm, progress=job.progress, cancelled=job.cancel.is_set
                )
                job.verification = {
                    "ok": True,
                    "verified": True,
                    "kem": metadata.kem_alg,
                    "formatVersion": metadata.version,
                    "bytesVerified": metadata.encrypted_payload_bytes - cfg.AES_TAG_BYTES,
                    "publicKeyFingerprint": core.get_private_key_public_fingerprint(raw, algorithm),
                }
            else:
                job.output = tempfile.TemporaryFile(mode="w+b", buffering=0)
                if job.mode == "encrypt":
                    stream.encrypt_stream(
                        job.input, job.output, raw, algorithm, progress=job.progress, cancelled=job.cancel.is_set
                    )
                else:
                    stream.decrypt_stream(
                        job.input,
                        job.output,
                        raw,
                        expected_kem_alg=algorithm,
                        progress=job.progress,
                        cancelled=job.cancel.is_set,
                    )
                job.result = {"filename": output_filename, "bytes": job.output.tell()}
                job.output.seek(0)
        finally:
            del raw

    async def _execute(self, job: FileJob, pem: str, password: str, output_filename: str) -> None:
        try:
            await job.lease.run_owned(self._process, job, pem, password, output_filename, on_cancel=job.cancel.set)
            job.state = "cancelled" if job.cancel.is_set() else "complete"
        except (stream.OperationCancelled, asyncio.CancelledError):
            job.state = "cancelled"
        except Exception as exc:
            job.state = "failed"
            if isinstance(exc, JobError):
                code, message = exc.code, exc.message
            elif isinstance(exc, core.CryptoDependencyError):
                code, message = "backend_unavailable", "The post-quantum backend is unavailable."
            elif isinstance(exc, OSError):
                code, message = "storage_failed", "Temporary storage failed. Check free disk space and try again."
            else:
                code, message = "operation_failed", "The operation failed. Check the file, key, and password."
            job.error = {"code": code, "message": message}
        finally:
            del pem, password
            if job.state != "complete":
                job.result = job.verification = None
            # close_files records a safe storage failure and discards the output if
            # closing the input fails; the background task must still finish cleanup.
            with suppress(OSError):
                job.close_files(keep_output=job.state == "complete")
            self._discard_if_finished(job)

    async def download(self, job: FileJob):
        # The response retains ownership through its final ASGI send, then calls
        # finish_download after closing this iterator, even if sending headers fails.
        if job.output is None:
            raise RuntimeError("Output storage is unavailable.")
        await finish_io(job.output.seek, 0)
        while not job.cancel.is_set():
            chunk = await finish_io(job.output.read, cfg.STREAM_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk

    def finish_download(self, job: FileJob) -> None:
        job.downloading = False
        job.download_finished.set()
        if job.cancel.is_set():
            self.cancel(job, discard=job.discard)
        self._discard_if_finished(job)

    def begin_download(self, job: FileJob) -> None:
        if job.state != "complete" or job.output is None or job.result is None:
            raise JobError(409, "result_unavailable", "There is no authenticated file result to download.")
        if job.downloading:
            raise JobError(409, "download_busy", "A download is already active. Wait before retrying.")
        job.downloading = True
        job.download_finished.clear()

    async def reap(self) -> None:
        while True:
            await asyncio.sleep(1)
            if self.job is not None and time.monotonic() >= self.job.deadline:
                try:
                    self.cancel(self.job, discard=True)
                except OSError:
                    logger.warning("Temporary job storage cleanup failed.")

    async def close(self) -> None:
        self.closed = True
        job = self.job
        try:
            if job is not None:
                self.cancel(job, discard=True)
                if job.upload_task is not None:
                    with suppress(asyncio.CancelledError, Exception):
                        await job.upload_task
                if job.task is not None:
                    with suppress(asyncio.CancelledError):
                        await job.task
                if job.downloading:
                    await job.download_finished.wait()
                if not job.downloading:
                    job.close_files()
        finally:
            await run_in_threadpool(self.worker.close)
