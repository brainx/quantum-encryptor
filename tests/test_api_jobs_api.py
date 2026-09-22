import asyncio
import json
import threading
from urllib.parse import urlencode

import pytest

import api_app
from api_jobs import JobStore
from crypto_config import cfg


def _form(fields):
    return urlencode(fields).encode(), [(b"content-type", b"application/x-www-form-urlencoded")]


def _key_form(password="", fingerprints=(), fingerprint_file=False):
    body = (
        b'--job-boundary\r\nContent-Disposition: form-data; name="key"; filename="key.pem"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\nsynthetic key\r\n"
        b'--job-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\n' + password.encode() + b"\r\n"
    )
    for fingerprint in fingerprints:
        disposition = 'Content-Disposition: form-data; name="expected_recipient_fingerprint"'
        if fingerprint_file:
            disposition += '; filename="fingerprint.txt"'
        body += b"--job-boundary\r\n" + disposition.encode() + b"\r\n\r\n" + fingerprint.encode() + b"\r\n"
    body += b"--job-boundary--\r\n"
    return body, [(b"content-type", b"multipart/form-data; boundary=job-boundary")]


async def _request(
    app,
    path,
    *,
    method="POST",
    body=b"",
    headers=(),
    auth=True,
    browser=False,
    send_failure=None,
    send_hook=None,
    asgi_spec="2.4",
):
    messages = []
    reads = 0
    request_headers = [
        (b"host", api_app.LOCAL_API_HOST_HEADER.encode()),
        (b"content-length", str(len(body)).encode()),
        *headers,
    ]
    if auth:
        request_headers.append((b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode()))
    if browser:
        request_headers.extend(
            [
                (b"origin", f"http://{api_app.LOCAL_API_HOST_HEADER}".encode()),
                (b"cookie", f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}".encode()),
            ]
        )

    async def receive():
        nonlocal reads
        reads += 1
        if reads == 1:
            return {"type": "http.request", "body": body, "more_body": False}
        if asgi_spec == "2.3":
            await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == send_failure:
            raise RuntimeError("synthetic response send failure")
        if send_hook is not None:
            await send_hook(message)
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": asgi_spec},
            "http_version": "1.1",
            "scheme": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": request_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 4000),
        },
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    data = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), data, reads


async def _reserve(app, mode="encrypt", size=7, filename="payload.bin"):
    body, headers = _form({"mode": mode, "size": size, "filename": filename})
    status, _headers, data, _reads = await _request(app, "/api/jobs", body=body, headers=headers)
    assert status == 200
    return json.loads(data)["job"]


@pytest.mark.parametrize("failure", ["blank", "malformed", "duplicate", "file", "decrypt", "verify"])
def test_job_start_rejects_invalid_recipient_fingerprint_fields_without_worker(monkeypatch, failure):
    fingerprint = "QE1-SHA3-256:" + "a" * 64
    values = [fingerprint]
    if failure == "blank":
        values = [""]
    elif failure == "malformed":
        values = [fingerprint + "\n"]
    elif failure == "duplicate":
        values *= 2
    monkeypatch.setattr(JobStore, "start", lambda *_args: pytest.fail("Invalid fingerprint must not start a job"))
    closed_uploads = []
    original_close = api_app.UploadFile.close

    async def close(upload):
        await original_close(upload)
        closed_uploads.append(upload.file.closed)

    monkeypatch.setattr(api_app.UploadFile, "close", close)

    async def scenario():
        app = api_app.create_app()
        store = app.app.state.jobs
        try:
            mode = failure if failure in {"decrypt", "verify"} else "encrypt"
            reserved = await _reserve(app, mode=mode)
            path = f'/api/jobs/{reserved["id"]}'
            status, _, _, _ = await _request(
                app,
                path + "/upload",
                method="PUT",
                body=b"payload",
                headers=[(b"content-type", b"application/octet-stream")],
            )
            assert status == 200
            body, headers = _key_form(fingerprints=values, fingerprint_file=failure == "file")
            status, response_headers, data, _ = await _request(app, path + "/start", body=body, headers=headers)
            assert status == 400 and json.loads(data)["error_code"] == "invalid_recipient_fingerprint"
            assert response_headers[b"cache-control"] == b"no-store"
            assert fingerprint.encode() not in data
            assert store.job.state == "ready" and store.job.task is None and store.job.output is None
            assert closed_uploads and all(closed_uploads)
            status, _, _, _ = await _request(app, path + "/clear")
            assert status == 200 and store.job is None
            lease = store.worker.acquire()
            assert lease is not None
            lease.close()
        finally:
            await store.close()

    asyncio.run(scenario())


def test_job_start_passes_supplied_recipient_fingerprint_to_worker(monkeypatch):
    fingerprint = "QE1-SHA3-256:" + "a" * 64
    received = []

    def process(self, job, pem, password, filename, expected_recipient_fingerprint):
        received.append(expected_recipient_fingerprint)

    monkeypatch.setattr(JobStore, "_process", process)

    async def scenario():
        app = api_app.create_app()
        store = app.app.state.jobs
        try:
            reserved = await _reserve(app)
            path = f'/api/jobs/{reserved["id"]}'
            await _request(
                app,
                path + "/upload",
                method="PUT",
                body=b"payload",
                headers=[(b"content-type", b"application/octet-stream")],
            )
            body, headers = _key_form(fingerprints=[fingerprint])
            status, _, _, _ = await _request(app, path + "/start", body=body, headers=headers)
            assert status == 200
            await store.job.task
            assert received == [fingerprint]
        finally:
            await store.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["encrypt", "decrypt", "verify"])
def test_jobs_upload_start_status_download_and_clear(monkeypatch, mode):
    event_loop_thread = threading.get_ident()

    def process(self, job, pem, password, output_filename, expected_recipient_fingerprint=None):
        assert expected_recipient_fingerprint is None
        assert threading.get_ident() != event_loop_thread
        assert pem == "synthetic key"
        assert password == ("" if mode == "encrypt" else "synthetic password")
        assert job.input.read() == b"payload"
        if mode == "verify":
            job.verification = {"ok": True, "verified": True, "bytesVerified": 7}
        else:
            import tempfile

            job.output = tempfile.TemporaryFile(mode="w+b")
            job.output.write(b"result bytes")
            job.output.seek(0)
            job.result = {"filename": output_filename, "bytes": 12}

    monkeypatch.setattr(JobStore, "_process", process)

    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        try:
            reserved = await _reserve(app, mode, filename="../payload.bin")
            path = f'/api/jobs/{reserved["id"]}'
            assert reserved["state"] == "awaiting_upload"
            status, _, data, _ = await _request(
                app,
                path + "/upload",
                method="PUT",
                body=b"payload",
                headers=[(b"content-type", b"application/octet-stream")],
            )
            assert status == 200 and json.loads(data)["job"]["state"] == "ready"
            body, headers = _key_form("" if mode == "encrypt" else "synthetic password")
            status, _, _, _ = await _request(app, path + "/start", body=body, headers=headers)
            assert status == 200
            await jobs.job.task
            status, response_headers, data, _ = await _request(app, path + "/status")
            assert status == 200 and json.loads(data)["job"]["state"] == "complete"
            assert response_headers[b"cache-control"] == b"no-store"
            assert b"synthetic key" not in data and b"synthetic password" not in data
            assert b"result bytes" not in data
            status, headers, data, _ = await _request(app, path + "/download", auth=False, browser=True)
            if mode == "verify":
                assert status == 409 and json.loads(data)["error_code"] == "result_unavailable"
            else:
                assert status == 200 and data == b"result bytes"
                assert b"attachment;" in headers[b"content-disposition"]
                if mode == "encrypt":
                    assert b"payload.bin.pqc" in headers[b"content-disposition"]
                assert headers[b"content-length"] == b"12"
                assert not jobs.job.downloading
                assert jobs.job.download_finished.is_set()
            output = jobs.job.output
            for _ in range(2):
                status, _, data, _ = await _request(app, path + "/clear")
                assert status == 200 and json.loads(data) == {"ok": True}
            assert jobs.job is None
            assert output is None or output.closed
            status, _, data, _ = await _request(app, path + "/status")
            assert status == 410 and json.loads(data)["error_code"] == "job_expired"
        finally:
            await jobs.close()

    asyncio.run(exercise())


def test_job_reservation_shares_admission_with_legacy_requests():
    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        try:
            job = await _reserve(app)
            for path in api_app.CryptoAdmissionMiddleware.paths:
                status, headers, data, reads = await _request(app, path, body=b"unparsed body")
                assert status == 429 and json.loads(data)["error_code"] == "server_busy"
                assert headers[b"retry-after"] == b"1"
                assert reads == 0
            body, headers = _form({"mode": "encrypt", "size": 0, "filename": "empty"})
            status, _, data, _ = await _request(app, "/api/jobs", body=body, headers=headers)
            assert status == 429 and json.loads(data)["error_code"] == "server_busy"
            await _request(app, f'/api/jobs/{job["id"]}/clear')
            lease = jobs.worker.acquire()
            assert lease is not None
            try:
                status, _, data, _ = await _request(app, "/api/jobs", body=body, headers=headers)
                assert status == 429 and json.loads(data)["error_code"] == "server_busy"
            finally:
                lease.close()
        finally:
            await jobs.close()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "suffix",
    [
        "",
        "/unknown/upload",
        "/unknown/start",
        "/unknown/status",
        "/unknown/cancel",
        "/unknown/clear",
        "/unknown/download",
    ],
)
def test_job_routes_require_auth_before_reading_body(suffix):
    async def exercise():
        app = api_app.create_app()
        try:
            status, _, data, reads = await _request(
                app, "/api/jobs" + suffix, method="PUT" if suffix.endswith("upload") else "POST", auth=False
            )
            assert status == 403 and json.loads(data)["error_code"] == "missing_api_token"
            assert reads == 0 and app.app.state.jobs.job is None
        finally:
            await app.app.state.jobs.close()

    asyncio.run(exercise())


def test_job_download_rejects_token_header_without_browser_session():
    async def exercise():
        app = api_app.create_app()
        try:
            job = await _reserve(app)
            status, _, data, _ = await _request(app, f'/api/jobs/{job["id"]}/download')
            assert status == 403 and json.loads(data)["error_code"] == "invalid_origin"
            assert not app.app.state.jobs.job.downloading
        finally:
            await app.app.state.jobs.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("size", ["-1", "nope", "1.5", "99999999999999999999999"])
def test_job_reservation_rejects_invalid_sizes(size):
    async def exercise():
        app = api_app.create_app()
        try:
            body, headers = _form({"mode": "encrypt", "size": size, "filename": "file"})
            status, _, data, _ = await _request(app, "/api/jobs", body=body, headers=headers)
            assert status == 400 and json.loads(data)["error_code"] == "invalid_job"
            assert app.app.state.jobs.job is None
        finally:
            await app.app.state.jobs.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("failure_stage", ["http.response.start", "http.response.body"])
def test_download_send_failure_releases_handle_even_before_generator_entry(failure_stage):
    async def exercise():
        import tempfile

        app = api_app.create_app()
        jobs = app.app.state.jobs
        try:
            reserved = await _reserve(app)
            job = jobs.job
            job.output = tempfile.TemporaryFile(mode="w+b")
            job.output.write(b"result")
            job.output.seek(0)
            job.result = {"filename": "result.bin", "bytes": 6}
            job.state = "complete"
            job.lease.close()
            with pytest.raises(RuntimeError, match="synthetic response send failure"):
                await _request(
                    app, f'/api/jobs/{reserved["id"]}/download', auth=False, browser=True, send_failure=failure_stage
                )
            assert not job.downloading and job.download_finished.is_set()
            output = job.output
            jobs.cancel(job, discard=True)
            assert output.closed and jobs.job is None
        finally:
            await jobs.close()

    asyncio.run(exercise())


def test_job_body_limits_allow_raw_streaming_and_keep_control_requests_small():
    assert api_app._api_body_limit("/api/jobs") == api_app.SMALL_FORM_MAX_BYTES
    assert api_app._api_body_limit("/api/jobs/id/upload") == api_app.encrypted_limit()
    assert api_app._api_body_limit("/api/jobs/id/start") == cfg.MAX_PEM_BYTES + api_app.SMALL_FORM_MAX_BYTES
    assert api_app._api_body_limit("/api/jobs/id/download") == api_app.SMALL_FORM_MAX_BYTES
    health = api_app._health_payload()["largeFiles"]
    assert health["maxPlaintextBytes"] == cfg.MAX_STREAM_FILE_BYTES
    assert health["maxEncryptedBytes"] == api_app.encrypted_limit()
    assert health["resultTtlSeconds"] == 900


@pytest.mark.parametrize("state", ["uploading", "running", "cancelling"])
@pytest.mark.parametrize("expired", [False, True])
def test_clear_active_job_rejects_without_changing_its_files(state, expired):
    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        try:
            reserved = await _reserve(app)
            job = jobs.job
            job.state = state
            if expired:
                job.deadline = 0
                job.discard = True
            source = job.input
            status, _, data, _ = await _request(app, f'/api/jobs/{reserved["id"]}/clear')
            assert status == 409 and json.loads(data)["error_code"] == "job_active"
            assert jobs.job is job and job.input is source and not source.closed
            job.state = "awaiting_upload"
        finally:
            await jobs.close()

    asyncio.run(exercise())


def test_download_owns_handle_until_final_asgi_send_finishes():
    async def exercise():
        import tempfile

        app = api_app.create_app()
        jobs = app.app.state.jobs
        final_send = asyncio.Event()
        release_send = asyncio.Event()
        response = None
        try:
            reserved = await _reserve(app)
            job = jobs.job
            job.output = tempfile.TemporaryFile(mode="w+b")
            job.output.write(b"result")
            job.output.seek(0)
            job.result = {"filename": "result.bin", "bytes": 6}
            job.state = "complete"
            job.lease.close()
            path = f'/api/jobs/{reserved["id"]}'

            async def block_final_send(message):
                if message["type"] == "http.response.body" and not message.get("more_body", False):
                    final_send.set()
                    await release_send.wait()

            response = asyncio.create_task(
                _request(app, path + "/download", auth=False, browser=True, send_hook=block_final_send)
            )
            await asyncio.wait_for(final_send.wait(), timeout=1)
            assert job.downloading and not job.download_finished.is_set()
            status, _, data, _ = await _request(app, path + "/download", auth=False, browser=True)
            assert status == 409 and json.loads(data)["error_code"] == "download_busy"
            status, _, data, _ = await _request(app, path + "/clear")
            assert status == 409 and json.loads(data)["error_code"] == "download_busy"
            assert not job.output.closed
            release_send.set()
            status, _, data, _ = await response
            assert status == 200 and data == b"result"
            assert not job.downloading and job.download_finished.is_set()
        finally:
            release_send.set()
            if response is not None:
                await response
            await jobs.close()

    asyncio.run(exercise())


def test_legacy_generation_does_not_block_health_and_keeps_job_admission_on_cancellation(monkeypatch):
    release = threading.Event()

    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        started = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()

        def generate(_password):
            assert threading.get_ident() != loop_thread
            loop.call_soon_threadsafe(started.set)
            assert release.wait(timeout=3)
            return {"publicPem": "synthetic public key"}

        monkeypatch.setattr(api_app, "_generate_key_pair", generate)
        monkeypatch.setattr(api_app, "_health_payload", lambda: {"backendReady": True})
        body, headers = _form({"password": "synthetic password"})
        request = asyncio.create_task(_request(app, "/api/keys/generate", body=body, headers=headers))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            status, _, _, _ = await asyncio.wait_for(_request(app, "/api/health", method="GET"), timeout=1)
            assert status == 200
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            body, headers = _form({"mode": "encrypt", "size": 0, "filename": "empty"})
            status, _, data, _ = await _request(app, "/api/jobs", body=body, headers=headers)
            assert status == 429 and json.loads(data)["error_code"] == "server_busy"
        finally:
            release.set()
            if not request.done():
                await request
            await jobs.close()

    asyncio.run(exercise())


def test_duplicate_content_length_rejected_before_job_body_read():
    async def exercise():
        app = api_app.create_app()
        try:
            status, _, data, reads = await _request(app, "/api/jobs", headers=[(b"content-length", b"0")])
            assert status == 400 and json.loads(data)["error_code"] == "invalid_content_length"
            assert reads == 0 and app.app.state.jobs.job is None
        finally:
            await app.app.state.jobs.close()

    asyncio.run(exercise())


def test_app_lifespan_cleans_reserved_job_and_stops_admission():
    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        async with app.app.router.lifespan_context(app.app):
            await _reserve(app)
            source = jobs.job.input
            assert not source.closed
        assert source.closed and jobs.job is None
        assert jobs.worker.acquire() is None

    asyncio.run(exercise())


@pytest.mark.parametrize("identifier", ["unknown", "文件"])
def test_unknown_job_status_and_clear_preserve_another_active_job(identifier):
    async def exercise():
        app = api_app.create_app()
        jobs = app.app.state.jobs
        try:
            await _reserve(app)
            job = jobs.job
            status, _, data, _ = await _request(app, f"/api/jobs/{identifier}/status")
            assert status == 410 and json.loads(data)["error_code"] == "job_expired"
            status, _, data, _ = await _request(app, f"/api/jobs/{identifier}/clear")
            assert status == 200 and json.loads(data) == {"ok": True}
            assert jobs.job is job and not job.input.closed
        finally:
            await jobs.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("cancel_mode", ["cancel", "expire", "shutdown"])
@pytest.mark.parametrize("asgi_spec", ["2.3", "2.4"])
def test_cancel_stops_download_blocked_in_response_send_and_cleans_job(cancel_mode, asgi_spec):
    async def exercise():
        import tempfile
        from contextlib import suppress

        app = api_app.create_app()
        jobs = app.app.state.jobs
        send_started = asyncio.Event()
        response = shutdown = None
        try:
            reserved = await _reserve(app)
            job = jobs.job
            job.output = output = tempfile.TemporaryFile(mode="w+b")
            output.write(b"result")
            output.seek(0)
            job.result = {"filename": "result.bin", "bytes": 6}
            job.state = "complete"
            job.lease.close()

            async def blocked_send(message):
                if message["type"] == "http.response.body":
                    send_started.set()
                    await asyncio.Event().wait()

            response = asyncio.create_task(
                _request(
                    app,
                    f'/api/jobs/{reserved["id"]}/download',
                    auth=False,
                    browser=True,
                    send_hook=blocked_send,
                    asgi_spec=asgi_spec,
                )
            )
            await asyncio.wait_for(send_started.wait(), timeout=1)
            assert job.downloading and not output.closed
            if cancel_mode == "shutdown":
                shutdown = asyncio.create_task(jobs.close())
            elif cancel_mode == "expire":
                job.deadline = 0
                with pytest.raises(api_app.JobError) as error:
                    jobs.get(job.id)
                assert error.value.code == "job_expired"
            else:
                jobs.cancel(job, discard=True)
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(response), timeout=1)
            if shutdown is not None:
                await asyncio.wait_for(shutdown, timeout=1)
            assert not job.downloading and job.download_finished.is_set()
            assert job.download_task is None
            assert output.closed and jobs.job is None
        finally:
            if response is not None:
                response.cancel()
                with suppress(asyncio.CancelledError):
                    await response
            if shutdown is not None:
                await shutdown
            await jobs.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("asgi_spec", ["2.3", "2.4"])
def test_cancel_download_waits_for_owned_read_before_closing_output(asgi_spec):
    async def exercise():
        import io
        from contextlib import suppress

        app = api_app.create_app()
        jobs = app.app.state.jobs
        read_started = asyncio.Event()
        release_read = threading.Event()
        loop = asyncio.get_running_loop()
        response = None

        class BlockingRead(io.BytesIO):
            def read(self, size=-1):
                loop.call_soon_threadsafe(read_started.set)
                assert release_read.wait(timeout=3)
                assert not self.closed
                return super().read(size)

        try:
            reserved = await _reserve(app)
            job = jobs.job
            job.output = output = BlockingRead(b"result")
            job.result = {"filename": "result.bin", "bytes": 6}
            job.state = "complete"
            job.lease.close()
            response = asyncio.create_task(
                _request(app, f'/api/jobs/{reserved["id"]}/download', auth=False, browser=True, asgi_spec=asgi_spec)
            )
            await asyncio.wait_for(read_started.wait(), timeout=1)
            jobs.cancel(job, discard=True)
            await asyncio.sleep(0)
            jobs.cancel(job, discard=True)
            await asyncio.sleep(0)
            assert not response.done() and not output.closed
            assert job.downloading and not job.download_finished.is_set()
            release_read.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(response, timeout=1)
            assert output.closed and jobs.job is None
            assert job.download_task is None and job.download_finished.is_set()
        finally:
            release_read.set()
            if response is not None:
                response.cancel()
                with suppress(asyncio.CancelledError):
                    await response
            await jobs.close()

    asyncio.run(exercise())
