import asyncio
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from crypto_config import cfg
import crypto_core as core
import api_app


def test_sanitize_download_filename_strips_paths_and_control_chars():
    assert api_app.sanitize_download_filename("../secret\x00.txt", "fallback.bin") == "secret.txt"
    assert api_app.sanitize_download_filename('bad"name;.pqc', "fallback.bin") == "bad_name_.pqc"
    assert api_app.sanitize_download_filename("", 'bad"fallback;.pqc') == "bad_fallback_.pqc"
    assert api_app.sanitize_download_filename("", "fallback.bin") == "fallback.bin"
    assert api_app.sanitize_download_filename("", "") == "download.bin"


def test_format_size_uses_mib_units():
    assert api_app.format_size(5 * 1024 * 1024) == "5.0 MiB"


def test_health_payload_is_safe_without_required_native_backend():
    payload = api_app._health_payload()

    assert payload["formatVersion"] == cfg.FORMAT_VERSION
    assert payload["configuredKem"] == cfg.KEM_ALG
    assert payload["dem"] == "AES-256-GCM"
    assert payload["apiToken"] == api_app.LOCAL_API_TOKEN
    assert payload["maxFileBytes"] == cfg.MAX_FILE_BYTES
    assert payload["passwordPolicy"]["minChars"] == cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS


def test_health_payload_reports_ready_backend(monkeypatch):
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: "ML-KEM-768")

    payload = api_app._health_payload()

    assert payload["backendReady"] is True
    assert payload["backendMessage"] == "Post-quantum backend ready."
    assert payload["kem"] == "ML-KEM-768"


def test_content_disposition_quotes_download_filename():
    header = api_app._content_disposition("encrypted file.pqc")

    assert 'filename="encrypted file.pqc"' in header
    assert "filename*=UTF-8''encrypted%20file.pqc" in header


def test_download_filename_suggestion_uses_existing_ui_helper():
    assert api_app.guess_decrypted_filename(Path("payload_encrypted.pqc")) == "payload"


def _multipart_form(
    files: list[tuple[str, str, bytes]], fields: dict[str, str] | None = None
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    boundary = "test-boundary"
    body = b""
    for name, value in (fields or {}).items():
        body += (f"--{boundary}\r\n" f'Content-Disposition: form-data; name="{name}"\r\n' "\r\n" f"{value}\r\n").encode(
            "utf-8"
        )
    for field_name, filename, content in files:
        body += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        ).encode("utf-8")
        body += content
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode("utf-8")
    headers = [
        (b"content-type", f"multipart/form-data; boundary={boundary}".encode("ascii")),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    return body, headers


def _multipart_body(field_name: str, filename: str, content: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    return _multipart_form([(field_name, filename, content)])


def _urlencoded_body(fields: dict[str, str]) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    body = urlencode(fields).encode("utf-8")
    headers = [
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    return body, headers


def _with_api_token(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return headers + [(b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii"))]


def _inspect_key_body_limit() -> int:
    limit = api_app._api_body_limit("/api/keys/inspect")
    assert limit is not None
    return limit


async def _call_app_raw(
    path: str, method: str = "POST", body: bytes = b"", headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    app = api_app.create_app()
    sent: list[dict[str, Any]] = []
    request_sent = False

    async def receive():
        nonlocal request_sent
        if request_sent:
            return {"type": "http.disconnect"}
        request_sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers or [(b"content-length", str(len(body)).encode("ascii"))],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 4000),
    }
    await app(scope, receive, send)

    start = next(message for message in sent if message["type"] == "http.response.start")
    status = int(start["status"])
    response_headers = [(bytes(name), bytes(value)) for name, value in start.get("headers", [])]
    response_body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, response_headers, response_body


async def _call_app(
    path: str, method: str = "POST", body: bytes = b"", headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[int, dict[str, object]]:
    status, _response_headers, response_body = await _call_app_raw(path, method, body, headers)
    return status, json.loads(response_body.decode("utf-8"))


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for header_name, value in headers:
        if header_name.lower() == name:
            return value.decode("latin1")
    return None


def _file_workflow_body() -> tuple[bytes, list[tuple[bytes, bytes]]]:
    return _multipart_form(
        [
            ("file", "payload.txt", b"hello"),
            ("public_key", "public.pem", b"public pem"),
        ],
        {"output_filename": "../safe output.pqc"},
    )


def _decrypt_workflow_body() -> tuple[bytes, list[tuple[bytes, bytes]]]:
    return _multipart_form(
        [
            ("file", "payload_encrypted.pqc", b"ciphertext"),
            ("private_key", "private.pem", b"private pem"),
        ],
        {"password": "correct horse battery staple", "output_filename": "../plain.txt"},
    )


def test_form_text_handles_optional_missing_and_rejects_upload_value():
    assert api_app._form_text({}, "output_filename", required=False) == ""

    upload = api_app.UploadFile(filename="field.txt", file=io.BytesIO(b"value"))
    try:
        try:
            api_app._form_text({"password": upload}, "password")
        except api_app.ApiError as exc:
            assert exc.code == "invalid_field"
        else:
            raise AssertionError("UploadFile text field should fail")
    finally:
        asyncio.run(upload.close())


def test_form_upload_rejects_missing_file():
    try:
        api_app._form_upload({}, "key")
    except api_app.ApiError as exc:
        assert exc.code == "missing_file"
    else:
        raise AssertionError("Missing upload should fail")


def test_read_upload_text_rejects_invalid_utf8():
    upload = api_app.UploadFile(filename="bad.pem", file=io.BytesIO(b"\xff"))

    try:
        try:
            asyncio.run(api_app._read_upload_text(upload, cfg.MAX_PEM_BYTES, "Key file"))
        except api_app.ApiError as exc:
            assert exc.code == "invalid_text"
        else:
            raise AssertionError("Invalid UTF-8 should fail")
    finally:
        asyncio.run(upload.close())


def test_read_upload_bytes_rejects_oversized_upload():
    upload = api_app.UploadFile(filename="huge.bin", file=io.BytesIO(b"12345"))

    try:
        try:
            asyncio.run(api_app._read_upload_bytes(upload, 4, "Input file"))
        except api_app.ApiError as exc:
            assert exc.code == "file_too_large"
        else:
            raise AssertionError("Oversized upload should fail")
    finally:
        asyncio.run(upload.close())


def test_health_route_returns_local_api_token():
    status, response_headers, response_body = asyncio.run(_call_app_raw("/api/health", method="GET"))
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 200
    assert payload["ok"] is True
    assert payload["apiToken"] == api_app.LOCAL_API_TOKEN
    assert _header(response_headers, b"cache-control") == "no-store"
    assert _header(response_headers, b"pragma") == "no-cache"


def test_post_api_rejects_missing_local_api_token():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 403
    assert payload["error_code"] == "missing_api_token"


def test_post_api_rejects_untrusted_origin():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")
    headers = _with_api_token(headers)
    headers.append((b"origin", b"https://evil.example"))

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"


def test_inspect_key_endpoint_rejects_invalid_pem_without_stack_trace():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload == {
        "ok": False,
        "error_code": "unsupported_key",
        "message": "Unsupported or insecure PEM key file.",
    }


def test_api_rejects_oversized_body_before_route_parsing():
    body, headers = _multipart_body("key", "huge.pem", b"x")
    headers = _with_api_token(
        [
            (name, str(_inspect_key_body_limit() + 1).encode("ascii")) if name == b"content-length" else (name, value)
            for name, value in headers
        ]
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 413
    assert payload["error_code"] == "request_too_large"


def test_api_rejects_missing_content_length_after_token_validation():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")
    headers = _with_api_token([(name, value) for name, value in headers if name != b"content-length"])

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 411
    assert payload["error_code"] == "length_required"


def test_api_rejects_invalid_content_length_after_token_validation():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")
    headers = _with_api_token(
        [(name, b"not-an-int") if name == b"content-length" else (name, value) for name, value in headers]
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 400
    assert payload["error_code"] == "invalid_content_length"


def test_api_rejects_stream_that_exceeds_declared_limit():
    body, headers = _multipart_body("key", "huge.pem", b"x" * (_inspect_key_body_limit() + 1))
    headers = _with_api_token([(name, b"1") if name == b"content-length" else (name, value) for name, value in headers])

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 413
    assert payload["error_code"] == "request_too_large"


def test_inspect_key_endpoint_returns_metadata(monkeypatch):
    body, headers = _multipart_body("key", "public.pem", b"public pem")
    key_info = {"key_type": "public", "kem": cfg.KEM_ALG}
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: key_info)

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=_with_api_token(headers)))

    assert status == 200
    assert payload["keyInfo"] == key_info
    assert payload["display"]["Key Type"] == "Public"


def test_inspect_key_endpoint_returns_safe_unexpected_error(monkeypatch):
    body, headers = _multipart_body("key", "public.pem", b"public pem")

    def fail_inspect(_pem: str) -> dict[str, str]:
        raise RuntimeError("internal path should not leak")

    monkeypatch.setattr(core, "inspect_key_pem_strict", fail_inspect)

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=_with_api_token(headers)))

    assert status == 500
    assert payload == {
        "ok": False,
        "error_code": "unexpected_error",
        "message": "An unexpected server error occurred.",
    }


def test_generate_keys_rejects_missing_password_after_form_parse():
    body, headers = _urlencoded_body({})

    status, payload = asyncio.run(_call_app("/api/keys/generate", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "missing_field"


def test_generate_keys_rejects_weak_password():
    body, headers = _urlencoded_body({"password": "short"})

    status, payload = asyncio.run(_call_app("/api/keys/generate", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "weak_password"


def test_generate_keys_returns_pem_payloads(monkeypatch):
    body, headers = _urlencoded_body({"password": "correct horse battery staple"})
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: cfg.KEM_ALG)
    monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: (b"public", b"private"))

    def save_key(raw_key: bytes, kem_alg: str, key_type: str, password: str | None = None) -> str:
        assert kem_alg == cfg.KEM_ALG
        if key_type == "private":
            assert password == "correct horse battery staple"
        return f"{key_type}:{raw_key.decode('ascii')}"

    monkeypatch.setattr(core, "save_key_pem", save_key)

    status, payload = asyncio.run(_call_app("/api/keys/generate", body=body, headers=_with_api_token(headers)))

    assert status == 200
    assert payload["publicPem"] == "public:public"
    assert payload["privatePem"] == "private:private"


def test_generate_keys_reports_backend_unavailable(monkeypatch):
    body, headers = _urlencoded_body({"password": "correct horse battery staple"})
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: cfg.KEM_ALG)
    monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: (None, None))

    status, payload = asyncio.run(_call_app("/api/keys/generate", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "backend_unavailable"


def test_generate_keys_reports_dependency_error(monkeypatch):
    body, headers = _urlencoded_body({"password": "correct horse battery staple"})

    def missing_backend(_kem: str) -> str:
        raise core.CryptoDependencyError("missing")

    monkeypatch.setattr(core, "resolve_kem_algorithm", missing_backend)

    status, payload = asyncio.run(_call_app("/api/keys/generate", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "backend_unavailable"


def test_encrypt_file_rejects_invalid_public_key(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (None, None, "private"))

    status, payload = asyncio.run(_call_app("/api/files/encrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "invalid_public_key"


def test_encrypt_file_returns_download(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.KEM_ALG, "public"))
    monkeypatch.setattr(core, "encrypt_file_pro", lambda data, _public_key, _kem: b"encrypted:" + data)

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/files/encrypt", body=body, headers=_with_api_token(headers))
    )

    assert status == 200
    assert response_body == b"encrypted:hello"
    assert _header(response_headers, b"content-disposition") is not None
    assert "safe output.pqc" in (_header(response_headers, b"content-disposition") or "")


def test_encrypt_file_reports_crypto_dependency_error(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.KEM_ALG, "public"))

    def fail_encrypt(_data: bytes, _public_key: bytes, _kem: str) -> bytes:
        raise core.CryptoDependencyError("missing")

    monkeypatch.setattr(core, "encrypt_file_pro", fail_encrypt)

    status, payload = asyncio.run(_call_app("/api/files/encrypt", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "backend_unavailable"


def test_encrypt_file_reports_encryption_failure(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.KEM_ALG, "public"))
    monkeypatch.setattr(core, "encrypt_file_pro", lambda _data, _public_key, _kem: None)

    status, payload = asyncio.run(_call_app("/api/files/encrypt", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "encryption_failed"


def test_decrypt_file_rejects_public_key_upload(monkeypatch):
    body, headers = _decrypt_workflow_body()
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: {"key_type": "public"})

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "invalid_private_key"


def test_decrypt_file_returns_download(monkeypatch):
    body, headers = _decrypt_workflow_body()
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: {"key_type": "private"})
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (b"private", cfg.KEM_ALG, "private"))
    monkeypatch.setattr(
        core,
        "decrypt_file_pro",
        lambda data, _private_key, expected_kem_alg=None: (b"plain:" + data, expected_kem_alg),
    )

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/files/decrypt", body=body, headers=_with_api_token(headers))
    )

    assert status == 200
    assert response_body == b"plain:ciphertext"
    assert "plain.txt" in (_header(response_headers, b"content-disposition") or "")


def test_decrypt_file_reports_failed_private_key_unlock(monkeypatch):
    body, headers = _decrypt_workflow_body()
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: {"key_type": "private"})
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (None, None, "private"))

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "private_key_failed"


def test_decrypt_file_reports_failed_ciphertext_authentication(monkeypatch):
    body, headers = _decrypt_workflow_body()
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: {"key_type": "private"})
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (b"private", cfg.KEM_ALG, "private"))
    monkeypatch.setattr(core, "decrypt_file_pro", lambda _data, _private_key, expected_kem_alg=None: (None, None))

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "decryption_failed"


def test_decrypt_file_rejects_unsupported_private_key(monkeypatch):
    body, headers = _decrypt_workflow_body()

    def invalid_key(_pem: str) -> dict[str, str]:
        raise core.InvalidKeyFormatError("bad key")

    monkeypatch.setattr(core, "inspect_key_pem_strict", invalid_key)

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "invalid_private_key"


def test_frontend_missing_returns_setup_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(api_app, "STATIC_APP_DIR", tmp_path / "missing-static-app")

    status, _headers, response_body = asyncio.run(_call_app_raw("/missing", method="GET"))

    assert status == 503
    assert b"npm run build" in response_body
