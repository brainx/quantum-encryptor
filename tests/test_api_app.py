import asyncio
import hashlib
import io
import json
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
import starlette.formparsers

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
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["dem"] == "AES-256-GCM"
    assert "apiToken" not in payload
    assert payload["maxFileBytes"] == cfg.MAX_FILE_BYTES
    assert payload["passwordPolicy"]["minChars"] == cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS


def test_health_payload_reports_ready_backend(monkeypatch):
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: "ML-KEM-768")

    payload = api_app._health_payload()

    assert payload["backendReady"] is True
    assert payload["backendMessage"] == "Post-quantum backend ready."
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["kemComponent"] == "ML-KEM-768"


def test_health_payload_reports_partial_capabilities(monkeypatch):
    def missing_current_backend(_kem):
        raise core.CryptoDependencyError("private backend detail")

    monkeypatch.setattr(core, "resolve_kem_algorithm", missing_current_backend)
    monkeypatch.setattr(core, "available_decryption_kem_algorithms", lambda: ("Kyber768",))

    payload = api_app._health_payload()

    assert payload["backendReady"] is False
    assert payload["capabilities"] == {
        "inspect": {"available": True, "reason": ""},
        "generate": {
            "available": False,
            "reason": "ML-KEM-768 is unavailable for new key generation.",
        },
        "encrypt": {
            "available": False,
            "reason": "ML-KEM-768 is unavailable for new encryption.",
        },
        "decrypt": {"available": True, "reason": ""},
    }
    assert "private backend detail" not in str(payload)


def test_content_disposition_quotes_download_filename():
    header = api_app._content_disposition("encrypted file.pqc")

    assert 'filename="encrypted file.pqc"' in header
    assert "filename*=UTF-8''encrypted%20file.pqc" in header


def test_content_disposition_uses_ascii_fallback_for_unicode_filename():
    response = api_app._download_response(b"encrypted", "秘密.pqc")
    header = response.headers["content-disposition"]

    assert header.isascii()
    assert 'filename="__.pqc"' in header
    assert "filename*=UTF-8''%E7%A7%98%E5%AF%86.pqc" in header


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
    path: str,
    method: str = "POST",
    body: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    *,
    host: str | None = None,
    expected_exception: type[Exception] | None = None,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    app = api_app.create_app()
    sent: list[dict[str, Any]] = []
    request_sent = False
    request_headers = list(headers) if headers is not None else [(b"content-length", str(len(body)).encode("ascii"))]
    if host is None:
        host = api_app.LOCAL_API_HOST_HEADER
    if host:
        request_headers.append((b"host", host.encode("ascii")))

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
        "headers": request_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 4000),
    }
    expected_exception_raised = False
    try:
        await app(scope, receive, send)
    except Exception as exc:
        if expected_exception is None or not isinstance(exc, expected_exception):
            raise
        expected_exception_raised = True
    if expected_exception is not None and not expected_exception_raised:
        raise AssertionError(f"Expected {expected_exception.__name__} to be raised by the ASGI app")

    start = next(message for message in sent if message["type"] == "http.response.start")
    status = int(start["status"])
    response_headers = [(bytes(name), bytes(value)) for name, value in start.get("headers", [])]
    response_body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, response_headers, response_body


async def _call_app(
    path: str,
    method: str = "POST",
    body: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    *,
    host: str | None = None,
) -> tuple[int, dict[str, object]]:
    status, _response_headers, response_body = await _call_app_raw(path, method, body, headers, host=host)
    return status, json.loads(response_body.decode("utf-8"))


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for header_name, value in headers:
        if header_name.lower() == name:
            return value.decode("latin1")
    return None


def _assert_api_no_store(headers: list[tuple[bytes, bytes]]) -> None:
    assert _header(headers, b"cache-control") == "no-store"
    assert _header(headers, b"pragma") == "no-cache"


def test_call_app_raw_requires_expected_exception_to_occur():
    with pytest.raises(
        AssertionError,
        match="Expected RuntimeError to be raised by the ASGI app",
    ):
        asyncio.run(
            _call_app_raw(
                "/api/health",
                method="GET",
                expected_exception=RuntimeError,
            )
        )


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


def _password_change_body(
    pem: bytes = b"encrypted private pem", **fields: str
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    passwords = {
        "current_password": "river metal orbit cactus 47",
        "new_password": "harbor maple cloud copper 93",
    }
    passwords.update(fields)
    return _multipart_form([("private_key", "../my?private.pem", pem)], passwords)


@pytest.fixture
def tracked_uploads(monkeypatch):
    uploads = []
    original_tempfile = starlette.formparsers.SpooledTemporaryFile

    def track(*args, **kwargs):
        upload = original_tempfile(*args, **kwargs)
        uploads.append(upload)
        return upload

    monkeypatch.setattr(starlette.formparsers, "SpooledTemporaryFile", track)
    try:
        yield uploads
    finally:
        for upload in uploads:
            upload.close()


@pytest.fixture
def recovery_key():
    public = bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES)
    private = bytes(cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES) + public + hashlib.sha3_256(public).digest() + bytes(32)
    password = "river metal orbit cactus 47"
    private_pem = core.save_key_pem(private, cfg.KEM_ALG, "private", password)
    public_pem = core.save_key_pem(public, cfg.KEM_ALG, "public")
    assert private_pem is not None and public_pem is not None
    return private, private_pem, public_pem, password


@pytest.fixture
def verifiable_file(monkeypatch, recovery_key):
    private, private_pem, _public_pem, password = recovery_key

    class FakeKEM:
        details = {"length_secret_key": len(private), "length_ciphertext": 32}

        def __init__(self, _alg):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    class FakeOQS:
        KeyEncapsulation = FakeKEM

    def shared_secret(raw_private):
        start = cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES
        return hashlib.sha256(raw_private[start : start + cfg.MLKEM768_PUBLIC_KEY_BYTES]).digest()

    monkeypatch.setattr(core, "_require_oqs", lambda: FakeOQS)
    monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", lambda _alg: (cfg.KEM_ALG,))
    monkeypatch.setattr(core, "_decapsulate_shared_secret", lambda _oqs, _alg, raw, _ct: shared_secret(raw))

    def encrypt(plaintext):
        alg = cfg.KEM_ALG.encode("ascii")
        nonce = bytes(cfg.AES_NONCE_BYTES)
        header = (
            cfg.MAGIC_BYTES
            + cfg.LEGACY_FORMAT_VERSION.to_bytes(2, "big")
            + len(alg).to_bytes(2, "big")
            + alg
            + (32).to_bytes(4, "big")
            + bytes(32)
            + nonce
        )
        return header + AESGCM(core.derive_symmetric_key_hkdf(shared_secret(private))).encrypt(nonce, plaintext, header)

    return encrypt, private_pem, password


def test_recovery_and_verification_health_flags_are_independent_of_native_backend(monkeypatch):
    def unavailable(_alg):
        raise core.CryptoDependencyError()

    monkeypatch.setattr(core, "resolve_kem_algorithm", unavailable)
    monkeypatch.setattr(core, "available_decryption_kem_algorithms", lambda: ())
    payload = api_app._health_payload()
    assert payload["supportsPublicKeyRecovery"] is True
    assert payload["supportsFileVerification"] is True
    assert payload["capabilities"]["decrypt"]["available"] is False


@pytest.mark.parametrize("supplied", ["none", "match", "different", "different_algorithm"])
def test_recover_public_api_preserves_key_and_reports_optional_match(
    monkeypatch, recovery_key, supplied, tracked_uploads
):
    private, private_pem, public_pem, password = recovery_key
    files = [("private_key", "../my?private.pem", private_pem.encode())]
    expected_match = None
    if supplied != "none":
        supplied_pem = public_pem.replace("\n", "\r\n")
        expected_match = supplied == "match"
        if supplied == "different":
            supplied_pem = core.save_key_pem(
                bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES - 32) + bytes(range(32)), cfg.KEM_ALG, "public"
            )
        elif supplied == "different_algorithm":
            supplied_pem = public_pem.replace(cfg.KEM_ALG, "Kyber768")
        assert supplied_pem is not None
        files.append(("public_key", "public.pem", supplied_pem.encode()))
    monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("Recovery must not require native backend"))
    body, headers = _multipart_form(files, {"password": password})

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/keys/recover-public", body=body, headers=_with_api_token(headers))
    )

    assert status == 200
    assert json.loads(response_body) == {
        "ok": True,
        "publicPem": public_pem,
        "kem": cfg.KEM_ALG,
        "publicKeyFingerprint": core.get_private_key_public_fingerprint(private, cfg.KEM_ALG),
        "publicFilename": "my_private_public.pem",
        "matchesSuppliedPublicKey": expected_match,
    }
    assert b"privatePem" not in response_body and password.encode() not in response_body
    assert tracked_uploads and all(upload.closed for upload in tracked_uploads)
    _assert_api_no_store(response_headers)


@pytest.mark.parametrize("supplied", [b"invalid public", b""])
def test_recover_public_api_rejects_invalid_optional_public_before_unlock(monkeypatch, supplied):
    monkeypatch.setattr(
        core, "recover_public_key_pem", lambda *_args: pytest.fail("Invalid public must fail before scrypt")
    )
    body, headers = _multipart_form(
        [("private_key", "private.pem", b"private pem"), ("public_key", "public.pem", supplied)],
        {"password": "password"},
    )
    status, payload = asyncio.run(_call_app("/api/keys/recover-public", body=body, headers=_with_api_token(headers)))
    assert status == 400
    assert payload["error_code"] == "invalid_public_key"


def test_inspect_file_api_explicitly_reports_unauthenticated_metadata(monkeypatch, verifiable_file, tracked_uploads):
    encrypt, _private_pem, _password = verifiable_file
    blob = encrypt(b"confidential plaintext")
    # Even a structurally valid file with a corrupted tag is only inspected, never verified.
    blob = blob[:-1] + bytes([blob[-1] ^ 1])
    monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("Inspection must not use liboqs"))
    body, headers = _multipart_body("file", "file.pqc", blob)

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/files/inspect", body=body, headers=_with_api_token(headers))
    )
    metadata = core.inspect_encrypted_file_strict(blob)
    assert status == 200
    assert json.loads(response_body) == {
        "ok": True,
        "authenticated": False,
        "metadata": {
            "formatVersion": cfg.LEGACY_FORMAT_VERSION,
            "kem": cfg.KEM_ALG,
            "headerBytes": metadata.header_bytes,
            "kemCiphertextBytes": 32,
            "x25519CiphertextBytes": 0,
            "encryptedPayloadBytes": metadata.encrypted_payload_bytes,
            "totalBytes": len(blob),
        },
    }
    _assert_api_no_store(response_headers)
    assert tracked_uploads and all(upload.closed for upload in tracked_uploads)


@pytest.mark.parametrize("plaintext", [b"", b"confidential plaintext"])
def test_verify_file_api_authenticates_without_returning_plaintext(
    verifiable_file, recovery_key, plaintext, tracked_uploads
):
    encrypt, private_pem, password = verifiable_file
    private, _private_pem, _public_pem, _password = recovery_key
    body, headers = _multipart_form(
        [("file", "file.pqc", encrypt(plaintext)), ("private_key", "private.pem", private_pem.encode())],
        {"password": password},
    )

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/files/verify", body=body, headers=_with_api_token(headers))
    )
    assert status == 200
    assert json.loads(response_body) == {
        "ok": True,
        "verified": True,
        "kem": cfg.KEM_ALG,
        "formatVersion": cfg.LEGACY_FORMAT_VERSION,
        "bytesVerified": len(plaintext),
        "publicKeyFingerprint": core.get_private_key_public_fingerprint(private, cfg.KEM_ALG),
    }
    assert b"confidential plaintext" not in response_body
    assert _header(response_headers, b"content-disposition") is None
    _assert_api_no_store(response_headers)
    assert tracked_uploads and all(upload.closed for upload in tracked_uploads)


@pytest.mark.parametrize(
    "failure, code",
    [
        ("tag", "verification_failed"),
        ("header", "verification_failed"),
        ("wrong_key", "verification_failed"),
        ("algorithm", "verification_failed"),
        ("malformed", "invalid_encrypted_file"),
        ("password", "private_key_failed"),
        ("backend", "backend_unavailable"),
    ],
)
def test_verify_file_api_rejects_failed_authentication_safely(
    monkeypatch, verifiable_file, recovery_key, failure, code
):
    encrypt, private_pem, password = verifiable_file
    blob = encrypt(b"confidential plaintext")
    if failure in {"tag", "header"}:
        index = -1 if failure == "tag" else core.inspect_encrypted_file_strict(blob).header_bytes - 1
        changed = bytearray(blob)
        changed[index] ^= 1
        blob = bytes(changed)
    elif failure == "wrong_key":
        public = bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES - 32) + bytes(range(32))
        private = bytes(cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES) + public + hashlib.sha3_256(public).digest() + bytes(32)
        private_pem = core.save_key_pem(private, cfg.KEM_ALG, "private", password)
    elif failure == "algorithm":
        private_pem = core.save_key_pem(recovery_key[0], "Kyber768", "private", password)
    elif failure == "malformed":
        blob = b"not an encrypted container"
    elif failure == "password":
        password = "incorrect but strong password 83"
    else:

        def unavailable(_alg):
            raise core.CryptoDependencyError("private backend detail")

        monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", unavailable)
    assert private_pem is not None
    body, headers = _multipart_form(
        [("file", "file.pqc", blob), ("private_key", "private.pem", private_pem.encode())], {"password": password}
    )

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/files/verify", body=body, headers=_with_api_token(headers))
    )
    payload = json.loads(response_body)
    assert status == (503 if failure == "backend" else 400)
    assert payload["error_code"] == code
    assert "verified" not in payload and "bytesVerified" not in payload and "publicKeyFingerprint" not in payload
    assert b"confidential plaintext" not in response_body and b"private backend detail" not in response_body
    _assert_api_no_store(response_headers)


def test_password_change_health_capability_does_not_require_native_backend(monkeypatch):
    def unavailable(*_args):
        raise core.CryptoDependencyError("unavailable")

    monkeypatch.setattr(core, "resolve_kem_algorithm", unavailable)
    monkeypatch.setattr(core, "available_decryption_kem_algorithms", unavailable)

    assert api_app._health_payload()["supportsKeyPasswordChange"] is True


def test_password_change_api_rewraps_existing_key_without_native_backend(monkeypatch):
    public_key = bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES)
    raw_private = bytes(1152) + public_key + hashlib.sha3_256(public_key).digest() + bytes(32)
    original = core.save_key_pem(raw_private, cfg.KEM_ALG, "private", "river metal orbit cactus 47")
    assert original is not None
    monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("Password changes must not use liboqs"))
    body, headers = _password_change_body(original.encode("ascii"))

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/keys/change-password", body=body, headers=_with_api_token(headers))
    )
    payload = json.loads(response_body)

    assert status == 200
    assert payload["ok"] is True
    assert payload["kem"] == cfg.KEM_ALG
    assert payload["privateFilename"] == "my_private_updated.pem"
    assert payload["publicKeyFingerprint"] == core.get_private_key_public_fingerprint(raw_private, cfg.KEM_ALG)
    assert core.load_key_pem(payload["privatePem"], "harbor maple cloud copper 93") == (
        raw_private,
        cfg.KEM_ALG,
        "private",
    )
    assert core.load_key_pem(payload["privatePem"], "river metal orbit cactus 47") == (None, None, None)
    _assert_api_no_store(response_headers)


@pytest.mark.parametrize(
    ("exception", "status_code", "error_code"),
    [
        (core.InvalidKeyFormatError("private detail"), 400, "invalid_private_key"),
        (core.UnencryptedPrivateKeyError("private detail"), 400, "invalid_private_key"),
        (core.UnsupportedKDFError("private detail"), 400, "invalid_private_key"),
        (core.UnsupportedAlgorithmError("private detail"), 400, "invalid_private_key"),
        (core.AuthenticationFailedError("private detail"), 400, "private_key_failed"),
        (core.PasswordRequiredError("private detail"), 400, "password_required"),
        (core.WeakPasswordError("private detail"), 400, "weak_password"),
        (core.CryptoCoreError("private detail"), 500, "password_change_failed"),
        (RuntimeError("private detail"), 500, "unexpected_error"),
    ],
)
def test_password_change_api_returns_safe_errors_and_recovers(monkeypatch, exception, status_code, error_code):
    def fail(*_args):
        raise exception

    monkeypatch.setattr(core, "rewrap_private_key_pem", fail)
    body, headers = _password_change_body()
    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/keys/change-password", body=body, headers=_with_api_token(headers))
    )
    payload = json.loads(response_body)

    assert status == status_code
    assert payload["error_code"] == error_code
    assert "private detail" not in payload["message"]
    assert "privatePem" not in payload
    _assert_api_no_store(response_headers)

    monkeypatch.setattr(core, "rewrap_private_key_pem", lambda *_args: ("updated", cfg.KEM_ALG, "fingerprint"))
    recovered_status, _payload = asyncio.run(
        _call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers))
    )
    assert recovered_status == 200


@pytest.mark.parametrize("field", ["current_password", "new_password"])
@pytest.mark.parametrize(
    "value, expected_status, error_code",
    [("", 400, "password_required"), ("é" * 2049, 413, "field_too_large")],
    ids=["empty", "too_many_utf8_bytes"],
)
def test_password_change_api_bounds_password_fields_before_crypto(
    monkeypatch, field, value, expected_status, error_code
):
    monkeypatch.setattr(core, "rewrap_private_key_pem", lambda *_args: pytest.fail("Crypto must not run"))
    body, headers = _password_change_body(**{field: value})

    status, payload = asyncio.run(_call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers)))

    assert status == expected_status
    assert payload["error_code"] == error_code


def test_password_change_api_bounds_pem_upload_before_crypto(monkeypatch):
    monkeypatch.setattr(core, "rewrap_private_key_pem", lambda *_args: pytest.fail("Crypto must not run"))
    monkeypatch.setattr(cfg, "MAX_PEM_BYTES", 4)
    body, headers = _password_change_body(b"12345")

    status, payload = asyncio.run(_call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers)))

    assert status == 413
    assert payload["error_code"] == "file_too_large"


@pytest.mark.parametrize(
    "failure, expected_status, error_code",
    [
        ("body_size", 413, "request_too_large"),
        ("missing_length", 411, "length_required"),
        ("missing_token", 403, "missing_api_token"),
        ("origin", 403, "forbidden_origin"),
    ],
)
@pytest.mark.parametrize(
    "path", ["/api/keys/change-password", "/api/keys/recover-public", "/api/files/inspect", "/api/files/verify"]
)
def test_protected_crypto_api_rejects_invalid_request_before_parse(
    monkeypatch, failure, expected_status, error_code, path
):
    async def must_not_parse(*_args, **_kwargs):
        pytest.fail("Invalid request must not be parsed")

    monkeypatch.setattr(api_app, "_form", must_not_parse)
    body, headers = _password_change_body()
    headers = _with_api_token(headers)
    if failure == "body_size":
        headers = [(name, value) for name, value in headers if name != b"content-length"]
        limit = api_app._api_body_limit(path)
        assert limit is not None
        headers.append((b"content-length", str(limit + 1).encode("ascii")))
    elif failure == "missing_length":
        headers = [(name, value) for name, value in headers if name != b"content-length"]
    elif failure == "missing_token":
        headers = [(name, value) for name, value in headers if name != b"x-quantum-encryptor-token"]
    else:
        headers.append((b"origin", b"https://evil.example"))

    status, response_headers, response_body = asyncio.run(_call_app_raw(path, body=body, headers=headers))

    assert status == expected_status
    assert json.loads(response_body)["error_code"] == error_code
    _assert_api_no_store(response_headers)


def test_password_change_api_cancellation_keeps_capacity_until_worker_finishes(monkeypatch):
    release = threading.Event()
    calls = []
    uploads = []
    original_tempfile = starlette.formparsers.SpooledTemporaryFile

    def track_upload(*args, **kwargs):
        upload = original_tempfile(*args, **kwargs)
        uploads.append(upload)
        return upload

    monkeypatch.setattr(starlette.formparsers, "SpooledTemporaryFile", track_upload)
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: cfg.KEM_ALG)
    monkeypatch.setattr(core, "available_decryption_kem_algorithms", lambda: (cfg.KEM_ALG,))

    async def exercise():
        started = asyncio.Event()
        loop = asyncio.get_running_loop()

        def change(*args):
            calls.append(args)
            loop.call_soon_threadsafe(started.set)
            assert release.wait(timeout=5), "Worker was not released"
            return "updated", cfg.KEM_ALG, "fingerprint"

        monkeypatch.setattr(core, "rewrap_private_key_pem", change)
        body, headers = _password_change_body()
        request = asyncio.create_task(
            _call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers))
        )
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            health_status, _payload = await asyncio.wait_for(_call_app("/api/health", method="GET"), timeout=1)
            assert health_status == 200
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            assert uploads and all(upload.closed for upload in uploads)

            status, response_headers, response_body = await asyncio.wait_for(
                _call_app_raw("/api/keys/change-password", body=body, headers=_with_api_token(headers)), timeout=1
            )
            assert status == 429
            assert json.loads(response_body)["error_code"] == "server_busy"
            assert _header(response_headers, b"retry-after") == "1"
            _assert_api_no_store(response_headers)
            assert len(calls) == 1
        finally:
            release.set()
            # Wait for the synchronous wrapper's finally, not merely the core call's return.
            acquired = await asyncio.to_thread(api_app._crypto_operation_lock.acquire, True, 2)
            assert acquired
            api_app._crypto_operation_lock.release()
            if not request.done():
                await request

        monkeypatch.setattr(core, "rewrap_private_key_pem", lambda *_args: ("new result", cfg.KEM_ALG, "fp"))
        status, payload = await _call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers))
        assert status == 200
        assert payload["privatePem"] == "new result"
        assert all(upload.closed for upload in uploads)

    asyncio.run(exercise())


def _new_crypto_workflow_body(path: str, password: str = "river metal orbit cactus 47"):
    if path == "/api/keys/recover-public":
        return _multipart_form([("private_key", "private.pem", b"private pem")], {"password": password})
    if path == "/api/files/inspect":
        return _multipart_body("file", "file.pqc", b"encrypted file")
    return _multipart_form(
        [("file", "file.pqc", b"encrypted file"), ("private_key", "private.pem", b"private pem")],
        {"password": password},
    )


@pytest.mark.parametrize("path", ["/api/keys/recover-public", "/api/files/verify"])
@pytest.mark.parametrize(
    "password, status_code, code",
    [("", 400, "password_required"), ("é" * 2049, 413, "field_too_large")],
    ids=["missing", "oversized_utf8"],
)
def test_new_crypto_api_password_bounds_precede_worker(monkeypatch, path, password, status_code, code):
    monkeypatch.setattr(api_app, "_run_crypto_operation", lambda *_args: pytest.fail("Worker must not start"))
    body, headers = _new_crypto_workflow_body(path, password)
    status, payload = asyncio.run(_call_app(path, body=body, headers=_with_api_token(headers)))
    assert status == status_code
    assert payload["error_code"] == code


@pytest.mark.parametrize(
    "path, field, limit_name",
    [
        ("/api/keys/recover-public", "private_key", "MAX_PEM_BYTES"),
        ("/api/keys/recover-public", "public_key", "MAX_PEM_BYTES"),
        ("/api/files/verify", "private_key", "MAX_PEM_BYTES"),
        ("/api/files/verify", "file", "MAX_ENCRYPTED_FILE_BYTES"),
        ("/api/files/inspect", "file", "MAX_ENCRYPTED_FILE_BYTES"),
    ],
)
def test_new_crypto_api_bounds_each_upload_before_worker(monkeypatch, path, field, limit_name):
    monkeypatch.setattr(cfg, limit_name, 4)
    monkeypatch.setattr(api_app, "_run_crypto_operation", lambda *_args: pytest.fail("Worker must not start"))
    files = [("file", "file.pqc", b"123"), ("private_key", "key.pem", b"123")]
    if path.endswith("recover-public"):
        files = [("private_key", "key.pem", b"123"), ("public_key", "public.pem", b"123")]
    elif path.endswith("inspect"):
        files = files[:1]
    files = [(name, filename, b"12345" if name == field else content) for name, filename, content in files]
    body, headers = _multipart_form(files, {} if path.endswith("inspect") else {"password": "pw"})
    status, payload = asyncio.run(_call_app(path, body=body, headers=_with_api_token(headers)))
    assert status == 413
    assert payload["error_code"] == "file_too_large"


@pytest.mark.parametrize(
    "path, operation",
    [
        ("/api/keys/recover-public", "_recover_public_key"),
        ("/api/files/verify", "_verify_encrypted_file"),
        ("/api/files/inspect", "_inspect_encrypted_file"),
    ],
)
def test_new_crypto_api_cancellation_retains_shared_worker_capacity(monkeypatch, path, operation, tracked_uploads):
    release = threading.Event()

    async def exercise():
        started = asyncio.Event()
        loop = asyncio.get_running_loop()

        def blocked(*_args):
            loop.call_soon_threadsafe(started.set)
            assert release.wait(timeout=5)
            raise core.CryptoCoreError("late worker error")

        monkeypatch.setattr(api_app, operation, blocked)
        body, headers = _new_crypto_workflow_body(path)
        request = asyncio.create_task(_call_app(path, body=body, headers=_with_api_token(headers)))
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            assert tracked_uploads and all(upload.closed for upload in tracked_uploads)
            for busy_path in (
                "/api/keys/change-password",
                "/api/keys/recover-public",
                "/api/files/verify",
                "/api/files/inspect",
            ):
                busy_body, busy_headers = (
                    _password_change_body()
                    if busy_path.endswith("change-password")
                    else _new_crypto_workflow_body(busy_path)
                )
                status, response_headers, response_body = await asyncio.wait_for(
                    _call_app_raw(busy_path, body=busy_body, headers=_with_api_token(busy_headers)), timeout=1
                )
                assert status == 429
                assert json.loads(response_body)["error_code"] == "server_busy"
                assert _header(response_headers, b"retry-after") == "1"
                _assert_api_no_store(response_headers)
                assert all(upload.closed for upload in tracked_uploads)
        finally:
            release.set()
            acquired = await asyncio.to_thread(api_app._crypto_operation_lock.acquire, True, 2)
            assert acquired
            api_app._crypto_operation_lock.release()
            if not request.done():
                await request
        monkeypatch.setattr(core, "rewrap_private_key_pem", lambda *_args: ("updated", cfg.KEM_ALG, "fingerprint"))
        body, headers = _password_change_body()
        status, payload = await _call_app("/api/keys/change-password", body=body, headers=_with_api_token(headers))
        assert status == 200
        assert payload["privatePem"] == "updated"

    asyncio.run(exercise())


def _invalid_key_request_headers(*extra_headers: tuple[bytes, bytes]) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")
    return body, headers + list(extra_headers)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:4000", ("http", "127.0.0.1", 4000)),
        ("HTTP://127.0.0.1:4000", ("http", "127.0.0.1", 4000)),
        ("http://127.0.0.1", ("http", "127.0.0.1", 80)),
        ("http://localhost:4000", ("http", "localhost", 4000)),
        ("http://[::1]:4000", ("http", "::1", 4000)),
        ("http://127.0.0.2:4000", ("http", "127.0.0.2", 4000)),
    ],
)
def test_parse_origin_normalizes_valid_http_authorities(value, expected):
    assert api_app._parse_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "null",
        "https://127.0.0.1:4000",
        "http://user@127.0.0.1:4000",
        "http://127.0.0.1:4000/path",
        "http://127.0.0.1:4000?query=1",
        "http://127.0.0.1:4000#fragment",
        "http://127.0.0.1:4000?",
        "http://127.0.0.1:4000#",
        "http://127.0.0.1:4000?#",
        " http://127.0.0.1:4000",
        "http://127.0.0.1:4000 ",
        "http://127.0.0.1:4000\n",
        "http://127.0.0.1:not-a-port",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:4000.evil",
    ],
)
def test_parse_origin_rejects_malformed_authorities(value):
    assert api_app._parse_origin(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1:4000", ("127.0.0.1", 4000)),
        ("localhost:4000", ("localhost", 4000)),
        ("[::1]:4000", ("::1", 4000)),
        ("127.0.0.2:4000", ("127.0.0.2", 4000)),
    ],
)
def test_parse_host_authority_normalizes_valid_authority(value, expected):
    assert api_app._parse_host_authority(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "null",
        "user@127.0.0.1:4000",
        "http://127.0.0.1:4000",
        "127.0.0.1:4000/path",
        "127.0.0.1:4000?query=1",
        "127.0.0.1:4000#fragment",
        "127.0.0.1:4000?",
        "127.0.0.1:4000#",
        "127.0.0.1:4000?#",
        " 127.0.0.1:4000",
        "127.0.0.1:4000 ",
        "127.0.0.1:4000\n",
        "127.0.0.1:not-a-port",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:4000.evil",
    ],
)
def test_parse_host_authority_rejects_malformed_authorities(value):
    assert api_app._parse_host_authority(value) is None


def test_allowed_browser_authorities_are_finite_and_exact():
    assert api_app._allowed_browser_authorities(4000, enable_vite_dev=False) == {
        ("http", "127.0.0.1", 4000),
    }
    assert api_app._allowed_browser_authorities(4000, enable_vite_dev=True) == {
        ("http", "127.0.0.1", 4000),
        ("http", "127.0.0.1", 4001),
    }


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


@pytest.mark.parametrize(
    ("path", "files", "fields", "error_code"),
    [
        ("/api/keys/inspect", [("wrong_field", "key.pem", b"key")], {}, "missing_file"),
        ("/api/keys/change-password", [("private_key", "key.pem", b"key")], {}, "password_required"),
        ("/api/keys/change-password", [("wrong_field", "key.pem", b"key")], {}, "missing_file"),
        ("/api/keys/recover-public", [("private_key", "key.pem", b"key")], {}, "password_required"),
        (
            "/api/keys/recover-public",
            [("private_key", "key.pem", b"key")],
            {"password": "secret"},
            "invalid_private_key",
        ),
        ("/api/files/inspect", [("file", "file.pqc", b"bad")], {}, "invalid_encrypted_file"),
        (
            "/api/files/verify",
            [("file", "file.pqc", b"bad"), ("private_key", "key.pem", b"key")],
            {"password": "secret"},
            "invalid_encrypted_file",
        ),
        ("/api/files/encrypt", [("file", "plain.txt", b"plaintext")], {}, "missing_file"),
        (
            "/api/files/decrypt",
            [("file", "file.pqc", b"ciphertext"), ("private_key", "private.pem", b"private key")],
            {},
            "missing_field",
        ),
        (
            "/api/files/encrypt",
            [("file", "plain.txt", b"too large"), ("public_key", "public.pem", b"public key")],
            {},
            "file_too_large",
        ),
    ],
)
def test_api_closes_all_uploads_after_validation_error(monkeypatch, path, files, fields, error_code):
    uploads = []
    original_tempfile = starlette.formparsers.SpooledTemporaryFile

    def track_upload(*args, **kwargs):
        upload = original_tempfile(*args, **kwargs)
        uploads.append(upload)
        return upload

    monkeypatch.setattr(starlette.formparsers, "SpooledTemporaryFile", track_upload)
    monkeypatch.setattr(api_app.cfg, "MAX_FILE_BYTES", 4)
    body, headers = _multipart_form(files, fields)

    try:
        status, payload = asyncio.run(_call_app(path, body=body, headers=_with_api_token(headers)))

        assert status in {400, 413}
        assert payload["error_code"] == error_code
        assert len(uploads) == len(files)
        assert all(upload.closed for upload in uploads)
    finally:
        for upload in uploads:
            upload.close()


def test_health_route_sets_auth_cookie_without_disclosing_token():
    status, response_headers, response_body = asyncio.run(_call_app_raw("/api/health", method="GET"))
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 200
    assert payload["ok"] is True
    assert "apiToken" not in payload
    set_cookie = _header(response_headers, b"set-cookie")
    assert set_cookie is not None
    assert f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie
    assert _header(response_headers, b"cache-control") == "no-store"
    assert _header(response_headers, b"pragma") == "no-cache"


def test_health_route_sets_auth_cookie_for_matching_browser_authority():
    status, response_headers, _response_body = asyncio.run(
        _call_app_raw(
            "/api/health",
            method="GET",
            headers=[(b"origin", b"http://127.0.0.1:4000")],
            host="127.0.0.1:4000",
        )
    )

    assert status == 200
    assert _header(response_headers, b"set-cookie") is not None


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1:4001",
        "localhost:4000",
        "[::1]:4000",
        "127.0.0.2:4000",
        "127.0.0.1:4000.evil",
        "127.0.0.1:4000?",
        "127.0.0.1:4000#",
        "127.0.0.1:4000?#",
        "",
    ],
)
def test_health_route_rejects_invalid_or_missing_host_without_setting_cookie(host):
    status, response_headers, response_body = asyncio.run(_call_app_raw("/api/health", method="GET", host=host))
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 403
    assert payload["error_code"] == "forbidden_host"
    assert _header(response_headers, b"set-cookie") is None


def test_health_route_rejects_duplicate_host_without_setting_cookie():
    status, response_headers, response_body = asyncio.run(
        _call_app_raw(
            "/api/health",
            method="GET",
            headers=[(b"host", b"127.0.0.1:4000")],
            host="127.0.0.1:4000",
        )
    )
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 403
    assert payload["error_code"] == "forbidden_host"
    assert _header(response_headers, b"set-cookie") is None


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:4001",
        "http://[::1]:4000",
        "http://127.0.0.2:4000",
        "http://127.0.0.1:4000.evil",
        "http://127.0.0.1:4000?",
        "http://127.0.0.1:4000#",
        "http://127.0.0.1:4000?#",
    ],
)
def test_health_route_rejects_present_invalid_origin_without_setting_cookie(origin):
    status, response_headers, response_body = asyncio.run(
        _call_app_raw(
            "/api/health",
            method="GET",
            headers=[(b"origin", origin.encode("ascii"))],
            host="127.0.0.1:4000",
        )
    )
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"
    assert _header(response_headers, b"set-cookie") is None


def test_health_route_allows_direct_navigation_without_origin():
    status, response_headers, _response_body = asyncio.run(
        _call_app_raw("/api/health", method="GET", host="127.0.0.1:4000")
    )

    assert status == 200
    assert _header(response_headers, b"set-cookie") is not None


def test_security_headers_are_applied_to_api_responses():
    status, response_headers, _body = asyncio.run(_call_app_raw("/api/health", method="GET"))

    assert status == 200
    csp = _header(response_headers, b"content-security-policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert _header(response_headers, b"x-content-type-options") == "nosniff"
    assert _header(response_headers, b"x-frame-options") == "DENY"
    assert _header(response_headers, b"referrer-policy") == "no-referrer"


def test_security_headers_cover_middleware_rejections():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")

    status, response_headers, _body = asyncio.run(_call_app_raw("/api/keys/inspect", body=body, headers=headers))

    assert status == 403
    assert _header(response_headers, b"x-content-type-options") == "nosniff"
    assert _header(response_headers, b"content-security-policy") is not None
    _assert_api_no_store(response_headers)


def test_api_cache_policy_replaces_weaker_handler_headers(monkeypatch):
    async def cacheable_health(_request):
        return api_app.Response(
            b"health",
            headers={"Cache-Control": "public, max-age=3600", "Pragma": "cache"},
        )

    monkeypatch.setattr(api_app, "health", cacheable_health)

    status, response_headers, _response_body = asyncio.run(_call_app_raw("/api/health", method="GET"))

    assert status == 200
    assert [value for name, value in response_headers if name.lower() == b"cache-control"] == [b"no-store"]
    assert [value for name, value in response_headers if name.lower() == b"pragma"] == [b"no-cache"]


def test_unhandled_api_error_is_not_cacheable(monkeypatch):
    async def failing_health(_request):
        raise RuntimeError("failed before response start")

    monkeypatch.setattr(api_app, "health", failing_health)

    status, response_headers, _response_body = asyncio.run(
        _call_app_raw(
            "/api/health",
            method="GET",
            expected_exception=RuntimeError,
        )
    )

    assert status == 500
    _assert_api_no_store(response_headers)


def test_post_api_accepts_auth_cookie():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")
    headers.append((b"cookie", f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}".encode("ascii")))
    headers.append((b"origin", b"http://127.0.0.1:4000"))

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 400
    assert payload["error_code"] == "unsupported_key"


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:4001",
        "http://localhost:4000",
    ],
)
def test_post_api_rejects_cookie_from_non_exact_browser_authority(origin):
    body, headers = _invalid_key_request_headers(
        (b"cookie", f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}".encode("ascii")),
        (b"origin", origin.encode("ascii")),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"


def test_post_api_rejects_cookie_without_origin():
    body, headers = _invalid_key_request_headers(
        (b"cookie", f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}".encode("ascii")),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "missing_api_token"


@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:4000"])
def test_post_api_accepts_explicit_token_from_exact_local_client(origin):
    extra_headers = [(b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii"))]
    if origin is not None:
        extra_headers.append((b"origin", origin.encode("ascii")))
    body, headers = _invalid_key_request_headers(*extra_headers)

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 400
    assert payload["error_code"] == "unsupported_key"


@pytest.mark.parametrize("origin", ["http://127.0.0.1:4001", "http://127.0.0.1:4000.evil"])
def test_post_api_rejects_explicit_token_with_invalid_origin(origin):
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
        (b"origin", origin.encode("ascii")),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"


def test_post_api_rejects_invalid_explicit_token_even_with_valid_cookie():
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", b"invalid-token"),
        (b"cookie", f"{api_app.LOCAL_API_TOKEN_COOKIE}={api_app.LOCAL_API_TOKEN}".encode("ascii")),
        (b"origin", b"http://127.0.0.1:4000"),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "missing_api_token"


@pytest.mark.parametrize(
    "host",
    ["", "127.0.0.1:4001", "[::1]:4000", "127.0.0.2:4000", "127.0.0.1:4000.evil"],
)
def test_post_api_rejects_missing_malformed_or_sibling_host(host):
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host=host))

    assert status == 403
    assert payload["error_code"] == "forbidden_host"


@pytest.mark.parametrize("origin", ["http://[::1]:4000", "http://127.0.0.2:4000"])
def test_post_api_rejects_ipv6_and_alternate_loopback_origins(origin):
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
        (b"origin", origin.encode("ascii")),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"


@pytest.mark.parametrize(
    ("host", "origin", "error_code"),
    [
        ("127.0.0.1:4001", None, "forbidden_host"),
        ("127.0.0.1:4000", "http://127.0.0.1:4001", "forbidden_origin"),
    ],
)
def test_authority_rejection_precedes_oversized_body_validation(host, origin, error_code):
    body = b"not-a-valid-multipart-body"
    headers = [
        (b"content-type", b"multipart/form-data; boundary=missing"),
        (b"content-length", str(_inspect_key_body_limit() + 1).encode("ascii")),
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
    ]
    if origin is not None:
        headers.append((b"origin", origin.encode("ascii")))

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host=host))

    assert status == 403
    assert payload["error_code"] == error_code


def test_post_api_rejects_duplicate_host():
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
        (b"host", b"127.0.0.1:4000"),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "forbidden_host"


def test_post_api_rejects_duplicate_origin():
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
        (b"origin", b"http://127.0.0.1:4000"),
        (b"origin", b"http://127.0.0.1:4000"),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4000"))

    assert status == 403
    assert payload["error_code"] == "forbidden_origin"


def test_forwarded_headers_do_not_rescue_an_invalid_direct_host():
    body, headers = _invalid_key_request_headers(
        (b"x-quantum-encryptor-token", api_app.LOCAL_API_TOKEN.encode("ascii")),
        (b"origin", b"http://127.0.0.1:4000"),
        (b"x-forwarded-host", b"127.0.0.1:4000"),
        (b"x-forwarded-proto", b"http"),
    )

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers, host="127.0.0.1:4001"))

    assert status == 403
    assert payload["error_code"] == "forbidden_host"


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

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/keys/inspect", body=body, headers=headers)
    )
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 413
    assert payload["error_code"] == "request_too_large"
    _assert_api_no_store(response_headers)


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
    fingerprint = "QE1-SHA3-256:" + "a" * 64
    key_info = {
        "key_type": "public",
        "kem": cfg.KEM_ALG,
        "public_key_fingerprint": fingerprint,
    }
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: key_info)

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=_with_api_token(headers)))

    assert status == 200
    assert payload["keyInfo"] == key_info
    assert payload["display"]["Key Type"] == "Public"
    assert payload["display"]["Public Key Fingerprint"] == fingerprint


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
    fingerprint = "QE1-SHA3-256:" + "b" * 64
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: cfg.KEM_ALG)
    monkeypatch.setattr(core, "generate_hybrid_keys", lambda _kem: (b"public", b"private"))

    def get_fingerprint(raw_key: bytes, kem_alg: str) -> str:
        assert raw_key == b"public"
        assert kem_alg == cfg.HYBRID_KEM_ALG
        return fingerprint

    monkeypatch.setattr(core, "get_public_key_fingerprint", get_fingerprint)

    def save_key(raw_key: bytes, kem_alg: str, key_type: str, password: str | None = None) -> str:
        assert kem_alg == cfg.HYBRID_KEM_ALG
        if key_type == "private":
            assert password == "correct horse battery staple"
        return f"{key_type}:{raw_key.decode('ascii')}"

    monkeypatch.setattr(core, "save_key_pem", save_key)

    status, response_headers, response_body = asyncio.run(
        _call_app_raw("/api/keys/generate", body=body, headers=_with_api_token(headers))
    )
    payload = json.loads(response_body.decode("utf-8"))

    assert status == 200
    assert payload["publicPem"] == "public:public"
    assert payload["privatePem"] == "private:private"
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["publicKeyFingerprint"] == fingerprint
    _assert_api_no_store(response_headers)


def test_generate_keys_reports_backend_unavailable(monkeypatch):
    body, headers = _urlencoded_body({"password": "correct horse battery staple"})
    monkeypatch.setattr(core, "resolve_kem_algorithm", lambda _kem: cfg.KEM_ALG)
    monkeypatch.setattr(core, "generate_hybrid_keys", lambda _kem: (None, None))

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


@pytest.mark.parametrize("legacy_kem", [cfg.KEM_ALG, cfg.LEGACY_HYBRID_KEM_ALG])
def test_encrypt_file_rejects_legacy_public_key(monkeypatch, legacy_kem):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", legacy_kem, "public"))
    monkeypatch.setattr(
        core,
        "encrypt_file_pro",
        lambda *_args: pytest.fail("legacy key must be rejected before encryption"),
    )

    status, payload = asyncio.run(_call_app("/api/files/encrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "legacy_public_key"


def test_encrypt_file_returns_download(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.HYBRID_KEM_ALG, "public"))
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
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.HYBRID_KEM_ALG, "public"))

    def fail_encrypt(_data: bytes, _public_key: bytes, _kem: str) -> bytes:
        raise core.CryptoDependencyError("missing")

    monkeypatch.setattr(core, "encrypt_file_pro", fail_encrypt)

    status, payload = asyncio.run(_call_app("/api/files/encrypt", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "backend_unavailable"


def test_encrypt_file_reports_encryption_failure(monkeypatch):
    body, headers = _file_workflow_body()
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.HYBRID_KEM_ALG, "public"))
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
    monkeypatch.setattr(
        core,
        "load_key_pem",
        lambda _pem, password=None: (b"private", cfg.HYBRID_KEM_ALG, "private"),
    )
    monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", lambda _suite: (cfg.KEM_ALG,))
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
    _assert_api_no_store(response_headers)


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
    monkeypatch.setattr(
        core,
        "load_key_pem",
        lambda _pem, password=None: (b"private", cfg.HYBRID_KEM_ALG, "private"),
    )
    monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", lambda _suite: (cfg.KEM_ALG,))
    monkeypatch.setattr(core, "decrypt_file_pro", lambda _data, _private_key, expected_kem_alg=None: (None, None))

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 400
    assert payload["error_code"] == "decryption_failed"


def test_decrypt_file_reports_suite_aware_backend_unavailable(monkeypatch):
    body, headers = _decrypt_workflow_body()
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: {"key_type": "private"})
    monkeypatch.setattr(
        core,
        "load_key_pem",
        lambda _pem, password=None: (b"private", cfg.LEGACY_HYBRID_KEM_ALG, "private"),
    )

    def missing_backend(_suite):
        raise core.CryptoDependencyError("legacy backends missing")

    monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", missing_backend, raising=False)
    monkeypatch.setattr(
        core,
        "decrypt_file_pro",
        lambda *_args, **_kwargs: pytest.fail("decryption must not run without a compatible backend"),
    )

    status, payload = asyncio.run(_call_app("/api/files/decrypt", body=body, headers=_with_api_token(headers)))

    assert status == 503
    assert payload["error_code"] == "backend_unavailable"


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


def test_static_response_keeps_its_own_cache_policy(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<div>built UI</div>", encoding="utf-8")
    monkeypatch.setattr(api_app, "STATIC_APP_DIR", tmp_path)

    status, response_headers, response_body = asyncio.run(_call_app_raw("/", method="GET"))

    assert status == 200
    assert response_body == b"<div>built UI</div>"
    assert _header(response_headers, b"cache-control") != "no-store"
    assert _header(response_headers, b"pragma") != "no-cache"


def test_api_cache_policy_does_not_mutate_reused_response(monkeypatch, tmp_path):
    shared_response = api_app.Response(
        b"shared",
        headers={"Cache-Control": "public, max-age=3600", "Pragma": "cache"},
    )

    async def shared_handler(_request):
        return shared_response

    monkeypatch.setattr(api_app, "health", shared_handler)
    monkeypatch.setattr(api_app, "frontend_missing", shared_handler)
    monkeypatch.setattr(api_app, "STATIC_APP_DIR", tmp_path / "missing-static-app")

    api_status, api_headers, _api_body = asyncio.run(_call_app_raw("/api/health", method="GET"))
    static_status, static_headers, _static_body = asyncio.run(_call_app_raw("/outside-api", method="GET"))

    assert api_status == 200
    assert [value for name, value in api_headers if name.lower() == b"cache-control"] == [b"no-store"]
    assert [value for name, value in api_headers if name.lower() == b"pragma"] == [b"no-cache"]
    assert static_status == 200
    assert [value for name, value in static_headers if name.lower() == b"cache-control"] == [b"public, max-age=3600"]
    assert [value for name, value in static_headers if name.lower() == b"pragma"] == [b"cache"]


def test_unmatched_api_response_is_not_cacheable():
    status, response_headers, _response_body = asyncio.run(_call_app_raw("/api/not-a-route", method="GET"))

    assert status >= 400
    _assert_api_no_store(response_headers)
