import asyncio
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest

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
