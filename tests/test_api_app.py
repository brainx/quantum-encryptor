import asyncio
import json
from pathlib import Path
from typing import Any

from crypto_config import cfg
import api_app


def test_sanitize_download_filename_strips_paths_and_control_chars():
    assert api_app.sanitize_download_filename("../secret\x00.txt", "fallback.bin") == "secret.txt"
    assert api_app.sanitize_download_filename('bad"name;.pqc', "fallback.bin") == "bad_name_.pqc"
    assert api_app.sanitize_download_filename("", 'bad"fallback;.pqc') == "bad_fallback_.pqc"
    assert api_app.sanitize_download_filename("", "fallback.bin") == "fallback.bin"


def test_health_payload_is_safe_without_required_native_backend():
    payload = api_app._health_payload()

    assert payload["formatVersion"] == cfg.FORMAT_VERSION
    assert payload["configuredKem"] == cfg.KEM_ALG
    assert payload["dem"] == "AES-256-GCM"
    assert payload["maxFileBytes"] == cfg.MAX_FILE_BYTES
    assert payload["passwordPolicy"]["minChars"] == cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS


def test_content_disposition_quotes_download_filename():
    header = api_app._content_disposition("encrypted file.pqc")

    assert 'filename="encrypted file.pqc"' in header
    assert "filename*=UTF-8''encrypted%20file.pqc" in header


def test_download_filename_suggestion_uses_existing_ui_helper():
    assert api_app.guess_decrypted_filename(Path("payload_encrypted.pqc")) == "payload"


def _multipart_body(field_name: str, filename: str, content: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    boundary = "test-boundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ).encode("utf-8")
    body += content
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")
    headers = [
        (b"content-type", f"multipart/form-data; boundary={boundary}".encode("ascii")),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    return body, headers


async def _call_app(
    path: str, method: str = "POST", body: bytes = b"", headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[int, dict[str, object]]:
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

    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return int(status), json.loads(response_body.decode("utf-8"))


def test_inspect_key_endpoint_rejects_invalid_pem_without_stack_trace():
    body, headers = _multipart_body("key", "bad.pem", b"not a supported key")

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 400
    assert payload == {
        "ok": False,
        "error_code": "unsupported_key",
        "message": "Unsupported or insecure PEM key file.",
    }


def test_api_rejects_oversized_body_before_route_parsing():
    body, headers = _multipart_body("key", "huge.pem", b"x")
    headers = [
        (
            (name, str(api_app._api_body_limit("/api/keys/inspect") + 1).encode("ascii"))
            if name == b"content-length"
            else (name, value)
        )
        for name, value in headers
    ]

    status, payload = asyncio.run(_call_app("/api/keys/inspect", body=body, headers=headers))

    assert status == 413
    assert payload["error_code"] == "request_too_large"
