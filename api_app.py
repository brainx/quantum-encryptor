"""ASGI API and static app server for the custom Quantum Encryptor web UI."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import logging
import mimetypes
import os
import re
import secrets
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from threading import Lock
from typing import Any, AsyncIterator, Callable, TypeVar
from urllib.parse import quote, urlsplit

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import BaseRoute, Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api_jobs import FileJob, JobError, JobStore, RESULT_TTL_SECONDS, encrypted_limit
from api_worker import CryptoWorker
from crypto_config import cfg
import crypto_core as core
from ui_helpers import format_key_info_for_display, guess_decrypted_filename

logger = logging.getLogger(__name__)

Authority = tuple[str, str, int]
CryptoResult = TypeVar("CryptoResult")


def _configured_port(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ValueError("PORT must be an integer from 1 through 65535.")
    try:
        port = int(value)
    except ValueError:
        raise ValueError("PORT must be an integer from 1 through 65535.") from None
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be an integer from 1 through 65535.")
    return port


def _allowed_browser_authorities(app_port: int, enable_vite_dev: bool) -> frozenset[Authority]:
    authorities = {("http", "127.0.0.1", app_port)}
    if enable_vite_dev:
        authorities.add(("http", "127.0.0.1", 4001))
    return frozenset(authorities)


APP_ROOT = Path(__file__).resolve().parent
MULTIPART_OVERHEAD_BYTES = 1024 * 1024
SMALL_FORM_MAX_BYTES = 64 * 1024
PASSWORD_FIELD_MAX_BYTES = 4096
_crypto_operation_lock = Lock()
LOCAL_API_PORT = _configured_port(os.environ.get("PORT", "4000"))
LOCAL_API_HOST_HEADER = f"127.0.0.1:{LOCAL_API_PORT}"
ALLOWED_BROWSER_AUTHORITIES = _allowed_browser_authorities(
    LOCAL_API_PORT,
    os.environ.get("QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV") == "1",
)
LOCAL_API_TOKEN = os.environ.get("QUANTUM_ENCRYPTOR_API_TOKEN") or secrets.token_urlsafe(32)
# Cookie name, not a secret value.
LOCAL_API_TOKEN_COOKIE = "qe_api_token"  # nosec B105
SECURITY_HEADERS = (
    (
        b"content-security-policy",
        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        b"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; "
        b"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
)
API_NO_STORE_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
)


def _static_app_dir() -> Path:
    source_static_app = APP_ROOT / "static" / "app"
    installed_static_app = Path(sys.prefix) / "static" / "app"
    if source_static_app.exists():
        return source_static_app
    if installed_static_app.exists():
        return installed_static_app
    return source_static_app


STATIC_APP_DIR = _static_app_dir()


class RequestBodyTooLarge(Exception):
    """Raised when an API request body exceeds the configured pre-parse limit."""


class _DuplicateHeaderError(Exception):
    """Raised when a security-sensitive request header is repeated."""


class ApiError(Exception):
    """Safe API error that can be returned to the browser."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def format_size(byte_count: int) -> str:
    """Format a byte count for user-facing validation messages."""
    mib = byte_count / (1024 * 1024)
    return f"{mib:.1f} MiB"


def sanitize_download_filename(filename: str, fallback: str) -> str:
    """Constrain user-controlled download names to a simple local filename."""
    candidate = _clean_download_filename(filename)
    fallback_candidate = _clean_download_filename(fallback)
    return candidate or fallback_candidate or "download.bin"


def _clean_download_filename(filename: str) -> str:
    candidate = Path(filename or "").name.strip()
    candidate = re.sub(r"[\x00-\x1f\x7f]+", "", candidate)
    candidate = re.sub(r'[\\/:;"<>|?*]+', "_", candidate)
    return candidate.strip()


def _json_error(error: ApiError) -> JSONResponse:
    return JSONResponse(
        {
            "ok": False,
            "error_code": error.code,
            "message": error.message,
        },
        status_code=error.status_code,
    )


def _success_json(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    body: dict[str, Any] = {"ok": True}
    body.update(payload)
    return JSONResponse(body, status_code=status_code)


def _safe_unexpected(operation: str, exc: Exception) -> JSONResponse:
    logger.exception("Unexpected %s API failure: %s", operation, exc)
    return _json_error(ApiError(500, "unexpected_error", "An unexpected server error occurred."))


def _content_disposition(filename: str) -> str:
    ascii_fallback = "".join(
        character if character.isascii() and 0x20 <= ord(character) < 0x7F else "_" for character in filename
    )
    ascii_fallback = ascii_fallback.replace("\\", "_").replace('"', "_") or "download.bin"
    quoted = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quoted}"


def _download_response(data: bytes, filename: str, media_type: str = "application/octet-stream") -> Response:
    return Response(
        data,
        media_type=media_type,
        headers={"Content-Disposition": _content_disposition(filename)},
    )


async def _form(request: Request, max_files: int = 2, max_fields: int = 6):
    try:
        return await request.form(
            max_files=max_files,
            max_fields=max_fields,
            max_part_size=cfg.MAX_ENCRYPTED_FILE_BYTES,
        )
    except RequestBodyTooLarge as exc:
        raise ApiError(
            413,
            "request_too_large",
            "Request body exceeds the configured size limit.",
        ) from exc
    except Exception as exc:
        raise ApiError(400, "invalid_form", "Could not parse the submitted form data.") from exc


def _api_body_limit(path: str) -> int | None:
    if path.startswith("/api/jobs/") and path.endswith("/upload"):
        return encrypted_limit()
    if path.startswith("/api/jobs/") and path.endswith("/start"):
        return cfg.MAX_PEM_BYTES + SMALL_FORM_MAX_BYTES
    if path == "/api/jobs" or path.startswith("/api/jobs/"):
        return SMALL_FORM_MAX_BYTES
    if path == "/api/keys/generate":
        return SMALL_FORM_MAX_BYTES
    if path in {"/api/keys/inspect", "/api/keys/change-password"}:
        return cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    if path == "/api/keys/recover-public":
        return 2 * cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    if path == "/api/files/inspect":
        return cfg.MAX_ENCRYPTED_FILE_BYTES + MULTIPART_OVERHEAD_BYTES
    if path == "/api/files/encrypt":
        return cfg.MAX_FILE_BYTES + cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    if path in {"/api/files/decrypt", "/api/files/verify"}:
        return cfg.MAX_ENCRYPTED_FILE_BYTES + cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    return None


def _header_value(scope: Scope, name: bytes) -> str | None:
    for header_name, value in scope.get("headers", []):
        if header_name.lower() == name:
            return value.decode("latin1")
    return None


def _single_header_value(scope: Scope, name: bytes) -> str | None:
    values = [value.decode("latin1") for header_name, value in scope.get("headers", []) if header_name.lower() == name]
    if len(values) > 1:
        raise _DuplicateHeaderError
    return values[0] if values else None


def _is_ascii_authority(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "?" not in value
        and "#" not in value
        and all(0x21 <= ord(character) < 0x7F for character in value)
    )


def _parse_origin(value: str | None) -> Authority | None:
    if not isinstance(value, str) or not _is_ascii_authority(value):
        return None
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port if parsed.port is not None else 80
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "http"
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        return None
    return ("http", hostname.lower(), port)


def _parse_host_authority(value: str | None) -> tuple[str, int] | None:
    if not isinstance(value, str) or not _is_ascii_authority(value) or value.lower() == "null":
        return None
    try:
        parsed = urlsplit(f"http://{value}")
        hostname = parsed.hostname
        port = parsed.port if parsed.port is not None else 80
    except ValueError:
        return None
    if (
        parsed.scheme != "http"
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        return None
    return (hostname.lower(), port)


def _validate_request_authorities(scope: Scope) -> tuple[bool, ApiError | None]:
    try:
        host_value = _single_header_value(scope, b"host")
    except _DuplicateHeaderError:
        host_value = None
    parsed_host = _parse_host_authority(host_value)
    host_authority = ("http", *parsed_host) if parsed_host is not None else None
    if host_authority not in ALLOWED_BROWSER_AUTHORITIES:
        return False, ApiError(403, "forbidden_host", "Request host is not allowed.")

    try:
        origin_value = _single_header_value(scope, b"origin")
    except _DuplicateHeaderError:
        return False, ApiError(403, "forbidden_origin", "Request origin is not allowed.")
    if origin_value is None:
        return False, None

    origin_authority = _parse_origin(origin_value)
    if origin_authority not in ALLOWED_BROWSER_AUTHORITIES or origin_authority != host_authority:
        return False, ApiError(403, "forbidden_origin", "Request origin is not allowed.")
    return True, None


def _cookie_value(scope: Scope, name: str) -> str | None:
    cookie_header = _single_header_value(scope, b"cookie")
    if not cookie_header:
        return None
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel is not None else None


def _is_state_changing_api(scope: Scope) -> bool:
    method = str(scope.get("method", "GET")).upper()
    path = str(scope.get("path", ""))
    return method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/")


def _has_valid_local_api_token(token: str | None) -> bool:
    if token is None:
        return False
    return secrets.compare_digest(token.encode("utf-8"), LOCAL_API_TOKEN.encode("utf-8"))


class LocalApiGuardMiddleware:
    """Require local browser context plus per-process token for state-changing API requests.

    The token is accepted from the HttpOnly auth cookie set by ``GET /api/health`` or from
    the ``X-Quantum-Encryptor-Token`` header for clients configured with
    ``QUANTUM_ENCRYPTOR_API_TOKEN``. It is never disclosed in API response bodies.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_state_changing_api(scope):
            await self.app(scope, receive, send)
            return

        has_valid_origin, authority_error = _validate_request_authorities(scope)
        if authority_error is not None:
            await _json_error(authority_error)(scope, receive, send)
            return

        try:
            token = _single_header_value(scope, b"x-quantum-encryptor-token")
        except _DuplicateHeaderError:
            # A repeated explicit credential must fail closed without trying the cookie.
            token = None
        else:
            if token is None and has_valid_origin:
                try:
                    token = _cookie_value(scope, LOCAL_API_TOKEN_COOKIE)
                except _DuplicateHeaderError:
                    token = None
        if not _has_valid_local_api_token(token):
            await _json_error(ApiError(403, "missing_api_token", "Missing or invalid local API token."))(
                scope, receive, send
            )
            return

        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Apply browser hardening headers to every HTTP response, including middleware errors."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_api_path = str(scope.get("path", "")).startswith("/api/")

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _value in headers}
                is_app_document = scope.get("path") in {"/", "/index.html"} and any(
                    name.lower() == b"content-type" and value.lower().startswith(b"text/html")
                    for name, value in headers
                )
                for name, value in SECURITY_HEADERS:
                    if name not in existing:
                        # Browser form POSTs need an actual Origin for exact-origin
                        # authorization. This still suppresses cross-origin referrers.
                        if name == b"referrer-policy" and is_app_document:
                            value = b"same-origin"
                        headers.append((name, value))
                if is_api_path:
                    for name, value in API_NO_STORE_HEADERS:
                        headers[:] = [
                            (existing_name, existing_value)
                            for existing_name, existing_value in headers
                            if existing_name.lower() != name
                        ]
                        headers.append((name, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


class ApiBodyLimitMiddleware:
    """Reject oversized API bodies before multipart parsing can spool uploads."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _api_body_limit(str(scope.get("path", "")))
        method = str(scope.get("method", "GET")).upper()
        if limit is None or method not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        try:
            content_length = _single_header_value(scope, b"content-length")
        except _DuplicateHeaderError:
            content_length = "invalid"
        if content_length is None:
            await _json_error(ApiError(411, "length_required", "API requests must include a Content-Length header."))(
                scope, receive, send
            )
            return
        try:
            if not content_length.isascii() or not content_length.isdecimal():
                raise ValueError
            parsed_length = int(content_length)
        except ValueError:
            await _json_error(ApiError(400, "invalid_content_length", "Invalid Content-Length header."))(
                scope, receive, send
            )
            return
        if parsed_length > limit:
            await _json_error(ApiError(413, "request_too_large", "Request body exceeds the configured size limit."))(
                scope, receive, send
            )
            return

        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > limit:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await _json_error(ApiError(413, "request_too_large", "Request body exceeds the configured size limit."))(
                scope, receive, send
            )


class CryptoAdmissionMiddleware:
    """Bound uploaded data and expensive work before reading an admitted request."""

    paths = frozenset(
        {
            "/api/keys/generate",
            "/api/keys/change-password",
            "/api/keys/recover-public",
            "/api/files/encrypt",
            "/api/files/decrypt",
            "/api/files/verify",
            "/api/files/inspect",
        }
    )

    def __init__(self, app: ASGIApp, worker: CryptoWorker) -> None:
        self.app = app
        self.worker = worker

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") not in self.paths:
            await self.app(scope, receive, send)
            return
        lease = self.worker.acquire()
        if lease is None:
            response = _json_error(
                ApiError(
                    429,
                    "server_busy",
                    "The local service is processing another operation. Wait for it to finish, then try again.",
                )
            )
            response.headers["Retry-After"] = "1"
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})["crypto_lease"] = lease
        try:
            await self.app(scope, receive, send)
        finally:
            # The lease also waits for any worker left running after cancellation.
            lease.close()


def _form_text(form: Any, name: str, required: bool = True) -> str:
    value = form.get(name)
    if value is None:
        if required:
            raise ApiError(400, "missing_field", f"Missing required field: {name}.")
        return ""
    if isinstance(value, UploadFile):
        raise ApiError(400, "invalid_field", f"Field {name} must be text.")
    return str(value)


def _form_upload(form: Any, name: str) -> UploadFile:
    value = form.get(name)
    if not isinstance(value, UploadFile):
        raise ApiError(400, "missing_file", f"Missing required file upload: {name}.")
    return value


async def _read_upload_bytes(upload: UploadFile, max_bytes: int, label: str) -> bytes:
    try:
        data = await upload.read(max_bytes + 1)
    except Exception as exc:
        raise ApiError(400, "read_failed", f"Could not read {label}.") from exc
    finally:
        await upload.close()
    if len(data) > max_bytes:
        raise ApiError(
            413,
            "file_too_large",
            f"{label} exceeds the maximum supported size of {format_size(max_bytes)}.",
        )
    return data


async def _read_upload_text(upload: UploadFile, max_bytes: int, label: str) -> str:
    data = await _read_upload_bytes(upload, max_bytes, label)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(400, "invalid_text", f"{label} must be a UTF-8 text file.") from exc


def _capability(available: bool, reason: str = "") -> dict[str, bool | str]:
    return {"available": available, "reason": "" if available else reason}


def _health_payload() -> dict[str, Any]:
    try:
        active_kem_component = core.resolve_kem_algorithm(cfg.KEM_ALG)
        current_backend_ready = True
    except Exception as exc:
        active_kem_component = cfg.KEM_ALG
        current_backend_ready = False
        logger.warning("Post-quantum backend readiness check failed: %s", exc)

    try:
        decrypt_ready = bool(core.available_decryption_kem_algorithms())
    except Exception as exc:
        decrypt_ready = False
        logger.warning("Decryption backend readiness check failed: %s", exc)

    capabilities = {
        "inspect": _capability(True),
        "generate": _capability(
            current_backend_ready,
            "ML-KEM-768 is unavailable for new key generation.",
        ),
        "encrypt": _capability(
            current_backend_ready,
            "ML-KEM-768 is unavailable for new encryption.",
        ),
        "decrypt": _capability(
            decrypt_ready,
            "No supported post-quantum decryption backend is available.",
        ),
    }
    backend_message = (
        "Post-quantum backend ready."
        if current_backend_ready
        else (
            "The ML-KEM backend is not ready, so new keys and ciphertexts cannot be created. "
            "Compatible encrypted archives may still be decryptable."
        )
    )

    return {
        "largeFiles": {
            "available": current_backend_ready or decrypt_ready,
            "maxPlaintextBytes": cfg.MAX_STREAM_FILE_BYTES,
            "maxEncryptedBytes": encrypted_limit(),
            "resultTtlSeconds": RESULT_TTL_SECONDS,
        },
        "supportsKeyPasswordChange": True,
        "supportsPublicKeyRecovery": True,
        "supportsFileVerification": True,
        "backendReady": current_backend_ready,
        "backendMessage": backend_message,
        "capabilities": capabilities,
        "formatVersion": cfg.FORMAT_VERSION,
        "kem": cfg.HYBRID_KEM_ALG,
        "kemComponent": active_kem_component,
        "configuredKem": cfg.KEM_ALG,
        "dem": "AES-256-GCM",
        "maxFileBytes": cfg.MAX_FILE_BYTES,
        "maxEncryptedFileBytes": cfg.MAX_ENCRYPTED_FILE_BYTES,
        "maxPemBytes": cfg.MAX_PEM_BYTES,
        "passwordPolicy": {
            "minChars": cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS,
            "minUniqueChars": cfg.PRIVATE_KEY_MIN_UNIQUE_CHARS,
        },
    }


async def health(request: Request) -> JSONResponse:
    _has_valid_origin, authority_error = _validate_request_authorities(request.scope)
    if authority_error is not None:
        return _json_error(authority_error)
    response = _success_json(await run_in_threadpool(_health_payload))
    # Deliver the per-process API token only as an HttpOnly, SameSite=Strict cookie so it
    # is never exposed in response bodies or to JavaScript, and is not sent cross-site.
    response.set_cookie(
        LOCAL_API_TOKEN_COOKIE,
        LOCAL_API_TOKEN,
        path="/",
        httponly=True,
        samesite="strict",
    )
    return response


async def inspect_key(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=1)
        pem_content = await _read_upload_text(_form_upload(form, "key"), cfg.MAX_PEM_BYTES, "Key file")
        key_info = core.inspect_key_pem_strict(pem_content)
        return _success_json(
            {
                "keyInfo": key_info,
                "display": format_key_info_for_display(key_info),
            }
        )
    except ApiError as exc:
        return _json_error(exc)
    except (core.InvalidKeyFormatError, core.UnencryptedPrivateKeyError, core.UnsupportedKDFError) as exc:
        logger.warning("Unsupported key upload: %s", exc)
        return _json_error(ApiError(400, "unsupported_key", "Unsupported or insecure PEM key file."))
    except Exception as exc:
        return _safe_unexpected("inspect-key", exc)
    finally:
        await request.close()


def _generate_key_pair(password: str) -> dict[str, Any]:
    try:
        core.validate_private_key_password(password)
    except (core.PasswordRequiredError, core.WeakPasswordError) as exc:
        raise ApiError(400, "weak_password", str(exc)) from exc

    active_kem_alg = core.resolve_kem_algorithm(cfg.KEM_ALG)
    raw_public_key, raw_private_key = core.generate_hybrid_keys(active_kem_alg)
    if not raw_public_key or not raw_private_key:
        raise ApiError(503, "backend_unavailable", "Could not generate a hybrid key pair.")

    public_key_fingerprint = core.get_public_key_fingerprint(raw_public_key, cfg.HYBRID_KEM_ALG)
    public_pem = core.save_key_pem(raw_public_key, cfg.HYBRID_KEM_ALG, "public")
    private_pem = core.save_key_pem(raw_private_key, cfg.HYBRID_KEM_ALG, "private", password=password)
    del raw_public_key
    del raw_private_key
    if not public_pem or not private_pem:
        raise ApiError(500, "pem_format_failed", "Could not format generated keys.")

    return {
        "kem": cfg.HYBRID_KEM_ALG,
        "publicPem": public_pem,
        "privatePem": private_pem,
        "publicKeyFingerprint": public_key_fingerprint,
        "publicFilename": "ml-kem-768_x25519_public.pem",
        "privateFilename": "ml-kem-768_x25519_private.pem",
    }


async def generate_keys(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=0)
        password = _form_text(form, "password")
        payload = await request.state.crypto_lease.run(_generate_key_pair, password)
        return _success_json(payload)
    except ApiError as exc:
        return _json_error(exc)
    except core.CryptoDependencyError:
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    except Exception as exc:
        return _safe_unexpected("generate-keys", exc)
    finally:
        await request.close()


def _run_crypto_operation(operation: Callable[..., CryptoResult], *args: Any) -> CryptoResult:
    # The worker owns admission so cancelling its awaiting request cannot release it early.
    if not _crypto_operation_lock.acquire(blocking=False):
        raise ApiError(429, "server_busy", "A cryptographic operation is already running. Try again shortly.")
    try:
        return operation(*args)
    finally:
        _crypto_operation_lock.release()


def _rewrap_private_key_pem(pem_content: str, current_password: str, new_password: str) -> tuple[str, str, str]:
    return _run_crypto_operation(core.rewrap_private_key_pem, pem_content, current_password, new_password)


async def change_key_password(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=1, max_fields=2)
        private_key_file = _form_upload(form, "private_key")
        current_password = _form_text(form, "current_password", required=False)
        new_password = _form_text(form, "new_password", required=False)
        if not current_password or not new_password:
            raise ApiError(400, "password_required", "The current and new private-key passwords are required.")
        if any(
            len(password.encode("utf-8")) > PASSWORD_FIELD_MAX_BYTES for password in (current_password, new_password)
        ):
            raise ApiError(413, "field_too_large", "Private-key passwords must not exceed 4096 UTF-8 bytes.")
        original_filename = sanitize_download_filename(private_key_file.filename or "", "private.pem")
        output_filename = sanitize_download_filename(
            f"{Path(original_filename).stem or 'private'}_updated.pem", "private_updated.pem"
        )
        pem_content = await _read_upload_text(private_key_file, cfg.MAX_PEM_BYTES, "Private key file")
        private_pem, kem_alg, fingerprint = await request.state.crypto_lease.run(
            _rewrap_private_key_pem, pem_content, current_password, new_password
        )
        return _success_json(
            {
                "privatePem": private_pem,
                "kem": kem_alg,
                "publicKeyFingerprint": fingerprint,
                "privateFilename": output_filename,
            }
        )
    except ApiError as exc:
        response = _json_error(exc)
        if exc.code == "server_busy":
            response.headers["Retry-After"] = "1"
        return response
    except (
        core.InvalidKeyFormatError,
        core.UnencryptedPrivateKeyError,
        core.UnsupportedKDFError,
        core.UnsupportedAlgorithmError,
    ):
        return _json_error(
            ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")
        )
    except core.PasswordRequiredError:
        return _json_error(
            ApiError(400, "password_required", "The current and new private-key passwords are required.")
        )
    except core.WeakPasswordError:
        return _json_error(
            ApiError(400, "weak_password", "Choose a strong new password that is different from the current password.")
        )
    except core.AuthenticationFailedError:
        return _json_error(
            ApiError(
                400, "private_key_failed", "Could not unlock the private key. Check the current password and key file."
            )
        )
    except core.CryptoCoreError:
        return _json_error(
            ApiError(500, "password_change_failed", "Could not encrypt the private key with the new password.")
        )
    except Exception as exc:
        return _safe_unexpected("change-key-password", exc)
    finally:
        await request.close()


def _workflow_password(form: Any) -> str:
    password = _form_text(form, "password", required=False)
    if not password:
        raise ApiError(400, "password_required", "The private-key password is required.")
    if len(password.encode("utf-8")) > PASSWORD_FIELD_MAX_BYTES:
        raise ApiError(413, "field_too_large", "Private-key passwords must not exceed 4096 UTF-8 bytes.")
    return password


def _crypto_workflow_error(operation: str, exc: Exception) -> JSONResponse:
    if isinstance(exc, ApiError):
        response = _json_error(exc)
        if exc.code == "server_busy":
            response.headers["Retry-After"] = "1"
        return response
    if isinstance(
        exc,
        (
            core.InvalidKeyFormatError,
            core.UnencryptedPrivateKeyError,
            core.UnsupportedKDFError,
            core.UnsupportedAlgorithmError,
        ),
    ):
        return _json_error(
            ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")
        )
    if isinstance(exc, core.AuthenticationFailedError):
        return _json_error(
            ApiError(400, "private_key_failed", "Could not unlock the private key. Check the password and key file.")
        )
    if isinstance(exc, core.PasswordRequiredError):
        return _json_error(ApiError(400, "password_required", "The private-key password is required."))
    if isinstance(exc, core.CryptoDependencyError):
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    return _safe_unexpected(operation, exc)


def _recover_public_key(pem_content: str, password: str, supplied_public_pem: str | None) -> dict[str, Any]:
    supplied_fingerprint = None
    if supplied_public_pem is not None:
        public_bytes, public_alg, key_type = core.load_key_pem(supplied_public_pem)
        if public_bytes is None or public_alg is None or key_type != "public":
            raise ApiError(400, "invalid_public_key", "Upload a supported PQC public key PEM file.")
        supplied_fingerprint = core.get_public_key_fingerprint(public_bytes, public_alg)
    public_pem, kem_alg, fingerprint = core.recover_public_key_pem(pem_content, password)
    return {
        "publicPem": public_pem,
        "kem": kem_alg,
        "publicKeyFingerprint": fingerprint,
        "matchesSuppliedPublicKey": (
            secrets.compare_digest(fingerprint, supplied_fingerprint) if supplied_fingerprint is not None else None
        ),
    }


async def recover_public_key(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=2, max_fields=1)
        private_key_file = _form_upload(form, "private_key")
        password = _workflow_password(form)
        original_filename = sanitize_download_filename(private_key_file.filename or "", "private.pem")
        public_filename = sanitize_download_filename(
            f"{Path(original_filename).stem or 'private'}_public.pem", "recovered_public.pem"
        )
        private_pem = await _read_upload_text(private_key_file, cfg.MAX_PEM_BYTES, "Private key file")
        supplied_public_pem = None
        if "public_key" in form:
            supplied_public_pem = await _read_upload_text(
                _form_upload(form, "public_key"), cfg.MAX_PEM_BYTES, "Public key file"
            )
        result = await request.state.crypto_lease.run(
            _run_crypto_operation, _recover_public_key, private_pem, password, supplied_public_pem
        )
        return _success_json({**result, "publicFilename": public_filename})
    except Exception as exc:
        return _crypto_workflow_error("recover-public-key", exc)
    finally:
        await request.close()


def _inspect_encrypted_file(encrypted_blob: bytes) -> core.EncryptedFileMetadata:
    try:
        return core.inspect_encrypted_file_strict(encrypted_blob)
    except core.SizeLimitError as exc:
        raise ApiError(413, "file_too_large", "Encrypted file exceeds the supported size.") from exc
    except (core.FileFormatError, core.UnsupportedAlgorithmError) as exc:
        raise ApiError(400, "invalid_encrypted_file", "Upload a supported encrypted PQC file.") from exc


async def inspect_file(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=1, max_fields=0)
        encrypted_blob = await _read_upload_bytes(
            _form_upload(form, "file"), cfg.MAX_ENCRYPTED_FILE_BYTES, "Encrypted file"
        )
        metadata = await request.state.crypto_lease.run(_run_crypto_operation, _inspect_encrypted_file, encrypted_blob)
        return _success_json(
            {
                "authenticated": False,
                "metadata": {
                    "formatVersion": metadata.version,
                    "kem": metadata.kem_alg,
                    "headerBytes": metadata.header_bytes,
                    "kemCiphertextBytes": metadata.kem_ciphertext_bytes,
                    "x25519CiphertextBytes": metadata.x25519_ciphertext_bytes,
                    "encryptedPayloadBytes": metadata.encrypted_payload_bytes,
                    "totalBytes": metadata.total_bytes,
                },
            }
        )
    except Exception as exc:
        return _crypto_workflow_error("inspect-file", exc)
    finally:
        await request.close()


def _verify_encrypted_file(encrypted_blob: bytes, private_pem: str, password: str) -> dict[str, Any]:
    metadata = _inspect_encrypted_file(encrypted_blob)
    key_info = core.inspect_key_pem_strict(private_pem)
    if key_info.get("key_type") != "private":
        raise core.InvalidKeyFormatError("An encrypted private key is required.")
    private_key, kem_alg, key_type = core.load_key_pem(private_pem, password)
    if private_key is None or kem_alg is None or key_type != "private":
        raise core.AuthenticationFailedError("Could not unlock the private key.")
    try:
        if kem_alg != metadata.kem_alg:
            raise ApiError(
                400, "verification_failed", "Verification failed. Check the private key and encrypted file integrity."
            )
        core.resolve_decryption_kem_algorithms(kem_alg)
        plaintext, detected_alg = core.decrypt_file_pro(encrypted_blob, private_key, expected_kem_alg=kem_alg)
        if plaintext is None:
            raise ApiError(
                400, "verification_failed", "Verification failed. Check the private key and encrypted file integrity."
            )
        try:
            return {
                "verified": True,
                "kem": detected_alg or kem_alg,
                "formatVersion": metadata.version,
                "bytesVerified": len(plaintext),
                "publicKeyFingerprint": core.get_private_key_public_fingerprint(private_key, kem_alg),
            }
        finally:
            # Verification authenticates in memory; no plaintext enters the HTTP response.
            del plaintext
    finally:
        del private_key


async def verify_file(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=2, max_fields=1)
        encrypted_upload = _form_upload(form, "file")
        private_upload = _form_upload(form, "private_key")
        password = _workflow_password(form)
        encrypted_blob = await _read_upload_bytes(encrypted_upload, cfg.MAX_ENCRYPTED_FILE_BYTES, "Encrypted file")
        private_pem = await _read_upload_text(private_upload, cfg.MAX_PEM_BYTES, "Private key file")
        result = await request.state.crypto_lease.run(
            _run_crypto_operation, _verify_encrypted_file, encrypted_blob, private_pem, password
        )
        return _success_json(result)
    except Exception as exc:
        return _crypto_workflow_error("verify-file", exc)
    finally:
        await request.close()


def _encrypt_bytes(input_data: bytes, public_pem: str) -> bytes:
    public_key_bytes, kem_alg_from_key, key_type = core.load_key_pem(public_pem)
    if not public_key_bytes or not kem_alg_from_key or key_type != "public":
        raise ApiError(400, "invalid_public_key", "Upload a supported PQC public key PEM file.")
    if kem_alg_from_key != cfg.HYBRID_KEM_ALG:
        raise ApiError(
            400,
            "legacy_public_key",
            "Generate a new ML-KEM-768+X25519-v2 public key for encryption.",
        )

    encrypted_blob = core.encrypt_file_pro(input_data, public_key_bytes, kem_alg_from_key)
    del input_data
    del public_key_bytes
    if encrypted_blob is None:
        raise ApiError(503, "encryption_failed", "Encryption failed. Check backend readiness and key compatibility.")

    return encrypted_blob


async def encrypt_file(request: Request) -> Response:
    try:
        form = await _form(request, max_files=2)
        uploaded_file = _form_upload(form, "file")
        public_key_file = _form_upload(form, "public_key")
        original_filename = Path(uploaded_file.filename or "file")
        suggested_filename = f"{original_filename.stem or 'file'}_encrypted.pqc"
        output_filename = sanitize_download_filename(
            _form_text(form, "output_filename", required=False), suggested_filename
        )

        input_data = await _read_upload_bytes(uploaded_file, cfg.MAX_FILE_BYTES, "Input file")
        public_pem = await _read_upload_text(public_key_file, cfg.MAX_PEM_BYTES, "Public key file")
        encrypted_blob = await request.state.crypto_lease.run(_encrypt_bytes, input_data, public_pem)
        del input_data

        return _download_response(encrypted_blob, output_filename)
    except ApiError as exc:
        return _json_error(exc)
    except core.CryptoDependencyError:
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    except Exception as exc:
        return _safe_unexpected("encrypt-file", exc)
    finally:
        await request.close()


def _decrypt_bytes(encrypted_blob: bytes, private_pem: str, password: str) -> bytes:
    key_info = core.inspect_key_pem_strict(private_pem)
    if key_info.get("key_type") != "private":
        raise ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")

    private_key_bytes, kem_alg_key, key_type = core.load_key_pem(private_pem, password=password)
    if not private_key_bytes or not kem_alg_key or key_type != "private":
        raise ApiError(400, "private_key_failed", "Could not unlock the private key. Check the password and key file.")

    core.resolve_decryption_kem_algorithms(kem_alg_key)
    decrypted_data, _detected_alg = core.decrypt_file_pro(
        encrypted_blob,
        private_key_bytes,
        expected_kem_alg=kem_alg_key,
    )
    del encrypted_blob
    del private_key_bytes
    if decrypted_data is None:
        raise ApiError(
            400,
            "decryption_failed",
            "Decryption failed. Check the private key, password, and encrypted file integrity.",
        )

    return decrypted_data


async def decrypt_file(request: Request) -> Response:
    try:
        form = await _form(request, max_files=2)
        encrypted_upload = _form_upload(form, "file")
        private_key_file = _form_upload(form, "private_key")
        password = _form_text(form, "password")
        original_filename = Path(encrypted_upload.filename or "encrypted.pqc")
        suggested_filename = guess_decrypted_filename(original_filename)
        output_filename = sanitize_download_filename(
            _form_text(form, "output_filename", required=False), suggested_filename
        )

        encrypted_blob = await _read_upload_bytes(encrypted_upload, cfg.MAX_ENCRYPTED_FILE_BYTES, "Encrypted file")
        private_pem = await _read_upload_text(private_key_file, cfg.MAX_PEM_BYTES, "Private key file")
        decrypted_data = await request.state.crypto_lease.run(_decrypt_bytes, encrypted_blob, private_pem, password)
        del encrypted_blob

        media_type, _ = mimetypes.guess_type(output_filename)
        return _download_response(decrypted_data, output_filename, media_type or "application/octet-stream")
    except ApiError as exc:
        return _json_error(exc)
    except (core.InvalidKeyFormatError, core.UnencryptedPrivateKeyError, core.UnsupportedKDFError):
        return _json_error(
            ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")
        )
    except core.CryptoDependencyError:
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    except Exception as exc:
        return _safe_unexpected("decrypt-file", exc)
    finally:
        await request.close()


def _job_error(exc: Exception) -> JSONResponse:
    if isinstance(exc, JobError):
        error = ApiError(exc.status, exc.code, exc.message)
    elif isinstance(exc, ApiError):
        error = exc
    elif isinstance(exc, RequestBodyTooLarge):
        error = ApiError(413, "request_too_large", "Request body exceeds the configured size limit.")
    elif isinstance(exc, OSError):
        error = ApiError(507, "storage_failed", "Temporary storage failed. Check free disk space and try again.")
    else:
        return _safe_unexpected("large-file-job", exc)
    response = _json_error(error)
    if error.code == "server_busy":
        response.headers["Retry-After"] = "1"
    return response


def _request_job(request: Request) -> tuple[JobStore, FileJob]:
    jobs: JobStore = request.app.state.jobs
    identifier = request.path_params["identifier"]
    if not identifier.isascii():
        raise JobError(410, "job_expired", "The temporary job has expired or was cleared. Run the operation again.")
    return jobs, jobs.get(identifier)


async def reserve_job(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=0, max_fields=3)
        mode = _form_text(form, "mode")
        filename = _form_text(form, "filename")
        size_text = _form_text(form, "size")
        if not size_text.isascii() or not size_text.isdecimal() or len(size_text) > 20:
            raise ApiError(400, "invalid_job", "Choose a supported operation and file size.")
        if len(filename.encode("utf-8")) > 1024:
            raise ApiError(400, "invalid_job", "The selected file name is too long.")
        filename = sanitize_download_filename(filename, "file")
        jobs: JobStore = request.app.state.jobs
        job = jobs.reserve(mode, filename, int(size_text))
        return _success_json({"job": job.snapshot()})
    except Exception as exc:
        return _job_error(exc)
    finally:
        await request.close()


async def upload_job(request: Request) -> JSONResponse:
    try:
        jobs, job = _request_job(request)
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/octet-stream":
            raise ApiError(415, "invalid_content_type", "Upload the file as application/octet-stream.")
        await jobs.upload(job, request.stream())
        return _success_json({"job": job.snapshot()})
    except Exception as exc:
        return _job_error(exc)
    finally:
        await request.close()


async def start_job(request: Request) -> JSONResponse:
    try:
        jobs, job = _request_job(request)
        form = await _form(request, max_files=1, max_fields=1)
        pem = await _read_upload_text(_form_upload(form, "key"), cfg.MAX_PEM_BYTES, "Key file")
        password = "" if job.mode == "encrypt" else _workflow_password(form)
        filename = f"{job.filename}.pqc" if job.mode == "encrypt" else guess_decrypted_filename(Path(job.filename))
        jobs.start(job, pem, password, sanitize_download_filename(filename, "download.bin"))
        return _success_json({"job": job.snapshot()})
    except Exception as exc:
        return _job_error(exc)
    finally:
        await request.close()


async def status_job(request: Request) -> JSONResponse:
    try:
        _jobs, job = _request_job(request)
        return _success_json({"job": job.snapshot()})
    except Exception as exc:
        return _job_error(exc)


async def cancel_job(request: Request) -> JSONResponse:
    try:
        jobs, job = _request_job(request)
        jobs.cancel(job)
        return _success_json({"job": job.snapshot()})
    except Exception as exc:
        return _job_error(exc)


async def clear_job(request: Request) -> JSONResponse:
    try:
        jobs: JobStore = request.app.state.jobs
        job = jobs.job
        identifier = request.path_params["identifier"]
        # Expiry may already have hidden a cancelling job from get(). Clearing must
        # still wait for that job's native work and file ownership to finish.
        if job is None or not identifier.isascii() or not secrets.compare_digest(job.id, identifier):
            return _success_json({})
        if job.downloading:
            raise JobError(409, "download_busy", "Wait for the active download to finish before clearing this job.")
        if job.state in {"running", "cancelling", "uploading"}:
            raise JobError(409, "job_active", "Cancel the operation and wait for it to stop before clearing this job.")
        jobs.cancel(job, discard=True)
        return _success_json({})
    except Exception as exc:
        return _job_error(exc)


class JobDownloadResponse(StreamingResponse):
    """Release download ownership even if sending headers never enters the iterator."""

    def __init__(self, jobs: JobStore, job: FileJob) -> None:
        if job.result is None:
            raise RuntimeError("The job has no downloadable result.")
        self.jobs = jobs
        self.job = job
        self.chunks = jobs.download(job)
        super().__init__(
            self.chunks,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": _content_disposition(job.result["filename"]),
                "Content-Length": str(job.result["bytes"]),
            },
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.job.download_task = asyncio.current_task()
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self.chunks.aclose()
            finally:
                self.job.download_task = None
                self.jobs.finish_download(self.job)


async def download_job(request: Request) -> Response:
    try:
        # Direct form downloads require the same local Origin and HttpOnly session.
        # Neither job IDs nor URL parameters act as bearer credentials.
        has_origin, authority_error = _validate_request_authorities(request.scope)
        if authority_error is not None:
            raise authority_error
        if not has_origin:
            raise ApiError(403, "invalid_origin", "A trusted browser Origin is required for downloads.")
        try:
            cookie = _cookie_value(request.scope, LOCAL_API_TOKEN_COOKIE)
        except _DuplicateHeaderError:
            cookie = None
        if not _has_valid_local_api_token(cookie):
            raise ApiError(403, "missing_api_token", "Missing or invalid local API token.")
        jobs, job = _request_job(request)
        jobs.begin_download(job)
        try:
            return JobDownloadResponse(jobs, job)
        except BaseException:
            jobs.finish_download(job)
            raise
    except Exception as exc:
        return _job_error(exc)


async def frontend_missing(_request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        "Quantum Encryptor web UI has not been built. Run `npm install` and `npm run build`, then start the server.",
        status_code=503,
    )


def create_app() -> ASGIApp:
    worker = CryptoWorker()
    jobs = JobStore(worker)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        reaper = asyncio.create_task(jobs.reap())
        try:
            yield
        finally:
            reaper.cancel()
            with suppress(asyncio.CancelledError):
                await reaper
            await jobs.close()

    routes: list[BaseRoute] = [
        Route("/api/health", health, methods=["GET"]),
        Route("/api/keys/inspect", inspect_key, methods=["POST"]),
        Route("/api/keys/generate", generate_keys, methods=["POST"]),
        Route("/api/keys/change-password", change_key_password, methods=["POST"]),
        Route("/api/keys/recover-public", recover_public_key, methods=["POST"]),
        Route("/api/files/inspect", inspect_file, methods=["POST"]),
        Route("/api/files/verify", verify_file, methods=["POST"]),
        Route("/api/files/encrypt", encrypt_file, methods=["POST"]),
        Route("/api/files/decrypt", decrypt_file, methods=["POST"]),
        Route("/api/jobs", reserve_job, methods=["POST"]),
        Route("/api/jobs/{identifier}/upload", upload_job, methods=["PUT"]),
        Route("/api/jobs/{identifier}/start", start_job, methods=["POST"]),
        Route("/api/jobs/{identifier}/status", status_job, methods=["POST"]),
        Route("/api/jobs/{identifier}/cancel", cancel_job, methods=["POST"]),
        Route("/api/jobs/{identifier}/clear", clear_job, methods=["POST"]),
        Route("/api/jobs/{identifier}/download", download_job, methods=["POST"]),
    ]
    if STATIC_APP_DIR.exists():
        routes.append(Mount("/", StaticFiles(directory=STATIC_APP_DIR, html=True), name="web"))
    else:
        routes.append(Route("/{path:path}", frontend_missing, methods=["GET"]))
    inner_app = Starlette(debug=False, routes=routes, lifespan=lifespan)
    inner_app.state.jobs = jobs
    inner_app.state.crypto_worker = worker
    inner_app.add_middleware(CryptoAdmissionMiddleware, worker=worker)
    inner_app.add_middleware(ApiBodyLimitMiddleware)
    inner_app.add_middleware(LocalApiGuardMiddleware)
    return SecurityHeadersMiddleware(inner_app)


app = create_app()


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - [%(module)s] - %(message)s",
    )
    uvicorn.run("api_app:app", host="127.0.0.1", port=LOCAL_API_PORT, reload=False)


if __name__ == "__main__":
    main()
