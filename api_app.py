"""ASGI API and static app server for the custom Quantum Encryptor web UI."""

from __future__ import annotations

import logging
import mimetypes
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import BaseRoute, Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from crypto_config import cfg
import crypto_core as core
from ui_helpers import format_key_info_for_display, guess_decrypted_filename

logger = logging.getLogger(__name__)

APP_ROOT = Path(__file__).resolve().parent
MULTIPART_OVERHEAD_BYTES = 1024 * 1024
SMALL_FORM_MAX_BYTES = 64 * 1024
LOCAL_API_TOKEN = os.environ.get("QUANTUM_ENCRYPTOR_API_TOKEN") or secrets.token_urlsafe(32)
ALLOWED_ORIGIN_PREFIXES = (
    "http://127.0.0.1:",
    "http://localhost:",
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
    if path == "/api/keys/generate":
        return SMALL_FORM_MAX_BYTES
    if path == "/api/keys/inspect":
        return cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    if path == "/api/files/encrypt":
        return cfg.MAX_FILE_BYTES + cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    if path == "/api/files/decrypt":
        return cfg.MAX_ENCRYPTED_FILE_BYTES + cfg.MAX_PEM_BYTES + MULTIPART_OVERHEAD_BYTES
    return None


def _header_value(scope: Scope, name: bytes) -> str | None:
    for header_name, value in scope.get("headers", []):
        if header_name.lower() == name:
            return value.decode("latin1")
    return None


def _is_state_changing_api(scope: Scope) -> bool:
    method = str(scope.get("method", "GET")).upper()
    path = str(scope.get("path", ""))
    return method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/")


def _is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return True
    return origin.startswith(ALLOWED_ORIGIN_PREFIXES)


def _has_valid_local_api_token(token: str | None) -> bool:
    if token is None:
        return False
    return secrets.compare_digest(token.encode("utf-8"), LOCAL_API_TOKEN.encode("utf-8"))


class LocalApiGuardMiddleware:
    """Require local browser context plus per-process token for state-changing API requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_state_changing_api(scope):
            await self.app(scope, receive, send)
            return

        origin = _header_value(scope, b"origin")
        if not _is_allowed_origin(origin):
            await _json_error(ApiError(403, "forbidden_origin", "Request origin is not allowed."))(scope, receive, send)
            return

        token = _header_value(scope, b"x-quantum-encryptor-token")
        if not _has_valid_local_api_token(token):
            await _json_error(ApiError(403, "missing_api_token", "Missing or invalid local API token."))(
                scope, receive, send
            )
            return

        await self.app(scope, receive, send)


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

        content_length = _header_value(scope, b"content-length")
        if content_length is None:
            await _json_error(ApiError(411, "length_required", "API requests must include a Content-Length header."))(
                scope, receive, send
            )
            return
        try:
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


def _health_payload() -> dict[str, Any]:
    try:
        active_kem_component = core.resolve_kem_algorithm(cfg.KEM_ALG)
        backend_ready = True
        backend_message = "Post-quantum backend ready."
    except Exception as exc:
        active_kem_component = cfg.KEM_ALG
        backend_ready = False
        backend_message = (
            "Post-quantum backend is not ready. Install native liboqs before generating keys or processing files."
        )
        logger.warning("Post-quantum backend readiness check failed: %s", exc)

    return {
        "backendReady": backend_ready,
        "backendMessage": backend_message,
        "formatVersion": cfg.FORMAT_VERSION,
        "kem": cfg.HYBRID_KEM_ALG,
        "kemComponent": active_kem_component,
        "configuredKem": cfg.KEM_ALG,
        "dem": "AES-256-GCM",
        "maxFileBytes": cfg.MAX_FILE_BYTES,
        "maxEncryptedFileBytes": cfg.MAX_ENCRYPTED_FILE_BYTES,
        "maxPemBytes": cfg.MAX_PEM_BYTES,
        "apiToken": LOCAL_API_TOKEN,
        "passwordPolicy": {
            "minChars": cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS,
            "minUniqueChars": cfg.PRIVATE_KEY_MIN_UNIQUE_CHARS,
        },
    }


async def health(_request: Request) -> JSONResponse:
    response = _success_json(_health_payload())
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
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


async def generate_keys(request: Request) -> JSONResponse:
    try:
        form = await _form(request, max_files=0)
        password = _form_text(form, "password")
        try:
            core.validate_private_key_password(password)
        except (core.PasswordRequiredError, core.WeakPasswordError) as exc:
            raise ApiError(400, "weak_password", str(exc)) from exc

        active_kem_alg = core.resolve_kem_algorithm(cfg.KEM_ALG)
        raw_public_key, raw_private_key = core.generate_hybrid_keys(active_kem_alg)
        if not raw_public_key or not raw_private_key:
            raise ApiError(503, "backend_unavailable", "Could not generate a hybrid key pair.")

        public_pem = core.save_key_pem(raw_public_key, cfg.HYBRID_KEM_ALG, "public")
        private_pem = core.save_key_pem(raw_private_key, cfg.HYBRID_KEM_ALG, "private", password=password)
        del raw_public_key
        del raw_private_key
        if not public_pem or not private_pem:
            raise ApiError(500, "pem_format_failed", "Could not format generated keys.")

        return _success_json(
            {
                "kem": cfg.HYBRID_KEM_ALG,
                "publicPem": public_pem,
                "privatePem": private_pem,
                "publicFilename": "ml-kem-768_x25519_public.pem",
                "privateFilename": "ml-kem-768_x25519_private.pem",
            }
        )
    except ApiError as exc:
        return _json_error(exc)
    except core.CryptoDependencyError:
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    except Exception as exc:
        return _safe_unexpected("generate-keys", exc)


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
        public_key_bytes, kem_alg_from_key, key_type = core.load_key_pem(public_pem)
        if not public_key_bytes or not kem_alg_from_key or key_type != "public":
            raise ApiError(400, "invalid_public_key", "Upload a supported PQC public key PEM file.")
        if kem_alg_from_key != cfg.HYBRID_KEM_ALG:
            raise ApiError(400, "legacy_public_key", "Generate a new ML-KEM-768+X25519 public key for encryption.")

        encrypted_blob = core.encrypt_file_pro(input_data, public_key_bytes, kem_alg_from_key)
        del input_data
        del public_key_bytes
        if encrypted_blob is None:
            raise ApiError(
                503, "encryption_failed", "Encryption failed. Check backend readiness and key compatibility."
            )

        return _download_response(encrypted_blob, output_filename)
    except ApiError as exc:
        return _json_error(exc)
    except core.CryptoDependencyError:
        return _json_error(ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."))
    except Exception as exc:
        return _safe_unexpected("encrypt-file", exc)


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
        key_info = core.inspect_key_pem_strict(private_pem)
        if key_info.get("key_type") != "private":
            raise ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")

        private_key_bytes, kem_alg_key, key_type = core.load_key_pem(private_pem, password=password)
        if not private_key_bytes or not kem_alg_key or key_type != "private":
            raise ApiError(
                400, "private_key_failed", "Could not unlock the private key. Check the password and key file."
            )

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


async def frontend_missing(_request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        "Quantum Encryptor web UI has not been built. Run `npm install` and `npm run build`, then start the server.",
        status_code=503,
    )


def create_app() -> Starlette:
    routes: list[BaseRoute] = [
        Route("/api/health", health, methods=["GET"]),
        Route("/api/keys/inspect", inspect_key, methods=["POST"]),
        Route("/api/keys/generate", generate_keys, methods=["POST"]),
        Route("/api/files/encrypt", encrypt_file, methods=["POST"]),
        Route("/api/files/decrypt", decrypt_file, methods=["POST"]),
    ]
    if STATIC_APP_DIR.exists():
        routes.append(Mount("/", StaticFiles(directory=STATIC_APP_DIR, html=True), name="web"))
    else:
        routes.append(Route("/{path:path}", frontend_missing, methods=["GET"]))
    app = Starlette(debug=False, routes=routes)
    app.add_middleware(ApiBodyLimitMiddleware)
    app.add_middleware(LocalApiGuardMiddleware)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - [%(module)s] - %(message)s",
    )
    port = int(os.environ.get("PORT", "4000"))
    uvicorn.run("api_app:app", host="127.0.0.1", port=port, reload=False)


if __name__ == "__main__":
    main()
