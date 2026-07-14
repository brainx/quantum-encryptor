# pqc_agent_tools.py
import argparse
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NoReturn, Optional, Sequence

from crypto_config import cfg
import crypto_core as core

EXIT_SUCCESS = 0
EXIT_UNEXPECTED = 1
EXIT_INVALID_INPUT = 2
EXIT_BACKEND_UNAVAILABLE = 3
EXIT_CRYPTO_FAILURE = 4
EXIT_PATH_VIOLATION = 5

# Environment variable name, not a password value.
DEFAULT_PASSWORD_ENV = "PQC_PRIVATE_KEY_PASSWORD"  # nosec B105


@dataclass
class AgentCommandError(Exception):
    error_code: str
    message: str
    exit_code: int
    operation: str = "parse"


class AgentArgumentParser(argparse.ArgumentParser):
    """argparse parser that reports failures through the agent JSON contract."""

    def error(self, message: str) -> NoReturn:
        raise AgentCommandError("invalid_args", message, EXIT_INVALID_INPUT)


@contextlib.contextmanager
def _suppress_library_output():
    """Keep stdout JSON-only even when native wrappers log during import/use."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


def _json_result(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True))


def _success(operation: str, **fields: Any) -> int:
    payload: dict[str, Any] = {
        "ok": True,
        "operation": operation,
        "format_version": cfg.FORMAT_VERSION,
    }
    payload.update(fields)
    _json_result(payload)
    return EXIT_SUCCESS


def _failure(operation: str, error_code: str, message: str) -> None:
    _json_result(
        {
            "ok": False,
            "operation": operation,
            "error_code": error_code,
            "message": message,
        }
    )


def _workspace_root() -> Path:
    return Path.cwd().resolve()


def _relative_to_workspace(path: Path, workspace: Path) -> str:
    return path.relative_to(workspace).as_posix()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _reject_unsafe_path_text(path_text: str) -> Path:
    path = Path(path_text)
    if not path_text.strip():
        raise AgentCommandError("invalid_path", "Path cannot be empty.", EXIT_PATH_VIOLATION)
    if path.is_absolute():
        raise AgentCommandError("path_outside_workspace", "Absolute paths are not allowed.", EXIT_PATH_VIOLATION)
    if ".." in path.parts:
        raise AgentCommandError(
            "path_outside_workspace", "Parent-directory traversal is not allowed.", EXIT_PATH_VIOLATION
        )
    return path


def _resolve_input_path(path_text: str, workspace: Path) -> Path:
    relative_path = _reject_unsafe_path_text(path_text)
    try:
        resolved = (workspace / relative_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AgentCommandError("invalid_path", "Input path could not be resolved.", EXIT_INVALID_INPUT) from exc
    if not _is_relative_to(resolved, workspace):
        raise AgentCommandError("path_outside_workspace", "Path escapes the workspace.", EXIT_PATH_VIOLATION)
    try:
        is_file = resolved.is_file()
    except OSError as exc:
        raise AgentCommandError("invalid_path", "Could not inspect input path.", EXIT_INVALID_INPUT) from exc
    if not is_file:
        raise AgentCommandError("invalid_path", "Input path must be a file.", EXIT_INVALID_INPUT)
    return resolved


def _resolve_output_path(path_text: str, workspace: Path, overwrite: bool) -> Path:
    relative_path = _reject_unsafe_path_text(path_text)
    parent = (workspace / relative_path).parent.resolve(strict=True)
    if not _is_relative_to(parent, workspace):
        raise AgentCommandError("path_outside_workspace", "Output path escapes the workspace.", EXIT_PATH_VIOLATION)

    resolved = parent / relative_path.name
    if resolved.exists():
        existing = resolved.resolve(strict=True)
        if not _is_relative_to(existing, workspace):
            raise AgentCommandError("path_outside_workspace", "Output path escapes the workspace.", EXIT_PATH_VIOLATION)
        if not overwrite:
            raise AgentCommandError(
                "output_exists",
                "Output file already exists. Pass --overwrite to replace it.",
                EXIT_INVALID_INPUT,
            )
        if not existing.is_file():
            raise AgentCommandError("invalid_path", "Output path must be a file.", EXIT_INVALID_INPUT)
        return existing

    return resolved


def _current_umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


def _target_file_mode(path: Path, private_file: bool) -> int:
    if private_file:
        return 0o600
    try:
        return path.stat().st_mode & 0o777
    except FileNotFoundError:
        return 0o666 & ~_current_umask()


def _fsync_parent_dir(path: Path) -> None:
    if os.name == "nt":
        return
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _write_new_file_exclusive(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd: Optional[int] = None
    created = False
    try:
        fd = os.open(path, flags, mode)
        created = True
        with os.fdopen(fd, "wb") as out:
            fd = None
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(path, mode)
        _fsync_parent_dir(path)
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise
    finally:
        if fd is not None:
            os.close(fd)


def _replace_file_atomically(path: Path, data: bytes, mode: int) -> None:
    tmp_path: Optional[Path] = None
    fd: Optional[int] = None
    try:
        raw_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        fd = raw_fd
        tmp_path = Path(tmp_name)
        with os.fdopen(raw_fd, "wb") as tmp_file:
            fd = None
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        os.chmod(path, mode)
        _fsync_parent_dir(path)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _atomic_write_file(path: Path, data: bytes, overwrite: bool, private_file: bool, operation: str) -> None:
    mode = _target_file_mode(path, private_file)
    if overwrite:
        _replace_file_atomically(path, data, mode)
        return
    try:
        _write_new_file_exclusive(path, data, mode)
    except FileExistsError as exc:
        raise AgentCommandError(
            "output_exists",
            "Output file already exists. Pass --overwrite to replace it.",
            EXIT_INVALID_INPUT,
            operation,
        ) from exc


def _open_workspace_input(path: Path, workspace: Path) -> int:
    """Open a resolved workspace file without following replacement symlinks."""
    if os.name == "nt":
        return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))

    relative_path = path.relative_to(workspace)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(workspace, directory_flags)
    try:
        for part in relative_path.parts[:-1]:
            next_fd = os.open(part, directory_flags | nofollow, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            relative_path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def _read_resolved_workspace_file_limited(
    path: Path,
    workspace: Path,
    max_bytes: int,
    too_large_message: str,
) -> bytes:
    fd: Optional[int] = None
    try:
        fd = _open_workspace_input(path, workspace)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise AgentCommandError("invalid_path", "Input path must be a file.", EXIT_INVALID_INPUT)
        if file_stat.st_size > max_bytes:
            raise AgentCommandError("file_too_large", too_large_message, EXIT_INVALID_INPUT)
        with os.fdopen(fd, "rb") as input_file:
            fd = None
            data = input_file.read(max_bytes + 1)
    except AgentCommandError:
        raise
    except OSError as exc:
        raise AgentCommandError("invalid_path", "Could not read input path.", EXIT_INVALID_INPUT) from exc
    finally:
        if fd is not None:
            os.close(fd)

    if len(data) > max_bytes:
        raise AgentCommandError("file_too_large", too_large_message, EXIT_INVALID_INPUT)
    return data


def _read_workspace_file_limited(path_text: str, workspace: Path, max_bytes: int) -> tuple[Path, bytes]:
    path = _resolve_input_path(path_text, workspace)
    data = _read_resolved_workspace_file_limited(
        path,
        workspace,
        max_bytes,
        "Input file exceeds the configured size limit.",
    )
    return path, data


def _read_workspace_text(path_text: str, workspace: Path, max_bytes: Optional[int] = None) -> tuple[Path, str]:
    path = _resolve_input_path(path_text, workspace)
    limit = cfg.MAX_PEM_BYTES if max_bytes is None else max_bytes
    data = _read_resolved_workspace_file_limited(
        path,
        workspace,
        limit,
        "Text input file exceeds the configured size limit.",
    )
    try:
        return path, data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentCommandError(
            "invalid_input",
            "File must be valid UTF-8 text.",
            EXIT_INVALID_INPUT,
        ) from exc


def _write_workspace_file(
    path_text: str,
    workspace: Path,
    data: bytes,
    overwrite: bool,
    operation: str,
    private_file: bool = False,
) -> Path:
    path = _resolve_output_path(path_text, workspace, overwrite)
    try:
        _atomic_write_file(path, data, overwrite, private_file, operation)
    except AgentCommandError:
        raise
    except OSError as exc:
        raise AgentCommandError("write_failed", "Could not write output file.", EXIT_INVALID_INPUT, operation) from exc
    return path


def _write_workspace_text(
    path_text: str,
    workspace: Path,
    data: str,
    overwrite: bool,
    operation: str,
    private_file: bool = False,
) -> Path:
    return _write_workspace_file(path_text, workspace, data.encode("ascii"), overwrite, operation, private_file)


def _password_from_env(env_name: str, operation: str, required: bool) -> Optional[str]:
    password = os.environ.get(env_name)
    if password:
        try:
            return core.validate_private_key_password(password)
        except (core.PasswordRequiredError, core.WeakPasswordError) as exc:
            raise AgentCommandError(
                "weak_password",
                f"Set {env_name} to a stronger private-key password: {exc}",
                EXIT_CRYPTO_FAILURE,
                operation,
            ) from exc
    if required:
        raise AgentCommandError(
            "password_required",
            f"Set {env_name} before running this command.",
            EXIT_CRYPTO_FAILURE,
            operation,
        )
    return None


def _agent_error_from_core(operation: str, exc: Exception) -> AgentCommandError:
    if isinstance(exc, core.PasswordRequiredError):
        return AgentCommandError(
            "password_required", "Private-key password is required.", EXIT_CRYPTO_FAILURE, operation
        )
    if isinstance(exc, core.WeakPasswordError):
        return AgentCommandError(
            "weak_password",
            str(exc),
            EXIT_CRYPTO_FAILURE,
            operation,
        )
    if isinstance(exc, core.UnencryptedPrivateKeyError):
        return AgentCommandError(
            "unencrypted_private_key",
            "Unencrypted private keys are rejected.",
            EXIT_CRYPTO_FAILURE,
            operation,
        )
    if isinstance(exc, core.UnsupportedKDFError):
        return AgentCommandError(
            "unsupported_kdf",
            "Private key uses missing, malformed, or unsupported KDF metadata.",
            EXIT_INVALID_INPUT,
            operation,
        )
    if isinstance(exc, core.InvalidKeyFormatError):
        return AgentCommandError(
            "invalid_key", "Key file is not a supported PQC PEM key.", EXIT_INVALID_INPUT, operation
        )
    if isinstance(exc, core.UnsupportedAlgorithmError):
        return AgentCommandError("unsupported_algorithm", str(exc), EXIT_INVALID_INPUT, operation)
    if isinstance(exc, core.SizeLimitError):
        return AgentCommandError(
            "file_too_large", "Input file exceeds the configured size limit.", EXIT_INVALID_INPUT, operation
        )
    if isinstance(exc, core.FileFormatError):
        return AgentCommandError(
            "invalid_file_format",
            "Input file is not a supported authenticated encrypted container.",
            EXIT_INVALID_INPUT,
            operation,
        )
    if isinstance(exc, core.CryptoDependencyError):
        return AgentCommandError("backend_unavailable", str(exc), EXIT_BACKEND_UNAVAILABLE, operation)
    return AgentCommandError("crypto_error", "Cryptographic operation failed.", EXIT_CRYPTO_FAILURE, operation)


def _resolve_backend(operation: str, kem_alg: str = cfg.KEM_ALG) -> str:
    try:
        with _suppress_library_output():
            return core.resolve_kem_algorithm(kem_alg)
    except core.CryptoDependencyError as exc:
        raise AgentCommandError("backend_unavailable", str(exc), EXIT_BACKEND_UNAVAILABLE, operation) from exc
    except core.UnsupportedAlgorithmError as exc:
        raise AgentCommandError("unsupported_algorithm", str(exc), EXIT_INVALID_INPUT, operation) from exc


def handle_health(_args: argparse.Namespace, workspace: Path) -> int:
    operation = "health"
    try:
        kem_component = _resolve_backend(operation)
        return _success(
            operation,
            backend_available=True,
            kem=cfg.HYBRID_KEM_ALG,
            kem_component=kem_component,
            workspace=workspace.name,
        )
    except AgentCommandError as exc:
        if exc.error_code == "backend_unavailable":
            _json_result(
                {
                    "ok": True,
                    "operation": operation,
                    "format_version": cfg.FORMAT_VERSION,
                    "backend_available": False,
                    "kem": cfg.HYBRID_KEM_ALG,
                    "kem_component": cfg.KEM_ALG,
                    "backend_error_code": exc.error_code,
                    "message": exc.message,
                    "workspace": workspace.name,
                }
            )
            return EXIT_SUCCESS
        raise


def handle_inspect_key(args: argparse.Namespace, workspace: Path) -> int:
    operation = "inspect-key"
    key_path, pem_content = _read_workspace_text(args.key, workspace)
    try:
        payload = core.inspect_key_pem_strict(pem_content)
    except Exception as exc:
        raise _agent_error_from_core(operation, exc) from exc

    payload["key"] = _relative_to_workspace(key_path, workspace)
    return _success(operation, **payload)


def handle_generate_keys(args: argparse.Namespace, workspace: Path) -> int:
    operation = "generate-keys"
    kem_component = _resolve_backend(operation)
    password = _password_from_env(args.password_env, operation, required=True)

    public_out = _resolve_output_path(args.public_out, workspace, args.overwrite)
    private_out = _resolve_output_path(args.private_out, workspace, args.overwrite)
    if public_out == private_out:
        raise AgentCommandError(
            "invalid_path", "Public and private output paths must differ.", EXIT_INVALID_INPUT, operation
        )

    with _suppress_library_output():
        public_key, private_key = core.generate_hybrid_keys(kem_component)
    if not public_key or not private_key:
        raise AgentCommandError("key_generation_failed", "Key generation failed.", EXIT_BACKEND_UNAVAILABLE, operation)

    public_pem = core.save_key_pem(public_key, cfg.HYBRID_KEM_ALG, "public")
    private_pem = core.save_key_pem(private_key, cfg.HYBRID_KEM_ALG, "private", password=password)
    del public_key
    del private_key

    if not public_pem or not private_pem:
        raise AgentCommandError("key_format_failed", "Could not format generated keys.", EXIT_CRYPTO_FAILURE, operation)

    public_path = _write_workspace_text(args.public_out, workspace, public_pem, args.overwrite, operation)
    private_path = _write_workspace_text(
        args.private_out,
        workspace,
        private_pem,
        args.overwrite,
        operation,
        private_file=True,
    )
    return _success(
        operation,
        kem=cfg.HYBRID_KEM_ALG,
        kem_component=kem_component,
        public_key=_relative_to_workspace(public_path, workspace),
        private_key=_relative_to_workspace(private_path, workspace),
        private_key_encrypted=True,
        private_key_kdf=cfg.PRIVATE_KEY_KDF_ALG,
    )


def handle_encrypt(args: argparse.Namespace, workspace: Path) -> int:
    operation = "encrypt"
    input_path, input_data = _read_workspace_file_limited(args.input, workspace, cfg.MAX_FILE_BYTES)
    public_key_path, public_key_pem = _read_workspace_text(args.public_key, workspace)
    output_path = _resolve_output_path(args.output, workspace, args.overwrite)

    public_key, kem_alg, key_type = core.load_key_pem(public_key_pem)
    if not public_key or not kem_alg or key_type != "public":
        raise AgentCommandError(
            "invalid_key", "Public key file is invalid or has the wrong key type.", EXIT_INVALID_INPUT, operation
        )
    if kem_alg != cfg.HYBRID_KEM_ALG:
        raise AgentCommandError(
            "legacy_public_key",
            "Generate a new ML-KEM-768+X25519 public key for encryption.",
            EXIT_INVALID_INPUT,
            operation,
        )

    _resolve_backend(operation)
    with _suppress_library_output():
        encrypted_blob = core.encrypt_file_pro(input_data, public_key, cfg.HYBRID_KEM_ALG)
    del input_data
    del public_key

    if encrypted_blob is None:
        raise AgentCommandError("encryption_failed", "Encryption failed.", EXIT_CRYPTO_FAILURE, operation)

    _write_workspace_file(args.output, workspace, encrypted_blob, args.overwrite, operation)
    return _success(
        operation,
        kem=cfg.HYBRID_KEM_ALG,
        input=_relative_to_workspace(input_path, workspace),
        public_key=_relative_to_workspace(public_key_path, workspace),
        output=_relative_to_workspace(output_path, workspace),
        bytes_written=len(encrypted_blob),
    )


def handle_inspect_file(args: argparse.Namespace, workspace: Path) -> int:
    operation = "inspect-file"
    input_path, encrypted_blob = _read_workspace_file_limited(args.input, workspace, cfg.MAX_ENCRYPTED_FILE_BYTES)
    try:
        metadata = core.inspect_encrypted_file_strict(encrypted_blob)
    except Exception as exc:
        raise _agent_error_from_core(operation, exc) from exc

    return _success(
        operation,
        input=_relative_to_workspace(input_path, workspace),
        encrypted_format_version=metadata.version,
        kem=metadata.kem_alg,
        header_bytes=metadata.header_bytes,
        kem_ciphertext_bytes=metadata.kem_ciphertext_bytes,
        x25519_ciphertext_bytes=metadata.x25519_ciphertext_bytes,
        encrypted_payload_bytes=metadata.encrypted_payload_bytes,
        total_bytes=metadata.total_bytes,
    )


def _load_required_private_key(
    private_key_path_text: str,
    password_env: str,
    workspace: Path,
    operation: str,
) -> tuple[Path, bytes, str]:
    private_key_path, private_key_pem = _read_workspace_text(private_key_path_text, workspace)
    try:
        key_info = core.inspect_key_pem_strict(private_key_pem)
    except Exception as exc:
        raise _agent_error_from_core(operation, exc) from exc

    if key_info["key_type"] != "private":
        raise AgentCommandError("invalid_key", "Private key is required.", EXIT_INVALID_INPUT, operation)

    password = _password_from_env(password_env, operation, required=True)
    private_key, kem_alg, loaded_key_type = core.load_key_pem(private_key_pem, password=password)
    if not private_key or not kem_alg or loaded_key_type != "private":
        raise AgentCommandError(
            "private_key_load_failed", "Could not load private key.", EXIT_CRYPTO_FAILURE, operation
        )
    return private_key_path, private_key, kem_alg


def handle_decrypt(args: argparse.Namespace, workspace: Path) -> int:
    operation = "decrypt"
    encrypted_path, encrypted_blob = _read_workspace_file_limited(args.input, workspace, cfg.MAX_ENCRYPTED_FILE_BYTES)
    if not encrypted_blob:
        raise AgentCommandError("invalid_input", "Encrypted input file is empty.", EXIT_INVALID_INPUT, operation)

    output_path = _resolve_output_path(args.output, workspace, args.overwrite)
    private_key_path, private_key, kem_alg = _load_required_private_key(
        args.private_key,
        args.password_env,
        workspace,
        operation,
    )

    _resolve_backend(operation)
    with _suppress_library_output():
        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_blob, private_key, expected_kem_alg=kem_alg)
    del encrypted_blob
    del private_key

    if decrypted_data is None:
        raise AgentCommandError(
            "decryption_failed",
            "Decryption failed. Check private key, password, and ciphertext integrity.",
            EXIT_CRYPTO_FAILURE,
            operation,
        )

    _write_workspace_file(args.output, workspace, decrypted_data, args.overwrite, operation, private_file=True)
    bytes_written = len(decrypted_data)
    del decrypted_data
    return _success(
        operation,
        kem=detected_alg or kem_alg,
        input=_relative_to_workspace(encrypted_path, workspace),
        private_key=_relative_to_workspace(private_key_path, workspace),
        output=_relative_to_workspace(output_path, workspace),
        bytes_written=bytes_written,
    )


def handle_verify_file(args: argparse.Namespace, workspace: Path) -> int:
    operation = "verify-file"
    encrypted_path, encrypted_blob = _read_workspace_file_limited(args.input, workspace, cfg.MAX_ENCRYPTED_FILE_BYTES)
    try:
        metadata = core.inspect_encrypted_file_strict(encrypted_blob)
    except Exception as exc:
        raise _agent_error_from_core(operation, exc) from exc

    private_key_path, private_key, kem_alg = _load_required_private_key(
        args.private_key,
        args.password_env,
        workspace,
        operation,
    )

    _resolve_backend(operation)
    with _suppress_library_output():
        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_blob, private_key, expected_kem_alg=kem_alg)
    del encrypted_blob
    del private_key

    if decrypted_data is None:
        raise AgentCommandError(
            "verification_failed",
            "Verification failed. Check private key, password, and ciphertext integrity.",
            EXIT_CRYPTO_FAILURE,
            operation,
        )

    bytes_verified = len(decrypted_data)
    del decrypted_data
    return _success(
        operation,
        kem=detected_alg or metadata.kem_alg,
        input=_relative_to_workspace(encrypted_path, workspace),
        private_key=_relative_to_workspace(private_key_path, workspace),
        bytes_verified=bytes_verified,
    )


def _add_password_env_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--password-env",
        default=DEFAULT_PASSWORD_ENV,
        help="Environment variable containing the private-key password.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = AgentArgumentParser(
        prog="quantum-encryptor-agent",
        description="Local JSON CLI for agentic Quantum Encryptor workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    health = subparsers.add_parser("health", help="Report backend readiness.")
    health.add_argument("--json", action="store_true", help="Accepted for explicit agent JSON mode.")
    health.set_defaults(handler=handle_health)

    generate = subparsers.add_parser("generate-keys", help="Generate a PQC key pair.")
    generate.add_argument("--public-out", required=True)
    generate.add_argument("--private-out", required=True)
    _add_password_env_argument(generate)
    generate.add_argument("--overwrite", action="store_true")
    generate.set_defaults(handler=handle_generate_keys)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt a workspace file.")
    encrypt.add_argument("--input", required=True)
    encrypt.add_argument("--public-key", required=True)
    encrypt.add_argument("--output", required=True)
    encrypt.add_argument("--overwrite", action="store_true")
    encrypt.set_defaults(handler=handle_encrypt)

    inspect_file = subparsers.add_parser("inspect-file", help="Inspect an encrypted workspace file.")
    inspect_file.add_argument("--input", required=True)
    inspect_file.set_defaults(handler=handle_inspect_file)

    decrypt = subparsers.add_parser("decrypt", help="Decrypt a workspace file.")
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--private-key", required=True)
    decrypt.add_argument("--output", required=True)
    _add_password_env_argument(decrypt)
    decrypt.add_argument("--overwrite", action="store_true")
    decrypt.set_defaults(handler=handle_decrypt)

    verify_file = subparsers.add_parser("verify-file", help="Authenticate an encrypted workspace file without output.")
    verify_file.add_argument("--input", required=True)
    verify_file.add_argument("--private-key", required=True)
    _add_password_env_argument(verify_file)
    verify_file.set_defaults(handler=handle_verify_file)

    inspect_key = subparsers.add_parser("inspect-key", help="Inspect a PQC PEM key.")
    inspect_key.add_argument("--key", required=True)
    inspect_key.set_defaults(handler=handle_inspect_key)

    return parser


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    workspace = _workspace_root()
    args: Optional[argparse.Namespace] = None
    try:
        args = parser.parse_args(argv)
        handler: Callable[[argparse.Namespace, Path], int] = args.handler
        return handler(args, workspace)
    except AgentCommandError as exc:
        operation = exc.operation
        if operation == "parse" and args is not None and getattr(args, "command", None):
            operation = args.command
        _failure(operation, exc.error_code, exc.message)
        return exc.exit_code
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_UNEXPECTED
    except Exception:
        _failure("unknown", "unexpected_error", "Unexpected error while running agent command.")
        return EXIT_UNEXPECTED


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
