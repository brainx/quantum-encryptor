"""
Tests for the local agent-facing CLI.
"""

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from crypto_config import cfg
import crypto_core as core
import pqc_agent_tools as tools


def _run_agent(argv, capsys):
    code = tools.run(argv)
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


def _valid_public_pem() -> str:
    key_bytes = bytes(range(cfg.X25519_KEY_BYTES)) + bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES)
    key_data = base64.b64encode(key_bytes).decode("ascii")
    return "\n".join(
        [
            cfg.PEM_PUBLIC_HEADER,
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
            key_data,
            cfg.PEM_PUBLIC_FOOTER,
            "",
        ]
    )


def _valid_private_pem(encrypted: bool = True) -> str:
    if encrypted:
        key_bytes = bytes(cfg.HYBRID_PRIVATE_KEY_BYTES + cfg.AES_TAG_BYTES)
    else:
        mlkem_public = bytes(cfg.MLKEM768_PUBLIC_KEY_BYTES)
        mlkem_private = (
            bytes(cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES)
            + mlkem_public
            + hashlib.sha3_256(mlkem_public).digest()
            + bytes(32)
        )
        key_bytes = bytes(cfg.X25519_KEY_BYTES) + mlkem_private
    key_data = base64.b64encode(key_bytes).decode("ascii")
    if not encrypted:
        return "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
                key_data,
                cfg.PEM_PRIVATE_FOOTER,
                "",
            ]
        )

    salt = base64.b64encode(b"0" * cfg.SCRYPT_SALT_BYTES).decode("ascii")
    nonce = base64.b64encode(b"1" * cfg.AES_NONCE_BYTES).decode("ascii")
    return "\n".join(
        [
            cfg.PEM_PRIVATE_HEADER,
            f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}",
            cfg.PEM_PROC_TYPE_HEADER,
            f"{cfg.PEM_DEK_INFO_HEADER}{salt},{nonce}",
            f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG},n={cfg.SCRYPT_N},r={cfg.SCRYPT_R},p={cfg.SCRYPT_P}",
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
            key_data,
            cfg.PEM_PRIVATE_FOOTER,
            "",
        ]
    )


def _private_key_info() -> dict[str, object]:
    return {
        "key_type": "private",
        "kem": cfg.HYBRID_KEM_ALG,
        "private_key_encrypted": True,
        "private_key_format_version": cfg.PEM_PRIVATE_KEY_FORMAT_VERSION,
        "private_key_kdf": cfg.PRIVATE_KEY_KDF_ALG,
    }


def _syntactic_encrypted_blob() -> bytes:
    alg = cfg.HYBRID_KEM_ALG.encode("utf-8")
    return (
        cfg.MAGIC_BYTES
        + cfg.FORMAT_VERSION.to_bytes(2, "big")
        + len(alg).to_bytes(2, "big")
        + alg
        + (1).to_bytes(4, "big")
        + b"x"
        + b"X" * cfg.X25519_KEY_BYTES
        + b"1" * cfg.AES_NONCE_BYTES
        + b"ciphertext-and-tag"
    )


def _stream_metadata(plaintext_bytes: int, kem: str = cfg.HYBRID_KEM_ALG, total_bytes: int | None = None):
    return core.EncryptedFileMetadata(
        version=cfg.FORMAT_VERSION,
        kem_alg=kem,
        header_bytes=0,
        kem_ciphertext_bytes=0,
        x25519_ciphertext_bytes=0,
        encrypted_payload_bytes=plaintext_bytes + cfg.AES_TAG_BYTES,
        total_bytes=total_bytes if total_bytes is not None else plaintext_bytes + cfg.AES_TAG_BYTES,
    )


def _mock_stream_encryption(monkeypatch, transform):
    def encrypt(source, sink, _public_key, _kem, **_kwargs):
        data = transform(source.read())
        sink.write(data)
        return _stream_metadata(0, total_bytes=len(data))

    monkeypatch.setattr(tools.streaming, "encrypt_stream", encrypt)


def test_health_reports_backend_unavailable_without_crashing(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)

    def missing_backend(_kem_alg=None):
        raise core.CryptoDependencyError("native backend missing")

    monkeypatch.setattr(core, "resolve_kem_algorithm", missing_backend)

    code, payload = _run_agent(["health", "--json"], capsys)

    assert code == tools.EXIT_SUCCESS
    assert payload["ok"] is True
    assert payload["operation"] == "health"
    assert payload["backend_available"] is False
    assert payload["backend_error_code"] == "backend_unavailable"


def test_inspect_key_returns_public_key_metadata(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    key_path = tmp_path / "recipient.pem"
    key_path.write_text(_valid_public_pem(), encoding="utf-8")

    code, payload = _run_agent(["inspect-key", "--key", "recipient.pem"], capsys)

    assert code == tools.EXIT_SUCCESS
    fingerprint = payload.pop("public_key_fingerprint")
    assert fingerprint.startswith("QE1-SHA3-256:")
    assert len(fingerprint) == len("QE1-SHA3-256:") + 64
    digest = fingerprint.removeprefix("QE1-SHA3-256:")
    assert digest == digest.lower()
    assert set(digest) <= set("0123456789abcdef")
    assert payload == {
        "ok": True,
        "operation": "inspect-key",
        "format_version": cfg.FORMAT_VERSION,
        "key": "recipient.pem",
        "key_type": "public",
        "kem": cfg.HYBRID_KEM_ALG,
    }


def test_inspect_key_unlocks_private_key_only_when_password_env_is_requested(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "correct horse battery staple")
    fingerprint = "QE1-SHA3-256:" + "c" * 64
    monkeypatch.setattr(
        core,
        "inspect_key_pem_strict",
        lambda _pem: _private_key_info(),
    )

    def load_private_key(_pem: str, password=None):
        assert password == "correct horse battery staple"
        return b"private", cfg.HYBRID_KEM_ALG, "private"

    monkeypatch.setattr(core, "load_key_pem", load_private_key)

    def get_fingerprint(private_key: bytes, kem_alg: str) -> str:
        assert private_key == b"private"
        assert kem_alg == cfg.HYBRID_KEM_ALG
        return fingerprint

    monkeypatch.setattr(core, "get_private_key_public_fingerprint", get_fingerprint, raising=False)

    code, payload = _run_agent(
        ["inspect-key", "--key", "private.pem", "--password-env", "AGENT_SECRET"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["public_key_fingerprint"] == fingerprint


def test_inspect_key_private_metadata_does_not_read_default_password_env(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(
        core,
        "inspect_key_pem_strict",
        lambda _pem: _private_key_info(),
    )
    monkeypatch.setattr(core, "load_key_pem", lambda *_args, **_kwargs: pytest.fail("private key must stay locked"))

    code, payload = _run_agent(["inspect-key", "--key", "private.pem"], capsys)

    assert code == tools.EXIT_SUCCESS
    assert "public_key_fingerprint" not in payload


def test_inspect_key_wrong_private_password_fails_without_fingerprint(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "incorrect horse battery staple")
    monkeypatch.setattr(
        core,
        "inspect_key_pem_strict",
        lambda _pem: _private_key_info(),
    )

    def reject_password(_pem: str, password=None):
        assert password == "incorrect horse battery staple"
        return None, None, None

    monkeypatch.setattr(core, "load_key_pem", reject_password)
    monkeypatch.setattr(
        core,
        "get_private_key_public_fingerprint",
        lambda *_args: pytest.fail("fingerprint must not be derived after failed unlock"),
        raising=False,
    )

    code, payload = _run_agent(
        ["inspect-key", "--key", "private.pem", "--password-env", "AGENT_SECRET"],
        capsys,
    )

    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["error_code"] == "private_key_load_failed"
    assert "public_key_fingerprint" not in payload


def test_inspect_key_rejects_unencrypted_private_key(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "private.pem").write_text(_valid_private_pem(encrypted=False), encoding="utf-8")

    code, payload = _run_agent(["inspect-key", "--key", "private.pem"], capsys)

    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["error_code"] == "unencrypted_private_key"


def test_inspect_key_rejects_oversized_pem_before_parse(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_PEM_BYTES", 16)
    (tmp_path / "huge.pem").write_text("A" * 17, encoding="utf-8")
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(["inspect-key", "--key", "huge.pem"], capsys)

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"


def test_inspect_key_reports_missing_path_as_invalid_input(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)

    code, payload = _run_agent(["inspect-key", "--key", "missing.pem"], capsys)

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["operation"] == "inspect-key"
    assert payload["error_code"] == "invalid_path"


def test_workspace_read_enforces_limit_against_understated_path_stat(monkeypatch, tmp_path):
    input_path = tmp_path / "growing.bin"
    input_path.write_bytes(b"12345")
    original_stat = Path.stat

    def understated_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == input_path:
            values = list(result)
            values[6] = 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "stat", understated_stat)

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._read_workspace_file_limited("growing.bin", tmp_path, max_bytes=1)

    assert exc.value.error_code == "file_too_large"


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow open required")
def test_workspace_read_rejects_file_replaced_by_symlink(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    input_path = workspace / "message.bin"
    input_path.write_bytes(b"inside")
    resolved = tools._resolve_input_path("message.bin", workspace)

    outside_path = tmp_path / "outside.bin"
    outside_path.write_bytes(b"outside")
    input_path.unlink()
    input_path.symlink_to(outside_path)

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._read_resolved_workspace_file_limited(resolved, workspace, 64, "too large")

    assert exc.value.error_code == "invalid_path"


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NONBLOCK"), reason="POSIX nonblocking open required")
def test_workspace_input_opens_final_descriptor_nonblocking(monkeypatch, tmp_path):
    input_path = tmp_path / "message.bin"
    input_path.write_bytes(b"message")
    opened_flags = []
    original_open = tools.os.open

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == input_path.name and dir_fd is not None:
            opened_flags.append(flags)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(tools.os, "open", tracking_open)

    fd = tools._open_workspace_input(input_path, tmp_path)
    os.close(fd)

    assert opened_flags
    assert opened_flags[-1] & os.O_NONBLOCK


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="POSIX FIFO support required",
)
def test_workspace_read_rejects_file_replaced_by_fifo(tmp_path):
    input_path = tmp_path / "message.bin"
    input_path.write_bytes(b"message")
    resolved = tools._resolve_input_path("message.bin", tmp_path)

    input_path.unlink()
    os.mkfifo(input_path)

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._read_resolved_workspace_file_limited(resolved, tmp_path, 64, "too large")

    assert exc.value.error_code == "invalid_path"


def test_path_boundary_rejects_absolute_and_parent_paths(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    key_path = tmp_path / "recipient.pem"
    key_path.write_text(_valid_public_pem(), encoding="utf-8")

    absolute_code, absolute_payload = _run_agent(["inspect-key", "--key", str(key_path)], capsys)
    parent_code, parent_payload = _run_agent(["inspect-key", "--key", "../recipient.pem"], capsys)

    assert absolute_code == tools.EXIT_PATH_VIOLATION
    assert absolute_payload["error_code"] == "path_outside_workspace"
    assert parent_code == tools.EXIT_PATH_VIOLATION
    assert parent_payload["error_code"] == "path_outside_workspace"


def test_path_boundary_rejects_symlink_escape(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    outside_path = tmp_path.parent / f"{tmp_path.name}-outside.pem"
    outside_path.write_text(_valid_public_pem(), encoding="utf-8")
    symlink_path = tmp_path / "escaped.pem"
    try:
        symlink_path.symlink_to(outside_path)
    except OSError:
        pytest.skip("Symlink creation is not available in this environment.")

    try:
        code, payload = _run_agent(["inspect-key", "--key", "escaped.pem"], capsys)
    finally:
        outside_path.unlink(missing_ok=True)

    assert code == tools.EXIT_PATH_VIOLATION
    assert payload["error_code"] == "path_outside_workspace"


def test_encrypt_rejects_existing_output_without_overwrite(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.txt").write_bytes(b"hello")
    (tmp_path / "recipient.pem").write_text(_valid_public_pem(), encoding="utf-8")
    output_path = tmp_path / "message.pqc"
    output_path.write_bytes(b"existing")

    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.HYBRID_KEM_ALG, "public"))
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    _mock_stream_encryption(monkeypatch, lambda _data: b"encrypted")

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "output_exists"
    assert output_path.read_bytes() == b"existing"

    overwrite_code, overwrite_payload = _run_agent(
        [
            "encrypt",
            "--input",
            "message.txt",
            "--public-key",
            "recipient.pem",
            "--output",
            "message.pqc",
            "--overwrite",
        ],
        capsys,
    )

    assert overwrite_code == tools.EXIT_SUCCESS
    assert overwrite_payload["output"] == "message.pqc"
    assert output_path.read_bytes() == b"encrypted"


def test_atomic_write_non_overwrite_uses_exclusive_create(monkeypatch, tmp_path):
    output_path = tmp_path / "new-output.bin"
    original_open = tools.os.open
    opened_flags = []

    def tracking_open(path, flags, mode=0o777, *args, **kwargs):
        if os.fspath(path) == os.fspath(output_path):
            opened_flags.append(flags)
        return original_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(tools.os, "open", tracking_open)

    tools._atomic_write_file(output_path, b"new", overwrite=False, private_file=False, operation="test")

    assert output_path.read_bytes() == b"new"
    assert any(flags & os.O_EXCL for flags in opened_flags)


def test_atomic_write_non_overwrite_rejects_existing_file(tmp_path):
    output_path = tmp_path / "existing.bin"
    output_path.write_bytes(b"existing")

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._atomic_write_file(output_path, b"new", overwrite=False, private_file=False, operation="test")

    assert exc.value.error_code == "output_exists"
    assert output_path.read_bytes() == b"existing"


def test_encrypt_rejects_oversized_public_key_before_parse(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_PEM_BYTES", 16)
    (tmp_path / "message.txt").write_bytes(b"hello")
    (tmp_path / "recipient.pem").write_text("A" * 17, encoding="utf-8")
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"
    assert not (tmp_path / "message.pqc").exists()


def test_encrypt_rejects_oversized_input_before_key_parse(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_STREAM_FILE_BYTES", 4)
    (tmp_path / "message.txt").write_bytes(b"12345")
    (tmp_path / "recipient.pem").write_text(_valid_public_pem(), encoding="utf-8")
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"
    assert not (tmp_path / "message.pqc").exists()


def test_decrypt_requires_password_env_for_encrypted_private_key(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.delenv("AGENT_SECRET", raising=False)

    code, payload = _run_agent(
        [
            "decrypt",
            "--input",
            "message.pqc",
            "--private-key",
            "private.pem",
            "--output",
            "message.txt",
            "--password-env",
            "AGENT_SECRET",
        ],
        capsys,
    )

    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["error_code"] == "password_required"


def test_decrypt_rejects_oversized_private_key_before_parse(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_PEM_BYTES", 16)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text("A" * 17, encoding="utf-8")
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(
        [
            "decrypt",
            "--input",
            "message.pqc",
            "--private-key",
            "private.pem",
            "--output",
            "message.txt",
        ],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"
    assert not (tmp_path / "message.txt").exists()


def test_decrypt_uses_password_env_and_writes_plaintext_file(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "correct horse battery staple")
    monkeypatch.setattr(
        tools,
        "_resolve_backend",
        lambda *_args, **_kwargs: pytest.fail("decryption must defer backend selection to the container"),
    )
    monkeypatch.setattr(
        tools,
        "_resolve_decryption_backends",
        lambda _operation, suite: (cfg.KEM_ALG,) if suite == cfg.KEM_ALG else pytest.fail("unexpected suite"),
    )

    def load_private_key(_pem, password=None):
        assert password == "correct horse battery staple"
        return b"private", cfg.KEM_ALG, "private"

    monkeypatch.setattr(core, "load_key_pem", load_private_key)

    def decrypt_file(_source, sink, _private_key, expected_kem_alg=None, **_kwargs):
        assert expected_kem_alg == cfg.KEM_ALG
        sink.write(b"plaintext")
        return _stream_metadata(len(b"plaintext"), cfg.KEM_ALG)

    monkeypatch.setattr(tools.streaming, "decrypt_stream", decrypt_file)

    code, payload = _run_agent(
        [
            "decrypt",
            "--input",
            "message.pqc",
            "--private-key",
            "private.pem",
            "--output",
            "message.txt",
            "--password-env",
            "AGENT_SECRET",
        ],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["output"] == "message.txt"
    assert "plaintext" not in json.dumps(payload)
    assert (tmp_path / "message.txt").read_bytes() == b"plaintext"
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "message.txt").stat().st_mode) == 0o600


def test_decrypt_reports_suite_aware_backend_unavailable(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(
        core,
        "load_key_pem",
        lambda _pem, password=None: (b"private", cfg.HYBRID_KEM_ALG, "private"),
    )

    def missing_backend(_suite):
        raise core.CryptoDependencyError("exact backend missing")

    monkeypatch.setattr(core, "resolve_decryption_kem_algorithms", missing_backend, raising=False)
    monkeypatch.setattr(
        tools.streaming,
        "decrypt_stream",
        lambda *_args, **_kwargs: pytest.fail("decryption must not run without a compatible backend"),
    )

    code, payload = _run_agent(
        ["decrypt", "--input", "message.pqc", "--private-key", "private.pem", "--output", "message.txt"],
        capsys,
    )

    assert code == tools.EXIT_BACKEND_UNAVAILABLE
    assert payload["error_code"] == "backend_unavailable"
    assert not (tmp_path / "message.txt").exists()


def test_decrypt_allows_ciphertext_overhead_above_plaintext_limit(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_STREAM_FILE_BYTES", 3)
    monkeypatch.setattr(tools.streaming, "encrypted_size_limit", lambda _limit: 64)
    (tmp_path / "message.pqc").write_bytes(b"encrypted-container")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(tools, "_resolve_decryption_backends", lambda _operation, suite: (suite,))
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (b"private", cfg.KEM_ALG, "private"))

    def decrypt_file(_source, sink, _private_key, expected_kem_alg=None, **_kwargs):
        assert expected_kem_alg == cfg.KEM_ALG
        sink.write(b"abc")
        return _stream_metadata(3, cfg.KEM_ALG)

    monkeypatch.setattr(tools.streaming, "decrypt_stream", decrypt_file)

    code, payload = _run_agent(
        ["decrypt", "--input", "message.pqc", "--private-key", "private.pem", "--output", "message.txt"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["bytes_written"] == 3
    assert (tmp_path / "message.txt").read_bytes() == b"abc"


def test_decrypt_rejects_encrypted_input_above_encrypted_limit(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_STREAM_FILE_BYTES", 3)
    monkeypatch.setattr(tools.streaming, "encrypted_size_limit", lambda _limit: 4)
    (tmp_path / "message.pqc").write_bytes(b"12345")
    (tmp_path / "private.pem").write_text("private key placeholder", encoding="utf-8")
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(
        ["decrypt", "--input", "message.pqc", "--private-key", "private.pem", "--output", "message.txt"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"
    assert not (tmp_path / "message.txt").exists()


def test_verify_file_rejects_encrypted_input_above_limit_before_private_key_parse(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tools.streaming, "encrypted_size_limit", lambda _limit: 4)
    (tmp_path / "message.pqc").write_bytes(b"12345")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setattr(core, "inspect_key_pem_strict", lambda _pem: pytest.fail("PEM parser should not run"))

    code, payload = _run_agent(
        ["verify-file", "--input", "message.pqc", "--private-key", "private.pem"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "file_too_large"


def test_generate_keys_uses_password_env_without_printing_key_material(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "generate_hybrid_keys", lambda _kem: (b"public", b"private"))
    fingerprint = "QE1-SHA3-256:" + "d" * 64
    monkeypatch.setattr(core, "get_public_key_fingerprint", lambda _key, _kem: fingerprint)

    def save_key_pem(key_bytes, kem_alg, key_type, password=None):
        assert kem_alg == cfg.HYBRID_KEM_ALG
        if key_type == "public":
            assert key_bytes == b"public"
            return "PUBLIC PEM\n"
        assert key_bytes == b"private"
        assert password == "correct horse battery staple"
        return "PRIVATE PEM\n"

    monkeypatch.setattr(core, "save_key_pem", save_key_pem)

    code, payload = _run_agent(
        ["generate-keys", "--public-out", "agent-public.pem", "--private-out", "agent-private.pem"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["private_key_encrypted"] is True
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["private_key_kdf"] == cfg.PRIVATE_KEY_KDF_ALG
    assert payload["public_key_fingerprint"] == fingerprint
    assert payload["public_key"] == "agent-public.pem"
    assert payload["private_key"] == "agent-private.pem"
    assert "PRIVATE PEM" not in json.dumps(payload)
    assert (tmp_path / "agent-public.pem").read_text(encoding="ascii") == "PUBLIC PEM\n"
    assert (tmp_path / "agent-private.pem").read_text(encoding="ascii") == "PRIVATE PEM\n"
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "agent-private.pem").stat().st_mode) == 0o600


def test_generate_keys_requires_password_env(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(tools.DEFAULT_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)

    code, payload = _run_agent(
        ["generate-keys", "--public-out", "agent-public.pem", "--private-out", "agent-private.pem"],
        capsys,
    )

    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["error_code"] == "password_required"
    assert not (tmp_path / "agent-public.pem").exists()
    assert not (tmp_path / "agent-private.pem").exists()


def test_generate_keys_rejects_weak_password_env(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "aaaaaaaaaaaaaaaa")
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "generate_hybrid_keys", lambda _kem: pytest.fail("key generation should not run"))

    code, payload = _run_agent(
        ["generate-keys", "--public-out", "agent-public.pem", "--private-out", "agent-private.pem"],
        capsys,
    )

    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["error_code"] == "weak_password"
    assert not (tmp_path / "agent-public.pem").exists()
    assert not (tmp_path / "agent-private.pem").exists()


def test_encrypt_mocked_flow_writes_encrypted_file(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.txt").write_bytes(b"hello")
    (tmp_path / "recipient.pem").write_text(_valid_public_pem(), encoding="utf-8")
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.HYBRID_KEM_ALG, "public"))
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    _mock_stream_encryption(monkeypatch, lambda data: b"encrypted:" + data)

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["output"] == "message.pqc"
    assert (tmp_path / "message.pqc").read_bytes() == b"encrypted:hello"


@pytest.mark.parametrize("legacy_kem", [cfg.KEM_ALG, cfg.LEGACY_HYBRID_KEM_ALG])
def test_encrypt_rejects_legacy_public_key(monkeypatch, tmp_path, capsys, legacy_kem):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.txt").write_bytes(b"hello")
    (tmp_path / "recipient.pem").write_text(_valid_public_pem(), encoding="utf-8")
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", legacy_kem, "public"))
    monkeypatch.setattr(
        tools,
        "_resolve_backend",
        lambda *_args, **_kwargs: pytest.fail("legacy key must be rejected before backend resolution"),
    )

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "legacy_public_key"
    assert not (tmp_path / "message.pqc").exists()


def test_inspect_file_returns_encrypted_container_metadata(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(_syntactic_encrypted_blob())

    code, payload = _run_agent(["inspect-file", "--input", "message.pqc"], capsys)

    assert code == tools.EXIT_SUCCESS
    assert payload["input"] == "message.pqc"
    assert payload["encrypted_format_version"] == cfg.FORMAT_VERSION
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["kem_ciphertext_bytes"] == 1
    assert payload["x25519_ciphertext_bytes"] == cfg.X25519_KEY_BYTES


@pytest.mark.parametrize("command", ["inspect-file", "verify-file"])
@pytest.mark.parametrize("failure", ["format", "size"])
def test_stream_preflight_failures_preserve_json_error_contract(monkeypatch, tmp_path, capsys, command, failure):
    monkeypatch.chdir(tmp_path)
    blob = b"not an encrypted file" if failure == "format" else _syntactic_encrypted_blob() + b"extra"
    (tmp_path / "input.pqc").write_bytes(blob)
    argv = [command, "--input", "input.pqc", "--max-file-bytes", "1"]
    if command == "verify-file":
        argv += ["--private-key", "unused.pem"]

    code, payload = _run_agent(argv, capsys)

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["operation"] == command
    assert payload["error_code"] == ("invalid_file_format" if failure == "format" else "file_too_large")


@pytest.mark.parametrize("command", ["encrypt", "decrypt", "verify-file"])
@pytest.mark.parametrize(
    "exception,error_code",
    [
        (core.SizeLimitError, "file_too_large"),
        (core.InvalidKeyFormatError, "invalid_key"),
        (core.UnsupportedAlgorithmError, "unsupported_algorithm"),
    ],
)
def test_stream_execution_failures_preserve_json_error_contract(
    monkeypatch, tmp_path, capsys, command, exception, error_code
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "input.pqc").write_bytes(_syntactic_encrypted_blob())
    public = command == "encrypt"
    (tmp_path / "key.pem").write_text(_valid_public_pem() if public else _valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(
        core, "load_key_pem", lambda *_args, **_kwargs: (b"key", cfg.HYBRID_KEM_ALG, "public" if public else "private")
    )
    monkeypatch.setattr(tools, "_resolve_backend", lambda *_args: cfg.KEM_ALG)
    monkeypatch.setattr(tools, "_resolve_decryption_backends", lambda *_args: (cfg.KEM_ALG,))

    def fail(*_args, **_kwargs):
        raise exception("Operation input is invalid.")

    method = "verify_stream" if command == "verify-file" else f"{command}_stream"
    monkeypatch.setattr(tools.streaming, method, fail)
    argv = [command, "--input", "input.pqc", "--public-key" if public else "--private-key", "key.pem"]
    if command != "verify-file":
        argv += ["--output", "output.bin"]
    code, payload = _run_agent(argv, capsys)

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["operation"] == command
    assert payload["error_code"] == error_code
    assert not (tmp_path / "output.bin").exists()
    assert not list(tmp_path.glob(".*.tmp"))


def test_verify_file_authenticates_without_writing_plaintext(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(_syntactic_encrypted_blob())
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "correct horse battery staple")
    monkeypatch.setattr(
        tools,
        "_resolve_backend",
        lambda *_args, **_kwargs: pytest.fail("verification must defer backend selection to the container"),
    )
    monkeypatch.setattr(
        tools,
        "_resolve_decryption_backends",
        lambda _operation, suite: (cfg.KEM_ALG,) if suite == cfg.HYBRID_KEM_ALG else pytest.fail("unexpected suite"),
    )
    monkeypatch.setattr(
        core,
        "load_key_pem",
        lambda _pem, password=None: (b"private", cfg.HYBRID_KEM_ALG, "private"),
    )

    def verify_file(_source, _private_key, expected_kem_alg=None, **_kwargs):
        assert expected_kem_alg == cfg.HYBRID_KEM_ALG
        return _stream_metadata(len(b"plaintext"))

    monkeypatch.setattr(tools.streaming, "verify_stream", verify_file)

    code, payload = _run_agent(
        [
            "verify-file",
            "--input",
            "message.pqc",
            "--private-key",
            "private.pem",
            "--password-env",
            "AGENT_SECRET",
        ],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["bytes_verified"] == len(b"plaintext")
    assert "plaintext" not in json.dumps(payload)
    assert not (tmp_path / "message.txt").exists()


def test_invalid_agent_args_return_json_error(capsys):
    code = tools.run(["inspect-key"])
    captured = capsys.readouterr()

    assert captured.err == ""
    assert code == tools.EXIT_INVALID_INPUT
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error_code"] == "invalid_args"


def test_health_reports_backend_available(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: cfg.KEM_ALG)

    code, payload = _run_agent(["health", "--json"], capsys)

    assert code == tools.EXIT_SUCCESS
    assert payload["backend_available"] is True
    assert payload["kem"] == cfg.HYBRID_KEM_ALG
    assert payload["kem_component"] == cfg.KEM_ALG
    assert payload["workspace"] == tmp_path.name


def test_path_helpers_reject_empty_paths_and_input_directories(tmp_path):
    with pytest.raises(tools.AgentCommandError) as empty_path:
        tools._reject_unsafe_path_text(" ")
    assert empty_path.value.error_code == "invalid_path"

    (tmp_path / "directory").mkdir()
    with pytest.raises(tools.AgentCommandError) as directory_input:
        tools._resolve_input_path("directory", tmp_path)
    assert directory_input.value.error_code == "invalid_path"


def test_output_path_rejects_existing_directory_even_with_overwrite(tmp_path):
    (tmp_path / "output").mkdir()

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._resolve_output_path("output", tmp_path, overwrite=True)

    assert exc.value.error_code == "invalid_path"


def test_output_path_reports_missing_parent_as_invalid_input(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.txt").write_bytes(b"hello")
    (tmp_path / "recipient.pem").write_text(_valid_public_pem(), encoding="utf-8")

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "missing/message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["operation"] == "encrypt"
    assert payload["error_code"] == "invalid_path"


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow open required")
@pytest.mark.parametrize("overwrite", [False, True])
def test_workspace_write_rejects_parent_replaced_by_symlink(monkeypatch, tmp_path, overwrite):
    workspace = tmp_path / "workspace"
    output_directory = workspace / "output"
    output_directory.mkdir(parents=True)
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    outside_file = outside_directory / "message.bin"
    if overwrite:
        (output_directory / "message.bin").write_bytes(b"inside")
        outside_file.write_bytes(b"outside")
    original_resolve = tools._resolve_output_path

    def replace_parent_after_resolution(*args, **kwargs):
        resolved = original_resolve(*args, **kwargs)
        output_directory.rename(workspace / "original-output")
        output_directory.symlink_to(outside_directory, target_is_directory=True)
        return resolved

    monkeypatch.setattr(tools, "_resolve_output_path", replace_parent_after_resolution)

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._write_workspace_file("output/message.bin", workspace, b"secret", overwrite, "decrypt", private_file=True)

    assert exc.value.error_code == "write_failed"
    if overwrite:
        assert outside_file.read_bytes() == b"outside"
    else:
        assert not outside_file.exists()


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow open required")
@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("fail_write", [False, True])
def test_workspace_write_stays_anchored_after_parent_is_opened(monkeypatch, tmp_path, overwrite, fail_write):
    workspace = tmp_path / "workspace"
    output_directory = workspace / "output"
    output_directory.mkdir(parents=True)
    original_directory = workspace / "original-output"
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    outside_file = outside_directory / "message.bin"
    outside_file.write_bytes(b"outside")
    outside_file.chmod(0o640)
    if overwrite:
        (output_directory / "message.bin").write_bytes(b"inside")
    original_write = tools._atomic_write_file

    def replace_parent_after_open(*args, **kwargs):
        output_directory.rename(original_directory)
        output_directory.symlink_to(outside_directory, target_is_directory=True)
        return original_write(*args, **kwargs)

    monkeypatch.setattr(tools, "_atomic_write_file", replace_parent_after_open)
    if fail_write:

        def fail_file_write(_fd):
            raise OSError("Injected output flush failure")

        monkeypatch.setattr(tools.os, "fsync", fail_file_write)

        with pytest.raises(tools.AgentCommandError) as exc:
            tools._write_workspace_file(
                "output/message.bin", workspace, b"secret", overwrite, "decrypt", private_file=True
            )
        assert exc.value.error_code == "write_failed"
        if overwrite:
            assert (original_directory / "message.bin").read_bytes() == b"inside"
        else:
            assert not (original_directory / "message.bin").exists()
    else:
        tools._write_workspace_file("output/message.bin", workspace, b"secret", overwrite, "decrypt", private_file=True)
        assert (original_directory / "message.bin").read_bytes() == b"secret"
        assert stat.S_IMODE((original_directory / "message.bin").stat().st_mode) == 0o600

    assert outside_file.read_bytes() == b"outside"
    assert stat.S_IMODE(outside_file.stat().st_mode) == 0o640
    assert not list(original_directory.glob("*.tmp"))
    assert list(outside_directory.iterdir()) == [outside_file]


def test_read_workspace_text_rejects_invalid_utf8(tmp_path):
    (tmp_path / "bad.pem").write_bytes(b"\xff")

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._read_workspace_text("bad.pem", tmp_path)

    assert exc.value.error_code == "invalid_input"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-anchored output required")
def test_workspace_overwrite_accepts_long_output_filename(tmp_path):
    output_path = tmp_path / ("m" * 236 + ".bin")
    output_path.write_bytes(b"old")
    output_path.chmod(0o640)

    written_path = tools._write_workspace_file(output_path.name, tmp_path, b"new", overwrite=True, operation="encrypt")

    assert written_path == output_path
    assert output_path.read_bytes() == b"new"
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [output_path]


def test_atomic_write_overwrite_replaces_file_and_preserves_mode(tmp_path):
    output_path = tmp_path / "existing.bin"
    output_path.write_bytes(b"old")
    output_path.chmod(0o640)

    tools._atomic_write_file(output_path, b"new", overwrite=True, private_file=False, operation="test")

    assert output_path.read_bytes() == b"new"
    if os.name != "nt":
        assert stat.S_IMODE(output_path.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    ("core_exc", "error_code", "exit_code"),
    [
        (core.PasswordRequiredError("missing"), "password_required", tools.EXIT_CRYPTO_FAILURE),
        (core.WeakPasswordError("weak"), "weak_password", tools.EXIT_CRYPTO_FAILURE),
        (core.UnencryptedPrivateKeyError("plain"), "unencrypted_private_key", tools.EXIT_CRYPTO_FAILURE),
        (core.UnsupportedKDFError("kdf"), "unsupported_kdf", tools.EXIT_INVALID_INPUT),
        (core.InvalidKeyFormatError("key"), "invalid_key", tools.EXIT_INVALID_INPUT),
        (core.UnsupportedAlgorithmError("alg"), "unsupported_algorithm", tools.EXIT_INVALID_INPUT),
        (core.SizeLimitError("large"), "file_too_large", tools.EXIT_INVALID_INPUT),
        (core.FileFormatError("format"), "invalid_file_format", tools.EXIT_INVALID_INPUT),
        (core.CryptoDependencyError("backend"), "backend_unavailable", tools.EXIT_BACKEND_UNAVAILABLE),
        (RuntimeError("other"), "crypto_error", tools.EXIT_CRYPTO_FAILURE),
    ],
)
def test_agent_error_from_core_maps_known_failures(core_exc, error_code, exit_code):
    converted = tools._agent_error_from_core("operation", core_exc)

    assert converted.operation == "operation"
    assert converted.error_code == error_code
    assert converted.exit_code == exit_code


def test_resolve_backend_maps_unsupported_algorithm(monkeypatch):
    def unsupported(_kem_alg):
        raise core.UnsupportedAlgorithmError("unsupported")

    monkeypatch.setattr(core, "resolve_kem_algorithm", unsupported)

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._resolve_backend("encrypt", "Unsupported")

    assert exc.value.error_code == "unsupported_algorithm"
    assert exc.value.exit_code == tools.EXIT_INVALID_INPUT


def test_generate_keys_rejects_same_output_path(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: pytest.fail("key generation should not run"))

    code, payload = _run_agent(
        ["generate-keys", "--public-out", "same.pem", "--private-out", "same.pem"],
        capsys,
    )

    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "invalid_path"


@pytest.mark.parametrize("command", ["encrypt", "decrypt", "inspect-file", "verify-file"])
@pytest.mark.parametrize("limit", ["0", "-1", "invalid", str(1024 * 1024 * 1024 + 1)])
def test_stream_commands_reject_invalid_plaintext_limits(command, limit, capsys):
    argv = [command, "--input", "input.bin", "--max-file-bytes", limit]
    if command in {"encrypt", "decrypt"}:
        argv += ["--output", "output.bin"]
    if command == "encrypt":
        argv += ["--public-key", "public.pem"]
    if command in {"decrypt", "verify-file"}:
        argv += ["--private-key", "private.pem"]
    code, payload = _run_agent(argv, capsys)
    assert code == tools.EXIT_INVALID_INPUT
    assert payload["error_code"] == "invalid_args"


@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("failure", ["write", "fsync", "publish", "cancel", "interrupt"])
def test_stream_output_failure_discards_stage_and_preserves_destination(monkeypatch, tmp_path, overwrite, failure):
    output = tmp_path / "output.bin"
    if overwrite:
        output.write_bytes(b"original")
        output.chmod(0o640)

    def write(sink):
        if os.name != "nt":
            assert stat.S_IMODE(os.fstat(sink.fileno()).st_mode) == 0o600
        sink.write(b"partial private data")
        if overwrite:
            assert output.read_bytes() == b"original"
        else:
            assert not output.exists()
        if failure == "write":
            raise OSError("disk full")
        if failure == "cancel":
            raise tools.streaming.OperationCancelled("cancelled")
        if failure == "interrupt":
            raise KeyboardInterrupt
        return None

    def fail(*_args, **_kwargs):
        raise OSError("injected failure")

    if failure == "fsync":
        monkeypatch.setattr(tools.os, "fsync", fail)
    if failure == "publish":
        monkeypatch.setattr(tools.os, "replace" if overwrite else "link", fail)
    expected = (
        KeyboardInterrupt
        if failure == "interrupt"
        else (tools.streaming.OperationCancelled if failure == "cancel" else tools.AgentCommandError)
    )
    with pytest.raises(expected):
        tools._write_workspace_stream("output.bin", tmp_path, write, overwrite, "decrypt", private_file=True)
    if overwrite:
        assert output.read_bytes() == b"original"
        if os.name != "nt":
            assert stat.S_IMODE(output.stat().st_mode) == 0o640
    else:
        assert not output.exists()
    assert not list(tmp_path.glob(".*.tmp"))


def test_stream_non_overwrite_rejects_destination_created_during_operation(tmp_path):
    output = tmp_path / "output.bin"

    def write(sink):
        sink.write(b"stream output")
        output.write_bytes(b"concurrent writer")

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._write_workspace_stream("output.bin", tmp_path, write, False, "encrypt")
    assert exc.value.error_code == "output_exists"
    assert output.read_bytes() == b"concurrent writer"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NOFOLLOW"), reason="POSIX descriptors required")
@pytest.mark.parametrize("overwrite", [False, True])
def test_stream_output_stays_anchored_during_parent_replacement(tmp_path, overwrite):
    workspace = tmp_path / "workspace"
    parent = workspace / "output"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = workspace / "original-output"
    if overwrite:
        (parent / "message.bin").write_bytes(b"original")
    (outside / "message.bin").write_bytes(b"outside")

    def write(sink):
        parent.rename(moved)
        parent.symlink_to(outside, target_is_directory=True)
        sink.write(b"private plaintext")
        return "written"

    _, result = tools._write_workspace_stream(
        "output/message.bin", workspace, write, overwrite, "decrypt", private_file=True
    )
    assert result == "written"
    assert (moved / "message.bin").read_bytes() == b"private plaintext"
    assert stat.S_IMODE((moved / "message.bin").stat().st_mode) == 0o600
    assert (outside / "message.bin").read_bytes() == b"outside"
    assert not list(moved.glob(".*.tmp"))


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "O_NOFOLLOW"), reason="POSIX descriptors required")
def test_stream_input_rejects_symlink_swap_before_open(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "input.bin"
    source.write_bytes(b"inside")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside secret")
    resolve = tools._resolve_input_path

    def swap_after_resolution(*args):
        result = resolve(*args)
        source.unlink()
        source.symlink_to(outside)
        return result

    monkeypatch.setattr(tools, "_resolve_input_path", swap_after_resolution)
    with pytest.raises(tools.AgentCommandError) as exc:
        with tools._open_workspace_stream("input.bin", workspace, 64):
            pytest.fail("replacement symlink must not open")
    assert exc.value.error_code == "invalid_path"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permits renaming an open input file")
def test_stream_input_keeps_original_descriptor_after_path_replacement(tmp_path):
    source_path = tmp_path / "input.bin"
    source_path.write_bytes(b"original contents")
    with tools._open_workspace_stream("input.bin", tmp_path, 64) as (_path, source):
        source_path.rename(tmp_path / "original.bin")
        source_path.write_bytes(b"replacement contents")
        assert source.read() == b"original contents"


@pytest.mark.parametrize("failure", ["cancel", "interrupt", "authentication"])
def test_decrypt_stream_failure_returns_json_without_publishing(monkeypatch, tmp_path, capsys, failure):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "input.pqc").write_bytes(b"ciphertext")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    output = tmp_path / "output.bin"
    output.write_bytes(b"original")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(core, "load_key_pem", lambda *_args, **_kwargs: (b"private", cfg.HYBRID_KEM_ALG, "private"))
    monkeypatch.setattr(tools, "_resolve_decryption_backends", lambda *_args: (cfg.KEM_ALG,))

    def decrypt(_source, sink, _key, **_kwargs):
        sink.write(b"unpublished data")
        if failure == "interrupt":
            raise KeyboardInterrupt
        if failure == "cancel":
            raise tools.streaming.OperationCancelled("private cancellation detail")
        raise core.AuthenticationFailedError("private crypto detail")

    monkeypatch.setattr(tools.streaming, "decrypt_stream", decrypt)
    code, payload = _run_agent(
        ["decrypt", "--input", "input.pqc", "--private-key", "private.pem", "--output", "output.bin", "--overwrite"],
        capsys,
    )
    assert code == tools.EXIT_CRYPTO_FAILURE
    assert payload["operation"] == "decrypt"
    assert payload["error_code"] == ("decryption_failed" if failure == "authentication" else "cancelled")
    assert "private cancellation detail" not in payload["message"]
    assert "private crypto detail" not in payload["message"]
    assert output.read_bytes() == b"original"
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("overwrite", [False, True])
def test_stream_reports_directory_sync_failure_after_publication(monkeypatch, tmp_path, overwrite):
    output = tmp_path / "output.bin"
    if overwrite:
        output.write_bytes(b"old")

    def directory_sync_failed(*_args):
        raise OSError("injected directory sync failure")

    monkeypatch.setattr(tools, "_fsync_parent_dir", directory_sync_failed)
    with pytest.raises(tools.AgentCommandError) as exc:
        tools._write_workspace_stream(
            "output.bin", tmp_path, lambda sink: sink.write(b"complete output"), overwrite, "decrypt", private_file=True
        )
    assert exc.value.error_code == "output_durability_failed"
    assert exc.value.exit_code == tools.EXIT_UNEXPECTED
    assert "published" in exc.value.message
    assert output.read_bytes() == b"complete output"
    assert not list(tmp_path.glob(".*.tmp"))
