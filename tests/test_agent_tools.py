"""
Tests for the local agent-facing CLI.
"""

import base64
import json
import os
import stat

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
    key_data = base64.b64encode(b"test-public-key").decode("ascii")
    return "\n".join(
        [
            cfg.PEM_PUBLIC_HEADER,
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
            key_data,
            cfg.PEM_PUBLIC_FOOTER,
            "",
        ]
    )


def _valid_private_pem(encrypted: bool = True) -> str:
    key_data = base64.b64encode(b"test-private-key").decode("ascii")
    if not encrypted:
        return "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
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
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
            key_data,
            cfg.PEM_PRIVATE_FOOTER,
            "",
        ]
    )


def _syntactic_encrypted_blob() -> bytes:
    alg = cfg.KEM_ALG.encode("utf-8")
    return (
        cfg.MAGIC_BYTES
        + cfg.FORMAT_VERSION.to_bytes(2, "big")
        + len(alg).to_bytes(2, "big")
        + alg
        + (1).to_bytes(4, "big")
        + b"x"
        + b"1" * cfg.AES_NONCE_BYTES
        + b"ciphertext-and-tag"
    )


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
    assert payload == {
        "ok": True,
        "operation": "inspect-key",
        "format_version": cfg.FORMAT_VERSION,
        "key": "recipient.pem",
        "key_type": "public",
        "kem": cfg.KEM_ALG,
    }


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

    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.KEM_ALG, "public"))
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "encrypt_file_pro", lambda _data, _public_key, _kem: b"encrypted")

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
    monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 4)
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
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)

    def load_private_key(_pem, password=None):
        assert password == "correct horse battery staple"
        return b"private", cfg.KEM_ALG, "private"

    monkeypatch.setattr(core, "load_key_pem", load_private_key)

    def decrypt_file(_blob, _private_key, expected_kem_alg=None):
        assert expected_kem_alg == cfg.KEM_ALG
        return b"plaintext", cfg.KEM_ALG

    monkeypatch.setattr(core, "decrypt_file_pro", decrypt_file)

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


def test_decrypt_allows_ciphertext_overhead_above_plaintext_limit(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 3)
    monkeypatch.setattr(cfg, "MAX_ENCRYPTED_FILE_BYTES", 64)
    (tmp_path / "message.pqc").write_bytes(b"encrypted-container")
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv(tools.DEFAULT_PASSWORD_ENV, "correct horse battery staple")
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (b"private", cfg.KEM_ALG, "private"))

    def decrypt_file(_blob, _private_key, expected_kem_alg=None):
        assert expected_kem_alg == cfg.KEM_ALG
        return b"abc", cfg.KEM_ALG

    monkeypatch.setattr(core, "decrypt_file_pro", decrypt_file)

    code, payload = _run_agent(
        ["decrypt", "--input", "message.pqc", "--private-key", "private.pem", "--output", "message.txt"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["bytes_written"] == 3
    assert (tmp_path / "message.txt").read_bytes() == b"abc"


def test_decrypt_rejects_encrypted_input_above_encrypted_limit(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 3)
    monkeypatch.setattr(cfg, "MAX_ENCRYPTED_FILE_BYTES", 4)
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
    monkeypatch.setattr(cfg, "MAX_ENCRYPTED_FILE_BYTES", 4)
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
    monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: (b"public", b"private"))

    def save_key_pem(key_bytes, kem_alg, key_type, password=None):
        assert kem_alg == cfg.KEM_ALG
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
    assert payload["private_key_kdf"] == cfg.PRIVATE_KEY_KDF_ALG
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
    monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: pytest.fail("key generation should not run"))

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
    monkeypatch.setattr(core, "load_key_pem", lambda _pem: (b"public", cfg.KEM_ALG, "public"))
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "encrypt_file_pro", lambda data, _public_key, _kem: b"encrypted:" + data)

    code, payload = _run_agent(
        ["encrypt", "--input", "message.txt", "--public-key", "recipient.pem", "--output", "message.pqc"],
        capsys,
    )

    assert code == tools.EXIT_SUCCESS
    assert payload["output"] == "message.pqc"
    assert (tmp_path / "message.pqc").read_bytes() == b"encrypted:hello"


def test_inspect_file_returns_encrypted_container_metadata(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(_syntactic_encrypted_blob())

    code, payload = _run_agent(["inspect-file", "--input", "message.pqc"], capsys)

    assert code == tools.EXIT_SUCCESS
    assert payload["input"] == "message.pqc"
    assert payload["encrypted_format_version"] == cfg.FORMAT_VERSION
    assert payload["kem"] == cfg.KEM_ALG
    assert payload["kem_ciphertext_bytes"] == 1


def test_verify_file_authenticates_without_writing_plaintext(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(_syntactic_encrypted_blob())
    (tmp_path / "private.pem").write_text(_valid_private_pem(), encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "correct horse battery staple")
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)
    monkeypatch.setattr(core, "load_key_pem", lambda _pem, password=None: (b"private", cfg.KEM_ALG, "private"))

    def decrypt_file(_blob, _private_key, expected_kem_alg=None):
        assert expected_kem_alg == cfg.KEM_ALG
        return b"plaintext", cfg.KEM_ALG

    monkeypatch.setattr(core, "decrypt_file_pro", decrypt_file)

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
    assert payload["kem"] == cfg.KEM_ALG
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


def test_read_workspace_text_rejects_invalid_utf8(tmp_path):
    (tmp_path / "bad.pem").write_bytes(b"\xff")

    with pytest.raises(tools.AgentCommandError) as exc:
        tools._read_workspace_text("bad.pem", tmp_path)

    assert exc.value.error_code == "invalid_input"


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
