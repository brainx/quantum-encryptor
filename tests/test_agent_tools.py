"""
Tests for the local agent-facing CLI.
"""

import base64
import json

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


def test_decrypt_requires_password_env_for_encrypted_private_key(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text("private key placeholder", encoding="utf-8")
    monkeypatch.delenv("AGENT_SECRET", raising=False)
    monkeypatch.setattr(core, "get_key_info_pem", lambda _pem: (cfg.KEM_ALG, "Private", True))

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


def test_decrypt_uses_password_env_and_writes_plaintext_file(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "message.pqc").write_bytes(b"encrypted")
    (tmp_path / "private.pem").write_text("private key placeholder", encoding="utf-8")
    monkeypatch.setenv("AGENT_SECRET", "correct horse battery staple")
    monkeypatch.setattr(core, "get_key_info_pem", lambda _pem: (cfg.KEM_ALG, "Private", True))
    monkeypatch.setattr(tools, "_resolve_backend", lambda _operation, kem_alg=cfg.KEM_ALG: kem_alg)

    def load_private_key(_pem, password=None):
        assert password == "correct horse battery staple"
        return b"private", cfg.KEM_ALG, "private"

    monkeypatch.setattr(core, "load_key_pem", load_private_key)
    monkeypatch.setattr(core, "decrypt_file_pro", lambda _blob, _private_key: (b"plaintext", cfg.KEM_ALG))

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
    assert payload["public_key"] == "agent-public.pem"
    assert payload["private_key"] == "agent-private.pem"
    assert "PRIVATE PEM" not in json.dumps(payload)
    assert (tmp_path / "agent-public.pem").read_text(encoding="ascii") == "PUBLIC PEM\n"
    assert (tmp_path / "agent-private.pem").read_text(encoding="ascii") == "PRIVATE PEM\n"


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
