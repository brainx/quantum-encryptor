"""CLI contracts for authenticated directory backups; native acceptance covers the real KEM."""

import json
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from crypto_config import cfg
import crypto_core as core
import pqc_agent_tools as tools


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "source" / "empty").mkdir(parents=True)
    (tmp_path / "source" / "message.txt").write_bytes(b"sensitive file content")
    xkey = (
        x25519.X25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    public = xkey + bytes(cfg.MLKEM768_PUBLIC_POLY_BYTES) + bytes(32)
    public_pem = core.save_key_pem(public, cfg.HYBRID_KEM_ALG, "public")
    assert public_pem
    (tmp_path / "public.pem").write_text(public_pem)
    monkeypatch.setattr(tools, "_resolve_backend", lambda *_args: cfg.KEM_ALG)
    monkeypatch.setattr(tools, "_resolve_decryption_backends", lambda *_args: (cfg.KEM_ALG,))
    monkeypatch.setattr(
        tools,
        "_load_required_private_key",
        lambda *_args: (tmp_path / "private.pem", b"private material", cfg.HYBRID_KEM_ALG),
    )

    def encrypt(source, sink, _key, kem, **kwargs):
        data = source.read()
        assert len(data) <= kwargs["max_file_bytes"]
        sink.write(b"test-container:" + data)
        return SimpleNamespace(kem_alg=kem, total_bytes=len(data) + 15)

    def decrypt(source, sink, _key, **_kwargs):
        data = source.read()
        if not data.startswith(b"test-container:"):
            raise core.AuthenticationFailedError("private authentication diagnostic")
        sink.write(data[15:])
        return SimpleNamespace(kem_alg=cfg.HYBRID_KEM_ALG)

    monkeypatch.setattr(tools.streaming, "encrypt_stream", encrypt)
    monkeypatch.setattr(tools.streaming, "decrypt_stream", decrypt)
    return tmp_path, core.get_public_key_fingerprint(public, cfg.HYBRID_KEM_ALG)


def run(capsys, arguments):
    status = tools.run(arguments)
    captured = capsys.readouterr()
    return status, json.loads(captured.out)


def backup(*extra):
    return ["backup-directory", "--input", "source", "--public-key", "public.pem", "--output", "backup.pqc", *extra]


def restore(*extra):
    return [
        "restore-directory",
        "--input",
        "backup.pqc",
        "--private-key",
        "private.pem",
        "--output",
        "restored",
        *extra,
    ]


@pytest.mark.skipif(os.name != "posix", reason="Initial safe directory support is macOS/Linux")
def test_directory_cli_roundtrip_preserves_tree_and_safe_metadata(workspace, capsys):
    root, fingerprint = workspace
    code, packed = run(capsys, backup("--expected-recipient-fingerprint", fingerprint))
    assert code == tools.EXIT_SUCCESS
    code, unpacked = run(capsys, restore())
    assert code == tools.EXIT_SUCCESS
    assert packed["files"] == unpacked["files"] == 1
    assert packed["source_bytes"] == unpacked["restored_bytes"] == len(b"sensitive file content")
    assert packed["public_key_fingerprint"] == fingerprint
    assert packed["archive_format"] == unpacked["archive_format"] == "zip-stored"
    assert (root / "restored" / "message.txt").read_bytes() == b"sensitive file content"
    assert (root / "restored" / "empty").is_dir()
    assert (root / "source" / "message.txt").read_bytes() == b"sensitive file content"
    for forbidden in (str(root), "sensitive file content", "private material", "PRIVATE KEY"):
        assert forbidden not in json.dumps([packed, unpacked])


@pytest.mark.parametrize("expected", ["", "QE1-SHA3-256:" + "a" * 64])
def test_directory_recipient_check_precedes_archive_access(workspace, monkeypatch, capsys, expected):
    root, _ = workspace
    monkeypatch.setattr(tools.archives, "pack_directory", lambda *_a, **_kw: pytest.fail("must check recipient first"))
    code, result = run(capsys, backup("--expected-recipient-fingerprint", expected))
    assert code == tools.EXIT_INVALID_INPUT
    assert result["error_code"] in {"invalid_recipient_fingerprint", "recipient_fingerprint_mismatch"}
    assert not (root / "backup.pqc").exists()


@pytest.mark.parametrize("target", ["source/new.pqc", "../escape.pqc", "absolute", "existing"])
def test_directory_backup_preflights_destination(workspace, capsys, target):
    root, _ = workspace
    (root / "existing").write_bytes(b"preserved")
    arguments = backup()
    arguments[arguments.index("--output") + 1] = str(root / "outside") if target == "absolute" else target
    code, result = run(capsys, arguments)
    assert code != tools.EXIT_SUCCESS
    assert result["error_code"] in {"invalid_path", "path_outside_workspace", "output_exists"}
    assert (root / "existing").read_bytes() == b"preserved"
    assert not (root / "source" / "new.pqc").exists()


def test_directory_backup_size_failure_preserves_overwrite_target(workspace, capsys):
    root, _ = workspace
    (root / "backup.pqc").write_bytes(b"original")
    code, result = run(capsys, backup("--max-file-bytes", "24", "--overwrite"))
    assert code != tools.EXIT_SUCCESS
    assert not result["ok"]
    assert (root / "backup.pqc").read_bytes() == b"original"


def test_directory_backup_rejects_symlink_source(workspace, capsys):
    root, _ = workspace
    (root / "alias").symlink_to("source", target_is_directory=True)
    arguments = backup()
    arguments[arguments.index("--input") + 1] = "alias"
    code, result = run(capsys, arguments)
    assert code == tools.EXIT_INVALID_INPUT
    assert result["error_code"] == "invalid_path"
    assert not (root / "backup.pqc").exists()


@pytest.mark.parametrize("failure", ["bad_authentication", "not_a_zip"])
def test_directory_restore_requires_authentication_and_valid_archive(workspace, capsys, monkeypatch, failure):
    root, _ = workspace
    (root / "backup.pqc").write_bytes(b"corrupt" if failure == "bad_authentication" else b"test-container:not zip")
    if failure == "bad_authentication":
        monkeypatch.setattr(
            tools.archives, "extract_archive", lambda *_a, **_kw: pytest.fail("must authenticate first")
        )
    code, result = run(capsys, restore())
    assert code != tools.EXIT_SUCCESS
    assert result["error_code"] == ("decryption_failed" if failure == "bad_authentication" else "invalid_archive")
    assert not (root / "restored").exists()
    assert "private authentication diagnostic" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["empty_directory", "file", "dangling_symlink"])
def test_directory_restore_never_replaces_existing_target(workspace, capsys, monkeypatch, kind):
    root, _ = workspace
    target = root / "restored"
    if kind == "empty_directory":
        target.mkdir()
    elif kind == "file":
        target.write_bytes(b"preserve")
    else:
        target.symlink_to("missing")
    monkeypatch.setattr(tools, "_load_required_private_key", lambda *_a: pytest.fail("preflight before unlock"))
    code, result = run(capsys, restore())
    assert code == tools.EXIT_INVALID_INPUT
    assert result["error_code"] == "output_exists"
    assert os.path.lexists(target)


def test_directory_restore_has_no_overwrite_option(capsys):
    code, result = run(capsys, restore("--overwrite"))
    assert code == tools.EXIT_INVALID_INPUT
    assert result["error_code"] == "invalid_args"


@pytest.mark.parametrize("failure", ["cancel", "disk"])
def test_directory_backup_failure_does_not_publish_partial_output(workspace, monkeypatch, capsys, failure):
    root, _ = workspace
    (root / "backup.pqc").write_bytes(b"original")

    def fail(_source, sink, *_args, **_kwargs):
        sink.write(b"partial encrypted backup")
        if failure == "cancel":
            raise KeyboardInterrupt
        raise OSError("secret filesystem details")

    monkeypatch.setattr(tools.streaming, "encrypt_stream", fail)
    code, result = run(capsys, backup("--overwrite"))
    assert code != tools.EXIT_SUCCESS
    assert result["error_code"] in {"cancelled", "write_failed"}
    assert (root / "backup.pqc").read_bytes() == b"original"
    assert not list(root.glob(".*.tmp"))
    assert "secret filesystem details" not in json.dumps(result)


def test_directory_backup_final_resolution_cannot_enter_source(workspace, monkeypatch):
    root, _ = workspace
    monkeypatch.setattr(tools, "_resolve_output_path", lambda *_args: root / "source" / "nested.pqc")
    with pytest.raises(tools.AgentCommandError) as error:
        tools._write_workspace_stream(
            "backup.pqc", root, lambda _sink: None, True, "backup-directory", excluded_directory=root / "source"
        )
    assert error.value.error_code == "invalid_path"


def test_directory_backup_rejects_case_alias_inside_source(workspace, capsys):
    root, _ = workspace
    if not (root / "SOURCE").is_dir():
        pytest.skip("Case-insensitive filesystem required")
    arguments = backup()
    arguments[arguments.index("--output") + 1] = "SOURCE/backup.pqc"
    code, result = run(capsys, arguments)
    assert code == tools.EXIT_INVALID_INPUT
    assert result["error_code"] == "invalid_path"
    assert not (root / "source" / "backup.pqc").exists()


def test_directory_writer_rejects_physical_alias_after_final_resolution(workspace, monkeypatch):
    root, _ = workspace
    original = type(root).samefile

    def alias(self, other):
        return True if self == root / "alias" and other == root / "source" else original(self, other)

    (root / "alias").mkdir()
    monkeypatch.setattr(type(root), "samefile", alias)
    with pytest.raises(tools.AgentCommandError) as error:
        tools._write_workspace_stream(
            "alias/backup.pqc",
            root,
            lambda _sink: pytest.fail("must reject first"),
            True,
            "backup-directory",
            excluded_directory=root / "source",
        )
    assert error.value.error_code == "invalid_path"
