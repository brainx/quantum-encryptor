"""Bounded-memory processing of existing PQC containers.

Caller-owned streams remain open. Output streams must be private staging files and
must only be published after successful return. Temporary ciphertext snapshots are
owned by this module; Python-managed key/plaintext buffers cannot be securely erased.
"""

from __future__ import annotations

import os
import struct
import tempfile
from typing import BinaryIO, Callable, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    AEADDecryptionContext,
    AEADEncryptionContext,
)

from crypto_config import cfg
import crypto_core as core

Progress = Callable[[str, int, int], None]
Cancelled = Callable[[], bool]


class OperationCancelled(core.CryptoCoreError):
    """The caller cancelled before the operation could finish."""


def encrypted_size_limit(max_file_bytes: int = cfg.MAX_STREAM_FILE_BYTES) -> int:
    """Return the largest supported container size for a bounded plaintext limit."""
    if type(max_file_bytes) is not int or not 0 <= max_file_bytes <= cfg.MAX_STREAM_FILE_BYTES:
        raise ValueError("Streaming file limit must be between zero and the configured streaming maximum.")
    return (
        max_file_bytes
        + struct.calcsize(cfg.HEADER_BASE_FORMAT)
        + 2
        + cfg.MAX_KEM_ALG_NAME_BYTES
        + 4
        + cfg.MAX_KEM_CIPHERTEXT_BYTES
        + cfg.X25519_KEY_BYTES
        + cfg.AES_NONCE_BYTES
        + cfg.AES_TAG_BYTES
    )


def _checkpoint(cancelled: Cancelled | None) -> None:
    if cancelled is not None and cancelled():
        raise OperationCancelled("Cryptographic operation cancelled.")


def _report(progress: Progress | None, phase: str, processed: int, total: int) -> None:
    if progress is not None:
        progress(phase, processed, total)


def _remaining_size(source: BinaryIO) -> int | None:
    try:
        if not source.seekable():
            return None
    except (OSError, AttributeError):
        return None
    position = source.tell()
    try:
        source.seek(0, os.SEEK_END)
        return max(0, source.tell() - position)
    finally:
        source.seek(position)


class _Reader:
    def __init__(self, source: BinaryIO, limit: int, cancelled: Cancelled | None = None):
        _checkpoint(cancelled)
        self.source = source
        self.limit = limit
        self.cancelled = cancelled
        self.count = 0
        self.total = _remaining_size(source)
        if self.total is not None and self.total > limit:
            raise core.SizeLimitError("Input exceeds the configured streaming size limit.")

    def read(self, size: int = -1) -> bytes:
        _checkpoint(self.cancelled)
        size = min(cfg.STREAM_CHUNK_BYTES, self.limit - self.count + 1, size if size >= 0 else cfg.STREAM_CHUNK_BYTES)
        data = self.source.read(size)
        if not isinstance(data, bytes) or len(data) > size:
            raise OSError("Binary source returned invalid data.")
        self.count += len(data)
        if self.count > self.limit:
            raise core.SizeLimitError("Input exceeds the configured streaming size limit.")
        _checkpoint(self.cancelled)
        return data


def _write_all(sink: BinaryIO, data: bytes, cancelled: Cancelled | None) -> None:
    remaining = memoryview(data)
    while remaining:
        _checkpoint(cancelled)
        written = sink.write(remaining)
        if not isinstance(written, int) or written <= 0 or written > len(remaining):
            raise OSError("Binary sink did not accept the output.")
        remaining = remaining[written:]


def _new_encryption_header(public_key: bytes, kem_alg: str) -> tuple[core.EncryptedFileHeader, bytes]:
    if kem_alg != cfg.HYBRID_KEM_ALG:
        raise core.UnsupportedAlgorithmError("New encryption requires the ML-KEM-768+X25519-v2 suite.")
    recipient_public, mlkem_public = core.unpack_hybrid_key(public_key, "public")
    resolved = core.resolve_kem_algorithm(cfg.KEM_ALG)
    oqs = core._require_oqs()
    with oqs.KeyEncapsulation(resolved) as kem:
        if kem.details.get("length_public_key", len(mlkem_public)) != len(mlkem_public):
            raise core.InvalidKeyFormatError("Public key length does not match the selected suite.")
        ciphertext_kem, mlkem_secret = kem.encap_secret(mlkem_public)
        if not 0 < len(ciphertext_kem) <= cfg.MAX_KEM_CIPHERTEXT_BYTES or kem.details.get(
            "length_ciphertext", len(ciphertext_kem)
        ) != len(ciphertext_kem):
            raise core.CryptoCoreError("KEM encapsulation returned an invalid ciphertext length.")
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_secret = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public))
    key = core.derive_hybrid_symmetric_key(mlkem_secret, x_secret, ephemeral_public, recipient_public, kem_alg)
    nonce = os.urandom(cfg.AES_NONCE_BYTES)
    suite = kem_alg.encode("utf-8")
    header = (
        struct.pack(cfg.HEADER_BASE_FORMAT, cfg.MAGIC_BYTES, cfg.FORMAT_VERSION)
        + struct.pack(">H", len(suite))
        + suite
        + struct.pack(">I", len(ciphertext_kem))
        + ciphertext_kem
        + ephemeral_public
        + nonce
    )
    return core.EncryptedFileHeader(cfg.FORMAT_VERSION, kem_alg, header, ciphertext_kem, ephemeral_public, nonce), key


def encrypt_stream(
    source: BinaryIO,
    sink: BinaryIO,
    public_key: bytes,
    kem_alg: str = cfg.HYBRID_KEM_ALG,
    *,
    max_file_bytes: int = cfg.MAX_STREAM_FILE_BYTES,
    progress: Progress | None = None,
    cancelled: Cancelled | None = None,
) -> core.EncryptedFileMetadata:
    """Encrypt to a staged sink, retaining the exact v4 header/ciphertext/tag layout."""
    encrypted_size_limit(max_file_bytes)
    reader = _Reader(source, max_file_bytes, cancelled)
    header, key = _new_encryption_header(public_key, kem_alg)
    encryptor = cast(AEADEncryptionContext, Cipher(algorithms.AES(key), modes.GCM(header.nonce)).encryptor())
    encryptor.authenticate_additional_data(header.header_aad)
    del key
    _report(progress, "encrypting", 0, reader.total or 0)
    _write_all(sink, header.header_aad, cancelled)
    while data := reader.read():
        _write_all(sink, encryptor.update(data), cancelled)
        _report(progress, "encrypting", reader.count, reader.total or 0)
    _checkpoint(cancelled)
    _write_all(sink, encryptor.finalize(), cancelled)
    _write_all(sink, encryptor.tag, cancelled)
    _report(progress, "encrypting", reader.count, reader.count)
    _checkpoint(cancelled)
    return header.metadata(reader.count + cfg.AES_TAG_BYTES)


def _payload_count(reader: _Reader, max_file_bytes: int, snapshot: BinaryIO | None = None) -> int:
    _check_payload_size(reader, max_file_bytes)
    count = 0
    while data := reader.read():
        count += len(data)
        if count > max_file_bytes + cfg.AES_TAG_BYTES:
            raise core.SizeLimitError("Encrypted payload exceeds the configured streaming size limit.")
        if snapshot is not None:
            _write_all(snapshot, data, reader.cancelled)
    if count < cfg.AES_TAG_BYTES:
        raise core.FileFormatError("AES-GCM payload is shorter than the authentication tag.")
    return count


def _check_payload_size(reader: _Reader, max_file_bytes: int) -> None:
    if reader.total is not None:
        remaining = reader.total - reader.count
        if remaining < cfg.AES_TAG_BYTES:
            raise core.FileFormatError("AES-GCM payload is shorter than the authentication tag.")
        if remaining > max_file_bytes + cfg.AES_TAG_BYTES:
            raise core.SizeLimitError("Encrypted payload exceeds the configured streaming size limit.")


def inspect_stream(source: BinaryIO, *, max_file_bytes: int = cfg.MAX_STREAM_FILE_BYTES) -> core.EncryptedFileMetadata:
    """Consume a bounded container and return unauthenticated metadata without a KEM backend."""
    reader = _Reader(source, encrypted_size_limit(max_file_bytes))
    header = core._read_encrypted_file_header(reader)
    return header.metadata(_payload_count(reader, max_file_bytes))


def _candidate_keys(header: core.EncryptedFileHeader, private_key: bytes, expected_kem_alg: str | None) -> list[bytes]:
    if expected_kem_alg is not None and expected_kem_alg != header.kem_alg:
        raise core.AuthenticationFailedError("Private key algorithm does not match the encrypted file.")
    core._validate_key_material(private_key, header.kem_alg, "private")
    x_secret = None
    recipient_public = b""
    mlkem_private = private_key
    if header.version == cfg.FORMAT_VERSION:
        x_private, mlkem_private = core.unpack_hybrid_key(private_key, "private")
        recipient = x25519.X25519PrivateKey.from_private_bytes(x_private)
        recipient_public = recipient.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        try:
            x_secret = recipient.exchange(x25519.X25519PublicKey.from_public_bytes(header.x25519_ephemeral_public))
        except ValueError as exc:
            raise core.FileFormatError("Invalid X25519 ephemeral public key.") from exc
    candidates = core.resolve_decryption_kem_algorithms(header.kem_alg)
    oqs = core._require_oqs()
    keys = []
    for candidate in candidates:
        with oqs.KeyEncapsulation(candidate) as kem:
            if len(mlkem_private) != kem.details["length_secret_key"] or len(header.ciphertext_kem) != kem.details.get(
                "length_ciphertext", len(header.ciphertext_kem)
            ):
                continue
        shared_secret = core._decapsulate_shared_secret(oqs, candidate, mlkem_private, header.ciphertext_kem)
        if x_secret is not None:
            keys.append(
                core.derive_hybrid_symmetric_key(
                    shared_secret, x_secret, header.x25519_ephemeral_public, recipient_public, header.kem_alg
                )
            )
        else:
            keys.append(core.derive_symmetric_key_hkdf(shared_secret))
    if not keys:
        raise core.InvalidKeyFormatError("Private key or KEM ciphertext length does not match the selected suite.")
    return keys


def _decryptor(key: bytes, header: core.EncryptedFileHeader) -> AEADDecryptionContext:
    context = cast(AEADDecryptionContext, Cipher(algorithms.AES(key), modes.GCM(header.nonce)).decryptor())
    context.authenticate_additional_data(header.header_aad)
    return context


def _process_payload(
    reader: _Reader,
    contexts: list[AEADDecryptionContext],
    max_file_bytes: int,
    progress: Progress | None,
    phase: str,
    sink: BinaryIO | None = None,
) -> tuple[int, bytes]:
    tail = b""
    processed = 0
    total = max(0, reader.total - reader.count - cfg.AES_TAG_BYTES) if reader.total is not None else 0
    _report(progress, phase, 0, total)
    while data := reader.read():
        combined = tail + data
        if len(combined) <= cfg.AES_TAG_BYTES:
            tail = combined
            continue
        payload, tail = combined[: -cfg.AES_TAG_BYTES], combined[-cfg.AES_TAG_BYTES :]
        processed += len(payload)
        if processed > max_file_bytes:
            raise core.SizeLimitError("Encrypted payload exceeds the configured streaming size limit.")
        for context in contexts:
            plaintext = context.update(payload)
            if sink is not None:
                _write_all(sink, plaintext, reader.cancelled)
            del plaintext
        _report(progress, phase, processed, total)
    if len(tail) != cfg.AES_TAG_BYTES:
        raise core.FileFormatError("AES-GCM payload is shorter than the authentication tag.")
    _checkpoint(reader.cancelled)
    return processed, tail


def _verify(
    source: BinaryIO,
    private_key: bytes,
    expected_kem_alg: str | None,
    max_file_bytes: int,
    progress: Progress | None,
    cancelled: Cancelled | None,
) -> tuple[core.EncryptedFileHeader, core.EncryptedFileMetadata, bytes]:
    reader = _Reader(source, encrypted_size_limit(max_file_bytes), cancelled)
    header = core._read_encrypted_file_header(reader)
    _check_payload_size(reader, max_file_bytes)
    keys = _candidate_keys(header, private_key, expected_kem_alg)
    contexts = [_decryptor(key, header) for key in keys]
    processed, tag = _process_payload(reader, contexts, max_file_bytes, progress, "verifying")
    for key, context in zip(keys, contexts):
        try:
            context.finalize_with_tag(tag)
        except InvalidTag:
            continue
        _report(progress, "verifying", processed, processed)
        _checkpoint(cancelled)
        return header, header.metadata(processed + cfg.AES_TAG_BYTES), key
    raise core.AuthenticationFailedError("Encrypted-file authentication failed.")


def verify_stream(
    source: BinaryIO,
    private_key: bytes,
    expected_kem_alg: str | None = None,
    *,
    max_file_bytes: int = cfg.MAX_STREAM_FILE_BYTES,
    progress: Progress | None = None,
    cancelled: Cancelled | None = None,
) -> core.EncryptedFileMetadata:
    """Authenticate while discarding each plaintext chunk; no plaintext is written."""
    _header, metadata, _key = _verify(source, private_key, expected_kem_alg, max_file_bytes, progress, cancelled)
    return metadata


def decrypt_stream(
    source: BinaryIO,
    sink: BinaryIO,
    private_key: bytes,
    expected_kem_alg: str | None = None,
    *,
    max_file_bytes: int = cfg.MAX_STREAM_FILE_BYTES,
    progress: Progress | None = None,
    cancelled: Cancelled | None = None,
) -> core.EncryptedFileMetadata:
    """Snapshot ciphertext, authenticate it, then decrypt into the caller's private staged sink."""
    reader = _Reader(source, encrypted_size_limit(max_file_bytes), cancelled)
    header = core._read_encrypted_file_header(reader)
    # TemporaryFile is private and unlinked on POSIX, and delete-on-close elsewhere.
    with tempfile.TemporaryFile(mode="w+b") as snapshot:
        _write_all(snapshot, header.header_aad, cancelled)
        _payload_count(reader, max_file_bytes, snapshot)
        snapshot.seek(0)
        header, metadata, key = _verify(snapshot, private_key, expected_kem_alg, max_file_bytes, progress, cancelled)
        snapshot.seek(metadata.header_bytes)
        payload_reader = _Reader(snapshot, metadata.encrypted_payload_bytes, cancelled)
        context = _decryptor(key, header)
        del key
        processed, tag = _process_payload(payload_reader, [context], max_file_bytes, progress, "decrypting", sink)
        try:
            final = context.finalize_with_tag(tag)
        except InvalidTag as exc:
            raise core.AuthenticationFailedError("Encrypted snapshot authentication failed.") from exc
        _write_all(sink, final, cancelled)
        _report(progress, "decrypting", processed, processed)
        _checkpoint(cancelled)
        return metadata
