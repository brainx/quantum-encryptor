"""Compatibility and failure-boundary tests for bounded streaming file operations."""

import hashlib
import io
import os
import struct
import tempfile
import tracemalloc

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_config import cfg
import crypto_core as core
import crypto_stream as streaming


def _keys(seed=b"S" * 32):
    public = bytes(cfg.MLKEM768_PUBLIC_POLY_BYTES) + seed
    private = bytes(cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES) + public + hashlib.sha3_256(public).digest() + bytes(32)
    x_private = x25519.X25519PrivateKey.generate()
    x_public = x_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_bytes = x_private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    return x_public + public, x_bytes + private


@pytest.fixture
def fake_backend(monkeypatch):
    attempts = []

    class FakeKEM:
        def __init__(self, algorithm, secret_key=None):
            self.algorithm = algorithm
            self.secret_key = secret_key
            self.details = {
                "length_public_key": cfg.MLKEM768_PUBLIC_KEY_BYTES,
                "length_secret_key": cfg.MLKEM768_PRIVATE_KEY_BYTES,
                "length_ciphertext": 32,
            }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def encap_secret(self, public):
            ciphertext = b"C" * 32
            return ciphertext, hashlib.sha256(self.algorithm.encode() + public + ciphertext).digest()

        def decap_secret(self, ciphertext):
            attempts.append(self.algorithm)
            start = cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES
            public = self.secret_key[start : start + cfg.MLKEM768_PUBLIC_KEY_BYTES]
            return hashlib.sha256(self.algorithm.encode() + public + ciphertext).digest()

    class FakeOQS:
        KeyEncapsulation = FakeKEM

        @staticmethod
        def get_enabled_kem_mechanisms():
            return (cfg.KEM_ALG, "Kyber768")

    monkeypatch.setattr(core, "oqs", FakeOQS)
    return attempts


class ShortReader(io.BytesIO):
    def read(self, size=-1):
        assert 0 <= size <= cfg.STREAM_CHUNK_BYTES
        return super().read(min(size, 7))


class ShortWriter(io.BytesIO):
    def write(self, data):
        return super().write(data[:11])


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65, 257])
def test_stream_round_trip_and_bytes_cross_compatibility(monkeypatch, fake_backend, size):
    monkeypatch.setattr(cfg, "STREAM_CHUNK_BYTES", 64)
    public, private = _keys()
    plaintext = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    sink = ShortWriter()
    metadata = streaming.encrypt_stream(ShortReader(plaintext), sink, public)
    blob = sink.getvalue()
    assert metadata == core.inspect_encrypted_file_strict(blob)
    assert core.decrypt_file_pro(blob, private, cfg.HYBRID_KEM_ALG) == (plaintext, cfg.HYBRID_KEM_ALG)
    output = ShortWriter()
    assert streaming.decrypt_stream(ShortReader(blob), output, private, cfg.HYBRID_KEM_ALG) == metadata
    assert output.getvalue() == plaintext
    assert streaming.inspect_stream(ShortReader(blob)) == metadata
    assert streaming.verify_stream(ShortReader(blob), private, cfg.HYBRID_KEM_ALG) == metadata
    original = core.encrypt_file_pro(plaintext, public)
    assert original is not None
    output = io.BytesIO()
    streaming.decrypt_stream(io.BytesIO(original), output, private)
    assert output.getvalue() == plaintext


@pytest.mark.parametrize("failure", ["tag", "payload", "nonce", "wrong_key", "truncated", "appended"])
def test_stream_decryption_never_writes_plaintext_before_authentication(fake_backend, failure):
    public, private = _keys()
    blob = core.encrypt_file_pro(b"secret plaintext", public)
    assert blob is not None
    header_size = core.inspect_encrypted_file_strict(blob).header_bytes
    if failure in {"tag", "payload", "nonce"}:
        offset = {"tag": -1, "payload": header_size, "nonce": header_size - 1}[failure]
        changed = bytearray(blob)
        changed[offset] ^= 1
        blob = bytes(changed)
    elif failure == "wrong_key":
        _public, private = _keys(b"W" * 32)
    elif failure == "truncated":
        blob = blob[:-1]
    else:
        blob += b"extra"
    output = io.BytesIO(b"existing staged content")
    output.seek(0, 2)
    with pytest.raises(core.AuthenticationFailedError):
        streaming.decrypt_stream(io.BytesIO(blob), output, private)
    assert output.getvalue() == b"existing staged content"
    with pytest.raises(core.AuthenticationFailedError):
        streaming.verify_stream(io.BytesIO(blob), private)


@pytest.mark.parametrize("limit", [-1, True, 1.5, 1024 * 1024 * 1024 + 1])
def test_invalid_limit_rejected_before_any_crypto(limit, monkeypatch):
    monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("Backend must not run"))
    with pytest.raises(ValueError):
        streaming.encrypted_size_limit(limit)
    with pytest.raises(ValueError):
        streaming.encrypt_stream(io.BytesIO(b""), io.BytesIO(), b"", max_file_bytes=limit)


def test_streaming_limit_is_separate_from_existing_memory_limit(monkeypatch, fake_backend):
    public, private = _keys()
    monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 16)
    assert core.encrypt_file_pro(bytes(17), public) is None
    encrypted = io.BytesIO()
    streaming.encrypt_stream(io.BytesIO(bytes(65)), encrypted, public, max_file_bytes=65)
    assert core.decrypt_file_pro(encrypted.getvalue(), private)[0] is None
    output = io.BytesIO()
    streaming.decrypt_stream(io.BytesIO(encrypted.getvalue()), output, private, max_file_bytes=65)
    assert len(output.getvalue()) == 65
    with pytest.raises(core.SizeLimitError):
        streaming.inspect_stream(io.BytesIO(encrypted.getvalue()), max_file_bytes=64)


def test_pre_cancelled_operations_do_not_read_write_or_call_backend(monkeypatch):
    class Unused(io.BytesIO):
        def read(self, _size=-1):
            pytest.fail("Cancelled source must not be read")

        def write(self, _data):
            pytest.fail("Cancelled sink must not be written")

    monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("Backend must not run"))
    with pytest.raises(streaming.OperationCancelled):
        streaming.encrypt_stream(Unused(), Unused(), b"", cancelled=lambda: True)
    with pytest.raises(streaming.OperationCancelled):
        streaming.decrypt_stream(Unused(), Unused(), b"", cancelled=lambda: True)
    with pytest.raises(streaming.OperationCancelled):
        streaming.verify_stream(Unused(), b"", cancelled=lambda: True)


def test_decryption_uses_snapshot_after_original_source_changes(fake_backend):
    public, private = _keys()
    blob = core.encrypt_file_pro(b"original message", public)
    assert blob is not None
    original = io.BytesIO(blob)
    changed = False

    def progress(phase, _processed, _total):
        nonlocal changed
        if phase == "verifying" and not changed:
            original.seek(0)
            original.write(b"X" * len(blob))
            changed = True

    output = io.BytesIO()
    streaming.decrypt_stream(original, output, private, progress=progress)
    assert changed
    assert output.getvalue() == b"original message"


def test_stream_encryption_matches_existing_v4_bytes_exactly(monkeypatch, fake_backend):
    public, _private = _keys()
    ephemeral = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32)))
    monkeypatch.setattr(x25519.X25519PrivateKey, "generate", lambda: ephemeral)
    monkeypatch.setattr(os, "urandom", lambda size: b"N" * size)
    plaintext = b"same header, key establishment, ciphertext and tag"
    expected = core.encrypt_file_pro(plaintext, public)
    output = io.BytesIO()
    streaming.encrypt_stream(io.BytesIO(plaintext), output, public)
    assert output.getvalue() == expected


def _archive(plaintext, public, suite, candidate):
    mlkem_public = public[cfg.X25519_KEY_BYTES :]
    kem_ciphertext = b"C" * 32
    shared_secret = hashlib.sha256(candidate.encode() + mlkem_public + kem_ciphertext).digest()
    version = cfg.FORMAT_VERSION if core.is_hybrid_key_algorithm(suite) else cfg.LEGACY_FORMAT_VERSION
    ephemeral_public = b""
    if version == cfg.FORMAT_VERSION:
        ephemeral = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32)))
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        recipient_public = public[: cfg.X25519_KEY_BYTES]
        x_secret = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public))
        key = core.derive_hybrid_symmetric_key(shared_secret, x_secret, ephemeral_public, recipient_public, suite)
    else:
        key = core.derive_symmetric_key_hkdf(shared_secret)
    nonce = b"N" * cfg.AES_NONCE_BYTES
    label = suite.encode()
    header = (
        struct.pack(cfg.HEADER_BASE_FORMAT, cfg.MAGIC_BYTES, version)
        + struct.pack(">H", len(label))
        + label
        + struct.pack(">I", len(kem_ciphertext))
        + kem_ciphertext
        + ephemeral_public
        + nonce
    )
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


@pytest.mark.parametrize(
    "suite,candidate",
    [
        (cfg.KEM_ALG, cfg.KEM_ALG),
        ("Kyber768", "Kyber768"),
        (cfg.LEGACY_HYBRID_KEM_ALG, cfg.KEM_ALG),
        (cfg.LEGACY_HYBRID_KEM_ALG, "Kyber768"),
    ],
)
def test_stream_decryption_preserves_authenticated_legacy_candidates(fake_backend, suite, candidate):
    public, private = _keys()
    blob = _archive(b"legacy archive", public, suite, candidate)
    if not core.is_hybrid_key_algorithm(suite):
        private = private[cfg.X25519_KEY_BYTES :]
    assert core.decrypt_file_pro(blob, private, suite) == (b"legacy archive", suite)
    output = io.BytesIO()
    metadata = streaming.decrypt_stream(ShortReader(blob), output, private, suite)
    assert metadata.kem_alg == suite
    assert output.getvalue() == b"legacy archive"
    assert streaming.verify_stream(ShortReader(blob), private, suite) == metadata
    assert candidate in fake_backend
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    output = io.BytesIO()
    with pytest.raises(core.AuthenticationFailedError):
        streaming.decrypt_stream(io.BytesIO(tampered), output, private, suite)
    assert output.getvalue() == b""


@pytest.fixture
def snapshots(monkeypatch):
    created = []
    original = tempfile.TemporaryFile

    def track(*args, **kwargs):
        snapshot = original(*args, **kwargs)
        if os.name == "posix":
            assert os.fstat(snapshot.fileno()).st_mode & 0o777 == 0o600
            assert os.fstat(snapshot.fileno()).st_nlink == 0
        created.append(snapshot)
        return snapshot

    monkeypatch.setattr(streaming.tempfile, "TemporaryFile", track)
    return created


@pytest.mark.parametrize("phase", ["verifying", "decrypting"])
def test_decrypt_cancellation_closes_snapshot_and_bounds_partial_staged_output(
    monkeypatch, fake_backend, snapshots, phase
):
    monkeypatch.setattr(cfg, "STREAM_CHUNK_BYTES", 64)
    public, private = _keys()
    blob = core.encrypt_file_pro(b"S" * 256, public)
    assert blob is not None
    cancel = False

    def progress(current_phase, processed, _total):
        nonlocal cancel
        if current_phase == phase and processed:
            cancel = True

    output = io.BytesIO()
    with pytest.raises(streaming.OperationCancelled):
        streaming.decrypt_stream(io.BytesIO(blob), output, private, progress=progress, cancelled=lambda: cancel)
    assert snapshots and all(snapshot.closed for snapshot in snapshots)
    assert len(output.getvalue()) == (0 if phase == "verifying" else 48)


@pytest.mark.parametrize("failure", ["read", "write", "cancel_copy", "authentication"])
def test_decrypt_snapshot_cleanup_on_every_failure(fake_backend, snapshots, failure):
    public, private = _keys()
    blob = core.encrypt_file_pro(b"S" * 128, public)
    assert blob is not None
    header_size = core.inspect_encrypted_file_strict(blob).header_bytes
    cancel = False

    class FailingSource(io.BytesIO):
        def read(self, size=-1):
            nonlocal cancel
            if self.tell() >= header_size:
                if failure == "read":
                    raise OSError("read failed")
                if failure == "cancel_copy":
                    cancel = True
            return super().read(size)

    class FailingSink(io.BytesIO):
        def write(self, data):
            if failure == "write":
                raise OSError("disk full")
            return super().write(data)

    if failure == "authentication":
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    error = (
        streaming.OperationCancelled
        if failure == "cancel_copy"
        else core.AuthenticationFailedError if failure == "authentication" else OSError
    )
    sink = FailingSink()
    with pytest.raises(error):
        streaming.decrypt_stream(FailingSource(blob), sink, private, cancelled=lambda: cancel)
    assert snapshots and all(snapshot.closed for snapshot in snapshots)
    assert sink.getvalue() == b""


@pytest.mark.parametrize("return_value", [0, None, 100000000])
def test_stream_rejects_nonprogressing_writes(fake_backend, return_value):
    public, _private = _keys()

    class BadSink(io.BytesIO):
        def write(self, _data):
            return return_value

    with pytest.raises(OSError):
        streaming.encrypt_stream(io.BytesIO(b"secret"), BadSink(), public)


def test_encrypt_cancellation_stops_before_final_tag(monkeypatch, fake_backend):
    monkeypatch.setattr(cfg, "STREAM_CHUNK_BYTES", 64)
    public, private = _keys()
    cancel = False

    def progress(_phase, processed, _total):
        nonlocal cancel
        cancel = processed > 0

    sink = io.BytesIO()
    with pytest.raises(streaming.OperationCancelled):
        streaming.encrypt_stream(io.BytesIO(b"S" * 256), sink, public, progress=progress, cancelled=lambda: cancel)
    assert core.decrypt_file_pro(sink.getvalue(), private)[0] is None


def test_nonseekable_inputs_are_bounded_and_report_actual_final_totals(fake_backend):
    class Nonseekable(ShortReader):
        def seekable(self):
            return False

        def tell(self):
            pytest.fail("Nonseekable reader must not be queried for position")

    public, private = _keys()
    events = []
    sink = io.BytesIO()
    metadata = streaming.encrypt_stream(
        Nonseekable(b"S" * 129), sink, public, progress=lambda *args: events.append(args)
    )
    assert events[0] == ("encrypting", 0, 0)
    assert events[-1] == ("encrypting", 129, 129)
    assert streaming.verify_stream(Nonseekable(sink.getvalue()), private) == metadata
    with pytest.raises(core.SizeLimitError):
        streaming.encrypt_stream(Nonseekable(b"S" * 129), io.BytesIO(), public, max_file_bytes=128)
    with pytest.raises(core.SizeLimitError):
        streaming.inspect_stream(Nonseekable(sink.getvalue()), max_file_bytes=128)


def test_streaming_peak_memory_does_not_scale_with_file_size(fake_backend):
    class GeneratedSource:
        def __init__(self, size):
            self.remaining = size

        def read(self, size=-1):
            assert 0 < size <= cfg.STREAM_CHUNK_BYTES
            count = min(size, self.remaining)
            self.remaining -= count
            return b"S" * count

    class DigestSink:
        def __init__(self):
            self.digest = hashlib.sha256()
            self.count = 0

        def write(self, data):
            self.digest.update(data)
            self.count += len(data)
            return len(data)

    size = 24 * cfg.STREAM_CHUNK_BYTES
    public, private = _keys()
    sink = DigestSink()
    expected = hashlib.sha256()
    for _ in range(24):
        expected.update(b"S" * cfg.STREAM_CHUNK_BYTES)
    with tempfile.TemporaryFile(mode="w+b") as encrypted:
        tracemalloc.start()
        try:
            streaming.encrypt_stream(GeneratedSource(size), encrypted, public)
            encrypted.seek(0)
            streaming.decrypt_stream(encrypted, sink, private)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert sink.count == size
    assert sink.digest.digest() == expected.digest()
    assert peak < 12 * cfg.STREAM_CHUNK_BYTES


def test_native_stream_bytes_cross_compatibility():
    if not core.is_kem_available(cfg.KEM_ALG):
        pytest.skip("Native ML-KEM-768 is unavailable.")
    public, private = core.generate_hybrid_keys()
    assert public is not None and private is not None
    output = io.BytesIO()
    streaming.encrypt_stream(io.BytesIO(b"native stream"), output, public)
    assert core.decrypt_file_pro(output.getvalue(), private)[0] == b"native stream"
    blob = core.encrypt_file_pro(b"native bytes", public)
    assert blob is not None
    output = io.BytesIO()
    streaming.decrypt_stream(io.BytesIO(blob), output, private)
    assert output.getvalue() == b"native bytes"
