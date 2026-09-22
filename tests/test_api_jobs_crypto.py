"""Exercise job processing with real PEM protection and streaming AES-GCM."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

import api_jobs as jobs
from api_worker import CryptoWorker
from crypto_config import cfg
import crypto_core as core

PASSWORD = "correct horse battery staple"
PLAINTEXT = b"private job content\x00" * 31


@dataclass
class KeyMaterial:
    public: bytes
    private: bytes
    public_pem: str
    private_pem: str


def _material(public: bytes, private: bytes) -> KeyMaterial:
    public_pem = core.save_key_pem(public, cfg.HYBRID_KEM_ALG, "public")
    private_pem = core.save_key_pem(private, cfg.HYBRID_KEM_ALG, "private", PASSWORD)
    assert public_pem is not None and private_pem is not None
    return KeyMaterial(public, private, public_pem, private_pem)


@pytest.fixture(scope="module")
def keys():
    def create(seed):
        public = bytes(cfg.MLKEM768_PUBLIC_POLY_BYTES) + seed
        private = bytes(cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES) + public + hashlib.sha3_256(public).digest() + bytes(32)
        x_private = x25519.X25519PrivateKey.generate()
        x_public = x_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        x_bytes = x_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        return _material(x_public + public, x_bytes + private)

    return create(b"S" * 32), create(b"W" * 32)


@pytest.fixture
def fake_oqs(monkeypatch):
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
            start = cfg.MLKEM768_PKE_PRIVATE_KEY_BYTES
            public = self.secret_key[start : start + cfg.MLKEM768_PUBLIC_KEY_BYTES]
            return hashlib.sha256(self.algorithm.encode() + public + ciphertext).digest()

    class FakeOQS:
        KeyEncapsulation = FakeKEM

        @staticmethod
        def get_enabled_kem_mechanisms():
            return (cfg.KEM_ALG,)

    monkeypatch.setattr(core, "oqs", FakeOQS)
    monkeypatch.setattr(cfg, "STREAM_CHUNK_BYTES", 64)


@pytest.fixture
def temporary_files(monkeypatch):
    created = []
    original = jobs.tempfile.TemporaryFile

    def track(*args, **kwargs):
        file = original(*args, **kwargs)
        created.append(file)
        if os.name == "posix":
            assert os.fstat(file.fileno()).st_mode & 0o777 == 0o600
            assert os.fstat(file.fileno()).st_nlink == 0
        return file

    # Both the job output and crypto_stream snapshot use this standard-library module.
    monkeypatch.setattr(jobs.tempfile, "TemporaryFile", track)
    yield created
    assert all(file.closed for file in created)


async def _chunks(data):
    for offset in range(0, len(data), 17):
        yield data[offset : offset + 17]


async def _ready(store, mode, data):
    job = store.reserve(mode, "input.pqc", len(data))
    await store.upload(job, _chunks(data))
    assert job.state == "ready"
    return job


async def _finish(store, job, pem, password=PASSWORD):
    store.start(job, pem, password, "result.bin")
    assert job.task is not None
    await asyncio.wait_for(job.task, 10)
    assert job.input is None
    snapshot = job.snapshot()
    assert pem not in str(snapshot) and password not in str(snapshot)
    return snapshot


async def _successful_operation(mode, material):
    store = jobs.JobStore(CryptoWorker())
    try:
        encrypted = core.encrypt_file_pro(PLAINTEXT, material.public)
        assert encrypted is not None
        job = await _ready(store, mode, PLAINTEXT if mode == "encrypt" else encrypted)
        phases = []
        original_progress = job.progress

        def progress(phase, processed, total):
            assert "result" not in job.snapshot() and "verification" not in job.snapshot()
            with pytest.raises(jobs.JobError) as error:
                store.begin_download(job)
            assert error.value.code == "result_unavailable"
            if mode == "decrypt" and phase == "verifying":
                assert job.output is not None and job.output.tell() == 0
            if phase == "decrypting":
                assert "verifying" in phases
            phases.append(phase)
            original_progress(phase, processed, total)

        job.progress = progress
        snapshot = await _finish(store, job, material.public_pem if mode == "encrypt" else material.private_pem)
        assert snapshot["state"] == "complete"
        assert snapshot["processedBytes"] == snapshot["totalBytes"] == len(PLAINTEXT)
        if mode == "verify":
            assert job.output is None and "result" not in snapshot
            assert snapshot["verification"] == {
                "ok": True,
                "verified": True,
                "kem": cfg.HYBRID_KEM_ALG,
                "formatVersion": cfg.FORMAT_VERSION,
                "bytesVerified": len(PLAINTEXT),
                "publicKeyFingerprint": core.get_public_key_fingerprint(material.public, cfg.HYBRID_KEM_ALG),
            }
            assert phases and set(phases) == {"verifying"}
        else:
            assert job.output is not None
            store.begin_download(job)
            try:
                output = b"".join([chunk async for chunk in store.download(job)])
            finally:
                store.finish_download(job)
            assert snapshot["result"] == {"filename": "result.bin", "bytes": len(output)}
            if mode == "encrypt":
                assert core.decrypt_file_pro(output, material.private)[0] == PLAINTEXT
                assert set(phases) == {"encrypting"}
            else:
                assert output == PLAINTEXT
                assert set(phases) == {"verifying", "decrypting"}
    finally:
        await store.close()
    assert store.worker.acquire() is None


@pytest.mark.parametrize("mode", ["encrypt", "decrypt", "verify"])
def test_jobs_run_real_stream_crypto_with_authenticated_results(fake_oqs, keys, temporary_files, mode):
    asyncio.run(_successful_operation(mode, keys[0]))


@pytest.mark.parametrize("matched", [False, True])
def test_job_recipient_fingerprint_checked_before_output_creation(
    monkeypatch, fake_oqs, keys, temporary_files, matched
):
    material, other = keys
    expected = core.get_public_key_fingerprint((material if matched else other).public, cfg.HYBRID_KEM_ALG)
    if not matched:
        monkeypatch.setattr(
            jobs.stream, "encrypt_stream", lambda *_args, **_kwargs: pytest.fail("Mismatch must not encrypt")
        )

    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = await _ready(store, "encrypt", PLAINTEXT)
            store.start(job, material.public_pem, "", "result.pqc", expected)
            assert job.task is not None
            await asyncio.wait_for(job.task, 10)
            if matched:
                assert job.state == "complete" and job.output is not None
                assert core.decrypt_file_pro(job.output.read(), material.private)[0] == PLAINTEXT
            else:
                assert job.snapshot()["error"] == {
                    "code": "recipient_fingerprint_mismatch",
                    "message": "The public key does not match the expected recipient fingerprint.",
                }
                assert job.state == "failed" and job.output is None and job.result is None
                assert len(temporary_files) == 1 and temporary_files[0].closed
                lease = store.worker.acquire()
                assert lease is not None
                lease.close()
        finally:
            await store.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode,expected", [("encrypt", ""), ("decrypt", "QE1-SHA3-256:" + "a" * 64), ("verify", "QE1-SHA3-256:" + "a" * 64)]
)
def test_job_recipient_fingerprint_invalid_start_does_not_launch_worker(temporary_files, mode, expected):
    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = await _ready(store, mode, b"input")
            with pytest.raises(core.InvalidRecipientFingerprintError):
                store.start(job, "unused key", "", "result", expected)
            assert job.state == "ready" and job.task is None and job.output is None
        finally:
            await store.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["decrypt", "verify"])
@pytest.mark.parametrize("failure", ["password", "wrong_key", "tampered_payload"])
def test_job_authentication_failures_have_no_plaintext_result(fake_oqs, keys, temporary_files, mode, failure):
    async def scenario():
        material, wrong_key = keys
        encrypted = core.encrypt_file_pro(PLAINTEXT, material.public)
        assert encrypted is not None
        if failure == "tampered_payload":
            offset = core.inspect_encrypted_file_strict(encrypted).header_bytes
            encrypted = encrypted[:offset] + bytes([encrypted[offset] ^ 1]) + encrypted[offset + 1 :]
        store = jobs.JobStore(CryptoWorker())
        try:
            job = await _ready(store, mode, encrypted)
            phases = []

            def progress(phase, processed, total):
                phases.append(phase)
                assert phase == "verifying"
                assert job.output is None or job.output.tell() == 0

            job.progress = progress
            pem = wrong_key.private_pem if failure == "wrong_key" else material.private_pem
            password = "incorrect password value" if failure == "password" else PASSWORD
            snapshot = await _finish(store, job, pem, password)
            assert snapshot["state"] == "failed"
            assert "result" not in snapshot and "verification" not in snapshot
            assert snapshot["error"]["code"] == ("private_key_failed" if failure == "password" else "operation_failed")
            assert job.output is None
            assert all(file.closed for file in temporary_files)
            with pytest.raises(jobs.JobError) as error:
                store.begin_download(job)
            assert error.value.code == "result_unavailable"
            if failure != "password":
                assert phases
        finally:
            await store.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["encrypt", "decrypt", "verify"])
@pytest.mark.parametrize("failure", ["malformed", "wrong_type", "unencrypted"])
def test_job_rejects_bad_keys_with_safe_errors(fake_oqs, keys, temporary_files, mode, failure):
    material = keys[0]
    if failure == "malformed":
        pem = "private diagnostic content that must not appear in the response"
    elif failure == "wrong_type":
        pem = material.private_pem if mode == "encrypt" else material.public_pem
    else:
        pem = "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
                base64.b64encode(material.private).decode("ascii"),
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )

    async def scenario():
        store = jobs.JobStore(CryptoWorker())
        try:
            job = await _ready(store, mode, b"input")
            snapshot = await _finish(store, job, pem)
            assert snapshot["state"] == "failed"
            assert snapshot["error"]["code"] == ("invalid_key" if failure == "wrong_type" else "operation_failed")
            assert "result" not in snapshot and "verification" not in snapshot
            assert job.output is None
            assert len(temporary_files) == 1 and temporary_files[0].closed
        finally:
            await store.close()

    asyncio.run(scenario())


def test_native_job_encrypt_decrypt_and_verify_round_trip(temporary_files):
    if not core.is_kem_available(cfg.KEM_ALG):
        pytest.skip("Native ML-KEM-768 is unavailable.")
    public, private = core.generate_hybrid_keys()
    assert public is not None and private is not None
    material = _material(public, private)
    for mode in ("encrypt", "decrypt", "verify"):
        asyncio.run(_successful_operation(mode, material))
