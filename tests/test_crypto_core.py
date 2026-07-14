"""
Unit tests for crypto_core module functionality.
"""

import base64
import hashlib
import os
import struct
import pytest
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import module to test
from crypto_config import cfg
import crypto_core as core


def _encrypted_blob_offsets(encrypted_data: bytes) -> dict[str, int]:
    """Return useful offsets for the project encrypted-file format."""
    fixed_header_size = struct.calcsize(cfg.HEADER_BASE_FORMAT)
    alg_len_offset = fixed_header_size
    alg_len = struct.unpack(">H", encrypted_data[alg_len_offset : alg_len_offset + 2])[0]
    alg_offset = alg_len_offset + 2
    kem_ct_len_offset = alg_offset + alg_len
    kem_ct_len = struct.unpack(">I", encrypted_data[kem_ct_len_offset : kem_ct_len_offset + 4])[0]
    kem_ct_offset = kem_ct_len_offset + 4
    version = struct.unpack(">H", encrypted_data[len(cfg.MAGIC_BYTES) : fixed_header_size])[0]
    x25519_offset = kem_ct_offset + kem_ct_len
    nonce_offset = x25519_offset + (cfg.X25519_KEY_BYTES if version == cfg.FORMAT_VERSION else 0)
    payload_offset = nonce_offset + cfg.AES_NONCE_BYTES
    return {
        "version": len(cfg.MAGIC_BYTES),
        "kem_ct": kem_ct_offset,
        "x25519_ct": x25519_offset,
        "nonce": nonce_offset,
        "payload": payload_offset,
        "tag": len(encrypted_data) - 1,
    }


def _tamper(data: bytes, offset: int) -> bytes:
    tampered = bytearray(data)
    tampered[offset] ^= 0x01
    return bytes(tampered)


def _syntactic_encrypted_blob(version: int = cfg.FORMAT_VERSION) -> bytes:
    alg = (cfg.HYBRID_KEM_ALG if version == 4 else cfg.KEM_ALG).encode("utf-8")
    x25519_ciphertext = b"X" * cfg.X25519_KEY_BYTES if version == 4 else b""
    return (
        cfg.MAGIC_BYTES
        + version.to_bytes(2, "big")
        + len(alg).to_bytes(2, "big")
        + alg
        + (1).to_bytes(4, "big")
        + b"x"
        + x25519_ciphertext
        + os.urandom(cfg.AES_NONCE_BYTES)
        + b"ciphertext-and-tag"
    )


def _fake_hybrid_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Return matching composite keys plus their ML-KEM components for fake-backend tests."""
    mlkem_private = b"M" * 32
    mlkem_public = hashlib.sha256(mlkem_private).digest()
    x25519_private_key = x25519.X25519PrivateKey.generate()
    x25519_private = x25519_private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    x25519_public = x25519_private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return (
        core.pack_hybrid_key(x25519_public, mlkem_public),
        core.pack_hybrid_key(x25519_private, mlkem_private),
        mlkem_public,
        mlkem_private,
    )


@pytest.fixture
def fake_oqs_backend(monkeypatch):
    """Provide deterministic KEM behavior without requiring a native liboqs installation."""

    class FakeKEM:
        def __init__(self, algorithm, secret_key=None):
            assert algorithm in {cfg.KEM_ALG, "Kyber768"}
            self.secret_key = secret_key
            self.details = {
                "length_public_key": 32,
                "length_secret_key": 32,
                "length_ciphertext": 32,
            }

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return None

        def encap_secret(self, public_key):
            ciphertext = b"C" * 32
            return ciphertext, hashlib.sha256(b"mlkem-share" + public_key + ciphertext).digest()

        def decap_secret(self, ciphertext):
            public_key = hashlib.sha256(self.secret_key).digest()
            return hashlib.sha256(b"mlkem-share" + public_key + ciphertext).digest()

    class FakeOQS:
        KeyEncapsulation = FakeKEM

        @staticmethod
        def get_enabled_kem_mechanisms():
            return [cfg.KEM_ALG]

    monkeypatch.setattr(core, "oqs", FakeOQS)
    return FakeOQS


def _legacy_v3_blob(plaintext: bytes, mlkem_public: bytes) -> bytes:
    """Build a valid legacy v3 container using the deterministic fake backend."""
    ciphertext_kem = b"C" * 32
    shared_secret = hashlib.sha256(b"mlkem-share" + mlkem_public + ciphertext_kem).digest()
    aes_key = core.derive_symmetric_key_hkdf(shared_secret)
    algorithm = cfg.KEM_ALG.encode("utf-8")
    nonce = b"N" * cfg.AES_NONCE_BYTES
    header = (
        struct.pack(cfg.HEADER_BASE_FORMAT, cfg.MAGIC_BYTES, 3)
        + struct.pack(">H", len(algorithm))
        + algorithm
        + struct.pack(">I", len(ciphertext_kem))
        + ciphertext_kem
        + nonce
    )
    return header + AESGCM(aes_key).encrypt(nonce, plaintext, header)


# Test fixtures
@pytest.fixture
def kem_algorithm():
    """Return a valid KEM algorithm for testing."""
    for candidate in cfg.ALLOWED_KEM_ALGS:
        if core.is_kem_available(candidate):
            return core.resolve_kem_algorithm(candidate)
    pytest.skip("No supported OQS KEM implementation is available.")


@pytest.fixture
def key_pair(kem_algorithm) -> Tuple[bytes, bytes]:
    """Generate a test key pair."""
    public_key, private_key = core.generate_oqs_keys(kem_algorithm)
    assert public_key is not None
    assert private_key is not None
    return public_key, private_key


@pytest.fixture
def hybrid_key_pair(kem_algorithm) -> Tuple[bytes, bytes]:
    """Generate an ML-KEM-768 + X25519 composite key pair."""
    public_key, private_key = core.generate_hybrid_keys(kem_algorithm)
    assert public_key is not None
    assert private_key is not None
    return public_key, private_key


# Tests
class TestKeyGeneration:
    """Tests for key generation functions."""

    def test_native_oqs_library_available_uses_find_library(self, monkeypatch):
        """A system-discoverable liboqs shared library is accepted."""
        monkeypatch.setattr(
            core.ctypes.util, "find_library", lambda name: "/usr/lib/liboqs.so" if name == "oqs" else None
        )

        assert core._native_oqs_library_available() is True

    def test_native_oqs_library_available_checks_install_path(self, monkeypatch, tmp_path):
        """OQS_INSTALL_PATH is checked for common shared-library directories."""
        monkeypatch.setattr(core.ctypes.util, "find_library", lambda _name: None)
        monkeypatch.delenv("OQS_INSTALL_PATH", raising=False)

        assert core._native_oqs_library_available() is False

        monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path))
        assert core._native_oqs_library_available() is False

        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "liboqs.so").write_text("", encoding="utf-8")

        assert core._native_oqs_library_available() is True

    def test_load_oqs_module_success_sets_global_module(self, monkeypatch):
        """A successful lazy import stores the oqs module for reuse."""
        fake_oqs = object()
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_oqs_load_error", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: True)
        monkeypatch.setattr(core.importlib, "import_module", lambda _name: fake_oqs)

        assert core._load_oqs_module() is fake_oqs
        assert core.oqs is fake_oqs
        assert core._oqs_load_error is None

    @pytest.mark.parametrize(
        "raised",
        [
            ImportError("missing wrapper"),
            RuntimeError("init failed"),
            ValueError("unexpected"),
        ],
    )
    def test_load_oqs_module_wraps_import_failures(self, monkeypatch, raised):
        """Import and initialization failures are surfaced as dependency errors."""
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_oqs_load_error", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: True)

        def fail_import(_module_name):
            raise raised

        monkeypatch.setattr(core.importlib, "import_module", fail_import)

        with pytest.raises(core.CryptoDependencyError):
            core._load_oqs_module()

        assert core.oqs is None
        assert core._oqs_load_error is not None

    def test_generate_oqs_keys(self, kem_algorithm):
        """Test generating key pairs."""
        public_key, private_key = core.generate_oqs_keys(kem_algorithm)
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        assert len(public_key) > 0
        assert len(private_key) > 0

    def test_generate_invalid_algorithm(self):
        """Test with invalid algorithm."""
        public_key, private_key = core.generate_oqs_keys("InvalidAlgorithm")
        assert public_key is None
        assert private_key is None

    def test_generate_hybrid_keys_combines_independent_x25519_and_ml_kem_keys(self, monkeypatch):
        """Composite keys contain independently generated X25519 and ML-KEM components."""
        monkeypatch.setattr(core, "generate_oqs_keys", lambda _kem: (b"mlkem-public", b"mlkem-private"))

        public_key, private_key = core.generate_hybrid_keys(cfg.KEM_ALG)

        assert public_key is not None
        assert private_key is not None
        x25519_public, mlkem_public = core.unpack_hybrid_key(public_key, "public")
        x25519_private, mlkem_private = core.unpack_hybrid_key(private_key, "private")
        derived_public = (
            x25519.X25519PrivateKey.from_private_bytes(x25519_private)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        assert derived_public == x25519_public
        assert mlkem_public == b"mlkem-public"
        assert mlkem_private == b"mlkem-private"

    @pytest.mark.parametrize("key_type", ["public", "private"])
    def test_unpack_hybrid_key_rejects_missing_component(self, key_type):
        """Composite keys fail closed unless both components are present."""
        with pytest.raises(core.InvalidKeyFormatError):
            core.unpack_hybrid_key(b"x" * cfg.X25519_KEY_BYTES, key_type)

    def test_resolve_invalid_algorithm_raises_typed_error(self):
        """Unsupported KEM names raise the typed core exception."""
        with pytest.raises(core.UnsupportedAlgorithmError):
            core.resolve_kem_algorithm("InvalidAlgorithm")

    def test_require_oqs_reports_unavailable_native_backend(self, monkeypatch):
        """Missing native liboqs is reported as a dependency error, not a process exit."""
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_oqs_load_error", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: False)

        with pytest.raises(core.CryptoDependencyError):
            core._require_oqs()

    def test_load_oqs_module_does_not_swallow_keyboard_interrupt(self, monkeypatch):
        """Control-flow interrupts must not be converted into backend dependency errors."""
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_oqs_load_error", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: True)

        def raise_keyboard_interrupt(_module_name):
            raise KeyboardInterrupt

        monkeypatch.setattr(core.importlib, "import_module", raise_keyboard_interrupt)

        with pytest.raises(KeyboardInterrupt):
            core._load_oqs_module()

        assert core.oqs is None

    def test_enabled_kem_mechanisms_supports_current_and_legacy_getters(self, monkeypatch):
        """liboqs-python getter name differences are normalized."""

        class ModernOQS:
            @staticmethod
            def get_enabled_kem_mechanisms():
                return [cfg.KEM_ALG]

        class LegacyOQS:
            @staticmethod
            def get_enabled_KEM_mechanisms():
                return ["Kyber768"]

        monkeypatch.setattr(core, "oqs", ModernOQS)
        assert core._enabled_kem_mechanisms() == (cfg.KEM_ALG,)

        monkeypatch.setattr(core, "oqs", LegacyOQS)
        assert core._enabled_kem_mechanisms() == ("Kyber768",)

        monkeypatch.setattr(core, "oqs", object())
        with pytest.raises(core.CryptoDependencyError):
            core._enabled_kem_mechanisms()

    def test_kem_aliases_and_resolve_alias_fallback(self, monkeypatch):
        """ML-KEM and Kyber aliases resolve to whichever compatible backend is enabled."""
        assert core._kem_aliases("ML-KEM-768") == ("ML-KEM-768", "Kyber768")
        assert core._kem_aliases("Kyber768") == ("Kyber768", "ML-KEM-768")
        assert core._kem_aliases("Other") == ("Other",)

        monkeypatch.setattr(core, "_enabled_kem_mechanisms", lambda: ("Kyber768",))
        assert core.resolve_kem_algorithm("ML-KEM-768") == "Kyber768"
        assert core.is_kem_available("ML-KEM-768") is True

        monkeypatch.setattr(core, "_enabled_kem_mechanisms", lambda: ())
        with pytest.raises(core.CryptoDependencyError):
            core.resolve_kem_algorithm("ML-KEM-768")
        assert core.is_kem_available("ML-KEM-768") is False


class TestOQSCompatibility:
    """Tests for liboqs-python API compatibility helpers."""

    def test_decapsulate_shared_secret_with_constructor_secret_key_api(self):
        """liboqs-python 0.15 keeps the private key on the KEM instance."""

        class ModernKEM:
            def __init__(self, alg_name, secret_key=None):
                self.alg_name = alg_name
                self.secret_key = secret_key

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc_value, _traceback):
                return None

            def decap_secret(self, ciphertext):
                assert self.alg_name == cfg.KEM_ALG
                assert self.secret_key == b"secret-key"
                assert ciphertext == b"ciphertext"
                return b"shared-secret"

        class ModernOQS:
            KeyEncapsulation = ModernKEM

        shared_secret = core._decapsulate_shared_secret(ModernOQS, cfg.KEM_ALG, b"secret-key", b"ciphertext")

        assert shared_secret == b"shared-secret"

    def test_decapsulate_shared_secret_with_legacy_two_argument_api(self):
        """Older liboqs-python bindings accepted the private key at decapsulation time."""

        class LegacyKEM:
            def __init__(self, alg_name, **kwargs):
                if kwargs:
                    raise TypeError("legacy constructor does not accept secret_key")
                self.alg_name = alg_name

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc_value, _traceback):
                return None

            def decap_secret(self, secret_key, ciphertext):
                assert self.alg_name == cfg.KEM_ALG
                assert secret_key == b"secret-key"
                assert ciphertext == b"ciphertext"
                return b"legacy-shared-secret"

        class LegacyOQS:
            KeyEncapsulation = LegacyKEM

        shared_secret = core._decapsulate_shared_secret(LegacyOQS, cfg.KEM_ALG, b"secret-key", b"ciphertext")

        assert shared_secret == b"legacy-shared-secret"

    def test_decapsulate_shared_secret_reraises_current_api_type_error(self):
        """If current and legacy liboqs calls fail, preserve the current API error."""

        class BrokenKEM:
            def __init__(self, _alg_name, **_kwargs):
                raise TypeError("current api failed")

        class BrokenOQS:
            KeyEncapsulation = BrokenKEM

        with pytest.raises(TypeError, match="current api failed"):
            core._decapsulate_shared_secret(BrokenOQS, cfg.KEM_ALG, b"secret-key", b"ciphertext")


class TestKeyDerivation:
    """Tests for key derivation functions."""

    def test_derive_symmetric_key_hkdf(self):
        """Test HKDF for symmetric key derivation."""
        # Use a test shared secret
        test_secret = os.urandom(32)
        derived_key = core.derive_symmetric_key_hkdf(test_secret)

        assert isinstance(derived_key, bytes)
        assert len(derived_key) == cfg.AES_KEY_BYTES

    def test_hybrid_combiner_matches_stable_reference_vector(self):
        """The v4 combiner is deterministic and binds both shares plus X25519 context."""
        mlkem_share = bytes(range(32))
        x25519_share = bytes(range(32, 64))
        ephemeral_public = b"E" * cfg.X25519_KEY_BYTES
        recipient_public = b"R" * cfg.X25519_KEY_BYTES
        expected = bytes.fromhex("e36c7ca1c6e4da6fd77989e52b576558d9fe5b6ef72fa119964bd8b3a8b3b298")

        combined = core.derive_hybrid_symmetric_key(
            mlkem_share,
            x25519_share,
            ephemeral_public,
            recipient_public,
            cfg.HYBRID_KEM_ALG,
        )

        assert combined == expected
        assert len(combined) == cfg.AES_KEY_BYTES

    def test_derive_key_from_password(self):
        """Test password-based key derivation."""
        test_password = "secure-test-password"
        test_salt = os.urandom(cfg.SCRYPT_SALT_BYTES)

        derived_key = core.derive_key_from_password(test_password, test_salt)

        assert isinstance(derived_key, bytes)
        assert len(derived_key) == cfg.AES_KEY_BYTES

        # Test with same password and salt - should get same key
        derived_key2 = core.derive_key_from_password(test_password, test_salt)
        assert derived_key == derived_key2

    def test_derive_key_empty_password(self):
        """Test password-based key derivation with empty password."""
        test_salt = os.urandom(cfg.SCRYPT_SALT_BYTES)

        with pytest.raises(core.PasswordRequiredError):
            core.derive_key_from_password("", test_salt)

    @pytest.mark.parametrize(
        "password",
        [
            "",
            "short",
            "aaaaaaaaaaaaaaaa",
            "1111111111111111",
            "password12345678",
        ],
    )
    def test_validate_private_key_password_rejects_weak_passwords(self, password):
        """The shared private-key password policy rejects trivial values."""
        with pytest.raises((core.PasswordRequiredError, core.WeakPasswordError)):
            core.validate_private_key_password(password)

    def test_validate_private_key_password_accepts_reasonable_passphrase(self):
        """A long passphrase with character variety is accepted."""
        assert core.validate_private_key_password("river metal orbit cactus 47") == "river metal orbit cactus 47"


class TestPrivateKeyEncryption:
    """Tests for private key encryption/decryption."""

    def test_encrypt_decrypt_private_key(self, key_pair):
        """Test encrypting and decrypting a private key."""
        _, private_key = key_pair
        test_password = "test-password-123"

        # Encrypt the private key
        metadata, encrypted_key = core.encrypt_private_key(private_key, test_password, cfg.KEM_ALG)

        assert metadata is not None
        assert encrypted_key is not None

        # Create the key data dict for decryption
        encrypted_key_data = {
            "format_version": metadata.format_version,
            "kem_alg": metadata.kem_alg,
            "salt": metadata.salt,
            "nonce": metadata.nonce,
            "encrypted_key": encrypted_key,
            "kdf": cfg.PRIVATE_KEY_KDF_ALG,
            "kdf_n": cfg.SCRYPT_N,
            "kdf_r": cfg.SCRYPT_R,
            "kdf_p": cfg.SCRYPT_P,
        }

        # Decrypt with correct password
        decrypted_key = core.decrypt_private_key(encrypted_key_data, test_password)
        assert decrypted_key is not None
        assert decrypted_key == private_key

        # Try decrypting with wrong password
        decrypted_key_wrong = core.decrypt_private_key(encrypted_key_data, "different-test-password")
        assert decrypted_key_wrong is None


class TestPEMKeyFormat:
    """Tests for PEM key format functions."""

    def test_save_load_public_key_pem(self, key_pair, kem_algorithm):
        """Test saving and loading a public key in PEM format."""
        public_key, _ = key_pair
        kem_alg = kem_algorithm

        # Save public key to PEM
        pem_string = core.save_key_pem(public_key, kem_alg, "public")
        assert pem_string is not None
        assert cfg.PEM_PUBLIC_HEADER in pem_string
        assert cfg.PEM_PUBLIC_FOOTER in pem_string

        # Load public key from PEM
        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_string)

        assert loaded_key is not None
        assert loaded_key == public_key
        assert loaded_alg == kem_alg
        assert loaded_type == "public"

    def test_save_private_key_pem_without_password_is_rejected(self, key_pair, kem_algorithm):
        """Private keys must be password protected."""
        _, private_key = key_pair
        kem_alg = kem_algorithm

        pem_string = core.save_key_pem(private_key, kem_alg, "private")

        assert pem_string is None

    def test_save_load_private_key_pem_with_password(self, key_pair, kem_algorithm):
        """Test saving and loading a private key with password."""
        _, private_key = key_pair
        kem_alg = kem_algorithm
        test_password = "secure-test-password"

        # Save private key to PEM (with password)
        pem_string = core.save_key_pem(private_key, kem_alg, "private", password=test_password)
        assert pem_string is not None
        assert cfg.PEM_PRIVATE_HEADER in pem_string
        assert cfg.PEM_PRIVATE_FOOTER in pem_string
        assert f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}" in pem_string
        assert cfg.PEM_PROC_TYPE_HEADER in pem_string  # Encrypted
        assert f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG}" in pem_string

        # Load private key from PEM with correct password
        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_string, password=test_password)

        assert loaded_key is not None
        assert loaded_key == private_key
        assert loaded_alg == kem_alg
        assert loaded_type == "private"

        # Try loading with wrong password
        loaded_key_wrong, _loaded_alg_wrong, _loaded_type_wrong = core.load_key_pem(
            pem_string, password="different-test-password"
        )

        assert loaded_key_wrong is None  # Decryption failed

    def test_save_load_current_private_key_pem_with_authenticated_metadata(self):
        """The current private-key PEM envelope authenticates metadata and round-trips."""
        password = "river metal orbit cactus 47"
        raw_private_key = b"private-key-bytes"

        pem_string = core.save_key_pem(raw_private_key, cfg.KEM_ALG, "private", password=password)

        assert pem_string is not None
        assert f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}" in pem_string
        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_string, password=password)
        assert loaded_key == raw_private_key
        assert loaded_alg == cfg.KEM_ALG
        assert loaded_type == "private"

    def test_save_load_hybrid_key_pem_uses_v3_authenticated_envelope(self):
        """New composite keys use the authenticated v3 private-key envelope."""
        password = "river metal orbit cactus 47"
        raw_public_key = core.pack_hybrid_key(b"P" * cfg.X25519_KEY_BYTES, b"mlkem-public")
        raw_private_key = core.pack_hybrid_key(b"S" * cfg.X25519_KEY_BYTES, b"mlkem-private")

        public_pem = core.save_key_pem(raw_public_key, cfg.HYBRID_KEM_ALG, "public")
        private_pem = core.save_key_pem(raw_private_key, cfg.HYBRID_KEM_ALG, "private", password=password)

        assert cfg.PEM_PRIVATE_KEY_FORMAT_VERSION == 3
        assert public_pem is not None
        assert private_pem is not None
        assert f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}" in public_pem
        assert f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}3" in private_pem
        assert core.load_key_pem(public_pem) == (raw_public_key, cfg.HYBRID_KEM_ALG, "public")
        assert core.load_key_pem(private_pem, password=password) == (
            raw_private_key,
            cfg.HYBRID_KEM_ALG,
            "private",
        )

        tampered = private_pem.replace(
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
            f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
        )
        assert core.load_key_pem(tampered, password=password) == (None, None, None)

    def test_hybrid_pem_rejects_payload_missing_ml_kem_component(self):
        """PEM serialization cannot bless a partial composite key as valid."""
        partial_key = b"X" * cfg.X25519_KEY_BYTES
        encoded = base64.b64encode(partial_key).decode("ascii")
        malformed_public_pem = "\n".join(
            [
                cfg.PEM_PUBLIC_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.HYBRID_KEM_ALG}",
                encoded,
                cfg.PEM_PUBLIC_FOOTER,
            ]
        )

        assert core.save_key_pem(partial_key, cfg.HYBRID_KEM_ALG, "public") is None
        assert core.load_key_pem(malformed_public_pem) == (None, None, None)

    def test_load_key_pem_accepts_authenticated_v2_private_key_for_legacy_decryption(self, monkeypatch):
        """Authenticated v2 ML-KEM private keys remain usable for decrypting v3 containers."""
        password = "river metal orbit cactus 47"
        monkeypatch.setattr(cfg, "PEM_PRIVATE_KEY_FORMAT_VERSION", 2)
        legacy_pem = core.save_key_pem(b"legacy-private", cfg.KEM_ALG, "private", password=password)
        assert legacy_pem is not None

        monkeypatch.setattr(cfg, "PEM_PRIVATE_KEY_FORMAT_VERSION", 3)
        loaded = core.load_key_pem(legacy_pem, password=password)

        assert loaded == (b"legacy-private", cfg.KEM_ALG, "private")

    def test_load_key_pem_rejects_oversized_public_key_payload(self, monkeypatch):
        """Decoded PEM key payloads are capped before acceptance."""
        monkeypatch.setattr(cfg, "MAX_RAW_KEY_BYTES", 3)
        key_data = base64.b64encode(b"four").decode("ascii")
        pem_content = "\n".join(
            [
                cfg.PEM_PUBLIC_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                key_data,
                cfg.PEM_PUBLIC_FOOTER,
            ]
        )

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_load_key_pem_rejects_oversized_private_key_payload_before_decrypt(self, monkeypatch):
        """Oversized encrypted private-key payloads fail before password KDF/decryption."""
        monkeypatch.setattr(cfg, "MAX_RAW_KEY_BYTES", 3)
        monkeypatch.setattr(
            core,
            "decrypt_private_key",
            lambda *_args, **_kwargs: pytest.fail("decrypt should not run"),
        )
        salt = base64.b64encode(os.urandom(cfg.SCRYPT_SALT_BYTES)).decode("ascii")
        nonce = base64.b64encode(os.urandom(cfg.AES_NONCE_BYTES)).decode("ascii")
        encrypted_key = base64.b64encode(b"four").decode("ascii")
        pem_content = "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}",
                cfg.PEM_PROC_TYPE_HEADER,
                f"{cfg.PEM_DEK_INFO_HEADER}{salt},{nonce}",
                f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG},n={cfg.SCRYPT_N},r={cfg.SCRYPT_R},p={cfg.SCRYPT_P}",
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                encrypted_key,
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(
            pem_content,
            password="river metal orbit cactus 47",
        )

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_private_key_pem_rejects_algorithm_metadata_tampering(self, monkeypatch):
        """Changing authenticated algorithm metadata breaks private-key decryption."""
        password = "river metal orbit cactus 47"
        monkeypatch.setattr(cfg, "ALLOWED_KEM_ALGS", (cfg.KEM_ALG, "Fake-KEM"))

        pem_string = core.save_key_pem(b"private-key-bytes", cfg.KEM_ALG, "private", password=password)
        assert pem_string is not None
        tampered = pem_string.replace(f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}", "Algorithm: Fake-KEM")

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(tampered, password=password)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_private_key_pem_rejects_kdf_metadata_tampering(self):
        """Changing authenticated KDF metadata breaks private-key decryption."""
        password = "river metal orbit cactus 47"
        pem_string = core.save_key_pem(b"private-key-bytes", cfg.KEM_ALG, "private", password=password)
        assert pem_string is not None
        tampered = pem_string.replace(f"n={cfg.SCRYPT_N}", "n=65536")

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(tampered, password=password)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_private_key_pem_rejects_dek_metadata_tampering(self):
        """Changing authenticated salt/nonce metadata breaks private-key decryption."""
        password = "river metal orbit cactus 47"
        pem_string = core.save_key_pem(b"private-key-bytes", cfg.KEM_ALG, "private", password=password)
        assert pem_string is not None
        dek_line = next(line for line in pem_string.splitlines() if line.startswith(cfg.PEM_DEK_INFO_HEADER))
        _salt_b64, nonce_b64 = dek_line[len(cfg.PEM_DEK_INFO_HEADER) :].split(",", 1)
        replacement_salt = base64.b64encode(b"2" * cfg.SCRYPT_SALT_BYTES).decode("ascii")
        tampered = pem_string.replace(dek_line, f"{cfg.PEM_DEK_INFO_HEADER}{replacement_salt},{nonce_b64}")

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(tampered, password=password)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_legacy_encrypted_private_key_without_format_version_is_rejected(self):
        """Legacy encrypted private-key PEMs with unsigned metadata fail closed."""
        salt = base64.b64encode(os.urandom(cfg.SCRYPT_SALT_BYTES)).decode("ascii")
        nonce = base64.b64encode(os.urandom(cfg.AES_NONCE_BYTES)).decode("ascii")
        encrypted_key = base64.b64encode(b"encrypted-key").decode("ascii")
        pem_content = "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                cfg.PEM_PROC_TYPE_HEADER,
                f"{cfg.PEM_DEK_INFO_HEADER}{salt},{nonce}",
                f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG},n={cfg.SCRYPT_N},r={cfg.SCRYPT_R},p={cfg.SCRYPT_P}",
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                encrypted_key,
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content, password="river metal orbit cactus 47")

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None
        with pytest.raises(core.InvalidKeyFormatError):
            core.inspect_key_pem_strict(pem_content)

    @pytest.mark.parametrize(
        "pem_content",
        [
            "",
            "not a pem file",
            "\n".join(
                [
                    cfg.PEM_PUBLIC_HEADER,
                    f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                    "not-valid-base64!",
                    cfg.PEM_PUBLIC_FOOTER,
                ]
            ),
            "\n".join(
                [
                    cfg.PEM_PUBLIC_HEADER,
                    "AQID",
                    cfg.PEM_PUBLIC_FOOTER,
                ]
            ),
        ],
    )
    def test_load_key_pem_rejects_malformed_input(self, pem_content):
        """Malformed PEM input fails closed."""
        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_load_encrypted_private_key_rejects_bad_dek_info_lengths(self):
        """Encrypted private key PEM metadata must use configured salt and nonce sizes."""
        bad_salt = base64.b64encode(b"short").decode("ascii")
        nonce = base64.b64encode(os.urandom(cfg.AES_NONCE_BYTES)).decode("ascii")
        encrypted_key = base64.b64encode(b"encrypted-key").decode("ascii")
        pem_content = "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}",
                cfg.PEM_PROC_TYPE_HEADER,
                f"{cfg.PEM_DEK_INFO_HEADER}{bad_salt},{nonce}",
                f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG},n={cfg.SCRYPT_N},r={cfg.SCRYPT_R},p={cfg.SCRYPT_P}",
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                encrypted_key,
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content, password="correct horse battery staple")

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None

    def test_load_unencrypted_private_key_pem_is_rejected(self):
        """Legacy unencrypted private keys fail closed."""
        private_key = base64.b64encode(b"private-key").decode("ascii")
        pem_content = "\n".join(
            [
                cfg.PEM_PRIVATE_HEADER,
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                private_key,
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content)

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None
        with pytest.raises(core.UnencryptedPrivateKeyError):
            core.inspect_key_pem_strict(pem_content)

    @pytest.mark.parametrize(
        "kdf_line",
        [
            "",
            "KDF: pbkdf2,iterations=390000",
            "KDF: scrypt,n=1024,r=8,p=1",
            "KDF: scrypt,n=32768,r=8",
            "KDF: scrypt,n=32768,r=8,p=text",
        ],
    )
    def test_encrypted_private_key_rejects_missing_or_weak_kdf_metadata(self, kdf_line):
        """Encrypted private-key PEM must declare the current scrypt policy."""
        salt = base64.b64encode(os.urandom(cfg.SCRYPT_SALT_BYTES)).decode("ascii")
        nonce = base64.b64encode(os.urandom(cfg.AES_NONCE_BYTES)).decode("ascii")
        encrypted_key = base64.b64encode(b"encrypted-key").decode("ascii")
        lines = [
            cfg.PEM_PRIVATE_HEADER,
            f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{cfg.PEM_PRIVATE_KEY_FORMAT_VERSION}",
            cfg.PEM_PROC_TYPE_HEADER,
            f"{cfg.PEM_DEK_INFO_HEADER}{salt},{nonce}",
        ]
        if kdf_line:
            lines.append(kdf_line)
        lines.extend(
            [
                f"{cfg.PEM_ALGORITHM_HEADER}{cfg.KEM_ALG}",
                encrypted_key,
                cfg.PEM_PRIVATE_FOOTER,
            ]
        )
        pem_content = "\n".join(lines)

        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_content, password="correct horse battery staple")

        assert loaded_key is None
        assert loaded_alg is None
        assert loaded_type is None


class TestFileEncryption:
    """Tests for file encryption/decryption."""

    def test_hybrid_v4_roundtrip_uses_both_key_establishment_components(self, fake_oqs_backend):
        """New encryption emits v4 and requires matching ML-KEM and X25519 private components."""
        public_key, private_key, _mlkem_public, _mlkem_private = _fake_hybrid_keys()

        encrypted_data = core.encrypt_file_pro(b"hybrid authenticated data", public_key, cfg.HYBRID_KEM_ALG)

        assert encrypted_data is not None
        metadata = core.inspect_encrypted_file_strict(encrypted_data)
        assert metadata.version == 4
        assert metadata.kem_alg == cfg.HYBRID_KEM_ALG
        assert metadata.kem_ciphertext_bytes == 32
        assert metadata.x25519_ciphertext_bytes == cfg.X25519_KEY_BYTES
        assert core.decrypt_file_pro(
            encrypted_data,
            private_key,
            expected_kem_alg=cfg.HYBRID_KEM_ALG,
        ) == (b"hybrid authenticated data", cfg.HYBRID_KEM_ALG)

        _wrong_public, wrong_private, _wrong_mlkem_public, _wrong_mlkem_private = _fake_hybrid_keys()
        wrong_x25519_private, _ = core.unpack_hybrid_key(wrong_private, "private")
        _correct_x25519_private, correct_mlkem_private = core.unpack_hybrid_key(private_key, "private")
        mixed_private = core.pack_hybrid_key(wrong_x25519_private, correct_mlkem_private)
        assert (
            core.decrypt_file_pro(
                encrypted_data,
                mixed_private,
                expected_kem_alg=cfg.HYBRID_KEM_ALG,
            )[0]
            is None
        )

    def test_hybrid_v4_rejects_wrong_ml_kem_component(self, fake_oqs_backend):
        """A matching X25519 key cannot compensate for the wrong ML-KEM private component."""
        public_key, private_key, _mlkem_public, _mlkem_private = _fake_hybrid_keys()
        encrypted_data = core.encrypt_file_pro(b"two component secret", public_key, cfg.HYBRID_KEM_ALG)
        assert encrypted_data is not None

        x25519_private, _correct_mlkem_private = core.unpack_hybrid_key(private_key, "private")
        wrong_private = core.pack_hybrid_key(x25519_private, b"W" * 32)

        assert (
            core.decrypt_file_pro(
                encrypted_data,
                wrong_private,
                expected_kem_alg=cfg.HYBRID_KEM_ALG,
            )[0]
            is None
        )

    def test_encrypt_refuses_legacy_v3_but_decrypt_accepts_authenticated_v3(self, fake_oqs_backend):
        """Legacy containers are decrypt-only so encryption cannot silently downgrade."""
        public_key, _private_key, mlkem_public, mlkem_private = _fake_hybrid_keys()
        legacy_blob = _legacy_v3_blob(b"legacy plaintext", mlkem_public)

        assert core.encrypt_file_pro(b"new plaintext", public_key, cfg.KEM_ALG) is None
        assert core.decrypt_file_pro(
            legacy_blob,
            mlkem_private,
            expected_kem_alg=cfg.KEM_ALG,
        ) == (b"legacy plaintext", cfg.KEM_ALG)

    def test_hybrid_v4_rejects_suite_downgrade_before_backend_use(self, monkeypatch):
        """A v4 container cannot relabel itself as the legacy single-KEM suite."""
        downgraded = _syntactic_encrypted_blob(version=4).replace(
            cfg.HYBRID_KEM_ALG.encode("utf-8"),
            cfg.KEM_ALG.encode("utf-8").ljust(len(cfg.HYBRID_KEM_ALG), b" "),
        )
        monkeypatch.setattr(core, "_require_oqs", lambda: pytest.fail("backend must not be reached"))

        decrypted, detected = core.decrypt_file_pro(downgraded, b"not-a-key")

        assert decrypted is None
        assert detected is None

    def test_encrypt_decrypt_file(self, hybrid_key_pair):
        """Test encrypting and decrypting a file."""
        public_key, private_key = hybrid_key_pair
        kem_alg = cfg.HYBRID_KEM_ALG

        # Test data
        test_data = b"This is test data to encrypt and decrypt."

        # Encrypt the data
        encrypted_data = core.encrypt_file_pro(test_data, public_key, kem_alg)
        assert encrypted_data is not None
        assert len(encrypted_data) > len(test_data)  # Encrypted data is larger due to header and tag

        # Decrypt the data
        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_data, private_key)

        assert decrypted_data is not None
        assert decrypted_data == test_data
        assert detected_alg == kem_alg

    def test_encrypt_decrypt_empty_file(self, hybrid_key_pair):
        """Empty file content still round trips with authenticated metadata."""
        public_key, private_key = hybrid_key_pair

        encrypted_data = core.encrypt_file_pro(b"", public_key, cfg.HYBRID_KEM_ALG)
        assert encrypted_data is not None

        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_data, private_key)

        assert decrypted_data == b""
        assert detected_alg == cfg.HYBRID_KEM_ALG

    def test_decrypt_with_wrong_key(self, hybrid_key_pair, kem_algorithm):
        """Test decrypting with wrong private key."""
        public_key, _ = hybrid_key_pair
        kem_alg = cfg.HYBRID_KEM_ALG

        # Generate a different key pair
        _, wrong_private_key = core.generate_hybrid_keys(kem_algorithm)

        # Test data
        test_data = b"This is test data to encrypt and decrypt."

        # Encrypt the data
        encrypted_data = core.encrypt_file_pro(test_data, public_key, kem_alg)

        # Try to decrypt with wrong key
        decrypted_data, _detected_alg = core.decrypt_file_pro(encrypted_data, wrong_private_key)

        # Should fail to decrypt
        assert decrypted_data is None

    @pytest.mark.parametrize("field", ["version", "kem_ct", "x25519_ct", "nonce", "payload", "tag"])
    def test_decrypt_rejects_tampered_encrypted_blob(self, hybrid_key_pair, field):
        """Tampering with authenticated header or ciphertext fields fails decryption."""
        public_key, private_key = hybrid_key_pair
        encrypted_data = core.encrypt_file_pro(b"authenticated test data", public_key, cfg.HYBRID_KEM_ALG)
        assert encrypted_data is not None
        offsets = _encrypted_blob_offsets(encrypted_data)

        decrypted_data, _detected_alg = core.decrypt_file_pro(_tamper(encrypted_data, offsets[field]), private_key)

        assert decrypted_data is None

    def test_decrypt_rejects_unsupported_kem_header(self):
        """Unsupported KEM identifiers are rejected before backend use."""
        bad_alg = b"Unsupported-KEM"
        encrypted_data = (
            cfg.MAGIC_BYTES
            + cfg.FORMAT_VERSION.to_bytes(2, "big")
            + len(bad_alg).to_bytes(2, "big")
            + bad_alg
            + (1).to_bytes(4, "big")
            + b"x"
            + os.urandom(cfg.AES_NONCE_BYTES)
            + b"tag"
        )

        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_data, b"")

        assert decrypted_data is None
        assert detected_alg is None

    def test_decrypt_rejects_private_key_algorithm_mismatch_before_backend_use(self):
        """A private key for a non-matching KEM cannot be used for a parsed container."""
        decrypted_data, detected_alg = core.decrypt_file_pro(
            _syntactic_encrypted_blob(),
            b"private-key",
            expected_kem_alg="Different-KEM",
        )

        assert decrypted_data is None
        assert detected_alg == cfg.HYBRID_KEM_ALG

    def test_canonical_kem_algorithm_treats_kyber768_as_ml_kem_768(self):
        """Configured ML-KEM/Kyber aliases remain compatible."""
        assert core.canonical_kem_algorithm("Kyber768") == "ML-KEM-768"
        assert core.canonical_kem_algorithm("ML-KEM-768") == "ML-KEM-768"
        assert core.canonical_kem_algorithm("Other-KEM") == "Other-KEM"

    def test_decrypt_rejects_legacy_file_format_versions(self):
        """Legacy encrypted-file formats are rejected instead of using unauthenticated-header fallback."""
        decrypted_data, detected_alg = core.decrypt_file_pro(_syntactic_encrypted_blob(version=2), b"")

        assert decrypted_data is None
        assert detected_alg is None

    def test_inspect_encrypted_file_without_backend(self, monkeypatch):
        """Encrypted-container metadata inspection does not require native liboqs."""
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: False)

        metadata = core.inspect_encrypted_file_strict(_syntactic_encrypted_blob())

        assert metadata.version == cfg.FORMAT_VERSION
        assert metadata.kem_alg == cfg.HYBRID_KEM_ALG
        assert metadata.kem_ciphertext_bytes == 1
        assert metadata.x25519_ciphertext_bytes == cfg.X25519_KEY_BYTES

    def test_inspect_encrypted_file_rejects_payload_shorter_than_gcm_tag(self):
        """A container cannot authenticate when its AES section lacks a full GCM tag."""
        encrypted_data = _syntactic_encrypted_blob()
        payload_offset = _encrypted_blob_offsets(encrypted_data)["payload"]
        malformed = encrypted_data[:payload_offset] + b"x" * (cfg.AES_TAG_BYTES - 1)

        with pytest.raises(core.FileFormatError, match="authentication tag"):
            core.inspect_encrypted_file_strict(malformed)

    def test_inspect_encrypted_file_rejects_payload_above_plaintext_bound(self, monkeypatch):
        """The AES section is bounded by plaintext size plus the GCM tag."""
        monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 3)
        encrypted_data = _syntactic_encrypted_blob()
        payload_offset = _encrypted_blob_offsets(encrypted_data)["payload"]
        oversized = encrypted_data[:payload_offset] + b"x" * (3 + cfg.AES_TAG_BYTES + 1)

        with pytest.raises(core.SizeLimitError, match="payload"):
            core.inspect_encrypted_file_strict(oversized)

    @pytest.mark.parametrize(
        "encrypted_data",
        [
            b"",
            cfg.MAGIC_BYTES[:3],
            cfg.MAGIC_BYTES + cfg.FORMAT_VERSION.to_bytes(2, "big"),
            cfg.MAGIC_BYTES + cfg.FORMAT_VERSION.to_bytes(2, "big") + b"\x00\x00",
            cfg.MAGIC_BYTES + cfg.FORMAT_VERSION.to_bytes(2, "big") + b"\x00\xff",
        ],
    )
    def test_decrypt_rejects_truncated_or_implausible_headers(self, encrypted_data):
        """Malformed encrypted-file headers fail closed before backend use."""
        decrypted_data, _detected_alg = core.decrypt_file_pro(encrypted_data, b"")

        assert decrypted_data is None

    def test_encrypt_rejects_oversized_input_before_backend_use(self, monkeypatch):
        """Size limits are enforced before native backend access."""
        monkeypatch.setattr(cfg, "MAX_FILE_BYTES", 3)
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: False)

        encrypted_data = core.encrypt_file_pro(b"four", b"", cfg.KEM_ALG)

        assert encrypted_data is None

    def test_decrypt_rejects_oversized_encrypted_blob_before_backend_use(self, monkeypatch):
        """Encrypted-container size limits are enforced before native backend access."""
        monkeypatch.setattr(cfg, "MAX_ENCRYPTED_FILE_BYTES", 3)
        monkeypatch.setattr(core, "oqs", None)
        monkeypatch.setattr(core, "_native_oqs_library_available", lambda: False)

        decrypted_data, detected_alg = core.decrypt_file_pro(b"four", b"")

        assert decrypted_data is None
        assert detected_alg is None
