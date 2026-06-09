"""
Unit tests for crypto_core module functionality.
"""

import base64
import os
import struct
import pytest
from typing import Tuple

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
    nonce_offset = kem_ct_offset + kem_ct_len
    payload_offset = nonce_offset + cfg.AES_NONCE_BYTES
    return {
        "version": len(cfg.MAGIC_BYTES),
        "kem_ct": kem_ct_offset,
        "nonce": nonce_offset,
        "payload": payload_offset,
        "tag": len(encrypted_data) - 1,
    }


def _tamper(data: bytes, offset: int) -> bytes:
    tampered = bytearray(data)
    tampered[offset] ^= 0x01
    return bytes(tampered)


def _syntactic_encrypted_blob(version: int = cfg.FORMAT_VERSION) -> bytes:
    alg = cfg.KEM_ALG.encode("utf-8")
    return (
        cfg.MAGIC_BYTES
        + version.to_bytes(2, "big")
        + len(alg).to_bytes(2, "big")
        + alg
        + (1).to_bytes(4, "big")
        + b"x"
        + os.urandom(cfg.AES_NONCE_BYTES)
        + b"ciphertext-and-tag"
    )


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


# Tests
class TestKeyGeneration:
    """Tests for key generation functions."""

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


class TestKeyDerivation:
    """Tests for key derivation functions."""

    def test_derive_symmetric_key_hkdf(self):
        """Test HKDF for symmetric key derivation."""
        # Use a test shared secret
        test_secret = os.urandom(32)
        derived_key = core.derive_symmetric_key_hkdf(test_secret)

        assert isinstance(derived_key, bytes)
        assert len(derived_key) == cfg.AES_KEY_BYTES

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


class TestPrivateKeyEncryption:
    """Tests for private key encryption/decryption."""

    def test_encrypt_decrypt_private_key(self, key_pair):
        """Test encrypting and decrypting a private key."""
        _, private_key = key_pair
        test_password = "test-password-123"

        # Encrypt the private key
        salt, nonce, encrypted_key = core.encrypt_private_key(private_key, test_password)

        assert salt is not None
        assert nonce is not None
        assert encrypted_key is not None

        # Create the key data dict for decryption
        encrypted_key_data = {
            "salt": salt,
            "nonce": nonce,
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
        decrypted_key_wrong = core.decrypt_private_key(encrypted_key_data, "wrong-password")
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
            pem_string, password="wrong-password"
        )

        assert loaded_key_wrong is None  # Decryption failed

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
                cfg.PEM_PROC_TYPE_HEADER,
                f"{cfg.PEM_DEK_INFO_HEADER}{bad_salt},{nonce}",
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

    def test_encrypt_decrypt_file(self, key_pair, kem_algorithm):
        """Test encrypting and decrypting a file."""
        public_key, private_key = key_pair
        kem_alg = kem_algorithm

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

    def test_encrypt_decrypt_empty_file(self, key_pair, kem_algorithm):
        """Empty file content still round trips with authenticated metadata."""
        public_key, private_key = key_pair

        encrypted_data = core.encrypt_file_pro(b"", public_key, kem_algorithm)
        assert encrypted_data is not None

        decrypted_data, detected_alg = core.decrypt_file_pro(encrypted_data, private_key)

        assert decrypted_data == b""
        assert detected_alg == kem_algorithm

    def test_decrypt_with_wrong_key(self, key_pair, kem_algorithm):
        """Test decrypting with wrong private key."""
        public_key, _ = key_pair
        kem_alg = kem_algorithm

        # Generate a different key pair
        _, wrong_private_key = core.generate_oqs_keys(kem_alg)

        # Test data
        test_data = b"This is test data to encrypt and decrypt."

        # Encrypt the data
        encrypted_data = core.encrypt_file_pro(test_data, public_key, kem_alg)

        # Try to decrypt with wrong key
        decrypted_data, _detected_alg = core.decrypt_file_pro(encrypted_data, wrong_private_key)

        # Should fail to decrypt
        assert decrypted_data is None

    @pytest.mark.parametrize("field", ["version", "kem_ct", "nonce", "payload", "tag"])
    def test_decrypt_rejects_tampered_encrypted_blob(self, key_pair, kem_algorithm, field):
        """Tampering with authenticated header or ciphertext fields fails decryption."""
        public_key, private_key = key_pair
        encrypted_data = core.encrypt_file_pro(b"authenticated test data", public_key, kem_algorithm)
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
        assert metadata.kem_alg == cfg.KEM_ALG
        assert metadata.kem_ciphertext_bytes == 1

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
