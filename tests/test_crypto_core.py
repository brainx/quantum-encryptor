"""
Unit tests for crypto_core module functionality.
"""

import os
import pytest
from typing import Tuple

# Import module to test
from crypto_config import cfg
import crypto_core as core


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
        test_salt = os.urandom(cfg.PBKDF2_SALT_BYTES)

        derived_key = core.derive_key_from_password(test_password, test_salt)

        assert isinstance(derived_key, bytes)
        assert len(derived_key) == cfg.AES_KEY_BYTES

        # Test with same password and salt - should get same key
        derived_key2 = core.derive_key_from_password(test_password, test_salt)
        assert derived_key == derived_key2

    def test_derive_key_empty_password(self):
        """Test password-based key derivation with empty password."""
        test_salt = os.urandom(cfg.PBKDF2_SALT_BYTES)

        with pytest.raises(ValueError):
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

    def test_save_load_private_key_pem_no_password(self, key_pair, kem_algorithm):
        """Test saving and loading a private key without password."""
        _, private_key = key_pair
        kem_alg = kem_algorithm

        # Save private key to PEM (no password)
        pem_string = core.save_key_pem(private_key, kem_alg, "private")
        assert pem_string is not None
        assert cfg.PEM_PRIVATE_HEADER in pem_string
        assert cfg.PEM_PRIVATE_FOOTER in pem_string
        assert cfg.PEM_PROC_TYPE_HEADER not in pem_string  # Not encrypted

        # Load private key from PEM
        loaded_key, loaded_alg, loaded_type = core.load_key_pem(pem_string)

        assert loaded_key is not None
        assert loaded_key == private_key
        assert loaded_alg == kem_alg
        assert loaded_type == "private"

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
        assert detected_alg == bad_alg.decode("utf-8")
