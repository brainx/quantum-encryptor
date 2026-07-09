# crypto_core.py
import os
import struct
import logging
import base64
import io
import binascii
import ctypes.util
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

# Configuration
from crypto_config import cfg

# Cryptography Libraries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag, InvalidKey  # For password decryption
from cryptography.hazmat.backends import default_backend

oqs = None
_oqs_load_error: Optional[str] = None

# Setup Logger
logger = logging.getLogger(__name__)


class CryptoCoreError(RuntimeError):
    """Base class for cryptographic workflow failures."""


class CryptoDependencyError(CryptoCoreError):
    """Raised when a required cryptography backend is unavailable."""


class UnsupportedAlgorithmError(ValueError):
    """Raised when a KEM identifier is not supported by this application."""


class FileFormatError(ValueError):
    """Raised when an encrypted file header or payload format is invalid."""


class PasswordRequiredError(CryptoCoreError):
    """Raised when a required private-key password is missing."""


class WeakPasswordError(ValueError):
    """Raised when a private-key password does not meet the security policy."""


class UnencryptedPrivateKeyError(ValueError):
    """Raised when an unencrypted private key is provided."""


class UnsupportedKDFError(ValueError):
    """Raised when private-key PEM metadata declares an unsupported KDF."""


class AuthenticationFailedError(CryptoCoreError):
    """Raised when authenticated decryption fails."""


class SizeLimitError(ValueError):
    """Raised when an input exceeds a configured in-memory size limit."""


class InvalidKeyFormatError(ValueError):
    """Raised when a key file is malformed or semantically invalid."""


@dataclass(frozen=True)
class EncryptedFileMetadata:
    """Non-secret encrypted-container metadata."""

    version: int
    kem_alg: str
    header_bytes: int
    kem_ciphertext_bytes: int
    encrypted_payload_bytes: int
    total_bytes: int


@dataclass(frozen=True)
class EncryptedFileParts:
    """Parsed encrypted-container parts used for decryption."""

    metadata: EncryptedFileMetadata
    header_aad: bytes
    ciphertext_kem: bytes
    nonce: bytes
    encrypted_data_aes: bytes


@dataclass(frozen=True)
class PrivateKeyPemMetadata:
    """Authenticated metadata for encrypted private-key PEM files."""

    format_version: int
    kem_alg: str
    kdf_name: str
    kdf_n: int
    kdf_r: int
    kdf_p: int
    salt: bytes
    nonce: bytes


COMMON_WEAK_PASSWORDS = {
    "passwordpassword",
    "password12345678",
    "qwertyuiopasdfgh",
}


def _native_oqs_library_available() -> bool:
    if ctypes.util.find_library("oqs"):
        return True

    install_path = os.environ.get("OQS_INSTALL_PATH")
    if not install_path:
        return False

    install_root = Path(install_path)
    library_names = ("liboqs.dylib", "liboqs.so", "oqs.dll", "liboqs.dll")
    for library_dir in ("lib", "lib64", "bin"):
        if any((install_root / library_dir / name).exists() for name in library_names):
            return True
    return False


def _load_oqs_module() -> Any:
    global oqs, _oqs_load_error

    if oqs is None:
        if not _native_oqs_library_available():
            _oqs_load_error = (
                "Native liboqs shared library not found. Install liboqs and set "
                "OQS_INSTALL_PATH if it is not installed in a standard library path."
            )
            raise CryptoDependencyError(_oqs_load_error)
        try:
            oqs = importlib.import_module("oqs")
            _oqs_load_error = None
        except ImportError as exc:
            _oqs_load_error = (
                "The liboqs-python package is required for post-quantum operations. "
                "Install project dependencies before running this operation."
            )
            raise CryptoDependencyError(_oqs_load_error) from exc
        except (RuntimeError, SystemExit) as exc:
            _oqs_load_error = f"Could not initialize liboqs-python: {exc}"
            raise CryptoDependencyError(_oqs_load_error) from exc
        except Exception as exc:
            _oqs_load_error = f"Unexpected error initializing liboqs-python: {exc}"
            raise CryptoDependencyError(_oqs_load_error) from exc
    return oqs


def _require_oqs() -> Any:
    if oqs is None:
        _load_oqs_module()
    if oqs is None:
        raise CryptoDependencyError(_oqs_load_error or "The post-quantum backend is unavailable.")
    return oqs


def _enabled_kem_mechanisms() -> Tuple[str, ...]:
    oqs_module = _require_oqs()
    getter = getattr(oqs_module, "get_enabled_kem_mechanisms", None)
    if getter is None:
        getter = getattr(oqs_module, "get_enabled_KEM_mechanisms", None)
    if getter is None:
        raise CryptoDependencyError("The installed oqs module does not expose enabled KEM mechanisms.")
    return tuple(getter())


def _kem_aliases(kem_alg: str) -> Tuple[str, ...]:
    if kem_alg == "ML-KEM-768":
        return ("ML-KEM-768", "Kyber768")
    if kem_alg == "Kyber768":
        return ("Kyber768", "ML-KEM-768")
    return (kem_alg,)


def is_allowed_kem_algorithm(kem_alg: Optional[str]) -> bool:
    """Return whether a KEM identifier is supported by this application."""
    return bool(kem_alg) and kem_alg in cfg.ALLOWED_KEM_ALGS


def canonical_kem_algorithm(kem_alg: str) -> str:
    """Normalize KEM aliases that are equivalent for this application."""
    if kem_alg in {"ML-KEM-768", "Kyber768"}:
        return "ML-KEM-768"
    return kem_alg


def resolve_kem_algorithm(kem_alg: Optional[str] = None) -> str:
    """Resolve a configured KEM name to one enabled by the installed OQS backend."""
    requested = kem_alg or cfg.KEM_ALG
    if not is_allowed_kem_algorithm(requested):
        raise UnsupportedAlgorithmError(f"Unsupported KEM algorithm: {requested!r}")

    enabled = set(_enabled_kem_mechanisms())
    for candidate in _kem_aliases(requested):
        if candidate in enabled:
            return candidate

    raise CryptoDependencyError(
        f"No supported KEM implementation is enabled. Requested {requested!r}; "
        f"allowed algorithms are {', '.join(cfg.ALLOWED_KEM_ALGS)}."
    )


def is_kem_available(kem_alg: Optional[str] = None) -> bool:
    """Best-effort availability check used by tests and UI diagnostics."""
    try:
        resolve_kem_algorithm(kem_alg)
        return True
    except Exception:
        return False


def _b64decode_strict(value: str, label: str) -> Optional[bytes]:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        logger.error("Invalid base64 in %s: %s", label, exc)
        return None


def _decapsulate_shared_secret(
    oqs_module: Any,
    kem_alg: str,
    secret_key_bytes: bytes,
    ciphertext_kem: bytes,
) -> bytes:
    """Decapsulate with liboqs-python versions that differ in secret-key handling."""
    try:
        with oqs_module.KeyEncapsulation(kem_alg, secret_key=secret_key_bytes) as kem:
            return kem.decap_secret(ciphertext_kem)
    except TypeError as current_api_error:
        try:
            with oqs_module.KeyEncapsulation(kem_alg) as kem:
                return kem.decap_secret(secret_key_bytes, ciphertext_kem)
        except TypeError:
            raise current_api_error


# --- KEM Key Generation ---


def generate_oqs_keys(
    kem_alg: str = cfg.KEM_ALG,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Generates raw PQC public/private key pair bytes using OQS."""
    logger.info(f"Attempting to generate raw keys for KEM: {kem_alg}")
    try:
        resolved_kem_alg = resolve_kem_algorithm(kem_alg)
        oqs_module = _require_oqs()
        with oqs_module.KeyEncapsulation(resolved_kem_alg) as kem:
            if kem.details["length_public_key"] <= 0 or kem.details["length_secret_key"] <= 0:
                logger.error(f"Invalid key length details for {resolved_kem_alg}. Cannot generate keys.")
                return None, None

            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

            # Basic validation
            if (
                not public_key
                or not secret_key
                or len(public_key) != kem.details["length_public_key"]
                or len(secret_key) != kem.details["length_secret_key"]
            ):
                logger.error(f"Key generation for {resolved_kem_alg} produced unexpected key sizes or empty keys.")
                return None, None

            logger.info(f"Successfully generated raw keys for {resolved_kem_alg}.")
            return public_key, secret_key
    except AttributeError as e:
        logger.error(f"Installed oqs module is missing expected API: {e}")
        return None, None
    except CryptoDependencyError as e:
        logger.error(str(e))
        return None, None
    except ValueError as e:
        logger.error(str(e))
        return None, None
    except Exception as e:
        if oqs is not None and isinstance(e, getattr(oqs, "MechanismNotEnabledError", ())):
            logger.error(f"KEM algorithm '{kem_alg}' is not enabled in this build of liboqs.")
            return None, None
        logger.exception(f"Unexpected error generating OQS keys for {kem_alg}: {e}")
        return None, None


# --- Key Derivation Functions ---


def derive_symmetric_key_hkdf(shared_secret: bytes) -> bytes:
    """Derives AES key from KEM shared secret using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=cfg.AES_KEY_BYTES,
        salt=cfg.HKDF_SALT,
        info=cfg.HKDF_INFO_AES,
        backend=default_backend(),
    )
    derived_key = hkdf.derive(shared_secret)
    # Drop this local reference only; immutable bytes are not securely zeroized in Python.
    del shared_secret
    return derived_key


def validate_private_key_password(password: Optional[str]) -> str:
    """Return a private-key password after enforcing the project security policy."""
    if not password:
        raise PasswordRequiredError("Private-key password is required.")
    if len(password) < cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS:
        raise WeakPasswordError(
            f"Private-key password must be at least {cfg.PRIVATE_KEY_MIN_PASSWORD_CHARS} characters."
        )
    if len(set(password)) < cfg.PRIVATE_KEY_MIN_UNIQUE_CHARS:
        raise WeakPasswordError("Private-key password has too little character variety.")
    normalized = "".join(password.lower().split())
    if normalized in COMMON_WEAK_PASSWORDS:
        raise WeakPasswordError("Private-key password is too common.")
    return password


def _current_private_key_kdf_metadata() -> Dict[str, int | str]:
    return {
        "name": cfg.PRIVATE_KEY_KDF_ALG,
        "n": cfg.SCRYPT_N,
        "r": cfg.SCRYPT_R,
        "p": cfg.SCRYPT_P,
    }


def _current_private_key_kdf_line() -> str:
    return f"{cfg.PEM_KDF_HEADER}{cfg.PRIVATE_KEY_KDF_ALG}," f"n={cfg.SCRYPT_N},r={cfg.SCRYPT_R},p={cfg.SCRYPT_P}"


def _private_key_metadata_aad(metadata: PrivateKeyPemMetadata) -> bytes:
    return b"\n".join(
        [
            b"PQC-PRIVATE-KEY-METADATA-AAD",
            f"format={metadata.format_version}".encode("ascii"),
            f"algorithm={metadata.kem_alg}".encode("utf-8"),
            f"kdf={metadata.kdf_name}".encode("ascii"),
            f"kdf_n={metadata.kdf_n}".encode("ascii"),
            f"kdf_r={metadata.kdf_r}".encode("ascii"),
            f"kdf_p={metadata.kdf_p}".encode("ascii"),
            b"salt=" + base64.b64encode(metadata.salt),
            b"nonce=" + base64.b64encode(metadata.nonce),
        ]
    )


def _parse_private_key_format_line(line: str) -> int:
    if not line.startswith(cfg.PEM_PRIVATE_KEY_FORMAT_HEADER):
        raise InvalidKeyFormatError("Encrypted private-key PEM is missing format metadata.")
    value = line[len(cfg.PEM_PRIVATE_KEY_FORMAT_HEADER) :].strip()
    try:
        format_version = int(value)
    except ValueError as exc:
        raise InvalidKeyFormatError("Encrypted private-key PEM has malformed format metadata.") from exc
    if format_version != cfg.PEM_PRIVATE_KEY_FORMAT_VERSION:
        raise InvalidKeyFormatError("Encrypted private-key PEM uses an unsupported format version.")
    return format_version


def _parse_private_key_kdf_line(line: str) -> Dict[str, int | str]:
    if not line.startswith(cfg.PEM_KDF_HEADER):
        raise UnsupportedKDFError("Encrypted private-key PEM is missing KDF metadata.")

    parts = line[len(cfg.PEM_KDF_HEADER) :].split(",")
    if not parts or parts[0] != cfg.PRIVATE_KEY_KDF_ALG:
        raise UnsupportedKDFError("Private-key PEM uses an unsupported KDF.")

    parsed: Dict[str, int | str] = {"name": parts[0]}
    for part in parts[1:]:
        if "=" not in part:
            raise UnsupportedKDFError("Private-key PEM has malformed KDF metadata.")
        name, value = part.split("=", 1)
        if name not in {"n", "r", "p"}:
            raise UnsupportedKDFError("Private-key PEM has unsupported KDF parameters.")
        try:
            parsed[name] = int(value)
        except ValueError as exc:
            raise UnsupportedKDFError("Private-key PEM has non-numeric KDF parameters.") from exc

    expected = _current_private_key_kdf_metadata()
    if parsed != expected:
        raise UnsupportedKDFError("Private-key PEM KDF parameters do not match the required policy.")
    return parsed


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a private-key encryption key from a password using scrypt."""
    validate_private_key_password(password)
    kdf = Scrypt(
        salt=salt,
        length=cfg.AES_KEY_BYTES,  # Derive key suitable for AES-256
        n=cfg.SCRYPT_N,
        r=cfg.SCRYPT_R,
        p=cfg.SCRYPT_P,
        backend=default_backend(),
    )
    password_bytes = password.encode("utf-8")
    try:
        return kdf.derive(password_bytes)
    finally:
        # Drop this local reference only; immutable bytes are not securely zeroized in Python.
        del password_bytes


# --- Private Key Encryption/Decryption ---


def encrypt_private_key(
    raw_private_key: bytes,
    password: str,
    kem_alg: str,
) -> Tuple[Optional[PrivateKeyPemMetadata], Optional[bytes]]:
    """Encrypt raw private key bytes with metadata authenticated as AES-GCM AAD."""
    try:
        validate_private_key_password(password)
    except (PasswordRequiredError, WeakPasswordError) as exc:
        logger.error(str(exc))
        return None, None

    salt = os.urandom(cfg.SCRYPT_SALT_BYTES)
    try:
        derived_key = derive_key_from_password(password, salt)
        nonce = os.urandom(cfg.AES_NONCE_BYTES)
        metadata = PrivateKeyPemMetadata(
            format_version=cfg.PEM_PRIVATE_KEY_FORMAT_VERSION,
            kem_alg=kem_alg,
            kdf_name=cfg.PRIVATE_KEY_KDF_ALG,
            kdf_n=cfg.SCRYPT_N,
            kdf_r=cfg.SCRYPT_R,
            kdf_p=cfg.SCRYPT_P,
            salt=salt,
            nonce=nonce,
        )
        aesgcm = AESGCM(derived_key)
        encrypted_key = aesgcm.encrypt(nonce, raw_private_key, _private_key_metadata_aad(metadata))
        logger.info("Private key encrypted successfully.")
        return metadata, encrypted_key
    except Exception as e:
        logger.exception(f"Failed to encrypt private key: {e}")
        return None, None
    finally:
        # Clean up derived key
        if "derived_key" in locals():
            del derived_key


def decrypt_private_key(encrypted_key_data: Dict[str, Any], password: str) -> Optional[bytes]:
    """Decrypts private key bytes using AES-GCM with a key derived from password."""
    if not password:
        logger.error("Password required for decrypting the private key, but none provided.")
        return None

    salt = encrypted_key_data.get("salt")
    nonce = encrypted_key_data.get("nonce")
    encrypted_key = encrypted_key_data.get("encrypted_key")

    if not salt or not nonce or not encrypted_key:
        logger.error("Missing salt, nonce, or encrypted data for private key decryption.")
        return None

    try:
        validate_private_key_password(password)
    except (PasswordRequiredError, WeakPasswordError) as exc:
        logger.error(str(exc))
        return None

    kdf_name = encrypted_key_data.get("kdf")
    kdf_n = encrypted_key_data.get("kdf_n")
    kdf_r = encrypted_key_data.get("kdf_r")
    kdf_p = encrypted_key_data.get("kdf_p")
    if kdf_name != cfg.PRIVATE_KEY_KDF_ALG or kdf_n != cfg.SCRYPT_N or kdf_r != cfg.SCRYPT_R or kdf_p != cfg.SCRYPT_P:
        logger.error("Encrypted private key uses unsupported KDF metadata.")
        return None

    format_version = encrypted_key_data.get("format_version")
    kem_alg = encrypted_key_data.get("kem_alg")
    use_legacy_aad = False
    metadata_format_version: Optional[int] = None
    metadata_kem_alg: Optional[str] = None
    if format_version is None:
        if cfg.ALLOW_LEGACY_PRIVATE_KEY_PEM:
            use_legacy_aad = True
        else:
            logger.error("Encrypted private key is missing authenticated format metadata.")
            return None
    elif format_version != cfg.PEM_PRIVATE_KEY_FORMAT_VERSION:
        logger.error("Encrypted private key uses unsupported format metadata.")
        return None
    else:
        metadata_format_version = format_version
    if not use_legacy_aad:
        if not isinstance(kem_alg, str) or not is_allowed_kem_algorithm(kem_alg):
            logger.error("Encrypted private key is missing or uses unsupported algorithm metadata.")
            return None
        metadata_kem_alg = kem_alg

    derived_key = None  # Ensure cleanup
    try:
        derived_key = derive_key_from_password(password, salt)
        aesgcm = AESGCM(derived_key)
        aad = None
        if not use_legacy_aad:
            if metadata_format_version is None or metadata_kem_alg is None:
                logger.error("Encrypted private key is missing authenticated format metadata.")
                return None
            metadata = PrivateKeyPemMetadata(
                format_version=metadata_format_version,
                kem_alg=metadata_kem_alg,
                kdf_name=kdf_name,
                kdf_n=kdf_n,
                kdf_r=kdf_r,
                kdf_p=kdf_p,
                salt=salt,
                nonce=nonce,
            )
            aad = _private_key_metadata_aad(metadata)
        raw_private_key = aesgcm.decrypt(nonce, encrypted_key, aad)
        logger.info("Private key decrypted successfully.")
        return raw_private_key
    except (InvalidTag, InvalidKey):
        logger.warning("Private key decryption failed: Invalid password or corrupted data (tag mismatch).")
        return None  # Indicate wrong password or corruption
    except Exception as e:
        logger.exception(f"Failed to decrypt private key: {e}")
        return None
    finally:
        if derived_key:
            del derived_key


# --- PEM Key Handling ---


def save_key_pem(key_bytes: bytes, kem_alg: str, key_type: str, password: Optional[str] = None) -> Optional[str]:
    """
    Saves key data (raw bytes) in PEM format. Encrypts private key if password is provided.

    Returns:
        PEM formatted string, or None on error.
    """
    if key_type not in ["public", "private"]:
        logger.error(f"Invalid key_type specified for saving: {key_type}")
        return None
    if not is_allowed_kem_algorithm(kem_alg):
        logger.error("Unsupported KEM algorithm specified for PEM saving.")
        return None

    pem_data_lines = []
    dek_info = ""
    encoded_key_b64 = ""

    if key_type == "public":
        if password:
            logger.warning(
                "Password provided for saving a public key, but public keys are not encrypted. Ignoring password."
            )
        pem_data_lines.append(cfg.PEM_PUBLIC_HEADER)
        pem_data_lines.append(f"{cfg.PEM_ALGORITHM_HEADER}{kem_alg}")
        encoded_key_b64 = base64.b64encode(key_bytes).decode("ascii")

    elif key_type == "private":
        pem_data_lines.append(cfg.PEM_PRIVATE_HEADER)
        if not password:
            logger.error("Private keys must be password protected.")
            return None

        metadata, encrypted_key = encrypt_private_key(key_bytes, password, kem_alg)
        if metadata and encrypted_key:
            salt_b64 = base64.b64encode(metadata.salt).decode("ascii")
            nonce_b64 = base64.b64encode(metadata.nonce).decode("ascii")
            encoded_key_b64 = base64.b64encode(encrypted_key).decode("ascii")
            dek_info = f"{cfg.PEM_DEK_INFO_HEADER}{salt_b64},{nonce_b64}"
            pem_data_lines.append(f"{cfg.PEM_PRIVATE_KEY_FORMAT_HEADER}{metadata.format_version}")
            pem_data_lines.append(cfg.PEM_PROC_TYPE_HEADER)
            pem_data_lines.append(dek_info)
            pem_data_lines.append(_current_private_key_kdf_line())
            pem_data_lines.append(f"{cfg.PEM_ALGORITHM_HEADER}{metadata.kem_alg}")  # Authenticated as PEM AAD
            logger.info("Saving encrypted private key to PEM.")
        else:
            logger.error("Failed to encrypt private key for PEM saving.")
            return None  # Encryption failed

    # Add base64 key data, formatted to 64 chars per line
    pem_data_lines.extend([encoded_key_b64[i : i + 64] for i in range(0, len(encoded_key_b64), 64)])

    # Add footer
    pem_data_lines.append(cfg.PEM_PUBLIC_FOOTER if key_type == "public" else cfg.PEM_PRIVATE_FOOTER)

    # Drop local references to private-key material. Python cannot guarantee secure zeroization.
    if key_type == "private":
        del key_bytes
        if "encrypted_key" in locals():
            del encrypted_key

    return "\n".join(pem_data_lines) + "\n"


def load_key_pem(
    pem_content: str, password: Optional[str] = None
) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    Loads key data from PEM string. Decrypts private key if necessary and password is provided.

    Returns:
        Tuple (raw_key_bytes, kem_algorithm, key_type), or (None, None, None) on error.
        key_type is 'public' or 'private'.
    """
    pem_content = pem_content.strip()
    lines = pem_content.splitlines()
    if not lines:
        logger.error("PEM content is empty.")
        return None, None, None

    header = lines[0]
    footer = lines[-1]
    key_type = None
    is_encrypted = False
    kem_alg = None
    private_key_format_version: Optional[int] = None
    dek_parts: Dict[str, Any] = {}
    kdf_parts: Dict[str, int | str] = {}
    key_b64_lines = []

    # Determine key type and check basic structure
    if header == cfg.PEM_PUBLIC_HEADER and footer == cfg.PEM_PUBLIC_FOOTER:
        key_type = "public"
        if password:
            logger.warning("Password provided when loading a public key. Ignoring password.")
    elif header == cfg.PEM_PRIVATE_HEADER and footer == cfg.PEM_PRIVATE_FOOTER:
        key_type = "private"
    else:
        logger.error("Invalid PEM format: Missing or mismatched headers/footers.")
        return None, None, None

    # Parse lines between header and footer
    for line in lines[1:-1]:
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        if line.startswith(cfg.PEM_ALGORITHM_HEADER):
            kem_alg = line[len(cfg.PEM_ALGORITHM_HEADER) :].strip()
        elif line.startswith(cfg.PEM_PRIVATE_KEY_FORMAT_HEADER):
            if key_type == "private":
                try:
                    private_key_format_version = _parse_private_key_format_line(line)
                except InvalidKeyFormatError as exc:
                    logger.error(str(exc))
                    return None, None, None
            else:
                logger.warning("Found private-key format header in a public key PEM. Ignoring.")
        elif line == cfg.PEM_PROC_TYPE_HEADER:
            if key_type == "private":
                is_encrypted = True
            else:
                logger.warning("Found encryption header in a public key PEM. Ignoring.")
        elif line.startswith(cfg.PEM_DEK_INFO_HEADER):
            if key_type == "private" and is_encrypted:
                try:
                    dek_info_content = line[len(cfg.PEM_DEK_INFO_HEADER) :]
                    salt_b64, nonce_b64 = dek_info_content.split(",", 1)
                    salt = _b64decode_strict(salt_b64, "private-key salt")
                    nonce = _b64decode_strict(nonce_b64, "private-key nonce")
                    if salt is None or nonce is None:
                        return None, None, None
                    if len(salt) != cfg.SCRYPT_SALT_BYTES or len(nonce) != cfg.AES_NONCE_BYTES:
                        logger.error("Encrypted private key PEM has invalid salt or nonce length.")
                        return None, None, None
                    dek_parts["salt"] = salt
                    dek_parts["nonce"] = nonce
                except ValueError as e:
                    logger.error(f"Invalid DEK-Info line format: {e}")
                    return None, None, None
            else:
                logger.warning("Found DEK-Info header unexpectedly. Ignoring.")
        elif line.startswith(cfg.PEM_KDF_HEADER):
            if key_type == "private" and is_encrypted:
                try:
                    kdf_parts = _parse_private_key_kdf_line(line)
                except UnsupportedKDFError as exc:
                    logger.error(str(exc))
                    return None, None, None
            else:
                logger.warning("Found KDF header unexpectedly. Ignoring.")
        else:
            # Assume it's base64 key data
            key_b64_lines.append(line)

    if not kem_alg:
        logger.error("Algorithm not specified in PEM file.")
        return None, None, None
    if not is_allowed_kem_algorithm(kem_alg):
        logger.error("Unsupported KEM algorithm in PEM file.")
        return None, None, None
    if not key_b64_lines:
        logger.error("No key data found in PEM file.")
        return None, None, None

    # Decode base64 data
    key_b64 = "".join(key_b64_lines)
    raw_or_encrypted_bytes = _b64decode_strict(key_b64, "PEM key data")
    if raw_or_encrypted_bytes is None:
        return None, None, None
    if len(raw_or_encrypted_bytes) > cfg.MAX_RAW_KEY_BYTES:
        logger.error("PEM key payload exceeds maximum raw key size.")
        return None, None, None

    # Handle decryption if necessary
    if key_type == "private" and is_encrypted:
        if not password:
            logger.error("Private key is encrypted, but no password provided.")
            return None, None, None  # Indicate password needed
        if "salt" not in dek_parts or "nonce" not in dek_parts:
            logger.error("Encrypted private key PEM is missing DEK-Info details (salt/nonce).")
            return None, None, None
        if not kdf_parts:
            logger.error("Encrypted private key PEM is missing required KDF metadata.")
            return None, None, None
        if private_key_format_version is None and not cfg.ALLOW_LEGACY_PRIVATE_KEY_PEM:
            logger.error("Encrypted private key PEM is missing authenticated format metadata.")
            return None, None, None

        dek_parts["encrypted_key"] = raw_or_encrypted_bytes
        dek_parts["format_version"] = private_key_format_version
        dek_parts["kem_alg"] = kem_alg
        dek_parts["kdf"] = kdf_parts.get("name")
        dek_parts["kdf_n"] = kdf_parts.get("n")
        dek_parts["kdf_r"] = kdf_parts.get("r")
        dek_parts["kdf_p"] = kdf_parts.get("p")
        raw_key_bytes = decrypt_private_key(dek_parts, password)

        if raw_key_bytes is None:
            logger.error("Private key decryption failed (likely wrong password or corruption).")
            # Return None to signal failure, keep kem_alg and key_type known if needed?
            # Let's return all None for consistency on failure.
            return None, None, None
        else:
            logger.info(f"Successfully loaded and decrypted private key for algorithm {kem_alg}.")
            # Drop local references to intermediate encrypted key material.
            del raw_or_encrypted_bytes
            del dek_parts
            return raw_key_bytes, kem_alg, key_type

    elif key_type == "private":  # Unencrypted private key
        logger.error("Unencrypted private keys are rejected by the current security policy.")
        return None, None, None
    else:  # Public key
        logger.info(f"Successfully loaded public key for algorithm {kem_alg}.")
        return raw_or_encrypted_bytes, kem_alg, key_type


def get_key_info_pem(pem_content: str) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Quickly inspects PEM content to get Algorithm, Key Type, and Encryption Status.
    Does not validate the key bytes themselves.

    Returns:
        Tuple (kem_algorithm, key_type, is_encrypted), or (None, None, False) on error.
    """
    pem_content = pem_content.strip()
    lines = pem_content.splitlines()
    if not lines:
        return None, None, False

    header = lines[0]
    footer = lines[-1]
    key_type = None
    is_encrypted = False
    kem_alg = None

    if header == cfg.PEM_PUBLIC_HEADER and footer == cfg.PEM_PUBLIC_FOOTER:
        key_type = "Public"
    elif header == cfg.PEM_PRIVATE_HEADER and footer == cfg.PEM_PRIVATE_FOOTER:
        key_type = "Private"
    else:
        return None, None, False  # Invalid format

    for line in lines[1:-1]:
        line = line.strip()
        if line.startswith(cfg.PEM_ALGORITHM_HEADER):
            kem_alg = line[len(cfg.PEM_ALGORITHM_HEADER) :].strip()
        elif line == cfg.PEM_PROC_TYPE_HEADER and key_type == "Private":
            is_encrypted = True
        # No need to parse DEK-Info or key data for this function

    if not kem_alg:
        return None, key_type, is_encrypted  # Algo missing
    if not is_allowed_kem_algorithm(kem_alg):
        return None, key_type, is_encrypted

    return kem_alg, key_type, is_encrypted


def inspect_key_pem_strict(pem_content: str) -> Dict[str, Any]:
    """Inspect key PEM metadata and enforce private-key security policy."""
    kem_alg, key_type, is_encrypted = get_key_info_pem(pem_content)
    if not kem_alg or not key_type:
        raise InvalidKeyFormatError("Key file is not a supported PQC PEM key.")

    result: Dict[str, Any] = {
        "kem": kem_alg,
        "key_type": key_type.lower(),
    }
    if key_type == "Private":
        if not is_encrypted:
            raise UnencryptedPrivateKeyError("Unencrypted private keys are rejected.")
        format_line = None
        kdf_line = None
        for line in pem_content.strip().splitlines()[1:-1]:
            stripped = line.strip()
            if stripped.startswith(cfg.PEM_PRIVATE_KEY_FORMAT_HEADER):
                format_line = stripped
            if stripped.startswith(cfg.PEM_KDF_HEADER):
                kdf_line = stripped
        if format_line is None and not cfg.ALLOW_LEGACY_PRIVATE_KEY_PEM:
            raise InvalidKeyFormatError("Encrypted private-key PEM is missing format metadata.")
        if format_line is not None:
            result["private_key_format_version"] = _parse_private_key_format_line(format_line)
        if kdf_line is None:
            raise UnsupportedKDFError("Encrypted private-key PEM is missing KDF metadata.")
        kdf_parts = _parse_private_key_kdf_line(kdf_line)
        result["private_key_encrypted"] = True
        result["private_key_kdf"] = kdf_parts["name"]
    return result


def _parse_encrypted_file_parts(encrypted_blob: bytes) -> EncryptedFileParts:
    if not encrypted_blob:
        raise FileFormatError("Encrypted input is empty.")
    if len(encrypted_blob) > cfg.MAX_ENCRYPTED_FILE_BYTES:
        raise SizeLimitError("Encrypted input exceeds maximum supported size.")

    input_buffer = io.BytesIO(encrypted_blob)
    try:
        header_fixed_size = struct.calcsize(cfg.HEADER_BASE_FORMAT)
        header_fixed_part = input_buffer.read(header_fixed_size)
        if len(header_fixed_part) < header_fixed_size:
            raise FileFormatError("File too short - truncated fixed header.")

        magic, version = struct.unpack(cfg.HEADER_BASE_FORMAT, header_fixed_part)
        if magic != cfg.MAGIC_BYTES:
            raise FileFormatError("Invalid magic bytes.")
        if version != cfg.FORMAT_VERSION:
            raise FileFormatError("Unsupported encrypted-file format version.")

        kem_alg_len_bytes = input_buffer.read(struct.calcsize(">H"))
        if len(kem_alg_len_bytes) < struct.calcsize(">H"):
            raise FileFormatError("Truncated header (KEM algo len).")
        kem_alg_len = struct.unpack(">H", kem_alg_len_bytes)[0]
        if kem_alg_len == 0 or kem_alg_len > cfg.MAX_KEM_ALG_NAME_BYTES:
            raise FileFormatError("Implausible KEM algorithm length in header.")

        kem_alg_bytes = input_buffer.read(kem_alg_len)
        if len(kem_alg_bytes) < kem_alg_len:
            raise FileFormatError("Truncated header (KEM algo name).")
        try:
            kem_alg_from_file = kem_alg_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileFormatError("KEM algorithm name is not valid UTF-8.") from exc
        if not is_allowed_kem_algorithm(kem_alg_from_file):
            raise UnsupportedAlgorithmError("Unsupported KEM algorithm in encrypted file.")

        kem_ct_len_bytes = input_buffer.read(struct.calcsize(">I"))
        if len(kem_ct_len_bytes) < struct.calcsize(">I"):
            raise FileFormatError("Truncated header (KEM CT len).")
        kem_ct_len = struct.unpack(">I", kem_ct_len_bytes)[0]
        if kem_ct_len == 0 or kem_ct_len > cfg.MAX_KEM_CIPHERTEXT_BYTES:
            raise FileFormatError("Implausible KEM ciphertext length.")

        ciphertext_kem = input_buffer.read(kem_ct_len)
        if len(ciphertext_kem) < kem_ct_len:
            raise FileFormatError("Truncated header (KEM CT).")

        nonce = input_buffer.read(cfg.AES_NONCE_BYTES)
        if len(nonce) < cfg.AES_NONCE_BYTES:
            raise FileFormatError("Truncated header (Nonce).")

        header_aad = encrypted_blob[: input_buffer.tell()]
        encrypted_data_aes = input_buffer.read()
        if len(encrypted_data_aes) < cfg.AES_TAG_BYTES:
            raise FileFormatError("AES-GCM payload is shorter than the authentication tag.")
        if len(encrypted_data_aes) > cfg.MAX_FILE_BYTES + cfg.AES_TAG_BYTES:
            raise SizeLimitError("AES-GCM payload exceeds maximum supported size.")

        metadata = EncryptedFileMetadata(
            version=version,
            kem_alg=kem_alg_from_file,
            header_bytes=len(header_aad),
            kem_ciphertext_bytes=len(ciphertext_kem),
            encrypted_payload_bytes=len(encrypted_data_aes),
            total_bytes=len(encrypted_blob),
        )
        return EncryptedFileParts(
            metadata=metadata,
            header_aad=header_aad,
            ciphertext_kem=ciphertext_kem,
            nonce=nonce,
            encrypted_data_aes=encrypted_data_aes,
        )
    finally:
        input_buffer.close()


def inspect_encrypted_file_strict(encrypted_blob: bytes) -> EncryptedFileMetadata:
    """Parse non-secret encrypted-container metadata without using the native backend."""
    return _parse_encrypted_file_parts(encrypted_blob).metadata


def inspect_encrypted_file(encrypted_blob: bytes) -> Optional[Dict[str, Any]]:
    """Compatibility wrapper for encrypted-container inspection."""
    try:
        metadata = inspect_encrypted_file_strict(encrypted_blob)
        return {
            "version": metadata.version,
            "kem": metadata.kem_alg,
            "header_bytes": metadata.header_bytes,
            "kem_ciphertext_bytes": metadata.kem_ciphertext_bytes,
            "encrypted_payload_bytes": metadata.encrypted_payload_bytes,
            "total_bytes": metadata.total_bytes,
        }
    except (FileFormatError, UnsupportedAlgorithmError, SizeLimitError) as exc:
        logger.error(str(exc))
        return None


# --- File Encryption / Decryption ---


def encrypt_file_pro(input_data: bytes, public_key_bytes: bytes, kem_alg: str = cfg.KEM_ALG) -> Optional[bytes]:
    """Encrypts input data using PQC KEM + AES-GCM with defined file format."""
    logger.info(f"Starting encryption with KEM: {kem_alg}")
    if len(input_data) > cfg.MAX_FILE_BYTES:
        logger.error("Input data exceeds maximum supported size.")
        return None
    if not input_data:
        logger.warning("Input data for encryption is empty.")
        # Empty files are valid; the encrypted output still carries header metadata and an auth tag.

    shared_secret_sender = None
    aes_key = None
    output_buffer = io.BytesIO()

    try:
        resolved_kem_alg = resolve_kem_algorithm(kem_alg)
        oqs_module = _require_oqs()
        with oqs_module.KeyEncapsulation(resolved_kem_alg) as kem:
            expected_public_key_len = kem.details.get("length_public_key")
            if expected_public_key_len and len(public_key_bytes) != expected_public_key_len:
                logger.error("Recipient public key length does not match the selected KEM algorithm.")
                return None

            # 1. KEM Encapsulation
            ciphertext_kem, shared_secret_sender = kem.encap_secret(public_key_bytes)
            expected_ciphertext_len = kem.details.get("length_ciphertext")
            if expected_ciphertext_len and len(ciphertext_kem) != expected_ciphertext_len:
                logger.error("KEM encapsulation produced an unexpected ciphertext length.")
                return None

            # 2. Derive AES Key securely
            aes_key = derive_symmetric_key_hkdf(shared_secret_sender)
            # Drop the local shared-secret reference. Python bytes are not securely zeroized.
            shared_secret_sender = None

            # 3. Generate Nonce
            nonce = os.urandom(cfg.AES_NONCE_BYTES)

            # 4. Construct File Header
            kem_alg_bytes = resolved_kem_alg.encode("utf-8")
            if len(kem_alg_bytes) > cfg.MAX_KEM_ALG_NAME_BYTES:
                logger.error("KEM algorithm name is too long for this file format.")
                return None
            # Pack fixed part
            output_buffer.write(struct.pack(cfg.HEADER_BASE_FORMAT, cfg.MAGIC_BYTES, cfg.FORMAT_VERSION))
            # Pack variable parts: Algo Len, Algo, CT Len, CT, Nonce
            # Use explicit packing formats for clarity
            output_buffer.write(struct.pack(">H", len(kem_alg_bytes)))  # Algo name len (ushort)
            output_buffer.write(kem_alg_bytes)
            output_buffer.write(struct.pack(">I", len(ciphertext_kem)))  # KEM CT len (uint)
            output_buffer.write(ciphertext_kem)
            output_buffer.write(nonce)  # Nonce (fixed size defined in cfg)

            header_aad = output_buffer.getvalue()

            # 5. AES-GCM Encryption. The full header is AAD so metadata tampering fails auth.
            aesgcm = AESGCM(aes_key)
            encrypted_data_aes = aesgcm.encrypt(nonce, input_data, header_aad)

            # 6. Append Encrypted Data
            output_buffer.write(encrypted_data_aes)

            encrypted_blob = output_buffer.getvalue()
            logger.info(f"Encryption successful. Output size: {len(encrypted_blob)} bytes.")
            return encrypted_blob

    except CryptoDependencyError as e:
        logger.error(str(e))
        return None
    except ValueError as e:
        logger.error(str(e))
        return None
    except AttributeError as e:
        logger.error(f"Installed oqs module is missing expected API: {e}")
        return None
    except Exception as e:
        if oqs is not None and isinstance(e, getattr(oqs, "MechanismNotEnabledError", ())):
            logger.error(f"KEM algorithm '{kem_alg}' is not enabled during encryption.")
            return None
        logger.exception(f"Unexpected error during encryption: {e}")
        return None
    finally:
        # Drop local references. Python bytes are not securely zeroized by reassignment/deletion.
        del aes_key
        del shared_secret_sender
        if "ciphertext_kem" in locals():
            del ciphertext_kem
        if "nonce" in locals():
            del nonce
        if "header_aad" in locals():
            del header_aad
        if "encrypted_data_aes" in locals():
            del encrypted_data_aes
        output_buffer.close()


def decrypt_file_pro(
    encrypted_blob: bytes,
    secret_key_bytes: bytes,
    expected_kem_alg: Optional[str] = None,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Decrypts data using PQC KEM + AES-GCM and defined file format."""
    logger.info("Starting decryption process.")
    shared_secret_receiver = None
    aes_key = None
    kem_alg_from_file = None

    try:
        parts = _parse_encrypted_file_parts(encrypted_blob)
        kem_alg_from_file = parts.metadata.kem_alg
        logger.info("Header validated: Magic=%r, Version=%s", cfg.MAGIC_BYTES, parts.metadata.version)
        if expected_kem_alg is not None and canonical_kem_algorithm(expected_kem_alg) != canonical_kem_algorithm(
            kem_alg_from_file
        ):
            logger.error("Private key algorithm does not match encrypted file algorithm.")
            return None, kem_alg_from_file

        # 3. KEM Decapsulation
        logger.debug(f"Performing KEM decapsulation with {kem_alg_from_file}...")
        oqs_module = _require_oqs()
        resolved_kem_alg = resolve_kem_algorithm(kem_alg_from_file)
        with oqs_module.KeyEncapsulation(resolved_kem_alg) as kem:
            # Verify secret key length matches the algorithm expectation?
            if len(secret_key_bytes) != kem.details["length_secret_key"]:
                logger.error("Provided secret key length does not match the encrypted file's KEM algorithm.")
                return None, kem_alg_from_file
            expected_ciphertext_len = kem.details.get("length_ciphertext")
            if expected_ciphertext_len and parts.metadata.kem_ciphertext_bytes != expected_ciphertext_len:
                logger.error("KEM ciphertext length does not match the encrypted file's KEM algorithm.")
                return None, kem_alg_from_file

            shared_secret_receiver = _decapsulate_shared_secret(
                oqs_module,
                resolved_kem_alg,
                secret_key_bytes,
                parts.ciphertext_kem,
            )
            logger.debug("KEM decapsulation successful.")

        # 4. Derive AES Key securely
        aes_key = derive_symmetric_key_hkdf(shared_secret_receiver)
        # Drop the local shared-secret reference. Python bytes are not securely zeroized.
        shared_secret_receiver = None

        # 5. AES-GCM Decryption
        logger.debug("Performing AES-GCM decryption...")
        aesgcm = AESGCM(aes_key)
        try:
            decrypted_data = aesgcm.decrypt(parts.nonce, parts.encrypted_data_aes, parts.header_aad)
            logger.info("AES-GCM decryption and authentication successful.")
            return decrypted_data, kem_alg_from_file
        except InvalidTag:
            logger.error("AES-GCM decryption failed: Authentication tag mismatch.")
            # This is a critical failure - indicates corruption, tampering, or wrong key
            return None, kem_alg_from_file
        except Exception as e_aes:
            logger.exception(f"AES-GCM decryption failed unexpectedly: {e_aes}")
            return None, kem_alg_from_file

    except (FileFormatError, UnsupportedAlgorithmError, SizeLimitError) as e_val:
        logger.error(f"Invalid or truncated file header: {e_val}")
        return None, kem_alg_from_file
    except CryptoDependencyError as e:
        logger.error(str(e))
        return None, kem_alg_from_file
    except Exception as e:
        if oqs is not None and isinstance(e, getattr(oqs, "MechanismNotEnabledError", ())):
            logger.error(f"KEM algorithm '{kem_alg_from_file}' from file is not enabled.")
            return None, kem_alg_from_file
        logger.exception(f"Unexpected error during decryption: {e}")
        return None, kem_alg_from_file
    finally:
        # Drop local references. Python bytes are not securely zeroized by reassignment/deletion.
        del aes_key
        del shared_secret_receiver
        if "parts" in locals():
            del parts
