# crypto_config.py


class CryptoConfig:
    """Configuration constants for the cryptographic operations."""

    # --- KEM Algorithm ---
    # Choose a NIST standard KEM. Ensure it's enabled in your liboqs build.
    # `Kyber768` is retained as a legacy alias for older liboqs builds.
    KEM_ALG = "ML-KEM-768"
    LEGACY_KEM_ALGS = ("Kyber768",)
    ALLOWED_KEM_ALGS = (KEM_ALG, *LEGACY_KEM_ALGS)

    # --- Data Encryption (DEM) ---
    AES_KEY_BYTES = 32  # AES-256
    AES_NONCE_BYTES = 12  # Standard GCM nonce size (96 bits)
    AES_TAG_BYTES = 16  # Standard GCM tag size (128 bits)

    # --- Key Derivation (KDF) ---
    # For deriving AES key from KEM shared secret
    HKDF_SALT = b"pqc-file-enc-hkdf-salt"  # Optional salt for HKDF
    HKDF_INFO_AES = b"pqc-file-enc-aes-key-derivation"  # Context for AES key derivation

    # For deriving keys from passwords for private key encryption
    PRIVATE_KEY_MIN_PASSWORD_CHARS = 16
    PRIVATE_KEY_KDF_ALG = "scrypt"
    SCRYPT_SALT_BYTES = 16
    SCRYPT_N = 32768
    SCRYPT_R = 8
    SCRYPT_P = 1
    # Context info for deriving private key encryption key
    HKDF_INFO_PRIVATE_KEY = b"pqc-private-key-encryption"

    # --- File Format ---
    MAGIC_BYTES = b"PQCENC"
    FORMAT_VERSION = 3  # v3 authenticates encrypted-file header metadata as AAD

    # Header structure (fixed part): Magic(6s), Version(H=ushort)
    HEADER_BASE_FORMAT = ">6s H"
    # Variable parts (lengths determined at runtime):
    # KEM Algo Len(H), KEM Algo(s), KEM CT Len(I=uint), KEM CT(s), Nonce(s)

    # --- PEM Key Format ---
    PEM_PUBLIC_HEADER = "-----BEGIN PQC PUBLIC KEY-----"
    PEM_PUBLIC_FOOTER = "-----END PQC PUBLIC KEY-----"
    PEM_PRIVATE_HEADER = "-----BEGIN PQC PRIVATE KEY-----"
    PEM_PRIVATE_FOOTER = "-----END PQC PRIVATE KEY-----"
    PEM_ALGORITHM_HEADER = "Algorithm: "
    PEM_KDF_HEADER = "KDF: "
    # Headers for encrypted private keys
    PEM_PROC_TYPE_HEADER = "Proc-Type: 4,ENCRYPTED"
    PEM_DEK_INFO_HEADER = "DEK-Info: AES-256-GCM,"  # Followed by salt_b64,nonce_b64

    # --- General ---
    MAX_FILE_BYTES = 100 * 1024 * 1024
    MAX_KEM_ALG_NAME_BYTES = 64
    MAX_KEM_CIPHERTEXT_BYTES = 1024 * 1024
    MAX_ENCRYPTED_FILE_BYTES = (
        MAX_FILE_BYTES
        + len(MAGIC_BYTES)
        + 2  # Format version
        + 2  # KEM algorithm name length
        + MAX_KEM_ALG_NAME_BYTES
        + 4  # KEM ciphertext length
        + MAX_KEM_CIPHERTEXT_BYTES
        + AES_NONCE_BYTES
        + AES_TAG_BYTES
    )


# Instantiate the config for easy import
cfg = CryptoConfig()
