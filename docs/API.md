# API Documentation

This document provides API notes for the core cryptographic functions in the Quantum Encryptor application.

## crypto_core Module

The `crypto_core` module provides the main cryptographic operations used by the application.

### Key Generation

```python
def generate_oqs_keys(kem_alg: str = cfg.KEM_ALG) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Generates raw PQC public/private key pair bytes using OQS.
    
    Args:
        kem_alg: The KEM algorithm to use, defaults to the one specified in config.
        
    Returns:
        Tuple containing (public_key, secret_key) as raw bytes, or (None, None) on error.
    """
```

The backend is loaded lazily. If native `liboqs` is unavailable, this returns `(None, None)` instead of terminating the process.

### Backend Availability

```python
def resolve_kem_algorithm(kem_alg: Optional[str] = None) -> str:
    """
    Validates the requested KEM and resolves it to an enabled OQS backend mechanism.
    """
```

```python
def is_kem_available(kem_alg: Optional[str] = None) -> bool:
    """
    Returns whether the requested KEM is available in the native OQS backend.
    """
```

### Key Derivation

```python
def derive_symmetric_key_hkdf(shared_secret: bytes) -> bytes:
    """
    Derives AES key from KEM shared secret using HKDF-SHA256.
    
    Args:
        shared_secret: The shared secret established via the KEM protocol.
        
    Returns:
        Derived AES key as bytes.
    """
```

```python
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derives an encryption key from a password using PBKDF2-HMAC-SHA256.
    
    Args:
        password: User-provided password.
        salt: Random salt bytes.
        
    Returns:
        Derived key suitable for AES-256.
        
    Raises:
        ValueError: If password is empty.
    """
```

### Private Key Encryption/Decryption

```python
def encrypt_private_key(raw_private_key: bytes, password: str) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]:
    """
    Encrypts raw private key bytes using AES-GCM with a key derived from password.
    
    Args:
        raw_private_key: The raw private key bytes to encrypt.
        password: The password to derive the encryption key from.
        
    Returns:
        Tuple containing (salt, nonce, encrypted_key), or (None, None, None) on error.
    """
```

```python
def decrypt_private_key(encrypted_key_data: Dict[str, bytes], password: str) -> Optional[bytes]:
    """
    Decrypts private key bytes using AES-GCM with a key derived from password.
    
    Args:
        encrypted_key_data: Dictionary containing 'salt', 'nonce', and 'encrypted_key'.
        password: The password for key derivation.
        
    Returns:
        Decrypted private key bytes, or None on error or wrong password.
    """
```

### PEM Key Handling

```python
def save_key_pem(
    key_bytes: bytes,
    kem_alg: str,
    key_type: str,
    password: Optional[str] = None
) -> Optional[str]:
    """
    Saves key data (raw bytes) in PEM format. Encrypts private key if password is provided.
    
    Args:
        key_bytes: Raw key bytes to save.
        kem_alg: The KEM algorithm identifier.
        key_type: Either "public" or "private".
        password: Optional password for private key encryption.
        
    Returns:
        PEM formatted string, or None on error.
    """
```

```python
def load_key_pem(
    pem_content: str,
    password: Optional[str] = None
) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    Loads key data from PEM string. Decrypts private key if necessary and password is provided.
    
    Args:
        pem_content: The PEM-formatted key data.
        password: Optional password for private key decryption.
        
    Returns:
        Tuple (raw_key_bytes, kem_algorithm, key_type), or (None, None, None) on error.
        key_type is 'public' or 'private'.
    """
```

### File Encryption/Decryption

```python
def encrypt_file_pro(
    input_data: bytes,
    public_key_bytes: bytes,
    kem_alg: str = cfg.KEM_ALG
) -> Optional[bytes]:
    """
    Encrypts file data using KEM+DEM hybrid encryption.
    
    Args:
        input_data: Raw file bytes to encrypt.
        public_key_bytes: Recipient's public key bytes.
        kem_alg: The KEM algorithm to use.
        
    Returns:
        Encrypted file bytes, or None on error.
    """
```

`encrypt_file_pro` rejects inputs larger than `cfg.MAX_FILE_BYTES`. Format version 3 authenticates the full encrypted-file header as AES-GCM associated data.

```python
def decrypt_file_pro(
    encrypted_data: bytes,
    private_key: bytes
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Decrypts file data using KEM+DEM hybrid decryption.
    
    Args:
        encrypted_data: Encrypted file bytes.
        private_key: Private key bytes for decryption.
        
    Returns:
        Tuple (decrypted_data, kem_algorithm), or (None, None) on error.
    """
```

## crypto_config Module

The `crypto_config` module provides configuration constants used by the cryptographic operations.

### Important Constants

- `KEM_ALG`: The post-quantum KEM algorithm used (default: "Kyber768")
- `ALLOWED_KEM_ALGS`: Accepted KEM identifiers (`ML-KEM-768` and legacy `Kyber768`)
- `AES_KEY_BYTES`: Size of AES key in bytes (32 for AES-256)
- `PBKDF2_ITERATIONS`: Number of iterations for password-based key derivation (390,000)
- `FORMAT_VERSION`: File format version for encrypted files
- `MAX_FILE_BYTES`: Maximum in-memory file size accepted by the UI and core encryption path

## Example Usage

### Generate and Save Keys

```python
from crypto_config import cfg
import crypto_core as core

# Generate key pair
kem_alg = core.resolve_kem_algorithm(cfg.KEM_ALG)
public_key, private_key = core.generate_oqs_keys(kem_alg)

# Save keys in PEM format
public_pem = core.save_key_pem(public_key, kem_alg, "public")
private_pem = core.save_key_pem(private_key, kem_alg, "private", password="long-secure-password")

# Write PEM files
with open("public_key.pem", "w") as f:
    f.write(public_pem)
    
with open("private_key.pem", "w") as f:
    f.write(private_pem)
```

### Encrypt and Decrypt a File

```python
from crypto_config import cfg
import crypto_core as core

# Load public key for encryption
with open("public_key.pem", "r") as f:
    pub_pem = f.read()
    
pub_key, kem_alg, key_type = core.load_key_pem(pub_pem)

# Encrypt a file
with open("secret_document.pdf", "rb") as f:
    file_data = f.read()
    
encrypted_data = core.encrypt_file_pro(file_data, pub_key, kem_alg)

with open("encrypted_document.pqc", "wb") as f:
    f.write(encrypted_data)

# Load private key for decryption
with open("private_key.pem", "r") as f:
    priv_pem = f.read()
    
priv_key, _, _ = core.load_key_pem(priv_pem, password="long-secure-password")

# Decrypt the file
with open("encrypted_document.pqc", "rb") as f:
    encrypted_data = f.read()
    
decrypted_data, _ = core.decrypt_file_pro(encrypted_data, priv_key)

with open("decrypted_document.pdf", "wb") as f:
    f.write(decrypted_data)
```
