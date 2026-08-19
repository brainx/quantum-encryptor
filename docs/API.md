# API Documentation

This document provides API notes for the core cryptographic functions in the Quantum Encryptor application.

## crypto_core Module

The `crypto_core` module provides the main cryptographic operations used by the application.

## Agent CLI

The `pqc_agent_tools` module exposes local JSON commands for automation agents. It does not start a network service and it does not print raw file bytes, plaintext, passwords, private keys, or absolute local paths.

```bash
mkdir -p keys data

python -m pqc_agent_tools health --json
export PQC_PRIVATE_KEY_PASSWORD='<strong-private-key-password>'
python -m pqc_agent_tools generate-keys --public-out keys/public.pem --private-out keys/private.pem
python -m pqc_agent_tools inspect-key --key keys/public.pem
python -m pqc_agent_tools inspect-key --key keys/private.pem
python -m pqc_agent_tools inspect-key --key keys/private.pem --password-env PQC_PRIVATE_KEY_PASSWORD
python -m pqc_agent_tools encrypt --input data/plain.txt --public-key keys/public.pem --output data/plain.pqc
python -m pqc_agent_tools inspect-file --input data/plain.pqc
python -m pqc_agent_tools verify-file --input data/plain.pqc --private-key keys/private.pem
python -m pqc_agent_tools decrypt --input data/plain.pqc --private-key keys/private.pem --output data/plain.out.txt
```

The installed console script is:

```bash
quantum-encryptor-agent health --json
```

Agent commands must use workspace-relative paths. Absolute paths, `..` traversal, symlink escapes, and existing output files are rejected unless the command includes `--overwrite`. Private-key and decrypted plaintext outputs are written with owner-only permissions on POSIX systems.

Private-key generation, decryption, and verification read passwords from an environment variable. The default variable is `PQC_PRIVATE_KEY_PASSWORD`; override it with `--password-env NAME`. `inspect-key` does not unlock an encrypted private key by default. Supplying `--password-env NAME` explicitly requests an authenticated unlock and adds the corresponding `public_key_fingerprint` only when the password and private-key structure validate.

## Local Web API

The custom web UI is served by `api_app.py` at exactly `http://127.0.0.1:<PORT>` (`http://127.0.0.1:4000` by default). `PORT` determines the sole trusted UI/API authority: `localhost`, IPv6 and other loopback addresses, and sibling ports are not aliases. Setting `QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1` on both the API and Vite processes adds only `http://127.0.0.1:4001` for Vite development and its `/api` proxy; every other value leaves that exception disabled.

`GET /api/health` sets the per-process local API token as an `HttpOnly`, `SameSite=Strict` cookie only when the direct `Host` is an allowed authority and, if an `Origin` header is present, it exactly matches that Host. The token is never disclosed in API response bodies, and forwarding headers are not trusted. For a state-changing `/api/*` request, cookie authentication requires an allowed, exactly parsed `Origin` equal to the direct allowed `Host`. Clients without an `Origin` header must present the token in `X-Quantum-Encryptor-Token` (for programmatic clients configured with `QUANTUM_ENCRYPTOR_API_TOKEN`); if that header is present but invalid, the request is rejected rather than falling back to the cookie. Requests without a valid token are rejected before route handlers parse uploaded files or form data. All responses include a restrictive `Content-Security-Policy` (including `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.

### Health capability contract

`GET /api/health` includes additive, operation-specific readiness information. New clients should use these capabilities to decide whether to enable each workflow:

```
{
  "capabilities": {
    "inspect": { "available": true, "reason": "" },
    "generate": { "available": true, "reason": "" },
    "encrypt": { "available": true, "reason": "" },
    "decrypt": { "available": true, "reason": "" }
  }
}
```

`backendReady` and `backendMessage` remain in the response for compatibility, while new clients use operation-specific capabilities. A capability `reason` is a safe user-facing summary of an unavailable operation; it is not a raw backend exception.

### Response caching and generated-key custody

Every HTTP response under `/api/*` carries `Cache-Control: no-store` and `Pragma: no-cache`, including JSON successes and errors, authorization or body-limit middleware rejections, unmatched API routes, framework-generated 500 responses, and file downloads. The policy is applied centrally so new API handlers inherit it; static UI responses outside `/api/*` keep their own cache behavior. These directives reduce retention by conforming HTTP caches but do not securely erase browser or process memory.

Key generation returns the public and encrypted private PEM directly in one response. The server does not retain a temporary downloadable key pair or provide a recovery endpoint; save both values immediately because explicit clearing removes the app's references and browser lifecycle transitions may lose the tab state. Browser history may also preserve and later restore a suspended document's state.

### Public-key fingerprint contract

Fingerprints are calculated only from canonically validated public-key bytes. The SHA3-256 preimage is the following exact byte sequence, where both lengths are unsigned big-endian integers:

```
b"QuantumEncryptor-PublicKey-Fingerprint-v1\x00"
|| uint16_be(len(algorithm_ascii))
|| algorithm_ascii
|| uint32_be(len(canonical_public_key))
|| canonical_public_key
```

The external representation is `QE1-SHA3-256:<64 lowercase hexadecimal characters>`. The exact ASCII algorithm label is covered, so relabeling the same bytes produces a different fingerprint. `QE1` versions this fingerprint construction independently; it does not change the encrypted-file format, PEM headers, or either existing format-version field.

`POST /api/keys/inspect` returns `keyInfo.public_key_fingerprint` for a validated public PEM and includes the same value under the display label `Public Key Fingerprint`. Metadata-only encrypted private-key inspection omits the field. `POST /api/keys/generate` returns the new pair's fingerprint as `publicKeyFingerprint`. The web UI shows the complete value in Generate, validated public-key inspection, and the compatible-recipient review before encryption.

The agent `generate-keys` and public `inspect-key` results use the JSON field `public_key_fingerprint`. For an encrypted private key, `inspect-key` omits it unless `--password-env NAME` is explicitly supplied; only a successful AES-GCM password authentication followed by canonical private-key validation permits derivation of the corresponding public key and fingerprint. No fingerprint is stored in or trusted from visible encrypted private-key metadata.

Compare the complete fingerprint over an independently authenticated channel separate from key delivery. Equality identifies the same validated algorithm label and canonical public bytes, but it is not a certificate, signature, trust chain, proof of identity, proof of private-key control, or protection against a channel that substitutes both the key and comparison value.

### Agent JSON Contract

Successful command output:

```json
{
  "ok": true,
  "operation": "encrypt",
  "format_version": 4,
  "kem": "ML-KEM-768+X25519-v2",
  "output": "data/plain.pqc"
}
```

Failure output:

```json
{
  "ok": false,
  "operation": "decrypt",
  "error_code": "decryption_failed",
  "message": "Decryption failed. Check private key, password, and ciphertext integrity."
}
```

Exit codes:

- `0`: success
- `1`: unexpected error
- `2`: invalid input
- `3`: backend unavailable
- `4`: cryptographic or authentication failure
- `5`: workspace path boundary violation

### Key Generation

New application keys are composite payloads with fixed-width X25519 material followed by ML-KEM material. The component key pairs are generated independently.

```python
def generate_hybrid_keys(kem_alg: str = cfg.KEM_ALG) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Generate independent X25519 and ML-KEM key pairs and return composite key payloads."""
```

`generate_oqs_keys` remains the low-level ML-KEM component generator used by `generate_hybrid_keys` and legacy compatibility code.

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

The core defines typed exceptions for backend, unsupported-algorithm, key-policy, KDF, size-limit, authentication, and file-format failures. Public UI-facing helpers still return `None` on many failures for UI compatibility, while the UI converts those failures into safe user-facing messages.

```python
class CryptoCoreError(RuntimeError): ...
class CryptoDependencyError(CryptoCoreError): ...
class UnsupportedAlgorithmError(ValueError): ...
class FileFormatError(ValueError): ...
class PasswordRequiredError(CryptoCoreError): ...
class WeakPasswordError(ValueError): ...
class UnencryptedPrivateKeyError(ValueError): ...
class UnsupportedKDFError(ValueError): ...
class AuthenticationFailedError(CryptoCoreError): ...
class SizeLimitError(ValueError): ...
class InvalidKeyFormatError(ValueError): ...
```

```python
def is_kem_available(kem_alg: Optional[str] = None) -> bool:
    """
    Returns whether the requested KEM is available in the native OQS backend.
    """
```

### Key Derivation

```python
def derive_hybrid_symmetric_key(
    mlkem_shared_secret: bytes,
    x25519_shared_secret: bytes,
    x25519_ephemeral_public: bytes,
    x25519_recipient_public: bytes,
    suite: str = cfg.HYBRID_KEM_ALG,
) -> bytes:
    """Combine ML-KEM and X25519 shares using an RFC 9980-inspired binding pattern."""
```

The SHA3-256 input binds both shared secrets, the ephemeral and recipient X25519 public keys, the suite identifier, and the `QuantumEncryptorCompositeKDFv1` domain separator.

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
    Derives a private-key encryption key from a password using scrypt.
    
    Args:
        password: User-provided password.
        salt: Random salt bytes.
        
    Returns:
        Derived key suitable for AES-256.
        
    Raises:
        PasswordRequiredError: If password is empty.
        WeakPasswordError: If password fails the configured length, variety, or known-weak-password policy.
    """
```

### Private Key Encryption/Decryption

New encrypted private-key PEM files use format version 3 metadata. The AES-GCM tag authenticates the private-key format version, hybrid suite, scrypt KDF name and parameters, salt, and nonce as associated data. Authenticated format-v2 ML-KEM private keys remain loadable for legacy v3 decryption. Salt and nonce are serialized as base64 in the PEM text but represented as bytes in `PrivateKeyPemMetadata`.

```python
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
```

```python
def encrypt_private_key(
    raw_private_key: bytes,
    password: str,
    kem_alg: str,
) -> Tuple[Optional[PrivateKeyPemMetadata], Optional[bytes]]:
    """
    Encrypts raw private key bytes using AES-GCM with a key derived from password.
    
    Args:
        raw_private_key: The raw private key bytes to encrypt.
        password: The password to derive the encryption key from.
        kem_alg: The private key KEM algorithm to authenticate in PEM metadata.
        
    Returns:
        Tuple containing (metadata, encrypted_key), or (None, None) on error.
    """
```

```python
def decrypt_private_key(encrypted_key_data: Dict[str, Any], password: str) -> Optional[bytes]:
    """
    Decrypts private key bytes using AES-GCM with a key derived from password.
    
    Args:
        encrypted_key_data: Dictionary containing encrypted key bytes plus format version,
            KEM algorithm, salt, nonce, and required scrypt KDF metadata.
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
    Saves key data (raw bytes) in PEM format. Private keys require password protection
    and include PQC-Key-Format: 3 metadata.
    
    Args:
        key_bytes: Raw key bytes to save.
        kem_alg: The KEM algorithm identifier.
        key_type: Either "public" or "private".
        password: Required password for private key encryption.
        
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
    Loads key data from PEM string. Private-key PEMs must be encrypted with
    PQC-Key-Format: 3 or authenticated legacy version 2 and the required scrypt metadata.
    
    Args:
        pem_content: The PEM-formatted key data.
        password: Required password for private key decryption.
        
    Returns:
        Tuple (raw_key_bytes, kem_algorithm, key_type), or (None, None, None) on error.
        key_type is 'public' or 'private'.
    """
```

```python
def get_public_key_fingerprint(key_bytes: bytes, kem_alg: str) -> str:
    """Validate canonical public-key bytes and return their versioned SHA3-256 fingerprint."""

def get_private_key_public_fingerprint(private_key_bytes: bytes, kem_alg: str) -> str:
    """Derive and fingerprint the public key from already authenticated private-key bytes."""
```

Callers must not pass encrypted PEM payload bytes or unauthenticated private-key metadata to either function. Public-key fingerprinting validates the supplied canonical key material; private-key fingerprinting additionally validates the private structure and its embedded ML-KEM public-key hash before deriving the public key.

### File Encryption/Decryption

```python
def encrypt_file_pro(
    input_data: bytes,
    public_key_bytes: bytes,
    kem_alg: str = cfg.HYBRID_KEM_ALG
) -> Optional[bytes]:
    """
    Encrypts file data using ML-KEM-768 + X25519 and AES-256-GCM.
    
    Args:
        input_data: Raw file bytes to encrypt.
        public_key_bytes: Recipient's public key bytes.
        kem_alg: Must be the configured hybrid suite.
        
    Returns:
        Encrypted file bytes, or None on error.
    """
```

`encrypt_file_pro` rejects plaintext inputs larger than `cfg.MAX_FILE_BYTES`, refuses legacy single-KEM public keys, and emits format version 4. The complete header—including the ML-KEM ciphertext and ephemeral X25519 public key—is AES-GCM associated data.

```python
def decrypt_file_pro(
    encrypted_data: bytes,
    private_key: bytes,
    expected_kem_alg: Optional[str] = None,
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Decrypts hybrid v4 files and authenticated legacy v3 files.
    
    Args:
        encrypted_data: Encrypted file bytes.
        private_key: Private key bytes for decryption.
        expected_kem_alg: Optional suite/KEM identity from the private key. If
            provided, it must exactly match the encrypted-container metadata.
        
    Returns:
        Tuple (decrypted_data, kem_algorithm), or (None, None) on error.
    """
```

Format version 4 is the only encryption format. The current `ML-KEM-768+X25519-v2` suite is the only write path. The ambiguous legacy `ML-KEM-768+X25519` suite and authenticated format version 3 remain decrypt-only; older formats are rejected. Legacy hybrid decryption tries only enabled ML-KEM-768/Kyber768 candidates and accepts one only after AES-GCM authentication succeeds.

```python
def inspect_encrypted_file_strict(encrypted_blob: bytes) -> EncryptedFileMetadata:
    """
    Parses non-secret encrypted-container metadata without using the native backend.
    """
```

## crypto_config Module

The `crypto_config` module provides configuration constants used by the cryptographic operations.

### Important Constants

- `KEM_ALG`: The post-quantum KEM algorithm used (default: "ML-KEM-768")
- `HYBRID_KEM_ALG`: The required new key/encryption suite (`ML-KEM-768+X25519-v2`)
- `LEGACY_HYBRID_KEM_ALG`: The decrypt-only ambiguous hybrid suite (`ML-KEM-768+X25519`)
- `ALLOWED_KEM_ALGS`: Exact KEM identifiers (`ML-KEM-768` and decrypt-only migration support for legacy `Kyber768`)
- `AES_KEY_BYTES`: Size of AES key in bytes (32 for AES-256)
- `PRIVATE_KEY_MIN_PASSWORD_CHARS`: Minimum private-key password length
- `PRIVATE_KEY_MIN_UNIQUE_CHARS`: Minimum private-key password character variety
- `PRIVATE_KEY_KDF_ALG`: Required private-key KDF (`scrypt`)
- `SCRYPT_N`, `SCRYPT_R`, `SCRYPT_P`: Required scrypt private-key KDF parameters
- `PEM_PRIVATE_KEY_FORMAT_VERSION`: Required encrypted private-key PEM metadata version
- `MAX_PEM_BYTES`: Maximum PEM/key bytes accepted before parsing
- `MAX_RAW_KEY_BYTES`: Maximum raw key payload accepted inside PEM
- `FORMAT_VERSION`: File format version for encrypted files
- `MAX_FILE_BYTES`: Maximum in-memory file size accepted by the UI and core encryption path
- `MAX_ENCRYPTED_FILE_BYTES`: Maximum encrypted-container size accepted by decryption, including bounded header and authentication overhead

## Example Usage

### Generate and Save Keys

```python
from crypto_config import cfg
import crypto_core as core

# Generate independent composite key pair
kem_alg = core.resolve_kem_algorithm(cfg.KEM_ALG)
public_key, private_key = core.generate_hybrid_keys(kem_alg)

# Save keys in PEM format
public_pem = core.save_key_pem(public_key, cfg.HYBRID_KEM_ALG, "public")
private_pem = core.save_key_pem(
    private_key,
    cfg.HYBRID_KEM_ALG,
    "private",
    password="river-metal-orbit-cactus-47",
)

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
    
priv_key, priv_kem_alg, _ = core.load_key_pem(priv_pem, password="river-metal-orbit-cactus-47")

# Decrypt the file
with open("encrypted_document.pqc", "rb") as f:
    encrypted_data = f.read()
    
decrypted_data, _ = core.decrypt_file_pro(encrypted_data, priv_key, expected_kem_alg=priv_kem_alg)

with open("decrypted_document.pdf", "wb") as f:
    f.write(decrypted_data)
```
