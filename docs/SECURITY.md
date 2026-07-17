# Security Considerations

This document outlines the security considerations for the Quantum Encryptor application, including the cryptographic primitives used, potential threats, and best practices.

## Cryptographic Design

The application uses post-quantum/traditional hybrid key establishment followed by authenticated symmetric encryption:

1. **Post-Quantum Component**: ML-KEM-768
   - NIST-selected post-quantum cryptographic algorithm
   - `Kyber768` is a distinct legacy algorithm accepted only where authenticated archive migration requires it
   - Designed to resist attacks from both classical and quantum computers

2. **Traditional Key-Establishment Component**: X25519
   - A fresh ephemeral X25519 key is generated for every encrypted file
   - The recipient's X25519 public key is stored alongside the ML-KEM public key
   - The ephemeral public key is authenticated as part of the encrypted-file header

3. **Hybrid Combiner**: SHA3-256
   - Uses an application-specific construction inspired by the component-binding pattern in RFC 9980
   - Binds both shared secrets, both X25519 public values, and the hybrid suite identifier
   - Produces the 256-bit AES key only when both component exchanges are present

4. **Data Encryption Mechanism (DEM)**: AES-256-GCM
   - Authenticated encryption with associated data (AEAD)
   - Provides confidentiality, integrity, and authenticity
   - 256-bit key length provides sufficient security margin
   - Encrypted-file format version 4 authenticates the complete hybrid header as associated data

5. **Legacy Key Derivation Function**: HKDF-SHA256
   - Used only when decrypting authenticated single-KEM format-v3 containers

6. **Password-based Key Derivation**: scrypt
   - Used for deriving keys from passwords for private key protection
   - Required parameters: `n=32768`, `r=8`, `p=1`
   - Salt size: 16 bytes (128 bits)
   - New encrypted private-key PEM format version 3 authenticates the hybrid suite, KDF metadata, salt, and nonce as AES-GCM associated data

## Threat Model

The application is designed to protect against the following threats:

1. **Quantum Computing Attacks**
   - Shor's algorithm breaking RSA/ECC-based encryption
   - Grover's algorithm reducing symmetric encryption strength

2. **Classical Cryptographic Attacks**
   - Brute force attacks on encryption keys
   - Side-channel attacks on implementation

3. **Password-related Threats**
   - Weak passwords used for private key protection
   - Brute force attacks on password-protected keys

4. **Implementation Vulnerabilities**
   - Memory leaks exposing sensitive information
   - Improper key management
   - Malformed or tampered encrypted-file headers
   - Malformed or tampered encrypted private-key PEM metadata
   - Hybrid-suite confusion between a private key and an encrypted container
   - Single-component substitution or version-downgrade attempts
   - Oversized PEM/key inputs causing avoidable memory pressure before parsing
   - Unexpected native backend failures during import/startup

## Current Mitigations

- Native `liboqs` is loaded lazily and missing backend support is treated as an unavailable dependency, not a process exit during import.
- Encrypted-file headers include magic bytes, version, suite name length, ML-KEM ciphertext length, X25519 ephemeral public key, and nonce validation.
- New encryption emits only format version 4 with the unambiguous `ML-KEM-768+X25519-v2` suite and requires exact ML-KEM-768 support.
- Authenticated format version 3 is accepted only for decryption; older unauthenticated formats remain rejected.
- Format versions 3 and 4 use the complete header as AES-GCM associated data, so header tampering fails authentication.
- New encrypted private-key PEM parsing requires `PQC-Key-Format: 3`; authenticated v2 ML-KEM keys remain decrypt-only for migration.
- PEM private-key encryption authenticates the private-key format version, suite, KDF parameters, salt, and nonce as AES-GCM associated data.
- PEM parsing uses strict base64 decoding and validates encrypted private-key salt, nonce, scrypt KDF metadata, maximum PEM size, and maximum raw key payload size.
- File decryption requires an exact private-key/container suite label match. The legacy `ML-KEM-768+X25519` label is decrypt-only; its bounded ML-KEM/Kyber migration fallback accepts a candidate only after AES-GCM authentication succeeds. Format-v3 containers use their exact stored KEM identity.
- Legacy hybrid public keys are rejected for encryption and must be regenerated under the current suite.
- The UI and core encryption path enforce a 100 MiB plaintext in-memory file limit; decryption accepts only the bounded encrypted-container size needed for header, KEM ciphertext, nonce, and tag overhead.
- The local web API requires a per-process `X-Quantum-Encryptor-Token` for state-changing `/api/*` requests and rejects non-local browser origins when an `Origin` header is present.
- Download filenames are reduced to local filenames before being passed to Streamlit.
- Private-key password protection requires at least 16 characters, at least 5 unique characters, and rejects known weak values in the core, UI, and agent CLI.
- Unencrypted private keys are rejected in the core, UI, and agent CLI.
- The core module defines its own logger but leaves root logging configuration to application entry points.
- The local agent CLI is not a network service, accepts only workspace-relative paths, rejects symlink escapes, creates non-overwrite outputs with exclusive file creation, stores private keys and decrypted plaintext with owner-only permissions on POSIX systems, and reads passwords from environment variables instead of command-line arguments.
- CI runs static checks, tests without native `liboqs`, and a native `liboqs` integration test job.

## Security Best Practices

To maximize the security of the application, follow these best practices:

### Key Management

1. **Private Key Protection**
   - Always use strong, unique passwords for private key encryption
   - Store private keys securely, ideally offline or in hardware security modules
   - Limit access to private key files using OS-level permissions

2. **Key Rotation**
   - Periodically generate new key pairs
   - Re-encrypt sensitive files with new keys

3. **Backup Management**
   - Securely back up private keys
   - Consider key recovery mechanisms for organizational use

### Usage Recommendations

1. **File Encryption**
   - Encrypt files before transferring them over untrusted networks
   - Verify the authenticity of public keys before use

2. **Password Selection**
   - Use high-entropy passwords (at least 16 characters)
   - Consider using password managers to generate and store strong passwords

3. **Secure Environment**
   - Run the application on trusted, up-to-date systems
   - Be aware of physical security (shoulder surfing, etc.)

## Limitations

The application has the following security limitations:

1. **Cryptographic Algorithm Status**
   - ML-KEM is relatively new, and cryptanalysis is ongoing
   - Future discoveries might reveal weaknesses

2. **Implementation Considerations**
   - The application relies on the security of underlying libraries (liboqs, cryptography)
   - No formal verification or independent security audit has been performed
   - The file and key formats are application-specific and are not OpenPGP-compatible

3. **Side-Channel Resistance**
   - The implementation does not provide explicit protections against timing attacks or other side channels
   - Hardware-level attacks (cache timing, power analysis) are not mitigated

4. **In-Memory Processing**
   - Files are processed in memory, so very large-file streaming is not supported
   - Sensitive data may remain in Python-managed memory until garbage collection
   - Local reference deletion in the implementation must not be treated as secure memory zeroization

## Reporting Security Issues

If you discover a security vulnerability in the application, report it privately through the maintainer's configured security contact or repository security advisory flow. Include reproduction steps, affected versions, and impact details.

## References

1. NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography
2. Kyber Algorithm Specification: https://pq-crystals.org/kyber/
3. OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
4. RFC 9980, Post-Quantum Cryptography in OpenPGP: https://www.rfc-editor.org/rfc/rfc9980.html
