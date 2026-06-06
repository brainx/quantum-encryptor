# Security Considerations

This document outlines the security considerations for the Quantum Encryptor application, including the cryptographic primitives used, potential threats, and best practices.

## Cryptographic Design

The application uses a hybrid cryptographic approach, combining post-quantum key encapsulation with classical symmetric encryption:

1. **Key Encapsulation Mechanism (KEM)**: ML-KEM-768
   - NIST-selected post-quantum cryptographic algorithm
   - `Kyber768` is accepted as a legacy compatibility alias for older OQS builds
   - Designed to resist attacks from both classical and quantum computers

2. **Data Encryption Mechanism (DEM)**: AES-256-GCM
   - Authenticated encryption with associated data (AEAD)
   - Provides confidentiality, integrity, and authenticity
   - 256-bit key length provides sufficient security margin
   - Encrypted-file format version 3 authenticates the file header as associated data

3. **Key Derivation Function (KDF)**: HKDF-SHA256
   - Derives symmetric encryption keys from KEM shared secrets
   - Uses domain separation to prevent key reuse across different contexts

4. **Password-based Key Derivation**: PBKDF2-HMAC-SHA256
   - Used for deriving keys from passwords for private key protection
   - Configurable iteration count (default: 390,000 iterations)
   - Salt size: 16 bytes (128 bits)

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
   - Unexpected native backend failures during import/startup

## Current Mitigations

- Native `liboqs` is loaded lazily and missing backend support is treated as an unavailable dependency, not a process exit during import.
- Encrypted-file headers include magic bytes, version, KEM name length, KEM ciphertext length, and nonce validation.
- Format version 3 uses the complete header as AES-GCM associated data, so header tampering fails authentication.
- PEM parsing uses strict base64 decoding and validates encrypted private-key salt and nonce lengths.
- The UI and core encryption path enforce a 100 MiB in-memory file limit.
- Download filenames are reduced to local filenames before being passed to Streamlit.
- Private-key password protection requires at least 16 characters in the UI.
- The core module defines its own logger but leaves root logging configuration to application entry points.
- The local agent CLI is not a network service, accepts only workspace-relative paths, rejects symlink escapes, and reads passwords from environment variables instead of command-line arguments.
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
