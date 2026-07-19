# Threat Model

## Security Goals

Quantum Encryptor protects local files with post-quantum key encapsulation and authenticated symmetric encryption. The security goal is to keep plaintext and private keys confidential, detect encrypted-container tampering, and fail closed for malformed keys, malformed encrypted files, weak passwords, and unavailable native cryptography backends.

## Assets

- Private-key PEM files and their passwords.
- Encrypted private-key PEM metadata, including KEM algorithm, KDF parameters, salt, and nonce.
- ML-KEM and X25519 shared secrets and derived AES keys.
- Plaintext input files and decrypted output files.
- Encrypted `.pqc` containers and their authenticated metadata.
- Local workspace file paths used by the agent CLI.

## Trust Boundaries

- Streamlit uploads are untrusted user-controlled files.
- Agent CLI arguments and environment variables are untrusted automation inputs.
- Public/private PEM files and `.pqc` files are attacker-controlled until parsed and authenticated.
- Native `liboqs` and Python `cryptography` are trusted dependencies but may be unavailable or misconfigured.
- The local filesystem is trusted only inside the current workspace for agent CLI operations.

## Abuse Cases

- Supplying malformed or legacy private-key PEM files to bypass password protection.
- Tampering with encrypted private-key PEM metadata to downgrade KDF parameters or confuse the KEM algorithm.
- Combining a private key for one suite label with an encrypted container carrying a different suite label.
- Substituting either the ML-KEM or X25519 component of a composite key.
- Relabeling a v4 hybrid container as a legacy single-KEM container to force a downgrade.
- Supplying weak, missing, or reused private-key passwords.
- Tampering with encrypted-file headers, KEM ciphertext, nonce, AES ciphertext, or authentication tag.
- Feeding oversized PEM, plaintext, or encrypted-container inputs to exhaust process memory.
- Using absolute paths, parent traversal, or symlinks to make the agent CLI read or write outside the workspace.
- Triggering native backend failures during import, key generation, encryption, or decryption.
- Leaking plaintext, private keys, passwords, raw bytes, or absolute local paths through JSON output or logs.

## Required Invariants

- Private keys are never saved or accepted unless encrypted with the required scrypt KDF metadata.
- New encrypted private-key PEM files must include `PQC-Key-Format: 3`, and private-key metadata must be authenticated as AES-GCM associated data.
- New encryption must require a composite `ML-KEM-768+X25519-v2` public key backed by exact ML-KEM-768 and must never fall back to Kyber or legacy single-KEM encryption.
- File decryption must reject a private-key suite label that does not exactly match the encrypted-container suite label.
- The ambiguous legacy `ML-KEM-768+X25519` suite is decrypt-only; ML-KEM/Kyber fallback is bounded and a candidate is accepted only after AES-GCM authentication succeeds.
- Encrypted files must be authenticated format version 4 or decrypt-only version 3 and must authenticate the complete header as AES-GCM associated data.
- Version 4 AES keys must bind both key shares, both X25519 public values, the suite identifier, and the application domain separator.
- PEM, plaintext, and encrypted-container inputs must be bounded before expensive parsing or cryptographic work.
- Decryption failures do not produce plaintext output files.
- Agent CLI paths stay workspace-relative and cannot escape through symlinks.
- Agent CLI JSON output never includes secret material or absolute local paths.
- Private-key files and decrypted plaintext outputs are written with owner-only permissions on POSIX systems.

## Current Mitigations

- Strict PEM base64, KDF, salt, nonce, format-version, KEM, and key-type validation.
- Mandatory private-key password policy with a minimum length of 16 characters, at least 5 unique characters, and known weak password rejection.
- scrypt private-key password derivation with fixed required parameters.
- Encrypted private-key PEM v3 metadata authenticated as AES-GCM associated data; authenticated v2 ML-KEM keys are accepted only for legacy v3 decryption.
- Private-key suite metadata checked against encrypted-container suite metadata before backend decapsulation.
- PEM/key, plaintext, and encrypted-container size checks before parsing or decrypting.
- v4 hybrid encrypted-container parsing with bounded ML-KEM and X25519 fields, plus decrypt-only authenticated-v3 compatibility.
- Application-specific SHA3-256 combiner inspired by RFC 9980's component binding, with domain separation and full-header AES-GCM authentication.
- AES-256-GCM with full encrypted-file header as associated data.
- Lazy native `liboqs` loading with dependency failures reported as unavailable backend state.
- Workspace-only agent CLI path validation, exclusive non-overwrite creation, atomic replacement on explicit overwrite, and JSON-only responses.

## Limitations

- The app processes files in memory and is not suitable for very large streaming workflows.
- Python cannot guarantee secure zeroization of immutable secret byte strings.
- No independent cryptographic audit or formal verification has been performed.
- The application-specific file and key formats are not interoperable with OpenPGP or another standardized container format.
- The hybrid construction has not undergone an independent cryptographic audit.
- Private-key recovery is impossible if the private-key password is lost.
