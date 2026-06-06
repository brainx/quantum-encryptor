# Threat Model

## Security Goals

Quantum Encryptor protects local files with post-quantum key encapsulation and authenticated symmetric encryption. The security goal is to keep plaintext and private keys confidential, detect encrypted-container tampering, and fail closed for malformed keys, malformed encrypted files, weak passwords, and unavailable native cryptography backends.

## Assets

- Private-key PEM files and their passwords.
- KEM shared secrets and derived AES keys.
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
- Supplying weak, missing, or reused private-key passwords.
- Tampering with encrypted-file headers, KEM ciphertext, nonce, AES ciphertext, or authentication tag.
- Feeding oversized files to exhaust process memory.
- Using absolute paths, parent traversal, or symlinks to make the agent CLI read or write outside the workspace.
- Triggering native backend failures during import, key generation, encryption, or decryption.
- Leaking plaintext, private keys, passwords, raw bytes, or absolute local paths through JSON output or logs.

## Required Invariants

- Private keys are never saved or accepted unless encrypted with the required scrypt KDF metadata.
- Encrypted files must be format version 3 and must authenticate the complete header as AES-GCM associated data.
- Decryption failures do not produce plaintext output files.
- Agent CLI paths stay workspace-relative and cannot escape through symlinks.
- Agent CLI JSON output never includes secret material or absolute local paths.
- Private-key files and decrypted plaintext outputs are written with owner-only permissions on POSIX systems.

## Current Mitigations

- Strict PEM base64, KDF, salt, nonce, and key-type validation.
- Mandatory private-key password policy with a minimum length of 16 characters.
- scrypt private-key password derivation with fixed required parameters.
- v3-only encrypted-container parsing with bounded header and ciphertext lengths.
- AES-256-GCM with full encrypted-file header as associated data.
- Lazy native `liboqs` loading with dependency failures reported as unavailable backend state.
- Workspace-only agent CLI path validation, overwrite protection, atomic writes, and JSON-only responses.

## Limitations

- The app processes files in memory and is not suitable for very large streaming workflows.
- Python cannot guarantee secure zeroization of immutable secret byte strings.
- No independent cryptographic audit or formal verification has been performed.
- The scheme is PQC-only, not a hybrid classical plus PQC construction.
- Private-key recovery is impossible if the private-key password is lost.
