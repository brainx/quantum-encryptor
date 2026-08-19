# Changelog

All notable changes to this project will be documented here.

This project follows a practical semantic-versioning style.

## [Unreleased]

### Added

- ML-KEM-768 + X25519 composite key generation and format-v4 encrypted containers.
- SHA3-256 hybrid key combiner binding both key shares, X25519 context, suite identifier, and application domain.
- Polished monochrome local web workflows with progressive technical details,
  responsive navigation, component tests, accessibility checks, and a native
  browser encryption round trip.

### Changed

- Retired the Streamlit application, temporary startup fallback, packaging
  surface, and superseded reference screenshots. `./start.sh` now serves the
  React/Vite interface through the loopback-only Python API as the sole GUI.
- Preserved decrypt-only compatibility for authenticated earlier containers and
  private-key formats, including the bounded ML-KEM/Kyber migration path.

### Security

- Raised the minimum `cryptography` version to 50.0.0 and refreshed the hash-locked runtime and development dependency sets to exclude the vulnerable 49.0.0 release.
- New encryption requires composite public keys and cannot silently downgrade to the legacy single-KEM format.
- Authenticated format-v3 containers and v2 ML-KEM private keys remain decrypt-only for migration.
- New keys and ciphertexts use the unambiguous `ML-KEM-768+X25519-v2` suite and require exact ML-KEM-768 support; Kyber768 is no longer treated as an interchangeable alias.
- Legacy hybrid archives remain recoverable through a bounded ML-KEM/Kyber fallback whose result is accepted only after AES-GCM authentication; legacy hybrid public keys are rejected for new encryption.
- The per-process local API token is no longer disclosed in the `GET /api/health` response body; it is delivered only as an `HttpOnly`, `SameSite=Strict` cookie, with the `X-Quantum-Encryptor-Token` header retained for programmatic clients configured via `QUANTUM_ENCRYPTOR_API_TOKEN`.
- All local web responses now include a restrictive Content Security Policy (including `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.

## [1.0.1] - 2026-06-21

### Added

- Custom local web UI backed by a Python ASGI API.
- Browser smoke testing for the custom web UI.
- Frontend build and type-check CI job.
- API request body size limiting before multipart parsing.
- Safer download filename handling.

### Security

- Native `liboqs` readiness is handled without crashing imports.
- API errors avoid exposing internal stack traces.
- Encrypted-file and private-key parsing continue to fail closed for malformed inputs.

## [1.0.0] - Initial stable release

### Added

- ML-KEM-768 file encryption with AES-256-GCM.
- Password-protected private-key PEM files using scrypt.
- Authenticated encrypted-file format metadata.
- Local JSON CLI for agent workflows.
- Threat model and security documentation.
