# Changelog

All notable changes to this project will be documented here.

This project follows a practical semantic-versioning style.

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
