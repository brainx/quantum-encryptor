# Test Suite for Quantum Encryptor

This directory contains unit tests for the Quantum Encryptor application.

## Running Tests

To run the tests, execute the following from the project root:

```bash
# Run all tests
./test.sh

# Run with the same core-module coverage gate used by CI
PYTHON=.venv/bin/python ./test.sh --cov=crypto_core --cov=pqc_agent_tools --cov=ui_helpers --cov-report=term-missing --cov-fail-under=70

# Run a specific test file
./test.sh tests/test_crypto_core.py
./test.sh tests/test_agent_tools.py
./test.sh tests/test_ui_helpers.py

# Run a specific test class
./test.sh tests/test_crypto_core.py::TestKeyGeneration

# Run a specific test
./test.sh tests/test_crypto_core.py::TestKeyGeneration::test_generate_oqs_keys
```

Set `PYTHON` to force a specific Python 3.10-3.13 interpreter or virtualenv:

```bash
PYTHON=.venv/bin/python ./test.sh
```

## Test Structure

The tests are organized by module and functionality:

- `test_crypto_core.py` - Tests for the core cryptographic functions
  - Key generation and management
  - Key derivation
  - Private key encryption/decryption
  - PEM format handling
  - File encryption/decryption
- `test_agent_tools.py` - Tests for the local JSON CLI safety boundary
  - Workspace-relative path validation
  - Input size checks before file parsing
  - Non-overwrite and explicit-overwrite file creation
  - Safe JSON error contracts
- `test_ui_helpers.py` - Tests for UI filename helpers
  - Local decrypted filename guesses
  - `.pqc` suffix handling
  - Path component stripping

## Writing New Tests

When adding features or fixing bugs, please add corresponding tests:

1. Create test functions with descriptive names
2. Follow the naming convention `test_<function_name>_<scenario>`
3. Add appropriate assertions
4. Use fixtures for common setup and teardown
5. Follow the existing class structure

## Dependencies

Test dependencies:
- pytest
- pytest-cov

Install these with:
```bash
pip install -r requirements-dev.txt
```

Native `liboqs` is required for the key generation and end-to-end file encryption tests. When native `liboqs` is unavailable, those tests skip and the non-backend validation still runs.

Security-critical tests cover composite ML-KEM/X25519 key generation, hybrid combiner binding, encrypted private-key PEM v3 metadata authentication, authenticated-v2 migration, version-downgrade and component-substitution rejection, malformed AES-GCM payload bounds, race-resistant bounded workspace reads, oversized input rejection, and no-overwrite output safety.

## Continuous Integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs:

- `black --check`
- `flake8`
- `mypy`
- Unit tests without native `liboqs`, with at least 80% coverage on core modules
- Frontend API client tests, build/type checks, and browser smoke tests
- Package build, `twine check`, isolated wheel import, agent CLI health, and installed web UI smoke tests
- Python runtime/development dependency audits with `pip-audit` and web dependency audits with `npm audit`
- Python security linting with `bandit`
- A native `liboqs` integration job so backend-dependent KEM round-trip tests run in CI

GitHub CodeQL default setup provides repository static analysis without a duplicate advanced-configuration workflow.

## Coverage Goals

- Maintain at least 80% test coverage on core modules in CI
- Prioritize coverage of security-critical functionality
