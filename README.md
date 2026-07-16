# Quantum Encryptor

A post-quantum cryptography tool for file encryption. New files combine ML-KEM-768 and X25519 key establishment with AES-256-GCM so confidentiality does not depend on either key-establishment component alone.

![Quantum Encryption](https://img.shields.io/badge/Encryption-Post--Quantum-blue)
![Python Version](https://img.shields.io/badge/Python-3.10--3.13-green)
![CI](https://github.com/brainx/Quantum-Encryptor/actions/workflows/ci.yml/badge.svg)

<p align="center">
  <a href="docs/SCREENSHOTS.md">
    <img
      src="docs/screenshots/custom-web-encrypt-workflow.png"
      alt="Quantum Encryptor custom web app showing the encrypt file workflow and backend readiness warning"
      width="900"
    >
  </a>
</p>

<p align="center">
  <strong>Dark local web interface for ML-KEM-768 + X25519 key generation, file encryption, decryption, and PEM key inspection.</strong>
</p>

## Features

- **Post-Quantum/Traditional Security**: Combines ML-KEM-768 with X25519 so confidentiality does not depend on one key-establishment algorithm
- **Authenticated File Encryption**: Derives AES-256-GCM keys from both ML-KEM and X25519 shared secrets
- **Password-Protected Keys**: Private keys are always encrypted with scrypt-derived AES-256-GCM keys
- **User-Friendly Interface**: Custom local web UI with a Python ASGI API
- **PEM Key Format**: Keys stored in PEM-like format with quantum algorithm extensions

## Screenshots

The backend readiness warning shown here is expected when native `liboqs` is not installed in the local environment. Click any image to open the full screenshot page.

<p>
  <a href="docs/SCREENSHOTS.md#custom-web-encrypt-workflow">
    <img src="docs/screenshots/custom-web-encrypt-workflow.png" alt="Custom web encrypt workflow" width="64%">
  </a>
  <a href="docs/SCREENSHOTS.md#custom-web-mobile-inspect">
    <img src="docs/screenshots/custom-web-mobile-inspect.png" alt="Custom web mobile key inspection workflow" width="32%">
  </a>
</p>

See [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) for the dedicated screenshot page.

## Project Documentation

- [Security policy](SECURITY.md)
- [Security design notes](docs/SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Changelog](CHANGELOG.md)

## Requirements

- Python 3.10 through 3.13
- Open Quantum Safe native `liboqs` shared library
- Open Quantum Safe `liboqs-python` wrapper, which imports as `oqs`
- Python dependencies listed in `requirements.txt`
- Node.js 20.19+ or 22.12+ and npm for building the custom web UI
- Optional hash-locked installs from `requirements-lock.txt` or `requirements-dev-lock.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/brainx/Quantum-Encryptor.git
   cd Quantum-Encryptor
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   npm install
   ```

   For a reproducible runtime install with pinned hashes:
   ```bash
   pip install --require-hashes -r requirements-lock.txt
   ```

4. Install or expose native `liboqs`.

   The app checks for a native `liboqs` shared library before importing `liboqs-python`, so startup and tests do not trigger wrapper auto-install side effects. If `liboqs` is not installed in a standard library path, set `OQS_INSTALL_PATH` to the install prefix that contains `lib/`, `lib64/`, or `bin/`.

   ```bash
   export OQS_INSTALL_PATH=/path/to/liboqs/install
   ```

## Usage

1. Start the application:
   ```bash
   ./start.sh
   ```

   The custom web app builds the frontend and listens on `127.0.0.1:4000` by default. Set `PORT` to override the local development port:
   ```bash
   PORT=4001 ./start.sh
   ```

   Set `PYTHON` if you want the wrapper scripts to use a specific interpreter:
   ```bash
   PYTHON=.venv/bin/python ./start.sh
   PYTHON=.venv/bin/python ./test.sh
   ```

   To run the legacy Streamlit UI during transition:
   ```bash
   LEGACY_STREAMLIT=1 ./start.sh
   ```

   Frontend development can run Vite separately on `127.0.0.1:4001`:
   ```bash
   npm run dev
   ```

2. Open the web interface in your browser. You can:
   - Generate a new post-quantum key pair
   - Encrypt files using a recipient's public key
   - Decrypt files using your private key
   - Access key utilities

## Verification

Run the Python test suite:

```bash
./test.sh
```

Run the custom frontend checks:

```bash
npm run build
npm run check
```

With the app already running on `127.0.0.1:4000`, run the browser smoke test:

```bash
npm run ui-smoke
```

The UI smoke test writes ignored screenshots under `tmp/ui-smoke/`.

### Key Generation

1. Select "Generate Keys" from the sidebar
2. Enter and confirm a strong private-key password
3. Generate the keys and download both public and private key files
4. Share your public key with others who want to send you encrypted files

### File Encryption

1. Select "Encrypt File" from the sidebar
2. Upload the file you want to encrypt
3. Upload the recipient's public key (.pem file)
4. Specify the output filename
5. Download the encrypted file

### File Decryption

1. Select "Decrypt File" from the sidebar
2. Upload the encrypted file (.pqc file)
3. Upload your private key (.pem file)
4. Enter your private-key password
5. Download the decrypted file

## Agent Usage

Local automation agents can use the deterministic JSON CLI instead of driving the Streamlit UI. Run commands from the repository workspace and pass only workspace-relative paths. Absolute paths, `..` traversal, symlink escapes, and accidental output overwrites are rejected.

```bash
mkdir -p keys data

python -m pqc_agent_tools health --json

export PQC_PRIVATE_KEY_PASSWORD='<strong-private-key-password>'
python -m pqc_agent_tools generate-keys \
  --public-out keys/agent-public.pem \
  --private-out keys/agent-private.pem

python -m pqc_agent_tools inspect-key --key keys/agent-public.pem
python -m pqc_agent_tools inspect-key --key keys/agent-private.pem

python -m pqc_agent_tools encrypt \
  --input data/message.txt \
  --public-key keys/agent-public.pem \
  --output data/message.pqc

python -m pqc_agent_tools inspect-file --input data/message.pqc
python -m pqc_agent_tools verify-file \
  --input data/message.pqc \
  --private-key keys/agent-private.pem

python -m pqc_agent_tools decrypt \
  --input data/message.pqc \
  --private-key keys/agent-private.pem \
  --output data/message.decrypted.txt
```

The installed console entry point is equivalent:

```bash
quantum-encryptor-agent health --json
```

The CLI prints JSON only and never includes plaintext, private keys, passwords, raw file bytes, or absolute local paths in its output. Private-key operations read passwords from the environment variable named by `--password-env`, defaulting to `PQC_PRIVATE_KEY_PASSWORD`.

## Security Considerations

- New encrypted files use format version 4 with ML-KEM-768 + X25519-derived AES-256-GCM keys and authenticate the complete file header as associated data
- New encrypted private-key PEM files require `PQC-Key-Format: 3`; private-key metadata, hybrid suite, KDF parameters, salt, and nonce are authenticated as AES-GCM associated data
- Authenticated format-v3 files and `PQC-Key-Format: 2` ML-KEM private keys remain decrypt-only for migration; encryption never silently downgrades
- Private keys must be password protected with scrypt-derived AES-256-GCM keys; unencrypted private keys and legacy encrypted private-key PEM metadata are rejected by default
- Private-key passwords require at least 16 characters, at least 5 unique characters, and must not match known weak values
- Decryption checks encrypted-file suite metadata against the private-key metadata; v4 requires `ML-KEM-768+X25519`, while v3 accepts the `ML-KEM-768`/`Kyber768` compatibility aliases
- Existing v2 ML-KEM private keys can decrypt authenticated v3 files, but creating new encrypted files requires generating a new composite key pair; re-encrypt migrated data with that new public key
- PEM/key reads are capped at 128 KiB before parsing; POSIX workspace inputs use descriptor-anchored, no-follow reads, and reads remain bounded even if a file changes during the operation
- The web UI enforces a 100 MiB plaintext processing limit because files are handled in memory; encrypted containers allow bounded header and authentication overhead above that plaintext limit
- State-changing local web API requests require a per-process API token and reject non-local browser origins when an `Origin` header is present
- The local agent CLI accepts only workspace-relative paths, returns machine-readable JSON without secret material, and writes private keys plus decrypted outputs with owner-only permissions on POSIX systems; non-overwrite output creation uses exclusive file creation
- Native `liboqs` is loaded lazily and missing backend support disables key generation/encryption instead of crashing the app
- CI runs Python formatting, linting, type checks, unit tests, custom web UI build/type checks, API client tests, browser UI smoke, isolated installed-wheel checks, Python/npm dependency audits, locked runtime install, and a native `liboqs` integration test job pinned to the matching 0.15.0 release commit; repository CodeQL default setup provides static analysis
- See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for repository trust boundaries, assets, abuse cases, and invariants
- **Disclaimer**: This software has not undergone an independent security audit and should be reviewed before production use

## Project Structure

- `crypto_config.py` - Configuration parameters for cryptographic operations
- `crypto_core.py` - Core cryptographic functions (key generation, encryption, decryption)
- `api_app.py` - Local ASGI API and static web UI server
- `pqc_agent_tools.py` - Local JSON CLI for agentic workflows
- `pqc_app.py` - Legacy Streamlit web application interface
- `web/` - React frontend source for the custom UI
- `package.json` / `vite.config.ts` - Frontend build configuration
- `ui_helpers.py` - UI-safe filename helpers
- `start.sh` - Local application startup script
- `test.sh` - Test runner
- `requirements-lock.txt` / `requirements-dev-lock.txt` - Hash-locked runtime and development dependency sets
- `pyproject.toml` / `setup.py` - Packaging metadata

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) for liboqs implementation
- [NIST](https://www.nist.gov/pqcrypto) for leading the post-quantum cryptography standardization effort
