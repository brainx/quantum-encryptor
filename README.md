# Quantum Encryptor

A post-quantum cryptography tool for file encryption. New files combine ML-KEM-768 and X25519 key establishment with AES-256-GCM so confidentiality does not depend on either key-establishment component alone.

![Quantum Encryption](https://img.shields.io/badge/Encryption-Post--Quantum-blue)
![Python Version](https://img.shields.io/badge/Python-3.10--3.13-green)
![CI](https://github.com/brainx/Quantum-Encryptor/actions/workflows/ci.yml/badge.svg)

<p align="center">
  <a href="docs/SCREENSHOTS.md">
    <img
      src="docs/screenshots/custom-web-encrypt-workflow.png"
      alt="Quantum Encryptor custom web app showing the Encrypt workflow and its technical details"
      width="900"
    >
  </a>
</p>

<p align="center">
  <strong>Monochrome local web interface for ML-KEM-768 + X25519 key generation, file encryption, decryption, and PEM key inspection.</strong>
</p>

## Features

- **Post-Quantum/Traditional Security**: Combines ML-KEM-768 with X25519 so confidentiality does not depend on one key-establishment algorithm
- **Authenticated File Encryption**: Derives AES-256-GCM keys from both ML-KEM and X25519 shared secrets
- **Password-Protected Keys**: Private keys are always encrypted with scrypt-derived AES-256-GCM keys
- **Public-Key Fingerprints**: Full versioned SHA3-256 identifiers support independent public-key comparison
- **User-Friendly Interface**: Custom local web UI with progressive technical details and a Python ASGI API
- **Batch Encryption**: Encrypt up to 25 files for one recipient with sequential processing, per-file results, cancellation, and explicit downloads
- **Batch Decryption**: Restore up to 25 encrypted files with one private key and password, retaining successful results when another file fails
- **Private-Key Password Changes**: Download a newly password-protected copy of the same private key without replacing your public key or re-encrypting existing files
- **Public-Key Recovery**: Recover the public PEM from an unlocked private key and check whether a supplied public key matches
- **File Verification**: Inspect encrypted-file metadata and authenticate an entire file without downloading its plaintext
- **PEM Key Format**: Keys stored in PEM-like format with quantum algorithm extensions

## Screenshots

The current browser smoke captures show the responsive Encrypt and Inspect key workflows. Click either image to open the full screenshot page.

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

   The custom web app builds the frontend and serves its UI and API at exactly `http://127.0.0.1:4000` by default. `PORT` selects the one trusted local UI/API authority; `localhost`, IPv6 and other loopback addresses, and sibling ports are not aliases for it. Set `PORT` to choose a different local development authority:
   ```bash
   PORT=4001 ./start.sh
   ```

   Set `PYTHON` if you want the wrapper scripts to use a specific interpreter:
   ```bash
   PYTHON=.venv/bin/python ./start.sh
   PYTHON=.venv/bin/python ./test.sh
   ```

   Keep `./start.sh` as the normal path. For frontend development, explicitly opt both processes into the one additional Vite authority, `http://127.0.0.1:4001`, and its `/api` proxy:
   ```bash
   QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1 SKIP_WEB_BUILD=1 ./start.sh
   QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1 npm run dev
   ```

   The switch must be set to exactly `1` for both processes; any other value leaves the Vite authority and proxy disabled.

2. Open the web interface in your browser. Choose the intent that matches your task:
   - **Encrypt**: protect a file for the holder of a recipient public key.
   - **Batch encrypt**: protect multiple files for the same recipient, then download each encrypted result.
   - **Decrypt**: recover a file with the matching encrypted private key and password.
   - **Batch decrypt**: recover several files with the same private key and download each successful result.
   - **Verify file**: inspect a container, then authenticate it using its private key without a plaintext download.
   - **Generate keys**: create a new public key and password-protected private key.
   - **Change password**: create an updated encrypted copy of an existing private key.
   - **Recover public key**: restore a lost public PEM and optionally check an existing public key against the private key.
   - **Inspect key**: check supported key metadata without exposing key material.

   Each workflow starts with plain-language guidance. Expand **Technical details** only when you need suite, format, or key-policy information.

### Local-only interface privacy

The custom interface processes selected files through the local Python service at `127.0.0.1`. It does not write generated keys to persistent web storage, collect telemetry, or load remote fonts or remote application assets. The UI does not display plaintext previews, passwords, private-key content, or the local API token.

Every `/api/*` response, including generated-key JSON, errors, middleware rejections, framework-generated 500 responses, and file downloads, is marked `Cache-Control: no-store` and `Pragma: no-cache`; static application assets keep their normal cache policy. These directives ask conforming HTTP caches not to retain API responses, but they are not secure deletion.

The web app keeps its generated-result references in the current tab's in-memory UI state. Save both files before clearing the result or leaving, reloading, or closing the page because those actions may lose the in-app result. Downloaded files are separate copies controlled by the browser, operating system, and destination. While the PEMs remain in the app, it requests the browser's standard leave-page warning. The browser controls whether that warning appears and its wording. Explicit clearing drops the app's React references but cannot zeroize managed memory. Browser history may instead suspend the document in the back/forward cache and later restore the same tab state.

### Public-key fingerprints

Successful key generation and validated public-key inspection return a complete fingerprint in the form `QE1-SHA3-256:<64 lowercase hexadecimal characters>`. The Generate workflow shows the fingerprint for the new pair, Inspect key shows it for a validated public key, and Encrypt shows the recipient fingerprint before encryption. Compare the entire value with the key owner over an independently authenticated channel, separate from the channel that delivered the key.

A matching fingerprint identifies the same validated algorithm label and canonical public-key bytes. It does not prove the owner's identity or control of the private key, certify that the key is trustworthy, or protect a comparison performed through the same compromised channel. Fingerprints are public identifiers and do not change the PEM or encrypted-file formats. Metadata-only inspection of an encrypted private key omits the fingerprint because deriving it requires an authenticated password unlock.

## Verification

Run the Python test suite:

```bash
./test.sh
```

Run the custom frontend checks:

```bash
npm run test:unit
npm run check
npm run build
```

With the app already running on `127.0.0.1:4000`, run the browser smoke test:

```bash
npm run ui-smoke
```

The UI smoke test writes ignored screenshots under `tmp/ui-smoke/`.

When a native `liboqs` installation is available to the running app, also run the real browser encryption round trip:

```bash
npm run ui-native
```

Do not treat the browser smoke test as proof that the native cryptographic backend is installed; it verifies the built interface against the local API contract. `npm run ui-native` verifies key generation, encryption, and decryption through the available native backend.

### Key Generation

1. Select "Generate keys" from the workflow navigation
2. Enter and confirm a strong private-key password
3. Save both files from the current tab before clearing the result or leaving the page
4. Share your public key and its complete fingerprint through independently authenticated channels

### File Encryption

1. Select "Encrypt" from the workflow navigation
2. Upload the file you want to encrypt
3. Upload the recipient's public key (.pem file)
4. Compare the complete recipient fingerprint over an independently authenticated channel
5. Specify the output filename
6. Download the encrypted file

### File Decryption

1. Select "Decrypt" from the workflow navigation
2. Upload the encrypted file (.pqc file)
3. Upload your private key (.pem file)
4. Enter your private-key password
5. Download the decrypted file

### Batch Encryption

1. Choose **Batch encrypt** and select or drop up to 25 files. Their combined plaintext size must fit the displayed file limit (100 MiB by default).
2. Select the recipient's public key and compare its complete fingerprint over an independently authenticated channel.
3. Choose **Encrypt batch**. Files run one at a time, with separate progress and error states. A failed file does not discard successful results or automatically retry the failed request.
4. Download each completed result. Batch output names retain the original extension, such as `report.pdf.pqc`; duplicate names receive a numeric suffix.
5. Choose **Clear batch** when finished. Results live only in the current tab; there is no persistent batch history or server-side recovery.

**Cancel batch** stops scheduling further files and aborts the active browser request. Native work already running may still finish on the server. Completed results remain available for download. If starting a download fails, retry that download without re-encrypting the file. The interface reports when a download starts; the browser determines whether it finishes. Navigation and page-leave warnings help protect results whose downloads have not been started, but browser-controlled warnings cannot guarantee recovery after a crash or forced close.

### Batch Decryption

Choose **Batch decrypt**, select up to 25 encrypted files within the displayed combined-size limit, and supply the encrypted private key and its password. The key's metadata is inspected before starting; its match to each file is verified only during authenticated decryption. Compatible legacy decryption keys remain supported.

Files are processed sequentially. A corrupt file or a file for another recipient shows its own error while successful results remain available. Download each result explicitly, then choose **Clear batch** to release the tab's plaintext references. Downloads can be retried without decrypting again. The password field is cleared when the batch starts; the active operation retains the password until it finishes or cancellation settles. Cancellation stops queued files and aborts the active browser request, but native work already running may still finish.

Decrypted files are sensitive plaintext. The app warns before navigating away while any plaintext result is retained, even if its download has started. Clearing results cannot guarantee memory zeroization or remove copies already downloaded by the browser.

### Change a Private-Key Password

1. Choose **Change password** and upload your encrypted private PEM key.
2. Enter its current password, then enter and confirm a different new password that meets the displayed policy.
3. Choose **Change key password** and download the updated encrypted private key. The displayed public-key fingerprint identifies the same key pair; existing ciphertext and the public key remain compatible.
4. Test the downloaded key with the new password before replacing any original copies. Choose **Clear updated key** to release the result from the tab.

This uses the existing scrypt/AES-GCM private-key format with fresh salt and nonce, and does not require a native post-quantum backend. It creates a separate download and does not overwrite the uploaded file. Copies protected with the old password still work with that password; this operation does not revoke old copies or recover a lost password.

The local API exposes `POST /api/keys/change-password` with multipart fields `private_key`, `current_password`, and `new_password`. Its JSON response contains the updated encrypted `privatePem`, `privateFilename`, `kem`, and authenticated `publicKeyFingerprint`. Health advertises support through `supportsKeyPasswordChange`.

### Public-Key Recovery and Pair Checking

Choose **Recover public key**, upload the encrypted private PEM, and enter its password. Optionally select a public PEM to compare. Recovery authenticates the private-key envelope, reconstructs its embedded or derived public key, and offers an explicit public-key download. The exact algorithm label and canonical public-key bytes are preserved, including compatible legacy key formats. A comparison reports whether both keys represent the same algorithm and public material; it does not certify their owner's identity. Compare the displayed fingerprint through a trusted channel when sharing the recovered key.

Recovery does not require the native post-quantum backend, change the private key, or recover a forgotten password. The password field is cleared when the request starts. `POST /api/keys/recover-public` accepts multipart `private_key`, `password`, and optional `public_key`; it returns `publicPem`, `publicFilename`, `kem`, `publicKeyFingerprint`, and `matchesSuppliedPublicKey` (`null` when no comparison was requested). Health advertises `supportsPublicKeyRecovery`.

### Encrypted-File Inspection and Verification

Choose **Verify file** and select an encrypted file. Inspection reads its format version, algorithm, and container sizes without a private key or native backend. These values remain unauthenticated until verification succeeds. To verify, select the matching encrypted private PEM, enter its password, and choose **Verify file**. Success reports the authenticated byte count and recipient fingerprint; corruption, a different key, or an incorrect password produces an error. Empty files are valid. Changing an input clears the previous result.

Verification requires the native backend and decrypts the bounded file in local service memory before discarding plaintext references. It returns no plaintext to the browser and initiates no download. It does not identify the sender or guarantee secure erasure of process memory. The password field is cleared when the request starts. Leaving the workflow aborts the browser request, although work already running in the local service may finish.

`POST /api/files/inspect` accepts multipart `file` and returns `authenticated: false` with a `metadata` object. `POST /api/files/verify` accepts `file`, `private_key`, and `password`; a successful report contains `verified: true`, `kem`, `formatVersion`, `bytesVerified`, and `publicKeyFingerprint`. Health advertises `supportsFileVerification`. Both use the existing encrypted-file size limit.

These endpoints follow the existing local API authentication, exact-origin, no-store, and upload-cleanup rules. Password changes, public-key recovery, file inspection, and file verification share one worker admission slot, retained until the operation finishes even if its HTTP request is cancelled. Busy requests receive `429` with `Retry-After: 1`; passwords are bounded to 4096 UTF-8 bytes and PEM files to the advertised limit.

## Automation Usage

Automation tools can use the deterministic JSON CLI instead of driving the browser interface. Run commands from the repository workspace and pass only workspace-relative paths. Absolute paths, `..` traversal, symlink escapes, and accidental output overwrites are rejected.

```bash
mkdir -p keys data

python -m pqc_agent_tools health --json

export PQC_PRIVATE_KEY_PASSWORD='<strong-private-key-password>'
python -m pqc_agent_tools generate-keys \
  --public-out keys/agent-public.pem \
  --private-out keys/agent-private.pem

python -m pqc_agent_tools inspect-key --key keys/agent-public.pem
python -m pqc_agent_tools inspect-key --key keys/agent-private.pem
python -m pqc_agent_tools inspect-key \
  --key keys/agent-private.pem \
  --password-env PQC_PRIVATE_KEY_PASSWORD

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

The CLI prints JSON only and never includes plaintext, private keys, passwords, raw file bytes, or absolute local paths in its output. Private-key generation, decryption, and verification read passwords from the environment variable named by `--password-env`, defaulting to `PQC_PRIVATE_KEY_PASSWORD`. `inspect-key` remains metadata-only for an encrypted private key unless `--password-env NAME` is explicitly supplied; after a successful authenticated unlock it returns the corresponding `public_key_fingerprint`.

## Security Considerations

- New encrypted files use format version 4 with the `ML-KEM-768+X25519-v2` suite and authenticate the complete file header as AES-GCM associated data
- New encrypted private-key PEM files require `PQC-Key-Format: 3`; private-key metadata, hybrid suite, KDF parameters, salt, and nonce are authenticated as AES-GCM associated data
- Authenticated format-v3 files and `PQC-Key-Format: 2` ML-KEM private keys remain decrypt-only for migration; encryption never silently downgrades
- Private keys must be password protected with scrypt-derived AES-256-GCM keys; unencrypted private keys and legacy encrypted private-key PEM metadata are rejected by default
- Private-key passwords require at least 16 characters, at least 5 unique characters, and must not match known weak values
- Decryption requires an exact private-key/container suite match. The ambiguous legacy `ML-KEM-768+X25519` suite is decrypt-only and selects ML-KEM or Kyber only after AES-GCM authentication succeeds; v3 uses its exact stored KEM identity
- Existing v2 ML-KEM private keys can decrypt authenticated v3 files, but creating new encrypted files requires generating a new composite key pair; re-encrypt migrated data with that new public key
- Legacy hybrid public keys must be regenerated before encryption; they are never relabeled or reused as current-suite keys
- Public-key fingerprints cover the exact algorithm label and canonically validated public-key bytes. Compare the complete value over an independently authenticated channel; a fingerprint is not a certificate, signature, or proof of key ownership
- Encrypted private-key metadata never claims a fingerprint before password authentication. The CLI derives the corresponding public fingerprint only after a successful opt-in unlock and canonical private-key validation
- PEM/key reads are capped at 128 KiB before parsing; POSIX workspace inputs use descriptor-anchored, no-follow reads, and reads remain bounded even if a file changes during the operation
- The web UI enforces a 100 MiB plaintext processing limit because files are handled in memory; encrypted containers allow bounded header and authentication overhead above that plaintext limit
- State-changing local web API requests require a per-process API token. Browser cookie requests require an exact allowed `Origin` that equals the direct `Host`; clients without an `Origin` header must send `X-Quantum-Encryptor-Token`, and an invalid header never falls back to the cookie. `GET /api/health` issues the cookie only for an allowed direct `Host` and, when present, a matching `Origin`; forwarding headers are not trusted
- Generated-key cache and leave-page guards reduce accidental retention or loss but do not protect against developer tools, browser extensions, or malicious local software. Browser and operating-system settings determine downloaded private-key file permissions; the web app cannot guarantee POSIX mode `0600`.
- The local agent CLI accepts only workspace-relative paths, returns machine-readable JSON without secret material, and writes private keys plus decrypted outputs with owner-only permissions on POSIX systems; non-overwrite output creation uses exclusive file creation
- Native `liboqs` is loaded lazily and missing backend support disables key generation/encryption instead of crashing the app
- CI runs Python formatting, linting, type checks, unit tests, custom web UI build/type checks, API client tests, browser UI smoke, isolated installed-wheel checks, Python/npm dependency audits, locked runtime install, and a native `liboqs` integration test job pinned to the matching 0.16.0 release commit; repository CodeQL default setup provides static analysis
- See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for repository trust boundaries, assets, abuse cases, and invariants
- **Disclaimer**: This software has not undergone an independent security audit and should be reviewed before production use

## Project Structure

- `crypto_config.py` - Configuration parameters for cryptographic operations
- `crypto_core.py` - Core cryptographic functions (key generation, encryption, decryption)
- `api_app.py` - Local ASGI API and static web UI server
- `pqc_agent_tools.py` - Local JSON CLI for automation workflows
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
