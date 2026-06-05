# Quantum Encryptor

A post-quantum cryptography tool for file encryption using quantum-resistant algorithms. This application combines post-quantum Key Encapsulation Mechanisms (KEM) with classical symmetric encryption to protect files against future quantum computer threats.

![Quantum Encryption](https://img.shields.io/badge/Encryption-Post--Quantum-blue)
![Python Version](https://img.shields.io/badge/Python-3.10--3.13-green)

## Features

- **Post-Quantum Security**: Uses ML-KEM-768, with Kyber768 retained as a legacy compatibility alias
- **Hybrid Encryption**: Combines quantum-resistant key exchange with AES-256-GCM symmetric encryption
- **Password-Protected Keys**: Optional password encryption for private keys
- **User-Friendly Interface**: Simple web-based UI built with Streamlit
- **PEM Key Format**: Keys stored in PEM-like format with quantum algorithm extensions

## Requirements

- Python 3.10 through 3.13
- Open Quantum Safe native `liboqs` shared library
- Open Quantum Safe `liboqs-python` wrapper, which imports as `oqs`
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/brainx/quantum-encryptor.git
   cd quantum-encryptor
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
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

   The app listens on `127.0.0.1:4000` by default. Set `PORT` to override the local development port:
   ```bash
   PORT=4001 ./start.sh
   ```

   Set `PYTHON` if you want the wrapper scripts to use a specific interpreter:
   ```bash
   PYTHON=.venv/bin/python ./start.sh
   PYTHON=.venv/bin/python ./test.sh
   ```

2. Open the web interface in your browser. You can:
   - Generate a new post-quantum key pair
   - Encrypt files using a recipient's public key
   - Decrypt files using your private key
   - Access key utilities

## Screenshots

Representative UI screenshots are available in [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md).

### Key Generation

1. Select "Generate Keys" from the sidebar
2. Choose whether to password-protect your private key
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
4. Enter your password if the private key is password-protected
5. Download the decrypted file

## Security Considerations

- Encrypted files use KEM-derived AES-256-GCM keys and authenticate file header metadata as associated data in format version 3
- Private key password protection uses PBKDF2-HMAC-SHA256 and AES-256-GCM
- The web UI enforces a 100 MiB per-file processing limit because files are handled in memory
- Native `liboqs` is loaded lazily and missing backend support disables key generation/encryption instead of crashing the app
- **Disclaimer**: This software has not undergone an independent security audit and should be reviewed before production use

## Project Structure

- `crypto_config.py` - Configuration parameters for cryptographic operations
- `crypto_core.py` - Core cryptographic functions (key generation, encryption, decryption)
- `pqc_app.py` - Streamlit web application interface
- `start.sh` - Local application startup script
- `test.sh` - Test runner
- `pyproject.toml` / `setup.py` - Packaging metadata

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) for liboqs implementation
- [NIST](https://www.nist.gov/pqcrypto) for leading the post-quantum cryptography standardization effort
