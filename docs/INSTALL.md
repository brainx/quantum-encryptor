# Detailed Installation Guide

This guide covers local installation for the Quantum Encryptor application.

## Prerequisites

- Python 3.10 through 3.13
- pip
- Native Open Quantum Safe `liboqs`
- `liboqs-python`, installed from `requirements.txt`
- C/C++ build tools and CMake if you build `liboqs` from source

The application checks for a native `liboqs` shared library before importing the Python wrapper. This prevents startup, tests, and imports from unexpectedly cloning or building native code.

## Python Environment

Create and activate a virtual environment from the project root:

```bash
python3.13 -m venv .venv
. .venv/bin/activate
```

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

For development and verification:

```bash
pip install -r requirements-dev.txt
```

## Native liboqs

Install `liboqs` separately and make sure the shared library is visible to the dynamic linker. If it is not installed in a standard library path, set `OQS_INSTALL_PATH` to the install prefix:

```bash
export OQS_INSTALL_PATH=/path/to/liboqs/install
```

The prefix should contain one of these shared-library locations:

- `lib/liboqs.so` or `lib/liboqs.dylib`
- `lib64/liboqs.so`
- `bin/oqs.dll` or `bin/liboqs.dll`

### Build From Source

Use the current Open Quantum Safe `liboqs` build instructions for your platform. A typical Unix-like source build is:

```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/path/to/liboqs/install
cmake --build build --parallel
cmake --install build
```

Then return to the project root and export `OQS_INSTALL_PATH` as shown above.

## Start The App

Use the project wrapper:

```bash
./start.sh
```

The default local address is `127.0.0.1:4000`. Override the port with:

```bash
PORT=4001 ./start.sh
```

Use `PYTHON` to force a specific interpreter:

```bash
PYTHON=.venv/bin/python ./start.sh
```

## Verify Installation

Run the test wrapper:

```bash
PYTHON=.venv/bin/python ./test.sh
```

When native `liboqs` is not available, backend-dependent tests are skipped and non-backend validation still runs. With native `liboqs` available, the key generation and file encryption/decryption tests exercise the real OQS path.

You can also check the available KEM mechanisms directly:

```python
import oqs

getter = getattr(oqs, "get_enabled_kem_mechanisms", None)
if getter is None:
    getter = oqs.get_enabled_KEM_mechanisms

print("ML-KEM-768" in getter() or "Kyber768" in getter())
```

## Troubleshooting

### Native liboqs Not Found

If the app reports that the post-quantum backend is not ready:

1. Confirm `liboqs` was built with shared libraries enabled.
2. Confirm `OQS_INSTALL_PATH` points to the install prefix, not directly to `lib/`.
3. Re-run `PYTHON=.venv/bin/python ./test.sh`.

### Unsupported Algorithm

The application accepts `ML-KEM-768` and the legacy compatibility alias `Kyber768`. If neither is enabled in your `liboqs` build, rebuild or install a `liboqs` version that includes ML-KEM/Kyber KEM support.
