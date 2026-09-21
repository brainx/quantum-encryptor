"""Exercise native large-file jobs over loopback HTTP without buffering file bodies."""

from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPConnection, HTTPResponse
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess  # nosec B404
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlencode

CHUNK_BYTES = 1024 * 1024
JSON_LIMIT = 1024 * 1024


class SmokeFailure(RuntimeError):
    """A failed acceptance assertion with a fixed, non-sensitive message."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


class Client:
    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"
        self.token = token
        self.cookie = ""
        self.health_checks = 0
        self.max_health_seconds = 0.0

    def connection(self, timeout: float = 15) -> HTTPConnection:
        return HTTPConnection("127.0.0.1", self.port, timeout=timeout, blocksize=CHUNK_BYTES)

    def headers(self) -> dict[str, str]:
        return {"Origin": self.origin, "Cookie": self.cookie}

    @staticmethod
    def decode(response: HTTPResponse, expected_status: int | tuple[int, ...] = 200) -> dict[str, Any]:
        payload = response.read(JSON_LIMIT + 1)
        require(len(payload) <= JSON_LIMIT, "JSON response exceeded its acceptance bound.")
        statuses = (expected_status,) if isinstance(expected_status, int) else expected_status
        require(response.status in statuses, f"Unexpected HTTP status: {response.status}.")
        decoded = json.loads(payload)
        require(isinstance(decoded, dict), "JSON response was not an object.")
        if response.status == 200:
            require(decoded.get("ok") is True, "API operation did not succeed.")
        return decoded

    def health(self) -> dict[str, Any]:
        connection = self.connection(timeout=2)
        started = time.monotonic()
        try:
            connection.request("GET", "/api/health", headers={"Origin": self.origin})
            response = connection.getresponse()
            cookie = SimpleCookie()
            cookie.load(response.getheader("Set-Cookie", ""))
            credential = cookie.get("qe_api_token")
            if credential is None:
                raise SmokeFailure("Health did not identify the owned local service.")
            require(
                secrets.compare_digest(credential.value, self.token),
                "Health did not identify the owned local service.",
            )
            self.cookie = f"qe_api_token={credential.value}"
            return self.decode(response)
        finally:
            self.max_health_seconds = max(self.max_health_seconds, time.monotonic() - started)
            connection.close()

    def post(self, path: str, fields: dict[str, str] | None = None) -> dict[str, Any]:
        body = urlencode(fields or {}).encode("ascii")
        headers = dict(self.headers(), **{"Content-Type": "application/x-www-form-urlencoded"})
        connection = self.connection()
        try:
            connection.request("POST", path, body=body, headers=headers)
            return self.decode(connection.getresponse())
        finally:
            connection.close()

    def upload(self, identifier: str, source: Path) -> None:
        connection = self.connection()
        try:
            with source.open("rb") as file:
                connection.request(
                    "PUT",
                    f"/api/jobs/{identifier}/upload",
                    body=file,
                    headers=dict(
                        self.headers(),
                        **{"Content-Type": "application/octet-stream", "Content-Length": str(source.stat().st_size)},
                    ),
                )
                require(self.decode(connection.getresponse())["job"]["state"] == "ready", "Upload was not ready.")
        finally:
            connection.close()

    def start(self, identifier: str, pem: str, password: str) -> dict[str, Any]:
        boundary = secrets.token_hex(24)
        body = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="key"; filename="key.pem"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n{pem}\r\n"
            f'--{boundary}\r\nContent-Disposition: form-data; name="password"\r\n\r\n{password}\r\n'
            f"--{boundary}--\r\n"
        ).encode("ascii")
        connection = self.connection()
        try:
            connection.request(
                "POST",
                f"/api/jobs/{identifier}/start",
                body=body,
                headers=dict(self.headers(), **{"Content-Type": f"multipart/form-data; boundary={boundary}"}),
            )
            return self.decode(connection.getresponse())["job"]
        finally:
            connection.close()

    def wait(self, identifier: str, job: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + 180
        while job["state"] in {"running", "cancelling"}:
            require(time.monotonic() < deadline, "The large-file job exceeded its time limit.")
            require(self.health().get("backendReady") is True, "Health failed while a job was active.")
            self.health_checks += 1
            job = self.post(f"/api/jobs/{identifier}/status")["job"]
            if job["state"] == "running":
                time.sleep(0.01)
        require(job["state"] == "complete", "A native large-file job failed.")
        return job

    def check_download_requires_cookie(self, identifier: str) -> None:
        connection = self.connection()
        try:
            connection.request(
                "POST",
                f"/api/jobs/{identifier}/download",
                body=b"",
                headers={"Origin": self.origin, "X-Quantum-Encryptor-Token": self.token},
            )
            error = self.decode(connection.getresponse(), expected_status=403)
            require(error.get("error_code") == "missing_api_token", "Download accepted a header-only credential.")
        finally:
            connection.close()

    def clear(self, identifier: str) -> None:
        # Receiving all bytes can precede the server's final response cleanup.
        deadline = time.monotonic() + 5
        while True:
            connection = self.connection(timeout=2)
            try:
                connection.request("POST", f"/api/jobs/{identifier}/clear", body=b"", headers=self.headers())
                result = self.decode(connection.getresponse(), expected_status=(200, 409))
            finally:
                connection.close()
            if result.get("ok") is True:
                return
            require(result.get("error_code") == "download_busy", "The finished job could not be cleared.")
            require(time.monotonic() < deadline, "The download did not release its job before the cleanup deadline.")
            time.sleep(0.01)

    def download(self, identifier: str, output: Path, expected_size: int) -> bytes:
        connection = self.connection()
        digest = hashlib.sha256()
        count = 0
        try:
            connection.request("POST", f"/api/jobs/{identifier}/download", body=b"", headers=self.headers())
            response = connection.getresponse()
            require(response.status == 200, "Authenticated download failed.")
            require(response.getheader("Content-Length") == str(expected_size), "Download length metadata differed.")
            require("no-store" in response.getheader("Cache-Control", ""), "Download was missing no-store protection.")
            with output.open("xb") as file:
                while chunk := response.read(CHUNK_BYTES):
                    count += len(chunk)
                    require(count <= expected_size, "Download exceeded its declared length.")
                    file.write(chunk)
                    digest.update(chunk)
            require(count == expected_size, "Download was truncated.")
        finally:
            connection.close()
        return digest.digest()


def stop_server(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def acceptance(size_mib: int) -> dict[str, Any]:
    size = size_mib * CHUNK_BYTES
    root = Path(__file__).resolve().parent.parent
    temporary_root = root / "tmp"
    temporary_root.mkdir(exist_ok=True)
    require(
        shutil.disk_usage(temporary_root).free >= size * 6 + 128 * CHUNK_BYTES,
        "Insufficient free disk space for the HTTP acceptance check.",
    )
    with tempfile.TemporaryDirectory(prefix="large-file-api-", dir=temporary_root) as directory:
        workspace = Path(directory)
        source = workspace / "source.bin"
        encrypted = workspace / "encrypted.pqc"
        restored = workspace / "restored.bin"
        block = os.urandom(CHUNK_BYTES)
        expected_digest = hashlib.sha256()
        with source.open("xb") as file:
            for _ in range(size_mib):
                file.write(block)
                expected_digest.update(block)
        token, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = dict(os.environ, PORT=str(port), QUANTUM_ENCRYPTOR_API_TOKEN=token, TMPDIR=str(workspace))
        # Keep child diagnostics private and bounded by the short-lived local run; never print credentials or PEMs.
        with tempfile.TemporaryFile(mode="w+b", dir=workspace) as log:
            process = subprocess.Popen(  # nosec B603 - fixed local module and interpreter, credentials only in env
                [sys.executable, "-m", "api_app"], cwd=root, env=environment, stdout=log, stderr=log
            )
            client = Client(port, token)
            try:
                deadline = time.monotonic() + 20
                while True:
                    require(process.poll() is None, "The owned API server exited during startup.")
                    try:
                        health = client.health()
                        break
                    except (ConnectionError, TimeoutError):
                        require(time.monotonic() < deadline, "API readiness exceeded its time limit.")
                        time.sleep(0.05)
                require(health.get("backendReady") is True, "The native post-quantum backend is unavailable.")
                require(health["maxFileBytes"] == 100 * CHUNK_BYTES, "The existing small-file limit changed.")
                require(health["largeFiles"]["maxPlaintextBytes"] >= size, "The large-file limit is too small.")
                keys = client.post("/api/keys/generate", {"password": password})
                for mode, input_file in (("encrypt", source), ("decrypt", encrypted), ("verify", encrypted)):
                    identifier = client.post(
                        "/api/jobs", {"mode": mode, "filename": input_file.name, "size": str(input_file.stat().st_size)}
                    )["job"]["id"]
                    client.upload(identifier, input_file)
                    pem = keys["publicPem"] if mode == "encrypt" else keys["privatePem"]
                    report = client.wait(
                        identifier, client.start(identifier, pem, "" if mode == "encrypt" else password)
                    )
                    if mode == "verify":
                        verification = report["verification"]
                        require(verification["verified"] is True, "File verification did not authenticate.")
                        require(verification["bytesVerified"] == size, "Verified plaintext size differed.")
                        require(
                            verification["publicKeyFingerprint"] == keys["publicKeyFingerprint"],
                            "Verification used a different public key identity.",
                        )
                        require("result" not in report, "Verification exposed a downloadable plaintext result.")
                    else:
                        client.check_download_requires_cookie(identifier)
                        output = encrypted if mode == "encrypt" else restored
                        actual_digest = client.download(identifier, output, report["result"]["bytes"])
                        if mode == "decrypt":
                            require(output.stat().st_size == size, "Restored plaintext size differed.")
                            require(actual_digest == expected_digest.digest(), "Restored plaintext digest differed.")
                    client.clear(identifier)
                require(client.health_checks > 0, "No health request was made while a job was active.")
                require(client.max_health_seconds < 2, "Health responses exceeded the responsiveness limit.")
            finally:
                stop_server(process)
        peak_mib = None
        if sys.platform in {"darwin", "linux"}:
            import resource

            peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            peak_mib = peak / (1024 * 1024 if sys.platform == "darwin" else 1024)
            require(peak_mib < 256, "Peak server RSS exceeded 256 MiB.")
        return {
            "ok": True,
            "bytes_verified": size,
            "peak_server_rss_mib": peak_mib,
            "health_checks_during_jobs": client.health_checks,
            "max_health_response_seconds": round(client.max_health_seconds, 3),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=128)
    args = parser.parse_args()
    if not 1 <= args.size_mib <= 1024:
        parser.error("--size-mib must be between 1 and 1024")
    try:
        result = acceptance(args.size_mib)
    except SmokeFailure as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "Unexpected HTTP acceptance failure."}))
        raise SystemExit(1) from None
    print(json.dumps(result))


if __name__ == "__main__":
    main()
