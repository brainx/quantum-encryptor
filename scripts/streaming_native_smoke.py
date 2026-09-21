"""Exercise the installed native backend and CLI with a bounded-memory large file."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile


def digest(path: Path) -> bytes:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return result.digest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.size_mib <= 1024:
        parser.error("--size-mib must be between 1 and 1024")
    size = args.size_mib * 1024 * 1024
    root = Path(__file__).resolve().parent.parent
    temporary_root = root / "tmp"
    temporary_root.mkdir(exist_ok=True)
    if shutil.disk_usage(temporary_root).free < size * 4 + 128 * 1024 * 1024:
        raise RuntimeError("Insufficient free disk space for the streaming acceptance check.")
    environment = dict(os.environ, PQC_PRIVATE_KEY_PASSWORD=secrets.token_urlsafe(32))

    with tempfile.TemporaryDirectory(prefix="streaming-native-", dir=temporary_root) as directory:
        workspace = Path(directory)
        relative = workspace.relative_to(root)

        def run(*arguments: str) -> dict:
            result = subprocess.run(  # nosec B603 - fixed local interpreter/module, argument array, synthetic inputs
                [sys.executable, "-m", "pqc_agent_tools", *arguments],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            payload = json.loads(result.stdout)
            if result.returncode or payload.get("ok") is not True:
                raise RuntimeError(f"Native CLI check failed: {payload.get('error_code', 'unknown')}")
            return payload

        public = str(relative / "public.pem")
        private = str(relative / "private.pem")
        source = str(relative / "source.bin")
        encrypted = str(relative / "encrypted.pqc")
        restored = str(relative / "restored.bin")
        run("generate-keys", "--public-out", public, "--private-out", private)
        block = os.urandom(1024 * 1024)
        with (root / source).open("wb") as output:
            for _ in range(args.size_mib):
                output.write(block)
        run("encrypt", "--input", source, "--public-key", public, "--output", encrypted)
        report = run("verify-file", "--input", encrypted, "--private-key", private)
        assert report["bytes_verified"] == size
        run("decrypt", "--input", encrypted, "--private-key", private, "--output", restored)
        assert (root / restored).stat().st_size == size
        assert digest(root / restored) == digest(root / source)
        if os.name == "posix":
            assert (root / restored).stat().st_mode & 0o777 == 0o600

        peak_mib = None
        if sys.platform in {"darwin", "linux"}:
            import resource

            peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            peak_mib = peak / (1024 * 1024 if sys.platform == "darwin" else 1024)
            assert peak_mib < 256, f"Peak child RSS exceeded 256 MiB: {peak_mib:.1f} MiB"
        print(json.dumps({"ok": True, "bytes_verified": size, "peak_child_rss_mib": peak_mib}))


if __name__ == "__main__":
    main()
