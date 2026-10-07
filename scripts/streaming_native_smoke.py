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

        def run(*arguments: str, expect_error: str | None = None) -> dict:
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
            if expect_error is not None:
                assert result.returncode != 0 and payload.get("ok") is False
                assert payload.get("error_code") == expect_error
                return payload
            if result.returncode or payload.get("ok") is not True:
                raise RuntimeError(f"Native CLI check failed: {payload.get('error_code', 'unknown')}")
            return payload

        public = str(relative / "public.pem")
        private = str(relative / "private.pem")
        recovered_public = str(relative / "recovered-public.pem")
        updated_private = str(relative / "updated-private.pem")
        source = str(relative / "source.bin")
        encrypted = str(relative / "encrypted.pqc")
        restored = str(relative / "restored.bin")
        generated = run("generate-keys", "--public-out", public, "--private-out", private)
        recovered = run(
            "recover-public-key",
            "--private-key",
            private,
            "--output",
            recovered_public,
            "--compare-public-key",
            public,
        )
        assert recovered["matches_supplied_public_key"] is True
        assert recovered["public_key_fingerprint"] == generated["public_key_fingerprint"]
        assert (root / recovered_public).read_bytes() == (root / public).read_bytes()
        original_private = (root / private).read_bytes()
        environment["PQC_NEW_PRIVATE_KEY_PASSWORD"] = secrets.token_urlsafe(32)
        updated = run(
            "change-key-password",
            "--private-key",
            private,
            "--output",
            updated_private,
            "--new-password-env",
            "PQC_NEW_PRIVATE_KEY_PASSWORD",
        )
        assert updated["public_key_fingerprint"] == generated["public_key_fingerprint"]
        assert (root / updated_private).read_bytes() != original_private
        assert (root / private).read_bytes() == original_private
        block = os.urandom(1024 * 1024)
        with (root / source).open("wb") as output:
            for _ in range(args.size_mib):
                output.write(block)
        run("encrypt", "--input", source, "--public-key", recovered_public, "--output", encrypted)
        report = run("verify-file", "--input", encrypted, "--private-key", private)
        assert report["bytes_verified"] == size
        run(
            "decrypt",
            "--input",
            encrypted,
            "--private-key",
            updated_private,
            "--password-env",
            "PQC_NEW_PRIVATE_KEY_PASSWORD",
            "--output",
            restored,
        )
        assert (root / restored).stat().st_size == size
        assert digest(root / restored) == digest(root / source)
        if os.name == "posix":
            assert (root / restored).stat().st_mode & 0o777 == 0o600
            assert (root / updated_private).stat().st_mode & 0o777 == 0o600

        folder = workspace / "documents"
        (folder / "nested" / "empty").mkdir(parents=True)
        (folder / "notes.txt").write_text("Confidential backup acceptance fixture", encoding="utf-8")
        (folder / "nested" / "résumé.bin").write_bytes(os.urandom(65536))
        (folder / "zero.bin").write_bytes(b"")
        backup = str(relative / "documents.pqc")
        destination = str(relative / "restored-documents")
        packed = run(
            "backup-directory",
            "--input",
            str(relative / "documents"),
            "--public-key",
            public,
            "--expected-recipient-fingerprint",
            str(generated["public_key_fingerprint"]),
            "--output",
            backup,
        )
        unpacked = run(
            "restore-directory",
            "--input",
            backup,
            "--private-key",
            updated_private,
            "--password-env",
            "PQC_NEW_PRIVATE_KEY_PASSWORD",
            "--output",
            destination,
        )
        assert packed["files"] == unpacked["files"] == 3
        assert packed["source_bytes"] == unpacked["restored_bytes"]
        assert (root / destination / "nested" / "empty").is_dir()
        for original in folder.rglob("*"):
            restored_entry = root / destination / original.relative_to(folder)
            if original.is_file():
                assert digest(original) == digest(restored_entry)
                assert restored_entry.stat().st_mode & 0o777 == 0o600
        run(
            "restore-directory",
            "--input",
            backup,
            "--private-key",
            private,
            "--output",
            destination,
            expect_error="output_exists",
        )
        damaged = bytearray((root / backup).read_bytes())
        damaged[-1] ^= 1
        damaged_path = str(relative / "damaged-backup.pqc")
        (root / damaged_path).write_bytes(damaged)
        rejected = str(relative / "rejected-restore")
        run(
            "restore-directory",
            "--input",
            damaged_path,
            "--private-key",
            private,
            "--output",
            rejected,
            expect_error="decryption_failed",
        )
        assert not (root / rejected).exists()

        peak_mib = None
        if sys.platform in {"darwin", "linux"}:
            import resource

            peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            peak_mib = peak / (1024 * 1024 if sys.platform == "darwin" else 1024)
            assert peak_mib < 256, f"Peak child RSS exceeded 256 MiB: {peak_mib:.1f} MiB"
        print(
            json.dumps(
                {
                    "ok": True,
                    "bytes_verified": size,
                    "peak_child_rss_mib": peak_mib,
                    "public_key_recovered": True,
                    "private_key_password_changed": True,
                    "directory_backup_restored": True,
                }
            )
        )


if __name__ == "__main__":
    main()
