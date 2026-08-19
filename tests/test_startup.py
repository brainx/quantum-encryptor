import ast
import os
from pathlib import Path
import subprocess
import sys

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_start_script_uses_api_app_when_legacy_flag_is_set(tmp_path):
    argv_log = tmp_path / "interpreter-argv.txt"
    interpreter = tmp_path / "python-stub"
    startup_script = tmp_path / "start.sh"
    static_app = tmp_path / "static" / "app"
    static_app.mkdir(parents=True)
    (static_app / "index.html").write_text("<!doctype html>", encoding="utf-8")
    startup_script.write_text((REPOSITORY_ROOT / "start.sh").read_text(encoding="utf-8"), encoding="utf-8")
    startup_script.chmod(0o755)
    interpreter.write_text(
        "#!/usr/bin/env sh\n" "set -eu\n" 'printf "%s\\n" "$@" > "$STARTUP_ARGV_LOG"\n',
        encoding="utf-8",
    )
    interpreter.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "PYTHON": str(interpreter),
            "LEGACY_STREAMLIT": "1",
            "SKIP_WEB_BUILD": "1",
            "STARTUP_ARGV_LOG": str(argv_log),
        }
    )

    completed = subprocess.run(
        [str(startup_script)],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert argv_log.read_text(encoding="utf-8").splitlines() == ["-m", "api_app"]


@pytest.mark.parametrize("port", ["", "0", "65536", "abc", " 4000 "])
def test_import_rejects_invalid_port_configuration_without_token_leakage(port):
    token = "test-token-must-not-appear"
    environment = os.environ.copy()
    environment.update(
        {
            "PORT": port,
            "PYTHONPATH": str(REPOSITORY_ROOT),
            "QUANTUM_ENCRYPTOR_API_TOKEN": token,
        }
    )

    completed = subprocess.run(
        [sys.executable, "-c", "import api_app"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "PORT must be an integer from 1 through 65535." in output
    assert token not in output


def test_import_rejects_huge_decimal_port_with_stable_error():
    environment = os.environ.copy()
    environment.update(
        {
            "PORT": "9" * 5000,
            "PYTHONPATH": str(REPOSITORY_ROOT),
        }
    )

    completed = subprocess.run(
        [sys.executable, "-c", "import api_app"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.rstrip().endswith("ValueError: PORT must be an integer from 1 through 65535.")
    assert "Exceeds the limit" not in completed.stderr


def test_start_script_preserves_explicitly_empty_port_for_shared_validation(tmp_path):
    interpreter = tmp_path / "python-stub"
    startup_script = tmp_path / "start.sh"
    static_app = tmp_path / "static" / "app"
    static_app.mkdir(parents=True)
    (static_app / "index.html").write_text("<!doctype html>", encoding="utf-8")
    startup_script.write_text((REPOSITORY_ROOT / "start.sh").read_text(encoding="utf-8"), encoding="utf-8")
    startup_script.chmod(0o755)
    interpreter.write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        'exec "$REAL_PYTHON" -c \'import os; print("PORT_VALUE=" + repr(os.environ["PORT"])); import api_app\'\n',
        encoding="utf-8",
    )
    interpreter.chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "PORT": "",
            "PYTHON": str(interpreter),
            "PYTHONPATH": str(REPOSITORY_ROOT),
            "REAL_PYTHON": sys.executable,
            "SKIP_WEB_BUILD": "1",
        }
    )

    completed = subprocess.run(
        [str(startup_script)],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "PORT_VALUE=''" in output
    assert "PORT must be an integer from 1 through 65535." in output


@pytest.mark.parametrize(
    ("vite_dev_value", "expected_authorities"),
    [
        ("1", [("http", "127.0.0.1", 4000), ("http", "127.0.0.1", 4001)]),
        (None, [("http", "127.0.0.1", 4000)]),
        ("", [("http", "127.0.0.1", 4000)]),
        ("0", [("http", "127.0.0.1", 4000)]),
        ("true", [("http", "127.0.0.1", 4000)]),
        (" 1", [("http", "127.0.0.1", 4000)]),
        ("1 ", [("http", "127.0.0.1", 4000)]),
    ],
)
def test_vite_development_authority_requires_exact_environment_opt_in(vite_dev_value, expected_authorities):
    environment = os.environ.copy()
    environment.update({"PORT": "4000", "PYTHONPATH": str(REPOSITORY_ROOT)})
    if vite_dev_value is None:
        environment.pop("QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV", None)
    else:
        environment["QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV"] = vite_dev_value

    completed = subprocess.run(
        [sys.executable, "-c", "import api_app; print(sorted(api_app.ALLOWED_BROWSER_AUTHORITIES))"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert ast.literal_eval(completed.stdout) == expected_authorities
