import os
from pathlib import Path
import subprocess

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
