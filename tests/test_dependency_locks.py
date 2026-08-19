import io
from pathlib import Path
import subprocess

import pytest

from scripts import check_dependency_locks as checker

SUPPORTED_TOOLCHAIN = {
    "platform": "Linux",
    "machine": "x86_64",
    "distribution": "ubuntu",
    "distribution-version": "24.04",
    "python": "3.13.15",
    "pip": "25.3",
    "pip-tools": "7.5.3",
    "packaging": "26.2",
    "build": "1.5.0",
    "click": "8.4.2",
    "pyproject-hooks": "1.2.0",
    "setuptools": "83.0.0",
    "wheel": "0.47.0",
    "node": "22.23.1",
    "npm": "10.9.8",
}


def write_lock_fixture(repository: Path) -> None:
    (repository / "pyproject.toml").write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0"]\n',
        encoding="utf-8",
    )
    (repository / "requirements.txt").write_text(
        "cryptography>=50.0.0\nhttptools>=0.8.0,<0.9\n",
        encoding="utf-8",
    )
    (repository / "requirements-dev.txt").write_text(
        "-r requirements.txt\npytest>=9\n",
        encoding="utf-8",
    )
    (repository / "requirements-lock.txt").write_text("runtime-lock\n", encoding="utf-8")
    (repository / "requirements-dev-lock.txt").write_text("development-lock\n", encoding="utf-8")
    (repository / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
    (repository / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")


def test_manifest_parity_rejects_changed_runtime_specifier(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    runtime_requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0"]\n',
        encoding="utf-8",
    )
    runtime_requirements.write_text("cryptography>=51.0.0\n", encoding="utf-8")

    with pytest.raises(checker.LockCheckError, match="cryptography"):
        checker.validate_manifest_parity(pyproject, runtime_requirements)


def test_manifest_parity_rejects_unexpected_runtime_only_dependency(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    runtime_requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0"]\n',
        encoding="utf-8",
    )
    runtime_requirements.write_text(
        "cryptography>=50.0.0\nrequests>=2\n",
        encoding="utf-8",
    )

    with pytest.raises(checker.LockCheckError, match="requests"):
        checker.validate_manifest_parity(pyproject, runtime_requirements)


def test_manifest_parity_rejects_project_dependency_missing_from_runtime_input(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    runtime_requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0", "starlette>=1.3.1,<2"]\n',
        encoding="utf-8",
    )
    runtime_requirements.write_text("cryptography>=50.0.0\n", encoding="utf-8")

    with pytest.raises(checker.LockCheckError, match="starlette"):
        checker.validate_manifest_parity(pyproject, runtime_requirements)


def test_manifest_parity_rejects_changed_httptools_exception(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    runtime_requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0"]\n',
        encoding="utf-8",
    )
    runtime_requirements.write_text(
        "cryptography>=50.0.0\nhttptools>=0.7\n",
        encoding="utf-8",
    )

    with pytest.raises(checker.LockCheckError, match="httptools"):
        checker.validate_manifest_parity(pyproject, runtime_requirements)


def test_manifest_parity_rejects_duplicate_project_dependency(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    runtime_requirements = tmp_path / "requirements.txt"
    pyproject.write_text(
        '[project]\ndependencies = ["cryptography>=50.0.0", "Cryptography<51"]\n',
        encoding="utf-8",
    )
    runtime_requirements.write_text("cryptography>=50.0.0\n", encoding="utf-8")

    with pytest.raises(checker.LockCheckError, match="Duplicate.*cryptography"):
        checker.validate_manifest_parity(pyproject, runtime_requirements)


@pytest.mark.parametrize(
    ("field", "unsupported_value"),
    [
        ("platform", "Darwin"),
        ("machine", "arm64"),
        ("distribution", "alpine"),
        ("distribution-version", "24.10"),
        ("python", "3.13.14"),
        ("pip", "26.0"),
        ("pip-tools", "7.5.2"),
        ("packaging", "26.1"),
        ("build", "1.4.0"),
        ("click", "8.3.0"),
        ("pyproject-hooks", "1.1.0"),
        ("setuptools", "82.0.0"),
        ("wheel", "0.46.0"),
        ("node", "22.22.0"),
        ("npm", "11.0.0"),
    ],
)
def test_toolchain_validation_rejects_noncanonical_value(field, unsupported_value):
    actual = SUPPORTED_TOOLCHAIN.copy()
    actual[field] = unsupported_value

    with pytest.raises(checker.LockCheckError, match=field):
        checker.validate_toolchain(actual)


def test_lock_check_reports_stale_runtime_lock_without_modifying_repository(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)

    def regenerate_runtime_lock(command, **kwargs):
        working_directory = Path(kwargs["cwd"])
        if command[-1] == "requirements.txt":
            (working_directory / "requirements-lock.txt").write_text("regenerated-lock\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(checker.LockCheckError, match="requirements-lock.txt"):
        checker.check_dependency_locks(
            repository,
            runner=regenerate_runtime_lock,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )

    assert (repository / "requirements-lock.txt").read_text(encoding="utf-8") == "runtime-lock\n"


def test_lock_check_reports_stale_development_lock(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)

    def regenerate_development_lock(command, **kwargs):
        working_directory = Path(kwargs["cwd"])
        if command[-1] == "requirements-dev.txt":
            (working_directory / "requirements-dev-lock.txt").write_text(
                "regenerated-development-lock\n",
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(checker.LockCheckError, match="requirements-dev-lock.txt"):
        checker.check_dependency_locks(
            repository,
            runner=regenerate_development_lock,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )


def test_lock_check_reports_stale_npm_lock(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)

    def regenerate_npm_lock(command, **kwargs):
        working_directory = Path(kwargs["cwd"])
        if Path(command[0]).name == "npm" and command[1] == "install":
            (working_directory / "package-lock.json").write_text(
                '{"lockfileVersion":3,"stale":true}\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(checker.LockCheckError, match="package-lock.json"):
        checker.check_dependency_locks(
            repository,
            runner=regenerate_npm_lock,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )


def test_lock_check_runs_canonical_commands_in_a_cleaned_temporary_copy(tmp_path, monkeypatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)
    monkeypatch.setenv("PIP_INDEX_URL", "https://untrusted.example/simple")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://extra.example/simple")
    monkeypatch.setenv("npm_config_legacy_peer_deps", "true")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/python")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/untrusted/hook.js")
    monkeypatch.setenv("GITHUB_TOKEN", "not-for-child-processes")
    calls = []

    def record_generator(command, **kwargs):
        calls.append((command, Path(kwargs["cwd"]), kwargs["env"], kwargs["check"]))
        return subprocess.CompletedProcess(command, 0)

    checker.check_dependency_locks(
        repository,
        runner=record_generator,
        toolchain=SUPPORTED_TOOLCHAIN,
        temp_parent=tmp_path,
    )

    python_executable = checker.os.path.abspath(checker.sys.executable)
    npm_executable = checker._resolve_executable("npm")
    assert [call[0] for call in calls] == [
        [
            python_executable,
            "-m",
            "piptools",
            "compile",
            "--generate-hashes",
            "--output-file=requirements-lock.txt",
            "requirements.txt",
        ],
        [
            python_executable,
            "-m",
            "piptools",
            "compile",
            "--allow-unsafe",
            "--generate-hashes",
            "--output-file=requirements-dev-lock.txt",
            "requirements-dev.txt",
        ],
        [
            npm_executable,
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
    ]
    working_directories = {call[1] for call in calls}
    assert len(working_directories) == 1
    working_directory = working_directories.pop()
    assert working_directory != repository
    assert not working_directory.exists()
    assert all(call[3] is True for call in calls)
    assert all(call[2]["PIP_INDEX_URL"] == "https://pypi.org/simple" for call in calls)
    assert all("PIP_EXTRA_INDEX_URL" not in call[2] for call in calls)
    assert all(call[2]["LC_ALL"] == "C.UTF-8" and call[2]["TZ"] == "UTC" for call in calls)
    assert all(call[2].get("npm_config_legacy_peer_deps") is None for call in calls)
    assert all(call[2]["PYTHONNOUSERSITE"] == "1" for call in calls)
    assert all("PYTHONPATH" not in call[2] and "NODE_OPTIONS" not in call[2] for call in calls)
    assert all("GITHUB_TOKEN" not in call[2] for call in calls)
    assert all(Path(call[2]["HOME"]).is_relative_to(working_directory) for call in calls)
    assert calls[0][2]["CUSTOM_COMPILE_COMMAND"].startswith("pip-compile --generate-hashes")
    assert calls[1][2]["CUSTOM_COMPILE_COMMAND"].startswith("pip-compile --allow-unsafe")
    assert "CUSTOM_COMPILE_COMMAND" not in calls[2][2]
    assert (repository / "requirements-lock.txt").read_text(encoding="utf-8") == "runtime-lock\n"
    assert (repository / "requirements-dev-lock.txt").read_text(encoding="utf-8") == "development-lock\n"
    assert (repository / "package-lock.json").read_text(encoding="utf-8") == '{"lockfileVersion":3}\n'


def test_stale_lock_diagnostic_bounds_large_diff(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)
    (repository / "requirements-lock.txt").write_text(
        "".join(f"original-{index}\n" for index in range(200)),
        encoding="utf-8",
    )

    def replace_runtime_lock(command, **kwargs):
        if command[-1] == "requirements.txt":
            Path(kwargs["cwd"], "requirements-lock.txt").write_text(
                "".join(f"regenerated-{index}\n" for index in range(200)),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(checker.LockCheckError) as caught:
        checker.check_dependency_locks(
            repository,
            runner=replace_runtime_lock,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )

    diagnostic_lines = str(caught.value).splitlines()
    assert len(diagnostic_lines) <= 82
    assert diagnostic_lines[-1] == "... diff truncated after 80 lines ..."


def test_lock_check_wraps_generator_failure_and_cleans_temporary_copy(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)

    def fail_generator(command, **kwargs):
        raise subprocess.CalledProcessError(7, command)

    with pytest.raises(checker.LockCheckError, match=r"pip-compile.*exit code 7"):
        checker.check_dependency_locks(
            repository,
            runner=fail_generator,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )

    assert list(tmp_path.glob("quantum-encryptor-lock-check-*")) == []


def test_lock_check_wraps_generator_timeout_and_cleans_temporary_copy(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)

    def time_out_generator(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with pytest.raises(checker.LockCheckError, match=r"pip-compile.*timed out"):
        checker.check_dependency_locks(
            repository,
            runner=time_out_generator,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )

    assert list(tmp_path.glob("quantum-encryptor-lock-check-*")) == []


def test_lock_check_reports_missing_input_before_running_generators(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)
    (repository / "requirements-dev-lock.txt").unlink()
    calls = []

    def record_unexpected_call(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(checker.LockCheckError, match="requirements-dev-lock.txt"):
        checker.check_dependency_locks(
            repository,
            runner=record_unexpected_call,
            toolchain=SUPPORTED_TOOLCHAIN,
            temp_parent=tmp_path,
        )

    assert calls == []


def test_toolchain_discovery_reads_python_and_node_tool_versions():
    def fake_version_command(command, **kwargs):
        executable = Path(command[0]).name
        output = {"node": "v22.23.1\n", "npm": "10.9.8\n"}[executable]
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    package_versions = {
        name: version
        for name, version in SUPPORTED_TOOLCHAIN.items()
        if name not in {"platform", "machine", "python", "node", "npm"}
    }

    actual = checker.discover_toolchain(
        runner=fake_version_command,
        distribution_version=package_versions.__getitem__,
        platform_name=lambda: "Linux",
        machine_name=lambda: "x86_64",
        python_version=lambda: "3.13.15",
        linux_distribution=lambda: ("ubuntu", "24.04"),
        executable_finder=lambda name: f"/canonical/bin/{name}",
    )

    assert actual == SUPPORTED_TOOLCHAIN


def test_linux_distribution_reads_ubuntu_release(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")

    assert checker._linux_distribution(os_release) == ("ubuntu", "24.04")


def test_main_returns_failure_and_reports_manifest_error(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)
    (repository / "requirements.txt").write_text("cryptography>=51.0.0\n", encoding="utf-8")
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = checker.main(
        repository=repository,
        runner=lambda *args, **kwargs: pytest.fail("generator should not run for an invalid manifest"),
        toolchain=SUPPORTED_TOOLCHAIN,
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 1
    assert stdout.getvalue() == ""
    assert "Dependency lock check failed" in stderr.getvalue()
    assert "cryptography" in stderr.getvalue()


def test_main_returns_success_after_all_generated_locks_match(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    write_lock_fixture(repository)
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = checker.main(
        repository=repository,
        runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
        toolchain=SUPPORTED_TOOLCHAIN,
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 0
    assert stdout.getvalue() == "Dependency manifests and lock files are consistent.\n"
    assert stderr.getvalue() == ""
