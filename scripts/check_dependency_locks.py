#!/usr/bin/env python3
"""Verify that dependency manifests and generated locks agree."""

import difflib
from importlib import metadata
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, TextIO

if sys.version_info >= (3, 11):
    import tomllib as toml_parser
else:  # Python 3.10 support; tomli is in the dev toolchain.
    import tomli as toml_parser

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

ALLOWED_RUNTIME_ONLY_REQUIREMENTS = {
    "httptools": Requirement("httptools>=0.8.0,<0.9"),
}
EXPECTED_TOOLCHAIN = {
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
CHECK_INPUTS = (
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-lock.txt",
    "requirements-dev-lock.txt",
    "package.json",
    "package-lock.json",
)
MAX_DIFF_LINES = 80
VERSION_CHECK_TIMEOUT_SECONDS = 30
GENERATOR_TIMEOUT_SECONDS = 300

Runner = Callable[..., subprocess.CompletedProcess]
ExecutableFinder = Callable[[str], str | None]


class LockCheckError(RuntimeError):
    """Raised when dependency metadata is inconsistent."""


def _linux_distribution(os_release_path: Path = Path("/etc/os-release")) -> tuple[str, str]:
    try:
        lines = os_release_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LockCheckError(f"Unable to read {os_release_path}: {exc}") from exc

    values: dict[str, str] = {}
    for line in lines:
        key, separator, raw_value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID"}:
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            values[key] = value

    if not values.get("ID") or not values.get("VERSION_ID"):
        raise LockCheckError(f"{os_release_path} does not identify a Linux distribution and version.")
    return values["ID"].lower(), values["VERSION_ID"]


def _resolve_executable(name: str, finder: ExecutableFinder = shutil.which) -> str:
    executable = finder(name)
    if not executable:
        raise LockCheckError(f"Required lock tool is not installed or not executable: {name}")
    return os.path.abspath(executable)


def validate_toolchain(actual: dict[str, str]) -> None:
    mismatches = [
        f"{name}={actual.get(name, '<missing>')} (expected {expected})"
        for name, expected in EXPECTED_TOOLCHAIN.items()
        if actual.get(name) != expected
    ]
    if mismatches:
        raise LockCheckError("Unsupported lock generator toolchain: " + "; ".join(mismatches))


def _command_version(runner: Runner, command: list[str]) -> str:
    try:
        completed = runner(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=VERSION_CHECK_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        raise LockCheckError(f"{command[0]} version check failed with exit code {exc.returncode}.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LockCheckError(
            f"{command[0]} version check timed out after {VERSION_CHECK_TIMEOUT_SECONDS} seconds."
        ) from exc
    except OSError as exc:
        raise LockCheckError(f"Unable to start {command[0]} for its version check: {exc}") from exc
    version = completed.stdout.strip()
    if not version:
        raise LockCheckError(f"{command[0]} version check returned no version.")
    return version


def discover_toolchain(
    *,
    runner: Runner = subprocess.run,
    distribution_version: Callable[[str], str] = metadata.version,
    platform_name: Callable[[], str] = platform.system,
    machine_name: Callable[[], str] = platform.machine,
    python_version: Callable[[], str] = platform.python_version,
    linux_distribution: Callable[[], tuple[str, str]] = _linux_distribution,
    executable_finder: ExecutableFinder = shutil.which,
) -> dict[str, str]:
    distribution_names = (
        "pip",
        "pip-tools",
        "packaging",
        "build",
        "click",
        "pyproject-hooks",
        "setuptools",
        "wheel",
    )
    try:
        distribution_versions = {name: distribution_version(name) for name in distribution_names}
    except metadata.PackageNotFoundError as exc:
        raise LockCheckError(f"Required lock tool is not installed: {exc.name}") from exc

    distribution, distribution_release = linux_distribution()
    node_executable = _resolve_executable("node", executable_finder)
    npm_executable = _resolve_executable("npm", executable_finder)

    return {
        "platform": platform_name(),
        "machine": machine_name(),
        "distribution": distribution,
        "distribution-version": distribution_release,
        "python": python_version(),
        **distribution_versions,
        "node": _command_version(runner, [node_executable, "--version"]).removeprefix("v"),
        "npm": _command_version(runner, [npm_executable, "--version"]),
    }


def _read_requirements(path: Path) -> dict[str, Requirement]:
    requirements: dict[str, Requirement] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise LockCheckError(f"Invalid requirement in {path.name}:{line_number}: {line}") from exc
        name = canonicalize_name(requirement.name)
        if name in requirements:
            raise LockCheckError(f"Duplicate requirement in {path.name}: {requirement.name}")
        requirements[name] = requirement
    return requirements


def validate_manifest_parity(pyproject_path: Path, runtime_requirements_path: Path) -> None:
    try:
        project_data = toml_parser.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, toml_parser.TOMLDecodeError) as exc:
        raise LockCheckError(f"Unable to parse {pyproject_path.name}: {exc}") from exc
    project_dependencies = project_data.get("project", {}).get("dependencies", [])
    if not isinstance(project_dependencies, list):
        raise LockCheckError(f"{pyproject_path.name} project.dependencies must be an array.")
    project_requirements: dict[str, Requirement] = {}
    for raw_requirement in project_dependencies:
        try:
            requirement = Requirement(raw_requirement)
        except (InvalidRequirement, TypeError) as exc:
            raise LockCheckError(f"Invalid project dependency in {pyproject_path.name}: {raw_requirement!r}") from exc
        name = canonicalize_name(requirement.name)
        if name in project_requirements:
            raise LockCheckError(f"Duplicate project dependency in {pyproject_path.name}: {name}")
        project_requirements[name] = requirement

    runtime_requirements = _read_requirements(runtime_requirements_path)
    missing_from_runtime = sorted(project_requirements.keys() - runtime_requirements.keys())
    if missing_from_runtime:
        raise LockCheckError("Project dependency missing from requirements.txt: " + ", ".join(missing_from_runtime))

    runtime_only = runtime_requirements.keys() - project_requirements.keys()
    unexpected_runtime_only = sorted(runtime_only - ALLOWED_RUNTIME_ONLY_REQUIREMENTS.keys())
    invalid_exceptions = sorted(
        name
        for name in runtime_only & ALLOWED_RUNTIME_ONLY_REQUIREMENTS.keys()
        if runtime_requirements[name] != ALLOWED_RUNTIME_ONLY_REQUIREMENTS[name]
    )
    if unexpected_runtime_only or invalid_exceptions:
        raise LockCheckError(
            "Unexpected runtime-only dependency: " + ", ".join(unexpected_runtime_only + invalid_exceptions)
        )

    mismatches = [
        name
        for name in sorted(project_requirements.keys() & runtime_requirements.keys())
        if project_requirements[name] != runtime_requirements[name]
    ]
    if mismatches:
        raise LockCheckError("Manifest dependency mismatch: " + ", ".join(mismatches))


def _bounded_diff(original: Path, regenerated: Path) -> str:
    lines = list(
        difflib.unified_diff(
            original.read_text(encoding="utf-8", errors="replace").splitlines(),
            regenerated.read_text(encoding="utf-8", errors="replace").splitlines(),
            fromfile=original.name,
            tofile=f"regenerated/{regenerated.name}",
            lineterm="",
        )
    )
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f"... diff truncated after {MAX_DIFF_LINES} lines ..."]
    return "\n".join(lines)


def _run_generator(
    runner: Runner,
    command: list[str],
    *,
    workdir: Path,
    environment: dict[str, str],
    tool_name: str | None = None,
) -> None:
    display_name = tool_name or command[0]
    try:
        runner(
            command,
            cwd=workdir,
            env=environment,
            check=True,
            timeout=GENERATOR_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        raise LockCheckError(f"{display_name} failed with exit code {exc.returncode}.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LockCheckError(f"{display_name} timed out after {GENERATOR_TIMEOUT_SECONDS} seconds.") from exc
    except OSError as exc:
        raise LockCheckError(f"Unable to start {display_name}: {exc}") from exc


def check_dependency_locks(
    repository: Path,
    *,
    runner: Runner = subprocess.run,
    toolchain: dict[str, str],
    temp_parent: Path | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> None:
    repository = repository.resolve()
    validate_toolchain(toolchain)
    missing_inputs = [name for name in CHECK_INPUTS if not (repository / name).is_file()]
    if missing_inputs:
        raise LockCheckError("Missing dependency input: " + ", ".join(missing_inputs))
    validate_manifest_parity(repository / "pyproject.toml", repository / "requirements.txt")

    node_executable = _resolve_executable("node", executable_finder)
    npm_executable = _resolve_executable("npm", executable_finder)
    python_executable = os.path.abspath(sys.executable)

    with tempfile.TemporaryDirectory(prefix="quantum-encryptor-lock-check-", dir=temp_parent) as raw_workdir:
        workdir = Path(raw_workdir)
        for name in CHECK_INPUTS:
            shutil.copyfile(repository / name, workdir / name)

        cache_root = workdir / "cache"
        home_root = workdir / "home"
        temp_root = workdir / "tmp"
        for directory in (cache_root, home_root, temp_root):
            directory.mkdir()
        executable_path = os.pathsep.join(
            dict.fromkeys(
                (
                    str(Path(node_executable).parent),
                    str(Path(npm_executable).parent),
                    "/usr/bin",
                    "/bin",
                )
            )
        )
        environment = {
            "CI": "1",
            "CUSTOM_COMPILE_COMMAND": (
                "pip-compile --generate-hashes --output-file=requirements-lock.txt requirements.txt"
            ),
            "HOME": str(home_root),
            "LC_ALL": "C.UTF-8",
            "PATH": executable_path,
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PIP_NO_INPUT": "1",
            "PIP_TOOLS_CACHE_DIR": str(cache_root / "pip-tools"),
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": str(temp_root),
            "TZ": "UTC",
            "XDG_CACHE_HOME": str(cache_root),
        }
        _run_generator(
            runner,
            [
                python_executable,
                "-m",
                "piptools",
                "compile",
                "--generate-hashes",
                "--output-file=requirements-lock.txt",
                "requirements.txt",
            ],
            workdir=workdir,
            environment=environment,
            tool_name="pip-compile",
        )

        original_lock = repository / "requirements-lock.txt"
        regenerated_lock = workdir / "requirements-lock.txt"
        if original_lock.read_bytes() != regenerated_lock.read_bytes():
            raise LockCheckError(
                f"{original_lock.name} is stale. Regenerate it with the canonical toolchain.\n"
                + _bounded_diff(original_lock, regenerated_lock)
            )

        dev_environment = environment.copy()
        dev_environment["CUSTOM_COMPILE_COMMAND"] = (
            "pip-compile --allow-unsafe --generate-hashes "
            "--output-file=requirements-dev-lock.txt requirements-dev.txt"
        )
        _run_generator(
            runner,
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
            workdir=workdir,
            environment=dev_environment,
            tool_name="pip-compile",
        )

        original_dev_lock = repository / "requirements-dev-lock.txt"
        regenerated_dev_lock = workdir / "requirements-dev-lock.txt"
        if original_dev_lock.read_bytes() != regenerated_dev_lock.read_bytes():
            raise LockCheckError(
                f"{original_dev_lock.name} is stale. Regenerate it with the canonical toolchain.\n"
                + _bounded_diff(original_dev_lock, regenerated_dev_lock)
            )

        npm_environment = {
            name: value for name, value in environment.items() if not name.lower().startswith("npm_config_")
        }
        npm_environment.pop("CUSTOM_COMPILE_COMMAND", None)
        npm_environment.update(
            {
                "npm_config_cache": str(cache_root / "npm"),
                "npm_config_registry": "https://registry.npmjs.org/",
                "npm_config_update_notifier": "false",
                "npm_config_userconfig": os.devnull,
            }
        )
        _run_generator(
            runner,
            [
                npm_executable,
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            workdir=workdir,
            environment=npm_environment,
        )

        original_npm_lock = repository / "package-lock.json"
        regenerated_npm_lock = workdir / "package-lock.json"
        if original_npm_lock.read_bytes() != regenerated_npm_lock.read_bytes():
            raise LockCheckError(
                f"{original_npm_lock.name} is stale. Regenerate it with the canonical toolchain.\n"
                + _bounded_diff(original_npm_lock, regenerated_npm_lock)
            )


def main(
    *,
    repository: Path | None = None,
    runner: Runner = subprocess.run,
    toolchain: dict[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    repository = repository or Path(__file__).resolve().parents[1]
    try:
        actual_toolchain = toolchain or discover_toolchain(runner=runner)
        check_dependency_locks(repository, runner=runner, toolchain=actual_toolchain)
    except LockCheckError as exc:
        print(f"Dependency lock check failed: {exc}", file=stderr)
        return 1

    print("Dependency manifests and lock files are consistent.", file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
