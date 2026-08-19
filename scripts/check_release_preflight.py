#!/usr/bin/env python3
"""Validate release metadata before expensive release jobs run."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

STABLE_TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
CHANGELOG_HEADING_RE = re.compile(r"^## \[([^]]+)](?:\s+-\s+(.+))?\s*$", re.MULTILINE)
CHANGELOG_BULLET_RE = re.compile(r"^-\s+\S", re.MULTILINE)
EMPTY_CHANGELOG_CATEGORY_RE = re.compile(r"### (?:Added|Changed|Deprecated|Removed|Fixed|Security)")
PYPROJECT_VERSION_RE = re.compile(r"""version\s*=\s*(?:"([^"]+)"|'([^']+)')\s*(?:#.*)?""")


class ReleasePreflightError(RuntimeError):
    """Raised when release metadata or Git state is unsafe to publish."""


@dataclass(frozen=True)
class ChangelogSection:
    name: str
    body: str


@dataclass(frozen=True)
class PreflightResult:
    tag: str
    version: str
    commit_oid: str
    main_oid: str


def parse_stable_tag(tag: str) -> str:
    """Return the version for an exact stable ``vMAJOR.MINOR.PATCH`` tag."""
    match = STABLE_TAG_RE.fullmatch(tag)
    if match is None:
        raise ReleasePreflightError(f"Release tag {tag!r} is invalid; expected exact stable SemVer vMAJOR.MINOR.PATCH.")
    return tag[1:]


def _read_pyproject_version(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleasePreflightError(f"Cannot read {path.name}: {exc}") from exc

    section = ""
    versions: list[str] = []
    for line in lines:
        stripped = line.strip()
        section_match = re.fullmatch(r"\[([^]]+)]", stripped)
        if section_match is not None:
            section = section_match.group(1)
            continue
        if section != "project" or not stripped.startswith("version"):
            continue
        version_match = PYPROJECT_VERSION_RE.fullmatch(stripped)
        if version_match is None:
            raise ReleasePreflightError("pyproject.toml [project].version must be a quoted string.")
        versions.append(version_match.group(1) or version_match.group(2))

    if len(versions) != 1:
        raise ReleasePreflightError("pyproject.toml must contain exactly one [project].version value.")
    return versions[0]


def _read_json(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleasePreflightError(f"Cannot parse {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleasePreflightError(f"{path.name} must contain a JSON object.")
    return value


def _required_string(mapping: Mapping[str, object], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ReleasePreflightError(f"{label} must be a non-empty string.")
    return value


def collect_version_fields(repo_root: Path) -> dict[str, str]:
    """Read every release-version field currently maintained by the repository."""
    package = _read_json(repo_root / "package.json")
    package_lock = _read_json(repo_root / "package-lock.json")
    packages = package_lock.get("packages")
    if not isinstance(packages, dict):
        raise ReleasePreflightError("package-lock.json packages must be a JSON object.")
    root_package = packages.get("")
    if not isinstance(root_package, dict):
        raise ReleasePreflightError('package-lock.json must contain the root package entry packages[""].')

    return {
        "pyproject.toml [project].version": _read_pyproject_version(repo_root / "pyproject.toml"),
        "package.json version": _required_string(package, "version", "package.json version"),
        "package-lock.json version": _required_string(package_lock, "version", "package-lock.json version"),
        'package-lock.json packages[""].version': _required_string(
            root_package,
            "version",
            'package-lock.json packages[""].version',
        ),
    }


def _read_changelog_sections(path: Path) -> list[ChangelogSection]:
    try:
        changelog = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleasePreflightError(f"Cannot read {path.name}: {exc}") from exc

    headings = list(CHANGELOG_HEADING_RE.finditer(changelog))
    sections: list[ChangelogSection] = []
    for index, heading in enumerate(headings):
        body_start = heading.end()
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
        sections.append(ChangelogSection(heading.group(1), changelog[body_start:body_end]))
    return sections


def _has_release_content(section: ChangelogSection) -> bool:
    for line in section.body.splitlines():
        stripped = line.strip()
        if not stripped or EMPTY_CHANGELOG_CATEGORY_RE.fullmatch(stripped):
            continue
        return True
    return False


def validate_release_metadata(repo_root: Path, tag: str, require_clean_unreleased: bool = False) -> str:
    """Validate the tag, repository version fields, and versioned changelog entry."""
    version = parse_stable_tag(tag)
    fields = collect_version_fields(repo_root)
    mismatches = [f"{label}={value!r}" for label, value in fields.items() if value != version]
    if mismatches:
        details = ", ".join(mismatches)
        raise ReleasePreflightError(f"Every version field must equal tag version {version!r}; found {details}.")

    sections = _read_changelog_sections(repo_root / "CHANGELOG.md")
    unreleased_sections = [section for section in sections if section.name == "Unreleased"]
    if len(unreleased_sections) != 1:
        raise ReleasePreflightError("CHANGELOG.md must contain exactly one ## [Unreleased] section.")
    if sections[0].name != "Unreleased":
        raise ReleasePreflightError("CHANGELOG.md must start its release headings with ## [Unreleased].")
    if require_clean_unreleased and _has_release_content(unreleased_sections[0]):
        raise ReleasePreflightError(
            "CHANGELOG.md ## [Unreleased] must not contain release-note content when publishing a tag."
        )

    release_sections = [section for section in sections if section.name == version]
    if len(release_sections) != 1:
        raise ReleasePreflightError(f"CHANGELOG.md must contain exactly one ## [{version}] release section.")
    if len(sections) < 2 or sections[1].name != version:
        raise ReleasePreflightError(
            f"CHANGELOG.md ## [{version}] must be the first release section after ## [Unreleased]."
        )
    if CHANGELOG_BULLET_RE.search(release_sections[0].body) is None:
        raise ReleasePreflightError(f"CHANGELOG.md ## [{version}] must contain at least one release-note bullet.")
    return version


def _run_git(repo_root: Path, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleasePreflightError(f"Cannot inspect Git release state: {exc}") from exc


def _git_output(repo_root: Path, args: Sequence[str], description: str) -> str:
    result = _run_git(repo_root, args)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise ReleasePreflightError(f"Cannot {description}: {detail}")
    return result.stdout.strip()


def _resolve_commit(repo_root: Path, revision: str, description: str) -> str:
    return _git_output(
        repo_root,
        ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        description,
    )


def validate_git_release(
    repo_root: Path,
    tag: str,
    commit: str,
    main_ref: str,
    require_tag_ref: bool,
) -> tuple[str, str]:
    """Validate that the release commit is the checked tag and is reachable from main."""
    parse_stable_tag(tag)
    commit_oid = _resolve_commit(repo_root, commit, f"resolve release commit {commit!r}")
    head_oid = _resolve_commit(repo_root, "HEAD", "resolve checked-out HEAD")
    if commit_oid != head_oid:
        raise ReleasePreflightError(f"Release commit {commit_oid} is not checked-out HEAD {head_oid}.")
    main_oid = _resolve_commit(repo_root, main_ref, f"resolve main ref {main_ref!r}")
    release_oid = commit_oid

    if require_tag_ref:
        tag_ref = f"refs/tags/{tag}"
        tag_type = _git_output(
            repo_root,
            ["cat-file", "-t", tag_ref],
            f"inspect release tag {tag!r}",
        )
        if tag_type != "tag":
            raise ReleasePreflightError(
                f"Release tag {tag!r} must be an annotated tag; found Git object type {tag_type!r}."
            )
        release_oid = _resolve_commit(repo_root, tag_ref, f"resolve release tag {tag!r}")
        if release_oid != commit_oid:
            raise ReleasePreflightError(
                f"Release tag {tag!r} resolves to {release_oid}, not checked-out commit {commit_oid}."
            )

    ancestry = _run_git(
        repo_root,
        ["merge-base", "--is-ancestor", release_oid, main_oid],
    )
    if ancestry.returncode == 1:
        raise ReleasePreflightError(f"Release commit {release_oid} is not reachable from main ref {main_ref!r}.")
    if ancestry.returncode != 0:
        detail = ancestry.stderr.strip() or ancestry.stdout.strip() or "unknown Git error"
        raise ReleasePreflightError(f"Cannot verify release ancestry: {detail}")
    return release_oid, main_oid


def run_preflight(
    repo_root: Path,
    tag: str,
    commit: str,
    main_ref: str,
    require_tag_ref: bool,
) -> PreflightResult:
    version = validate_release_metadata(
        repo_root,
        tag,
        require_clean_unreleased=require_tag_ref,
    )
    commit_oid, main_oid = validate_git_release(repo_root, tag, commit, main_ref, require_tag_ref)
    return PreflightResult(tag, version, commit_oid, main_oid)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail closed on inconsistent or unsafe release metadata.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    tag_group = parser.add_mutually_exclusive_group(required=True)
    tag_group.add_argument("--tag", help="Release tag to validate")
    tag_group.add_argument(
        "--tag-from-project",
        action="store_true",
        help="Use v<pyproject version> for non-publishing workflow dispatches",
    )
    parser.add_argument("--commit", default="HEAD", help="Release commit to validate")
    parser.add_argument(
        "--main-ref",
        default="refs/remotes/origin/main",
        help="Fetched main ref that must contain the release commit",
    )
    parser.add_argument(
        "--require-tag-ref",
        action="store_true",
        help="Require an annotated local tag that resolves to --commit",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        if args.tag_from_project:
            fields = collect_version_fields(repo_root)
            tag = f"v{fields['pyproject.toml [project].version']}"
        else:
            tag = args.tag
        result = run_preflight(
            repo_root,
            tag,
            args.commit,
            args.main_ref,
            args.require_tag_ref,
        )
    except ReleasePreflightError as exc:
        print(f"release preflight failed: {exc}", file=sys.stderr)
        return 1

    print(f"release preflight passed for {result.tag}: " f"{result.commit_oid[:12]} is reachable from {args.main_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
