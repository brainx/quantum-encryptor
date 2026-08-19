import json
import re
import subprocess
from pathlib import Path

import pytest

from scripts import check_release_preflight as preflight


def test_release_workflow_wires_preflight_before_expensive_jobs() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.index("release-preflight:") < workflow.index("native-oqs-release:")
    assert "needs: release-preflight" in workflow
    assert "--tag-from-project" in workflow
    assert '--tag "${RELEASE_REF_NAME}" --require-tag-ref' in workflow
    assert "if: github.ref_type == 'tag'" in workflow
    assert "/git/tags/${tag_object}" in workflow
    assert ".tag, .object.type, .object.sha" in workflow
    assert ".verification.verified" in workflow
    assert "python -m pip install --require-hashes -r requirements-dev-lock.txt" in workflow
    assert "tag_object: ${{ steps.verify_release_tag.outputs.tag_object }}" in workflow
    assert "EXPECTED_TAG_OBJECT: ${{ needs.release-preflight.outputs.tag_object }}" in workflow
    assert '"/repos/${GITHUB_REPOSITORY}/git/ref/tags/${RELEASE_TAG}"' in workflow
    assert "--draft" in workflow
    assert 'gh release edit "${RELEASE_TAG}" --draft=false' in workflow
    assert "pip install --require-hashes -r requirements-lock.txt" in workflow
    assert "pip install --no-deps dist/*.whl" in workflow
    action_refs = re.findall(r"uses:\s+(actions/[^@\s]+)@([^\s]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for _, ref in action_refs)


def _write_release_files(
    repo_root: Path,
    version: str = "1.2.3",
    changelog: str | None = None,
) -> None:
    (repo_root / "pyproject.toml").write_text(
        f'[project]\nname = "quantum-encryptor"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (repo_root / "package.json").write_text(
        json.dumps({"name": "quantum-encryptor-web", "version": version}),
        encoding="utf-8",
    )
    (repo_root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "quantum-encryptor-web",
                "version": version,
                "packages": {"": {"version": version}},
            }
        ),
        encoding="utf-8",
    )
    (repo_root / "CHANGELOG.md").write_text(
        changelog
        or (
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "### Security\n\n"
            "- Added a release metadata gate.\n\n"
            "## [1.2.2] - 2026-08-01\n\n"
            "- Previous release.\n"
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "tag",
    [
        "1.2.3",
        "v1.2",
        "v1.2.3-rc.1",
        "v1.2.3+build.1",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2.3\n",
    ],
)
def test_parse_stable_tag_rejects_noncanonical_or_unstable_tags(tag: str) -> None:
    with pytest.raises(preflight.ReleasePreflightError, match="exact stable SemVer"):
        preflight.parse_stable_tag(tag)


def test_validate_release_metadata_accepts_all_matching_fields(tmp_path: Path) -> None:
    _write_release_files(tmp_path)

    assert preflight.validate_release_metadata(tmp_path, "v1.2.3") == "1.2.3"
    assert preflight.collect_version_fields(tmp_path) == {
        "pyproject.toml [project].version": "1.2.3",
        "package.json version": "1.2.3",
        "package-lock.json version": "1.2.3",
        'package-lock.json packages[""].version': "1.2.3",
    }


def test_validate_release_metadata_rejects_lockfile_root_mismatch(tmp_path: Path) -> None:
    _write_release_files(tmp_path)
    package_lock = json.loads((tmp_path / "package-lock.json").read_text(encoding="utf-8"))
    package_lock["packages"][""]["version"] = "1.2.2"
    (tmp_path / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")

    with pytest.raises(preflight.ReleasePreflightError, match=r'packages\[""\]\.version'):
        preflight.validate_release_metadata(tmp_path, "v1.2.3")


def test_validate_release_metadata_rejects_unreleased_only_changelog(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "### Added\n\n"
            "- Work that was never moved into a release section.\n"
        ),
    )

    with pytest.raises(preflight.ReleasePreflightError, match=r"exactly one ## \[1\.2\.3\]"):
        preflight.validate_release_metadata(tmp_path, "v1.2.3")


def test_publishing_rejects_content_left_under_unreleased(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "### Added\n\n"
            "- Work that was not moved into the release section.\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "### Security\n\n"
            "- Added a release metadata gate.\n"
        ),
    )

    assert preflight.validate_release_metadata(tmp_path, "v1.2.3") == "1.2.3"
    with pytest.raises(preflight.ReleasePreflightError, match="must not contain release-note content"):
        preflight.validate_release_metadata(
            tmp_path,
            "v1.2.3",
            require_clean_unreleased=True,
        )


def test_publishing_rejects_descriptive_unreleased_heading(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "### Removed Python 3.10 support\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "### Security\n\n"
            "- Added a release metadata gate.\n"
        ),
    )

    with pytest.raises(preflight.ReleasePreflightError, match="must not contain release-note content"):
        preflight.validate_release_metadata(
            tmp_path,
            "v1.2.3",
            require_clean_unreleased=True,
        )


def test_publishing_rejects_duplicate_unreleased_sections(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "### Security\n\n"
            "- Added a release metadata gate.\n\n"
            "## [Unreleased]\n\n"
            "- Hidden release-note content.\n"
        ),
    )

    with pytest.raises(preflight.ReleasePreflightError, match=r"exactly one ## \[Unreleased\]"):
        preflight.validate_release_metadata(
            tmp_path,
            "v1.2.3",
            require_clean_unreleased=True,
        )


def test_validate_release_metadata_rejects_empty_release_section(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "### Security\n\n"
            "## [1.2.2] - 2026-08-01\n\n"
            "- Previous release.\n"
        ),
    )

    with pytest.raises(preflight.ReleasePreflightError, match="release-note bullet"):
        preflight.validate_release_metadata(tmp_path, "v1.2.3")


def test_validate_release_metadata_requires_current_release_first(tmp_path: Path) -> None:
    _write_release_files(
        tmp_path,
        changelog=(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "## [1.2.4] - 2026-08-20\n\n"
            "- Later release.\n\n"
            "## [1.2.3] - 2026-08-19\n\n"
            "- Requested release.\n"
        ),
    )

    with pytest.raises(preflight.ReleasePreflightError, match="first release section"):
        preflight.validate_release_metadata(tmp_path, "v1.2.3")


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _initialize_git_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "--initial-branch=main")
    _git(repo_root, "config", "user.name", "Release Test")
    _git(repo_root, "config", "user.email", "release-test@example.invalid")
    _write_release_files(repo_root)
    _git(repo_root, "add", "pyproject.toml", "package.json", "package-lock.json", "CHANGELOG.md")
    _git(repo_root, "commit", "-m", "prepare release")
    return repo_root


def test_validate_git_release_accepts_annotated_tag_on_main(tmp_path: Path) -> None:
    repo_root = _initialize_git_repo(tmp_path)
    _git(repo_root, "tag", "-a", "v1.2.3", "-m", "v1.2.3")

    commit_oid, main_oid = preflight.validate_git_release(repo_root, "v1.2.3", "HEAD", "main", require_tag_ref=True)

    assert commit_oid == _git(repo_root, "rev-parse", "HEAD")
    assert main_oid == _git(repo_root, "rev-parse", "main")


def test_validate_git_release_rejects_lightweight_tag(tmp_path: Path) -> None:
    repo_root = _initialize_git_repo(tmp_path)
    _git(repo_root, "tag", "v1.2.3")

    with pytest.raises(preflight.ReleasePreflightError, match="annotated tag"):
        preflight.validate_git_release(repo_root, "v1.2.3", "HEAD", "main", require_tag_ref=True)


def test_validate_git_release_rejects_tag_checkout_mismatch(tmp_path: Path) -> None:
    repo_root = _initialize_git_repo(tmp_path)
    _git(repo_root, "tag", "-a", "v1.2.3", "-m", "v1.2.3")
    (repo_root / "after-tag.txt").write_text("later\n", encoding="utf-8")
    _git(repo_root, "add", "after-tag.txt")
    _git(repo_root, "commit", "-m", "commit after tag")

    with pytest.raises(preflight.ReleasePreflightError, match="not checked-out commit"):
        preflight.validate_git_release(repo_root, "v1.2.3", "HEAD", "main", require_tag_ref=True)


def test_validate_git_release_binds_explicit_commit_to_head(tmp_path: Path) -> None:
    repo_root = _initialize_git_repo(tmp_path)
    tagged_commit = _git(repo_root, "rev-parse", "HEAD")
    _git(repo_root, "tag", "-a", "v1.2.3", "-m", "v1.2.3")
    (repo_root / "after-tag.txt").write_text("later\n", encoding="utf-8")
    _git(repo_root, "add", "after-tag.txt")
    _git(repo_root, "commit", "-m", "commit after tag")

    with pytest.raises(preflight.ReleasePreflightError, match="not checked-out HEAD"):
        preflight.validate_git_release(
            repo_root,
            "v1.2.3",
            tagged_commit,
            "main",
            require_tag_ref=True,
        )


def test_validate_git_release_rejects_commit_outside_main(tmp_path: Path) -> None:
    repo_root = _initialize_git_repo(tmp_path)
    _git(repo_root, "switch", "-c", "release-only")
    (repo_root / "release-only.txt").write_text("release\n", encoding="utf-8")
    _git(repo_root, "add", "release-only.txt")
    _git(repo_root, "commit", "-m", "release outside main")
    _git(repo_root, "tag", "-a", "v1.2.3", "-m", "v1.2.3")

    with pytest.raises(preflight.ReleasePreflightError, match="not reachable from main"):
        preflight.validate_git_release(repo_root, "v1.2.3", "HEAD", "main", require_tag_ref=True)
