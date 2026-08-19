# Release Checklist

Use this checklist before publishing a new release.

## Pre-release

- [ ] Set the same stable version in `pyproject.toml`, `package.json`, and both
      the top-level and root-package version fields in `package-lock.json`
- [ ] Move every release note from `Unreleased` into a populated section for
      that exact version; leave only optional empty category headings under `Unreleased`
- [ ] Regenerate `requirements-lock.txt`
- [ ] Regenerate `requirements-dev-lock.txt`
- [ ] Run Python tests
- [ ] Run frontend build
- [ ] Run frontend type check
- [ ] Run browser smoke test
- [ ] Run native `liboqs` round trip
- [ ] Build Python artifacts
- [ ] Smoke-test the installed wheel web UI
- [ ] Run `twine check dist/*`
- [ ] Generate artifact checksums

## Commands

```bash
python -m pip install --require-hashes -r requirements-dev-lock.txt
npm ci
python -m black --check .
python -m flake8 api_app.py crypto_config.py crypto_core.py pqc_agent_tools.py ui_helpers.py setup.py tests
python -m mypy api_app.py crypto_config.py crypto_core.py pqc_agent_tools.py ui_helpers.py tests
./test.sh --cov=crypto_core --cov=pqc_agent_tools --cov=ui_helpers --cov=api_app --cov-report=term-missing --cov-fail-under=80
npm run build
npm run check
python -m build
python -m twine check dist/*
cd dist && shasum -a 256 * > SHA256SUMS.txt
```

## Publish

- Confirm immutable releases are enabled for the repository.
- Confirm an active tag ruleset blocks updates and deletions for stable release tags.
- Confirm the release commit is reachable from `main`.
- Create a signed annotated `vMAJOR.MINOR.PATCH` Git tag on that commit.
- Push the tag.
- Confirm the release workflow passed, including tag-signature verification,
  draft asset upload, and the final live-tag identity check.
- Confirm the GitHub Release contains verified artifacts and `SHA256SUMS.txt`.
- Verify GitHub release notes match `CHANGELOG.md`.
