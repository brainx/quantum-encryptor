# Release Checklist

Use this checklist before publishing a new release.

## Pre-release

- [ ] Confirm version in `pyproject.toml`
- [ ] Confirm version in `package.json`
- [ ] Confirm version in `package-lock.json`
- [ ] Update `CHANGELOG.md`
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
python -m pip install -r requirements-dev.txt
npm ci
python -m black --check .
python -m flake8 api_app.py crypto_config.py crypto_core.py pqc_agent_tools.py pqc_app.py ui_helpers.py setup.py tests
python -m mypy api_app.py crypto_config.py crypto_core.py pqc_agent_tools.py pqc_app.py ui_helpers.py tests
./test.sh --cov=crypto_core --cov=pqc_agent_tools --cov=ui_helpers --cov=api_app --cov-report=term-missing --cov-fail-under=80
npm run build
npm run check
python -m build
python -m twine check dist/*
cd dist && shasum -a 256 * > SHA256SUMS.txt
```

## Publish

- Create a signed Git tag.
- Push the tag.
- Confirm the release workflow passed.
- Confirm the GitHub Release contains verified artifacts and `SHA256SUMS.txt`.
- Verify GitHub release notes match `CHANGELOG.md`.
