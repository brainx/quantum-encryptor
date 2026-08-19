# CI Dependency Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore green dependency audits and Bandit checks by raising the vulnerable `cryptography` floor, repairing both reproducible locks, and narrowly suppressing the cookie-name false positive.

**Architecture:** Keep compatible ranges in the runtime input files and exact hashes in the two generated lock files. Preserve the existing Sphinx/docutils ceiling and Linux-only development markers, and make no runtime authorization or cryptographic-format change.

**Tech Stack:** Python 3.13, pip-tools 7.5.3, pip-audit 2.10.1, Bandit 1.9.4, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-08-19-ci-recovery-design.md`

## Global Constraints

- `requirements.txt` and `pyproject.toml` require `cryptography>=50.0.0`.
- `requirements-dev.txt` continues to retain `docutils<0.23`.
- Regenerate `requirements-lock.txt` and `requirements-dev-lock.txt` with Python 3.13 and the repository's existing `pip-compile` commands.
- Linux-only `jeepney` and `SecretStorage` markers remain in the development input and generated lock.
- Do not merge, copy, or recreate the broad package upgrades from Dependabot PR #31.
- Do not change cryptographic algorithms, formats, parameters, runtime behavior, CI workflow structure, Dependabot grouping, branch protection, release automation, or local API authorization.
- Publish only after both hash-locked installs, `pip check`, all three Python dependency audits, Bandit, and `git diff --check` pass.

---

## File Structure

- `requirements.txt`: source-of-truth runtime dependency ranges.
- `pyproject.toml`: packaged runtime dependency metadata; must match `requirements.txt`.
- `requirements-dev.txt`: development dependency ranges and the preserved Sphinx/docutils compatibility ceiling.
- `requirements-lock.txt`: generated, hash-verified runtime resolution for Python 3.13.
- `requirements-dev-lock.txt`: generated, hash-verified development resolution for Python 3.13.
- `api_app.py`: local ASGI application; only the public cookie-name annotation changes.
- `CHANGELOG.md`: user-visible security/dependency repair note.

### Task 1: Raise the dependency floor and document the narrow repair

**Files:**
- Modify: `requirements.txt:2`
- Modify: `pyproject.toml:15-21`
- Modify: `api_app.py:30-38`
- Modify: `CHANGELOG.md:25-33`

**Interfaces:**
- Consumes: the existing compatible runtime dependency ranges and `LOCAL_API_TOKEN_COOKIE: str` constant.
- Produces: matching `cryptography>=50.0.0` constraints for direct and packaged installs, with the unchanged cookie name `qe_api_token` carrying a Bandit B105 suppression.

- [ ] **Step 1: Confirm the old dependency floor is still present**

Run:

```bash
python3.13 -c 'from pathlib import Path; assert "cryptography>=50.0.0" in Path("requirements.txt").read_text() and "cryptography>=50.0.0" in Path("pyproject.toml").read_text()'
```

Expected: the command exits non-zero with `AssertionError`, proving both source files have not yet been repaired.

- [ ] **Step 2: Raise the runtime floor in both dependency sources**

Apply these exact replacements:

```text
# requirements.txt
liboqs-python>=0.14.1,<1.0
cryptography>=50.0.0

# pyproject.toml
dependencies = [
  "liboqs-python>=0.14.1,<1.0",
  "cryptography>=50.0.0",
  "starlette>=1.3.1,<2",
  "uvicorn>=0.49.0,<1",
  "python-multipart>=0.0.32,<1"
]
```

- [ ] **Step 3: Apply the reviewed Bandit suppression without changing the cookie value**

Replace the constant declaration with:

```python
# Cookie name, not a secret value.
LOCAL_API_TOKEN_COOKIE = "qe_api_token"  # nosec B105
```

- [ ] **Step 4: Record the security repair in the changelog**

Add this bullet under `## [Unreleased]` → `### Security`:

```markdown
- Raised the minimum `cryptography` version to 50.0.0 and refreshed the hash-locked runtime and development dependency sets to exclude the vulnerable 49.0.0 release.
```

- [ ] **Step 5: Verify the source constraints and scope**

Run:

```bash
python3.13 -c 'from pathlib import Path; runtime = Path("requirements.txt").read_text(); package = Path("pyproject.toml").read_text(); dev = Path("requirements-dev.txt").read_text(); api = Path("api_app.py").read_text(); assert runtime.count("cryptography>=50.0.0") == 1; assert package.count("cryptography>=50.0.0") == 1; assert "docutils<0.23" in dev; assert "LOCAL_API_TOKEN_COOKIE = \"qe_api_token\"  # nosec B105" in api'
git diff -- requirements.txt pyproject.toml requirements-dev.txt api_app.py CHANGELOG.md
```

Expected: the Python assertion exits 0; the diff contains only the two version-floor edits, cookie-name comment/suppression, and one changelog bullet, with no change to `requirements-dev.txt`.

- [ ] **Step 6: Commit the input and annotation changes**

```bash
git add requirements.txt pyproject.toml api_app.py CHANGELOG.md
git diff --cached --check
git diff --cached
git commit -m "fix: raise cryptography security floor"
```

Expected: the staged diff passes whitespace validation and the commit contains exactly four files.

### Task 2: Regenerate the Python 3.13 lock files

**Files:**
- Modify: `requirements-lock.txt:1-154`
- Modify: `requirements-dev-lock.txt:1-1325`

**Interfaces:**
- Consumes: `requirements.txt` with `cryptography>=50.0.0`, `requirements-dev.txt` with `docutils<0.23`, and the existing lock files as pip-tools' pin-preservation baseline.
- Produces: Python 3.13 lock files accepted by `pip install --require-hashes`, with `cryptography>=50.0.0`, `docutils<0.23`, and unchanged Linux-only marker coverage.

- [ ] **Step 1: Verify the required interpreter and lock compiler**

Run:

```bash
python3.13 --version
lock_tool_dir="$(mktemp -d /tmp/qe-lock-tools.XXXXXX)"
python3.13 -m venv "$lock_tool_dir"
"$lock_tool_dir/bin/python" -m pip install "pip-tools==7.5.3"
"$lock_tool_dir/bin/pip-compile" --version
```

Expected: Python reports `3.13.x`, installation succeeds, and pip-compile reports `7.5.3`.

- [ ] **Step 2: Regenerate the runtime lock using the repository command**

Run in the same shell that defines `lock_tool_dir`:

```bash
"$lock_tool_dir/bin/pip-compile" --generate-hashes --output-file=requirements-lock.txt requirements.txt
```

Expected: resolution succeeds and `requirements-lock.txt` retains its generated-file header while selecting a `cryptography` version at or above 50.0.0.

- [ ] **Step 3: Regenerate the development lock using the repository command**

Run in the same shell that defines `lock_tool_dir`:

```bash
"$lock_tool_dir/bin/pip-compile" --allow-unsafe --generate-hashes --output-file=requirements-dev-lock.txt requirements-dev.txt
```

Expected: resolution succeeds, `docutils` remains below 0.23, and unsafe build tooling remains explicitly locked.

- [ ] **Step 4: Assert the resolved security and compatibility boundaries**

Run:

```bash
python3.13 - <<'PY'
from pathlib import Path
import re

runtime = Path("requirements-lock.txt").read_text()
dev = Path("requirements-dev-lock.txt").read_text()

for name, content in (("runtime", runtime), ("development", dev)):
    match = re.search(r"^cryptography==(\d+)\.(\d+)\.(\d+)", content, re.MULTILINE)
    assert match, f"{name} lock has no cryptography pin"
    assert tuple(map(int, match.groups())) >= (50, 0, 0), match.group(0)

docutils = re.search(r"^docutils==(\d+)\.(\d+)(?:\.(\d+))?", dev, re.MULTILINE)
assert docutils, "development lock has no docutils pin"
docutils_version = tuple(int(part or 0) for part in docutils.groups())
assert docutils_version < (0, 23, 0), docutils.group(0)
assert 'sys_platform == "linux"' in dev
assert "secretstorage==" in dev.lower()
assert "jeepney==" in dev.lower()
PY
```

Expected: all assertions pass with no output.

- [ ] **Step 5: Review lock-only changes for unrelated upgrades**

Run:

```bash
git diff --stat -- requirements-lock.txt requirements-dev-lock.txt
git diff -- requirements-lock.txt requirements-dev-lock.txt
```

Expected: changes are limited to dependency pins and hashes required by the new `cryptography` floor; the docutils pin and Linux-only packages remain compatible with the input files. Stop if unrelated broad upgrades appear.

- [ ] **Step 6: Commit the regenerated locks**

```bash
git add requirements-lock.txt requirements-dev-lock.txt
git diff --cached --check
git diff --cached
git commit -m "chore: refresh secure dependency locks"
```

Expected: the staged diff passes whitespace validation and the commit contains exactly the two generated lock files.

### Task 3: Verify clean hash-locked installs and security gates

**Files:**
- Verify: `requirements.txt`
- Verify: `requirements-lock.txt`
- Verify: `requirements-dev-lock.txt`
- Verify: `api_app.py`
- Verify: `crypto_core.py`
- Verify: `pqc_agent_tools.py`
- Verify: `ui_helpers.py`

**Interfaces:**
- Consumes: the committed dependency inputs, generated hashes, and B105 suppression from Tasks 1–2.
- Produces: reproducible evidence that the runtime and development locks install cleanly, are internally consistent, have no reported Python advisories, and pass the repository's Bandit target set.

- [ ] **Step 1: Create clean runtime and development environments**

Run:

```bash
runtime_venv_dir="$(mktemp -d /tmp/qe-ci-runtime.XXXXXX)"
dev_venv_dir="$(mktemp -d /tmp/qe-ci-dev.XXXXXX)"
python3.13 -m venv "$runtime_venv_dir"
python3.13 -m venv "$dev_venv_dir"
```

Expected: both virtual environments are created successfully under `/tmp`.

- [ ] **Step 2: Verify the runtime hash lock**

Run in the same shell that defines `runtime_venv_dir`:

```bash
"$runtime_venv_dir/bin/python" -m pip install --require-hashes -r requirements-lock.txt
"$runtime_venv_dir/bin/python" -m pip check
```

Expected: the hash-locked install succeeds and `pip check` prints `No broken requirements found.`

- [ ] **Step 3: Verify the development hash lock**

Run in the same shell that defines `dev_venv_dir`:

```bash
"$dev_venv_dir/bin/python" -m pip install --require-hashes -r requirements-dev-lock.txt
"$dev_venv_dir/bin/python" -m pip check
```

Expected: the hash-locked install succeeds and `pip check` prints `No broken requirements found.`

- [ ] **Step 4: Run all three Python dependency audits**

Run in the same shell that defines `dev_venv_dir`:

```bash
"$dev_venv_dir/bin/python" -m pip_audit -r requirements.txt
"$dev_venv_dir/bin/python" -m pip_audit -r requirements-lock.txt
"$dev_venv_dir/bin/python" -m pip_audit -r requirements-dev-lock.txt
```

Expected: every command reports `No known vulnerabilities found` and exits 0.

- [ ] **Step 5: Run the repository's Python security lint target**

Run:

```bash
"$dev_venv_dir/bin/python" -m bandit -q -r api_app.py crypto_core.py pqc_agent_tools.py ui_helpers.py
```

Expected: Bandit exits 0 and reports no findings.

- [ ] **Step 6: Review final repository state**

Run:

```bash
git status --short
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git diff origin/main...HEAD
git log --oneline --decorate origin/main..HEAD
```

Expected: no uncommitted implementation changes remain; the branch contains only the worktree ignore, design, plan, dependency-floor/annotation/changelog, and lockfile commits; the complete diff matches this plan and contains no secrets, private paths, temporary files, or unrelated edits.

### Task 4: Publish the focused recovery pull request

**Files:**
- Publish: committed branch diff against `origin/main`

**Interfaces:**
- Consumes: the reviewed branch and exact successful verification evidence from Task 3.
- Produces: a focused pull request targeting `main`, with no merge or dependency on Dependabot PR #31.

- [ ] **Step 1: Rename the local branch to its public delivery name**

Run:

```bash
git branch -m fix/ci-dependency-locks
git branch --show-current
```

Expected: the current branch is `fix/ci-dependency-locks`.

- [ ] **Step 2: Recheck publication targets and history**

Run:

```bash
git status --short
git remote -v
git log --oneline --decorate -n 10
git diff --check origin/main...HEAD
```

Expected: the working tree is clean, `origin` targets `brainx/quantum-encryptor`, and the branch is based on current `origin/main` with only the reviewed commits.

- [ ] **Step 3: Push the branch without force**

Run:

```bash
git push -u origin fix/ci-dependency-locks
```

Expected: Git creates or updates the remote branch without a force push and configures upstream tracking.

- [ ] **Step 4: Create the pull request**

Run:

```bash
gh pr create \
  --repo brainx/quantum-encryptor \
  --base main \
  --head fix/ci-dependency-locks \
  --title "Fix vulnerable dependency locks" \
  --body $'## Summary\n\n- require cryptography 50.0.0 or newer in both runtime dependency sources\n- regenerate the Python 3.13 runtime and development locks while preserving docutils<0.23\n- suppress Bandit B105 only for the public cookie-name constant\n\n## Verification\n\n- hash-locked runtime install and pip check: passed\n- hash-locked development install and pip check: passed\n- pip-audit for requirements.txt, requirements-lock.txt, and requirements-dev-lock.txt: passed\n- Bandit for the Python application modules: passed\n- git diff --check: passed'
```

Expected: GitHub creates one open pull request from `fix/ci-dependency-locks` into `main`.

- [ ] **Step 5: Follow required checks to a terminal result**

Run:

```bash
gh pr checks --repo brainx/quantum-encryptor --watch --fail-fast
```

Expected: all required CI and CodeQL checks complete successfully. If a task-related check fails, inspect its log, apply the smallest scoped correction, rerun the relevant local gate, commit, and push normally before watching checks again.
