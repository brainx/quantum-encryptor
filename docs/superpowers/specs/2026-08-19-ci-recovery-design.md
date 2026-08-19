# CI Recovery and Dependency Lock Repair Design

## Objective

Restore a green, trustworthy `main` branch with the smallest dependency and
security-lint change that resolves the observed failures. The change must keep
the reproducible runtime and development lock files installable on Python 3.13,
preserve the documented Sphinx/docutils compatibility ceiling, and avoid the
unrelated upgrades bundled into Dependabot PR #31.

## Current Failure

The dependency specifications allow a safe current `cryptography` release, but
both checked-in lock files pin `cryptography==49.0.0`. The security job therefore
passes when auditing a fresh resolution of `requirements.txt` and fails when it
audits the reproducible locks because that pinned release is affected by
`PYSEC-2026-3552`. The first fixed release is `50.0.0`.

Dependabot PR #31 is not a suitable repair. It combines eighteen upgrades and
changes `docutils<0.23` to `docutils<0.24`, allowing `docutils==0.23` even though
the currently resolved Sphinx 9.1 line requires `docutils<0.23`. That makes the
development lock internally inconsistent.

Bandit also reports the string assigned to `LOCAL_API_TOKEN_COOKIE` as a
hard-coded password. The value is a public cookie name rather than a secret.
The existing staged `# nosec B105` annotation is the correct narrow suppression
when accompanied by an explanatory comment.

## Scope

The implementation will:

1. Change the runtime dependency floor from `cryptography>=42.0.0` to
   `cryptography>=50.0.0` in `requirements.txt` and `pyproject.toml`.
2. Preserve `docutils<0.23` in `requirements-dev.txt`.
3. Regenerate `requirements-lock.txt` and `requirements-dev-lock.txt` with
   Python 3.13 and the repository's existing `pip-compile` commands.
4. Apply the documented `# nosec B105` suppression to the cookie-name constant
   in `api_app.py`.
5. Add a concise changelog entry describing the safe dependency floor and
   reproducible-lock repair.

The implementation will not:

- merge, copy, or recreate the broad package upgrades from PR #31;
- change cryptographic algorithms, formats, parameters, or runtime behavior;
- relax the Sphinx/docutils compatibility cap;
- change CI workflow structure, Dependabot grouping, branch protection, or
  release automation in this pull request;
- modify local API authorization beyond the non-functional Bandit annotation.

## Dependency Model

The input specifications continue to express compatible ranges, while the lock
files provide exact, hash-verified builds:

- `requirements.txt` and `pyproject.toml` require `cryptography>=50.0.0`.
- `requirements-dev.txt` continues to include `requirements.txt` and retain
  `docutils<0.23`.
- `requirements-lock.txt` is regenerated from `requirements.txt`.
- `requirements-dev-lock.txt` is regenerated from `requirements-dev.txt` with
  unsafe build tooling included, as required by the existing lock policy.

Lock generation must use Python 3.13 so the resulting environment matches the
locked-install and security jobs. Linux-only `jeepney` and `SecretStorage`
markers must remain in the development input and generated lock.

## Failure Handling

The work stops rather than publishing a partial lock repair when any of these
conditions occurs:

- `pip-compile` cannot resolve both input sets;
- a hash-locked install fails in a clean temporary virtual environment;
- `pip check` reports an inconsistent environment;
- any runtime, locked-runtime, or development audit reports a vulnerability;
- Bandit reports the cookie-name constant or another task-related finding;
- regeneration changes dependency inputs or unrelated repository files beyond
  the explicitly listed scope.

An unrelated upstream advisory discovered during verification is reported and
kept out of this slice unless it prevents the required clean audit. If it blocks
the audit, the minimum fixed version becomes part of the same dependency-floor
repair and is documented before publication.

## Verification

Use clean temporary Python 3.13 virtual environments and run:

```bash
runtime_venv_dir="$(mktemp -d /tmp/qe-ci-runtime.XXXXXX)"
python3.13 -m venv "$runtime_venv_dir"
"$runtime_venv_dir/bin/python" -m pip install --require-hashes -r requirements-lock.txt
"$runtime_venv_dir/bin/python" -m pip check

dev_venv_dir="$(mktemp -d /tmp/qe-ci-dev.XXXXXX)"
python3.13 -m venv "$dev_venv_dir"
"$dev_venv_dir/bin/python" -m pip install --require-hashes -r requirements-dev-lock.txt
"$dev_venv_dir/bin/python" -m pip check
"$dev_venv_dir/bin/python" -m pip_audit -r requirements.txt
"$dev_venv_dir/bin/python" -m pip_audit -r requirements-lock.txt
"$dev_venv_dir/bin/python" -m pip_audit -r requirements-dev-lock.txt
"$dev_venv_dir/bin/python" -m bandit -q -r api_app.py crypto_core.py pqc_agent_tools.py ui_helpers.py
```

Finally run `git diff --check` and review the complete diff. The repository CI
then supplies the broader Python, frontend, package, browser, and native-liboqs
coverage; this focused repair does not claim those suites passed locally unless
they are actually run.

## Delivery and Rollback

Publish the change as one maintainer-authored pull request targeting `main`.
The title and body describe only the dependency-floor, lock, and lint repair and
contain the exact verification results. Do not merge PR #31 as part of this
work.

Rollback is a normal revert of the focused commit. Because the change raises a
minimum dependency version and regenerates locks without changing stored data or
file formats, rollback requires no migration or recovery procedure.

## Follow-up Boundaries

After `main` is green, separate designs and pull requests cover:

1. exact-origin loopback authorization;
2. generated-key custody guardrails;
3. required-check branch protection;
4. smaller Dependabot groups and a fail-fast lock gate;
5. canonical PEM parsing and public-key fingerprints;
6. release preflight and provenance.

None of those follow-ups may be folded into the CI-recovery pull request.
