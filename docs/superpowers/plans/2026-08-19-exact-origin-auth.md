# Exact-Origin Local API Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restrict browser cookie authorization to the exact configured loopback UI authority, preserve explicit token clients, and make the Vite development authority an explicit finite exception.

**Architecture:** Parse direct `Host` and browser `Origin` headers into normalized `(scheme, host, port)` tuples and compare them against a finite configured set. Browser requests require exact Origin/Host equality; Origin-less requests require the explicit token header. The health endpoint gates cookie issuance on the same authority policy, and Vite preserves its browser-facing Host only when development access is explicitly enabled.

**Tech Stack:** Python 3.10–3.13, Starlette ASGI, pytest, TypeScript, Vite 8, Vitest 4

**Spec:** `docs/superpowers/specs/2026-08-19-exact-origin-auth-design.md`

## Global Constraints

- Default allowed browser authority is exactly `http://127.0.0.1:<PORT>`.
- `QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1` adds only `http://127.0.0.1:4001`; every other value remains disabled.
- Never authorize `localhost`, arbitrary loopback ports, IPv6, forwarded headers, URL prefixes, or Host-derived arbitrary origins.
- Browser cookie authorization requires a present, exact allowed Origin matching an exact allowed Host.
- Origin-less programmatic calls remain supported only through a valid `X-Quantum-Encryptor-Token` header.
- A present explicit token header takes precedence and cannot fall back to the cookie when invalid.
- `GET /api/health` returns no cookie for a missing, malformed, or unapproved Host, or for a present mismatched Origin.
- Preserve the existing token value generation, constant-time comparison, cookie attributes, response security headers, and pre-body-parse guard ordering.
- Do not change cryptographic code, formats, dependency versions, CI workflow structure, or other roadmap items.

---

## File Structure

- `api_app.py`: validated port configuration, authority parsing, exact authorization policy, health-cookie gate, and server port use.
- `tests/test_api_app.py`: parser, authorization, Host, cookie, and explicit-token regressions.
- `tests/test_startup.py`: invalid `PORT` startup/configuration regression.
- `vite.config.ts`: pure testable config builder and opt-in development proxy.
- `web/src/vite-config.test.ts`: closed-default and enabled-proxy unit tests.
- `README.md`: exact normal authority and explicit two-process Vite setup.
- `docs/API.md`: local API credential and authority contract.
- `docs/SECURITY.md`: exact browser-origin mitigation.
- `docs/THREAT_MODEL.md`: corrected SameSite statement and local-process limitation.
- `CHANGELOG.md`: user-visible hardening note.

### Task 1: Add failing Python authority and authorization regressions

**Files:**
- Modify: `tests/test_api_app.py:134-338`
- Modify: `tests/test_startup.py:1-43`

**Interfaces:**
- Exercises: `_parse_origin(value)`, `_parse_host_authority(value)`, `_allowed_browser_authorities(app_port, enable_vite_dev)`, `LocalApiGuardMiddleware`, and `GET /api/health`.
- Produces: a default ASGI test Host of `127.0.0.1:<configured port>` and explicit overrides for missing/malformed authority cases.

- [ ] **Step 1: Teach the ASGI test helper to send an ordinary Host**

Add a keyword-only `host` argument to `_call_app_raw` and `_call_app`:

```python
async def _call_app_raw(
    path: str,
    method: str = "POST",
    body: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    *,
    host: str | None = None,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    request_headers = list(headers) if headers is not None else [
        (b"content-length", str(len(body)).encode("ascii"))
    ]
    if host is None:
        host = api_app.LOCAL_API_HOST_HEADER
    if host:
        request_headers.append((b"host", host.encode("ascii")))
```

Use `request_headers` in the ASGI scope. Give `_call_app` the same keyword-only
argument and forward it. Tests that need no Host pass `host=""`; malformed Host
tests pass the exact malformed string.

- [ ] **Step 2: Add strict parser and finite-configuration tests**

Add parameterized tests proving:

```python
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:4000", ("http", "127.0.0.1", 4000)),
        ("HTTP://127.0.0.1:4000", ("http", "127.0.0.1", 4000)),
        ("http://127.0.0.1", ("http", "127.0.0.1", 80)),
    ],
)
def test_parse_origin_normalizes_valid_http_authorities(value, expected):
    assert api_app._parse_origin(value) == expected
```

Reject `None`, `""`, `"null"`, HTTPS, `localhost` only through the allowlist,
userinfo, paths, queries, fragments, surrounding whitespace, control
characters, nonnumeric ports, out-of-range ports, and crafted suffixes such as
`http://127.0.0.1:4000.evil`. Add corresponding strict Host cases. Assert the
default allowed set has one authority and the enabled development set adds only
`("http", "127.0.0.1", 4001)`.

- [ ] **Step 3: Replace the permissive cookie success test with exact browser context**

The cookie success case must send both:

```python
(b"host", b"127.0.0.1:4000")
(b"origin", b"http://127.0.0.1:4000")
```

through the helper's Host argument and request headers. It must continue
reaching the route and returning `unsupported_key`, proving authorization—not
key parsing—succeeded.

- [ ] **Step 4: Add the negative browser and positive explicit-client matrix**

Add focused state-changing request tests for:

- cookie plus sibling `127.0.0.1` port → `403 forbidden_origin`;
- cookie plus `localhost` on the configured port → `403 forbidden_origin`;
- cookie plus missing Origin → `403 missing_api_token`;
- header token plus no Origin and exact Host → reaches route;
- header token plus exact Origin and Host → reaches route;
- header token plus malformed/mismatched Origin → `403 forbidden_origin`;
- valid cookie plus invalid explicit header → `403 missing_api_token`;
- missing, malformed, duplicate, or sibling Host → `403 forbidden_host`;
- duplicate Origin → `403 forbidden_origin`;
- forwarded Host/proto headers do not rescue an invalid direct Host.

Use the existing invalid PEM route response as proof of successful guard
passage; do not mock cryptographic behavior.

- [ ] **Step 5: Add health-cookie authority tests**

Keep the current successful cookie-attribute assertions with the default exact
Host. Add cases proving:

- matching Origin and Host still set the cookie;
- sibling-port, `localhost`, malformed, duplicate, and missing Host return
  `403 forbidden_host` with no `Set-Cookie`;
- a present sibling or malformed Origin returns `403 forbidden_origin` with no
  `Set-Cookie`;
- absent Origin with exact Host still supports curl/direct navigation.

- [ ] **Step 6: Add invalid `PORT` configuration subprocess coverage**

In `tests/test_startup.py`, parameterize invalid values `0`, `65536`, `abc`,
and whitespace-padded input. Start a clean interpreter with `-c "import
api_app"`, set `PYTHONPATH` to the repository root, and assert non-zero exit plus
the stable message `PORT must be an integer from 1 through 65535.` without a
trace containing any token value.

- [ ] **Step 7: Run the new tests and observe the expected failure**

Run:

```bash
python3.13 -m pytest tests/test_api_app.py tests/test_startup.py -q
```

Expected: failures identify the missing parser/configuration helpers, missing
Host gate, permissive origin handling, and Origin-less cookie acceptance. No
unrelated existing test should fail.

- [ ] **Step 8: Commit the failing regressions**

```bash
git add tests/test_api_app.py tests/test_startup.py
git diff --cached --check
git diff --cached
git commit -m "test: define exact local API authority policy"
```

### Task 2: Implement strict authority parsing and request authorization

**Files:**
- Modify: `api_app.py:5-50`
- Modify: `api_app.py:168-234`
- Modify: `api_app.py:419-432`
- Modify: `api_app.py:615-623`

**Interfaces:**
- Produces: `Authority = tuple[str, str, int]`, `LOCAL_API_PORT: int`, `LOCAL_API_HOST_HEADER: str`, `_parse_origin`, `_parse_host_authority`, `_allowed_browser_authorities`, and `_validate_request_authorities`.
- Preserves: `LOCAL_API_TOKEN`, `LOCAL_API_TOKEN_COOKIE`, route paths, response shapes, and security middleware.

- [ ] **Step 1: Add validated configuration and a finite authority set**

Import `urlsplit`. Define the fixed host/scheme/development port and parse
`PORT` once. `_configured_port` must reject non-ASCII-decimal input and values
outside 1–65535 with:

```text
PORT must be an integer from 1 through 65535.
```

Build the immutable allowlist through:

```python
def _allowed_browser_authorities(app_port: int, enable_vite_dev: bool) -> frozenset[Authority]:
    authorities = {("http", "127.0.0.1", app_port)}
    if enable_vite_dev:
        authorities.add(("http", "127.0.0.1", 4001))
    return frozenset(authorities)
```

Enable the second entry only when the environment value is exactly `"1"`.

- [ ] **Step 2: Implement strict Origin and Host parsers**

Use a shared ASCII/control check and `urlsplit`, catching `ValueError` around
hostname and port access. `_parse_origin` requires `http`, netloc, hostname, no
userinfo, and empty path/query/fragment. `_parse_host_authority` parses
`"http://" + value` under the same constraints. Both normalize the hostname to
lowercase and use port 80 when omitted.

Do not check allowed hostnames inside the parser; syntactic parsing and finite
authorization are separate concerns.

- [ ] **Step 3: Require one direct Host and validate an optional Origin**

Add `_single_header_value` that raises a private duplicate-header error when a
security-sensitive header appears more than once. Add
`_validate_request_authorities(scope)` returning whether a valid Origin was
present plus an optional `ApiError`:

1. parse one Host and require membership in `ALLOWED_BROWSER_AUTHORITIES`;
2. if Origin is absent, return `(False, None)`;
3. parse one Origin, require membership, and require equality with Host;
4. return `forbidden_host` or `forbidden_origin` without inspecting forwarding
   headers.

- [ ] **Step 4: Split header-token and browser-cookie paths**

In `LocalApiGuardMiddleware`:

1. reject the authority error before body parsing;
2. read the explicit token header independently;
3. if it is present, validate only it;
4. otherwise, accept the cookie only when a validated Origin was present;
5. return `missing_api_token` for all invalid credential cases.

Update `_cookie_value` to reject duplicate Cookie headers and keep
constant-time `_has_valid_local_api_token` unchanged.

- [ ] **Step 5: Gate health cookie issuance**

Change `health` to use its `Request`. Run `_validate_request_authorities` before
building the success response. Return the corresponding JSON error immediately
on failure and set no cookie. Preserve the exact existing success payload,
cookie attributes, and cache headers.

- [ ] **Step 6: Reuse the validated port for the listener**

Replace the second `int(os.environ.get("PORT", "4000"))` conversion in `main`
with `LOCAL_API_PORT`, ensuring the listener and authorization policy cannot
disagree.

- [ ] **Step 7: Run focused Python verification**

```bash
python3.13 -m pytest tests/test_api_app.py tests/test_startup.py -q
python3.13 -m black --check api_app.py tests/test_api_app.py tests/test_startup.py
python3.13 -m flake8 api_app.py tests/test_api_app.py tests/test_startup.py
```

Expected: all focused tests, formatting, and lint checks pass.

- [ ] **Step 8: Commit the implementation**

```bash
git add api_app.py
git diff --cached --check
git diff --cached
git commit -m "fix: enforce exact local API authorities"
```

### Task 3: Make Vite development trust explicit and testable

**Files:**
- Modify: `vite.config.ts:1-27`
- Create: `web/src/vite-config.test.ts`

**Interfaces:**
- Produces: `createViteConfig(environment)` pure builder.
- Consumes: `PORT` and `QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV`.

- [ ] **Step 1: Add failing Vite configuration tests**

Import `createViteConfig` from the root config. Assert that an empty environment
produces no `/api` proxy. Assert that this environment:

```typescript
{
  PORT: "4020",
  QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: "1"
}
```

produces a `/api` proxy with target `http://127.0.0.1:4020` and
`changeOrigin: false`. Assert that `"true"` does not enable the proxy.

- [ ] **Step 2: Observe the test fail before configuration changes**

```bash
npx vitest run web/src/vite-config.test.ts
```

Expected: import failure because `createViteConfig` does not exist.

- [ ] **Step 3: Export the pure Vite configuration builder**

Use `loadEnv(mode, ".", "")` in the default `defineConfig` callback so the
builder receives `PORT` and the opt-in switch without introducing Node global
types. Preserve the existing root, React plugin, fixed Vite host/port,
`strictPort`, build directory, and Vitest settings.

Set `server.proxy` to `undefined` by default. When enabled, configure only:

```typescript
{
  "/api": {
    target: `http://127.0.0.1:${environment.PORT ?? "4000"}`,
    changeOrigin: false
  }
}
```

- [ ] **Step 4: Run the frontend/config checks**

```bash
npx vitest run web/src/vite-config.test.ts
npm run check
npm run build
```

Expected: the new config tests, existing 65 component tests, three API-client
tests, TypeScript checks, and production build pass. Record actual counts rather
than assuming them if they change.

- [ ] **Step 5: Commit the Vite change**

```bash
git add vite.config.ts web/src/vite-config.test.ts
git diff --cached --check
git diff --cached
git commit -m "fix: make Vite API trust explicit"
```

### Task 4: Document the exact authority contract and complete review

**Files:**
- Modify: `README.md:98-117,227-243`
- Modify: `docs/API.md:36-40`
- Modify: `docs/SECURITY.md:65-84`
- Modify: `docs/THREAT_MODEL.md:53-74`
- Modify: `CHANGELOG.md:25-35`

**Interfaces:**
- Documents: `PORT`, `QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV`, exact browser authority, header-token exception, Host-gated health cookie, and local-software limitation.

- [ ] **Step 1: Update normal and Vite startup guidance**

Keep `./start.sh` as the normal path. Explain that `PORT` determines the one
trusted API/UI authority. Replace the implicit Vite command with an explicit
two-terminal example:

```bash
QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1 SKIP_WEB_BUILD=1 ./start.sh
QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1 npm run dev
```

State that the switch adds only `http://127.0.0.1:4001` and must be set for both
processes.

- [ ] **Step 2: Correct the API and security contract**

Document that cookie requests require exact parsed Origin/Host equality and
that missing-Origin clients must use the explicit token header. Document that
health issues the cookie only for an allowed Host and never trusts forwarding
headers.

Replace the threat-model claim that cross-site requests “cannot carry” a
SameSite cookie. State instead that SameSite helps with cross-site delivery but
does not isolate loopback ports; exact authority validation provides that
boundary. Retain the limitation that malicious local software is not blocked.

- [ ] **Step 3: Add one changelog security bullet**

Under Unreleased Security, record exact Host/Origin validation, Origin-less
cookie rejection, and the explicit Vite exception without claiming protection
from malicious local processes.

- [ ] **Step 4: Run the complete focused gate**

```bash
python3.13 -m pytest tests/test_api_app.py tests/test_startup.py -q
npm run check
npm run build
python3.13 -m black --check api_app.py tests/test_api_app.py tests/test_startup.py
python3.13 -m flake8 api_app.py tests/test_api_app.py tests/test_startup.py
git diff --check
git status --short
git diff main...HEAD --stat
git diff main...HEAD
```

Expected: all targeted checks pass, only listed files and the governing
spec/plan differ from `main`, no token value or machine-specific path appears,
and the diff contains no forwarding-header trust or prefix authorization.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md docs/API.md docs/SECURITY.md docs/THREAT_MODEL.md CHANGELOG.md
git diff --cached --check
git diff --cached
git commit -m "docs: explain exact local API authority"
```

- [ ] **Step 6: Obtain whole-branch review and publish**

Run an independent security-focused whole-branch review against the design.
Resolve every critical or important finding. Push `fix/exact-origin-auth`, open
a pull request targeting `main`, and include exact local verification results,
compatibility changes, security boundary, and rollback note. Merge only at the
reviewed head after every required check is green, then observe the matching
post-merge `main` workflow reach a successful terminal state.
