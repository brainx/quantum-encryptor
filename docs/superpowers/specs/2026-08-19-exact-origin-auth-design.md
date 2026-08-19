# Exact-Origin Local API Authorization Design

## Objective

Harden the loopback web API so a browser credential can authorize a
state-changing request only from the exact local UI authority that the project
serves. Preserve the explicit header-token contract for non-browser clients,
keep the supported Vite development workflow available through a deliberate
opt-in, and fail closed when request authority data is missing or malformed.

## Current Failure

The API currently accepts any `Origin` string beginning with
`http://127.0.0.1:` or `http://localhost:`. That admits every loopback port and
also admits non-browser strings that merely share the prefix. The host-only API
cookie is shared across ports, and `SameSite=Strict` is not a port-origin
boundary. A page served by an unrelated loopback service can therefore submit
the cookie to the API and pass the current prefix check.

The guard also accepts a cookie when `Origin` is absent, and `GET /api/health`
issues the cookie without validating `Host`. Those behaviors blur the boundary
between a browser cookie and the explicit token intended for programmatic
clients.

## Protected Assets and Trust Boundaries

The protected operations generate private keys, inspect supplied keys, encrypt
plaintext, and decrypt ciphertext. Request bodies can contain private keys,
passwords, and plaintext. The relevant boundary is between:

- the built-in UI served at `http://127.0.0.1:<PORT>`;
- the one supported Vite development UI at `http://127.0.0.1:4001`;
- unrelated browser pages, including pages on other loopback ports; and
- explicit local automation that possesses `QUANTUM_ENCRYPTOR_API_TOKEN`.

Malicious local software remains outside this control's protection. A local
process can choose its own `Host` and `Origin` headers and can call the health
endpoint directly. This change prevents browser cross-origin use of the shared
cookie; it does not claim to isolate the API from other software running under
the local user.

## Authority Configuration

`PORT` remains the single source of truth for the built-in API/UI port and
defaults to `4000`. It must be an ASCII decimal integer from 1 through 65535;
invalid values fail during application startup rather than creating an
ambiguous authorization policy.

The default allowed browser authority set contains exactly:

```text
http://127.0.0.1:<PORT>
```

`localhost`, arbitrary `127.0.0.1` ports, IPv6 loopback, forwarded authorities,
and network interfaces are not aliases and are not accepted.

Setting `QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV=1` adds exactly:

```text
http://127.0.0.1:4001
```

No other value enables the development exception. The Vite proxy is present
only under the same switch, derives its API target from `PORT`, and explicitly
preserves the browser-facing `Host` with `changeOrigin: false`. This lets the
backend compare the Vite request's exact browser Origin and Host while keeping
the development trust expansion deliberate and finite.

## Parsing Policy

Origin and Host values are parsed into a normalized tuple of scheme, lowercase
hostname, and effective port. Comparison is tuple equality; authorization never
uses string prefixes or substrings.

Origin parsing must reject:

- a missing or empty value when an Origin is required;
- duplicate headers;
- non-ASCII values, surrounding whitespace, and control characters;
- schemes other than `http`;
- missing hostnames, invalid or out-of-range ports, and malformed IPv6;
- usernames, passwords, paths, queries, fragments, and the literal `null`.

For HTTP, an omitted port normalizes to port 80. Scheme and hostname case may
normalize according to URL parsing rules, but `localhost` and `127.0.0.1` remain
distinct authorities.

Host parsing applies the same strict character, userinfo, hostname, port, path,
query, and fragment checks to an authority without a scheme. The API uses only
the direct `Host` header and the configured `http` scheme. It does not trust
`Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`, or other proxy metadata.

## Authorization Decision

All state-changing `/api/*` requests first require one valid Host in the finite
allowed-authority set. If an Origin is present, it must parse successfully, be
in that same finite set, and equal the parsed Host authority. An invalid Host or
Origin is rejected before request-body parsing.

Credential handling is then deliberately split:

| Request context | Credential | Result |
| --- | --- | --- |
| Exact allowed Origin and matching Host | Valid HttpOnly cookie | Allow |
| Exact allowed Origin and matching Host | Valid explicit token header | Allow |
| Missing Origin and allowed Host | Valid explicit token header | Allow |
| Missing Origin | Cookie only | Reject |
| Wrong or malformed Origin/Host | Any credential | Reject |
| Duplicate or invalid explicit token header | Cookie also present | Reject |

The explicit `X-Quantum-Encryptor-Token` header takes precedence when present.
An invalid explicit value cannot silently fall back to a cookie. Token equality
continues to use constant-time comparison.

## Health Cookie Issuance

`GET /api/health` validates authority before setting the token cookie:

- `Host` must parse as an exact allowed authority;
- if `Origin` is present, it must be exact, allowed, and equal to `Host`;
- an absent Origin remains valid for direct navigation and command-line health
  probes when Host is valid;
- an authority rejection returns `403` and never includes `Set-Cookie`.

The cookie remains host-only with `Path=/`, `HttpOnly`, and
`SameSite=Strict`. It does not receive `Secure` while the documented direct
loopback service uses HTTP. Health responses retain `Cache-Control: no-store`
and `Pragma: no-cache`.

## Failure Responses

Invalid or unapproved Host values return the stable code `forbidden_host`.
Invalid, missing-when-required, mismatched, or unapproved Origin values return
`forbidden_origin`. Missing, duplicate, or invalid credentials return the
existing `missing_api_token` response. All errors remain generic and continue
to receive the existing security headers.

## Verification

Focused Python tests cover strict parsing, duplicate headers, exact built-in and
Vite authorities, sibling loopback ports, the `localhost` alias, malformed
values, Host-gated cookie bootstrap, Origin-less cookie rejection, explicit
header-token clients, and failure-before-body-parsing behavior.

The Vite configuration is exposed through a pure configuration builder so its
default closed state and explicit development proxy can be unit tested. The
development test asserts the fixed origin, `PORT`-derived target, and
`changeOrigin: false` behavior. Existing TypeScript, API-client, and component
checks remain in the normal `npm run check` path.

Targeted local verification is:

```bash
python3.13 -m pytest tests/test_api_app.py tests/test_startup.py -q
npm run check
python3.13 -m black --check api_app.py tests/test_api_app.py tests/test_startup.py
python3.13 -m flake8 api_app.py tests/test_api_app.py tests/test_startup.py
git diff --check
```

Repository CI supplies the broader package, browser, native-liboqs, audit, and
CodeQL coverage before merge.

## Documentation and Compatibility

Update the README, API documentation, security guide, threat model, and
changelog to describe exact authority validation, the programmatic header-token
exception, explicit Vite setup, and the actual limits of SameSite. The normal
built-in UI and documented `PORT` override remain compatible. Browser access
through `localhost`, raw cookie-only scripts, and implicit Vite proxying are
intentionally rejected.

## Scope Exclusions

This pull request does not change cryptographic formats or algorithms, add
network-facing deployment support, trust reverse proxies, add TLS, defend
against malicious local processes, add rate limiting or workload admission, or
implement the separate key-custody, PEM-fingerprint, dependency-automation, or
release-preflight roadmap items.

## Delivery and Rollback

Deliver this hardening as a separate pull request targeting `main`. Merge only
after focused local checks, independent whole-branch review, and all required
remote checks pass. Rollback is a normal revert; the change modifies request
authorization and documentation without migrating stored data or file formats.
