# Security Policy

## Supported Versions

The current supported line is:

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities.

Use GitHub Security Advisories for this repository, or contact the maintainer privately.

Include:

- A clear description of the issue
- Reproduction steps
- Affected version or commit
- Expected impact
- Any suggested mitigation

## Security Scope

This project is a local file-encryption tool using post-quantum KEM plus authenticated symmetric encryption.

Out of scope:

- Social engineering
- Physical compromise of the user device
- Malware already running as the user
- Lost private-key passwords
- Side-channel attacks not explicitly mitigated by Python or the underlying native libraries

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for design details and limitations.
