# Security Policy

## Supported Versions

Security patches are provided for the latest stable release and the
immediately preceding minor release.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| 0.x     | :x:                |

## Reporting a Vulnerability

**Do not open a public issue.** The Aegis WAF project follows a
coordinated disclosure process.

Email security vulnerabilities to **security@aegis-waf.dev**.

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Affected version(s)
- Any known mitigations

### Response Timeline

| Action                     | Target  |
| -------------------------- | ------- |
| Acknowledgment             | 48 hrs  |
| Assessment complete        | 5 days  |
| Patch released             | 14 days |
| Public disclosure          | 30 days |

We will keep you informed throughout the process and credit you in the
advisory (unless you prefer anonymity).

## Security Design

Aegis WAF is a reverse proxy with a security-first architecture:

- Built in Rust for memory safety
- Zero unsafe code policy in core parsing paths
- Fuzzed HTTP parsing with cargo-fuzz
- Rate limiting enforced independently of upstream
- TLS termination handled before request inspection

## Responsible Disclosure Scope

In-scope:

- Request smuggling and HTTP desync attacks
- Rule bypass mechanisms
- Denial-of-service vectors
- Information leakage
- Configuration injection

Out-of-scope:

- Vulnerabilities in upstream applications
- Social engineering
- Physical attacks
- Denial-of-service caused by misconfiguration

## Audit Artifacts

CI runs `cargo audit` and `cargo deny` on every push to `main` and on
a weekly schedule. Audit reports from the workflows are available under
the Actions tab.
