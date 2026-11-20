# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do not open a public issue.

- Email: **security@cloudflare.com** (subject prefix `[FlareID]`), or
- GitHub private vulnerability reporting on this repository, if enabled.

Include the affected version/commit, reproduction steps or proof-of-concept,
and the security impact you believe applies. We aim to acknowledge reports
within 3 business days and will coordinate disclosure timing with you.

## Supported versions

Security fixes land on the latest release line (`v4.x`). Older releases are
not backpatched — upgrade to the current release.

## Scope

In scope: the FlareID worker, its D1/KV/Secrets data, the admin console and
APIs, the SAML/OIDC/SCIM/LDAP protocol surfaces, and the deployment
artifacts in this repository (`wrangler.jsonc`, `terraform/`).

Out of scope: the Cloudflare platform itself, operator-managed
infrastructure, and social engineering.

## Security posture

The implemented security model — platform isolation, protocol hardening,
cryptography, the edge security stack (`terraform/`), conformance testing,
and the audit process — is documented in [docs/security.md](docs/security.md),
with the edge deployment runbook in [docs/secure-edge.md](docs/secure-edge.md).
