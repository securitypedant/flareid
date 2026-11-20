# Security posture

How FlareID is secured, end to end — and how to deploy it that way. This guide is the overview; the deep description lives in the repo at `docs/security.md`.

## The three layers

**Platform.** FlareID runs as a Cloudflare Worker: no OS, SSH or host to attack. State lives in managed D1/KV/Secrets, and the network absorbs DDoS. The `workers.dev` origin sits behind Cloudflare Access — the only path in is the shielded public hostname.

**Application.** Every protocol surface is implemented defensively: XSW-hardened SAML signature verification on both bindings, per-SP encryption policies honoring SP metadata, an instance `disabled_algorithms` deny-list, spec-correct error responses (`InvalidNameIDPolicy`, `NoAuthnContext`), session/step-up binding, bounded dynamic clients, permission-area RBAC, and a tamper-evident audit chain.

**Verification.** The security behavior is regression-tested by external conformance tools — OpenID Foundation (OIDC), SAMLscope (SAML), SCIM Verify — plus repeated adversarial audits with committed findings, and a ~725-test suite on every change.

## Hardening the edge

The `terraform/` module deploys the zone security stack in front of the IdP:

- Custom WAF rules: admin-plane source ACL, cleartext deny, method allow-list, oversized-body block
- Per-IP rate limits on login, token, SSO and SCIM endpoints
- API Shield: OpenAPI schema validation on `/api` and `/scim` — the same schema that powers the API reference, so docs and enforcement can't drift
- TLS ≥1.2/1.3, always-HTTPS zone settings; optional managed rulesets

The runbook is `docs/secure-edge.md`; apply it, then re-run the [conformance suites](conformance.md) against the shielded hostname as your regression check.

## Operating checklist

1. Keep Access enabled on `workers.dev`; restrict the admin plane by ACL or mTLS.
2. Set `disabled_algorithms` in [security settings](security.md) to your crypto policy.
3. Every release: `npm run docs:api` → `terraform apply`, so the schema tracks new endpoints.
4. Report vulnerabilities per `SECURITY.md`.
