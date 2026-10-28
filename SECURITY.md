# Security policy

## Reporting a vulnerability

Please report security issues privately, using GitHub's
[private vulnerability reporting](https://github.com/securitypedant/flareid/security/advisories/new)
on this repository. Do not open a public issue for anything that affects the
security of a deployment.

I will acknowledge a report within a few days. This is a personal project
without a staffed security team, so please be realistic about response times -
and please do say if you intend to publish, so the timing can be coordinated.

## This is not an official Cloudflare product

FlareID runs on Cloudflare Workers but is not built, maintained or supported by
Cloudflare, Inc. Do not report FlareID vulnerabilities to Cloudflare. If you
believe you have found a vulnerability in the Cloudflare *platform*, that
belongs in [their programme](https://hackerone.com/cloudflare) instead.

## What is in scope

A deployed FlareID instance, running the code in this repository as documented.
In particular: the OIDC endpoints, the session and MFA implementation, the
provisioning API and its authentication, the admin and account interfaces, and
the SQL and template handling behind them.

## Known gaps - please do not report these as findings

[ROADMAP.md](ROADMAP.md) is deliberately explicit about where this project is
not yet production-grade, and the P0 list there is already known. At the time of
writing that includes:

- **Password hashing** is PBKDF2-HMAC-SHA256 at 100,000 iterations, below the
  600,000 OWASP currently recommends.
- **No CSRF tokens or `Origin` checks** on state-changing forms. `SameSite=Lax`
  covers the cross-site case, but a same-site sibling origin is not covered.
- **No security headers** - no CSP, `frame-ancestors`, `Referrer-Policy` or
  HSTS.
- **No garbage collection** of expired authorization codes, access tokens,
  sessions or trusted devices.
- **PKCE is optional**, and `plain` is still advertised.
- **Refresh tokens** neither expire nor rotate.

Novel findings, or anything materially worse than the above, are very welcome.

## Things that are deliberate, and why

- **A deployment starts with no users and no default password.** There is no
  shipped credential to find. The first administrator is created through the
  provisioning API using the `BOOTSTRAP_TOKEN` Worker secret, which stops
  working once setup completes.
- **`BOOTSTRAP_TOKEN` keeps answering one route after setup**
  (`POST /api/v1/recovery/admin-reset`), because the alternative for a
  locked-out deployment is hand-editing the database. It is audited loudly, and
  deleting the secret removes the route's only key.
- **A private key is committed** at `test/fixtures/signing-key.ts`. It signs
  test fixtures only. Tests that assert an `id_token` verifies against
  `/jwks.json` need both halves of a keypair, and a key generated at test time
  cannot be in a static Worker config.
- **OIDC client secrets are stored as unsalted SHA-256.** They are
  high-entropy machine-generated values, not passwords, so a slow KDF buys
  nothing here. Access and refresh tokens are handled the same way.
