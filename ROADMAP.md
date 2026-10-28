# FlareID roadmap

FlareID is a **functional but not yet production-grade** identity provider.
This file is deliberately honest about the gap: everything marked below as a
P0 was found by reading the code, and none of it should be a surprise to anyone
deciding whether to point real traffic at this.

## Done

- OIDC: `/authorize`, `/token` (authorization_code + refresh_token, PKCE),
  `/userinfo`, `/jwks.json`, `/introspect`, `/revoke`, discovery
- Password (PBKDF2) plus optional per-user TOTP MFA, backup codes, trusted
  devices, and an option to require MFA for everyone
- Flat groups, multi-domain UPNs, HR attributes exposed as claims
- SCIM 2.0 *client*: pushes users and groups to an external SCIM server,
  scoped to all groups or a chosen set
- Admin UX: users, groups, clients, API keys, domains, settings, branding,
  audit log
- Self-service: MFA enrolment, password change, sessions and connected apps
- Server-tracked sessions, listable and revocable by the user or an admin
- Signing key rotation with an overlap window
- Audit logging with requesting IP and user agent, including actions taken
  through the API
- Basic login rate limiting and lockout
- **Provisioning API** at `/api/v1`, and no shipped credential: a fresh install
  has no users and no default password, and the first administrator is created
  over the API with a deploy-time bootstrap token
- **A test suite** running inside the Workers runtime against the real
  migrations, plus CI

## P0 - before pointing anything that matters at this

1. ~~**No automated tests at all.**~~ Done - 73 tests covering the crypto
   primitives, the OIDC flows and the whole provisioning API.
2. ~~**A shipped administrator with a committed password hash.**~~ Done - the
   migrations seed no users.
3. **Password hashing is below current guidance.** PBKDF2-HMAC-SHA256 at
   100,000 iterations; OWASP currently says 600,000 for PBKDF2-SHA256. The
   iteration count is already stored per row, so the path is clear: move to
   `scrypt` via `node:crypto` (now available in Workers) or raise the count,
   with a versioned `password_algo` column and rehash-on-login.
4. **No CSRF defence on state-changing forms.** There are no tokens and no
   `Origin`/`Referer` checks anywhere. `SameSite=Lax` on the session cookie
   blocks cross-*site* POSTs, which covers the classic attack - but any app on
   the same registrable domain is same-site, so an XSS on a sibling subdomain
   can drive `/admin`. Needs per-session tokens and an `Origin` check.
5. **No security headers.** No CSP, `frame-ancestors`, `Referrer-Policy` or
   HSTS. CSP needs nonces first, since all CSS and JS is currently inline.
6. **Expired state is never garbage-collected.** There is no `scheduled`
   handler, so `auth_codes`, `access_tokens`, `sessions`, `trusted_devices` and
   `audit_log` only shrink incidentally. Needs a Cron Trigger and retention
   settings; unbounded D1 growth is a real operational failure.
7. **PKCE is optional and `plain` is accepted.** The token endpoint only
   verifies PKCE when the authorization code carried a challenge, and discovery
   advertises `plain`. Require S256 for public clients and drop `plain`.
8. **Refresh tokens never expire and are never rotated.** There is no
   `expires_at`, and the refresh grant hands back the same token. Needs expiry,
   rotation, and reuse detection that revokes the family.

## P1 - to call it a real identity provider

9. **Outbound email** (Cloudflare Email Sending). Unblocks 10 and 11.
10. **Self-service password recovery.** Today the only path is an
    admin-initiated reset.
11. **Invitation and activation flow**, instead of an admin relaying a
    temporary password.
12. **RP-initiated logout** (`end_session_endpoint`) and front-channel logout,
    so a relying party can end the IdP session too.
13. **Consent screen** for non-trusted clients, with a per-client trusted flag.
14. **Public and native clients**: PKCE-only, no secret,
    `token_endpoint_auth_method: none`.
15. **Per-client claim and scope allowlist.** `buildClaims()` returns the same
    full set - email, name, groups, job title, department, manager, amr - to
    every client regardless of what it needs. A real data-minimisation gap.
16. **SCIM 2.0 *server***, for inbound provisioning. FlareID is a SCIM client
    only; anything calling itself an identity provider has to be provisionable
    from an HR system or an upstream directory.
17. **CSV import** in the admin UI, on top of the import API.
18. **WebAuthn / passkeys.** Previously listed as out of scope; phishing
    -resistant MFA is table stakes now.
19. **OIDC conformance.** Run the OpenID Foundation Basic OP profile in CI.
    Also fill the discovery gaps (`grant_types_supported`,
    `response_modes_supported`, a complete `claims_supported`) and implement
    `auth_time`, `at_hash`, `acr`, `prompt` and `max_age`, none of which are
    present.
20. **Self-service profile editing** for low-risk fields.
21. **SAML 2.0.** See [SAML-implementation.md](SAML-implementation.md) - it is
    achievable to the saml2int bar, and is staged behind the P0 items above
    because the test harness is what makes it safe to write.

## P2 - operational maturity

22. Granular admin roles - today `Super Admins` is all or nothing. An auditor,
    a user admin and a client admin are the obvious three.
23. Step-up re-authentication for sensitive actions: minting API keys,
    disabling MFA, rotating a client secret.
24. Signing keys in D1 or KV rather than environment variables, so rotation
    does not need a redeploy. ES256 alongside RS256, which SAML also wants.
25. Breached-password check via the HIBP k-anonymity API; Turnstile on login
    and recovery.
26. Audit log export (Logpush or R2), a retention policy, and tamper-evidence.
27. Observability: structured logs, login success and failure metrics,
    alerting.
28. Documented backup, restore and disaster recovery for D1; a directory export
    endpoint.
29. Scale: paginated and searchable group-membership editing - the current
    member checklist will not survive ten thousand users - documented tested
    ceilings, and rule-based dynamic groups.
30. Branding: logo upload, per-domain branding, custom CSS.
31. An accessibility and internationalisation pass on the login, MFA and
    consent pages.
32. Versioned releases, semver, a changelog, and a published Terraform snippet
    for the Access integration.
33. A naming and trademark review. "FlareID" is Cloudflare-adjacent, and the
    README needs to keep saying plainly that this is not an official Cloudflare
    product.

## Explicitly out of scope

These are decisions, not oversights.

- **Self-service signup.** Admin-only provisioning is the point.
- **Nested groups.** Flat by design: the practical benefit of nesting is small,
  the implementation cost is real - recursive expansion, cycle detection,
  performance - and SCIM consumers like Cloudflare Access expect flat, resolved
  membership anyway, so nesting would not survive the trip. If a concrete need
  ever appears, prefer a capped one-level "group of groups", cycle-checked and
  expanded to a flat set at read time, over true hierarchy.
- **Multi-tenancy.** One organisation per deployment.
- **SAML artifact binding, the SOAP back-channel, ECP/PAOS and Name Identifier
  Management.** These are what separate OASIS "IdP" conformance from saml2int,
  and nobody deploys them. See SAML-implementation.md.

## Notes

### Per-client claim filtering (item 15)

`buildClaims()` in `src/lib/jwt.ts` returns the same claim set to every client.
A client that only needs to check group membership still receives job title,
department and manager. The standard shape of the fix is a per-client allowlist
of top-level claims, stored on `oauth_clients`, editable from the client's
admin page, and applied in `buildClaims()`/`signIdToken()` and in `/userinfo`.

It is a real security and privacy property rather than a nice-to-have, which is
why it sits in P1 rather than P2.

### Where the demo suite went

FlareID grew up inside a workshop repository, which seeded thirty fictional
employees, a `company.com` domain and an administrator into its migrations, and
carried an app launcher linking to five sibling demo applications. All of that
is gone. The directory now arrives after deployment through the provisioning
API, from a bundle that repository generates and POSTs - which is why
`docs/api.md` exists and why the migrations are a single clean baseline.
