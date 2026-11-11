# FlareID roadmap

FlareID is a **functional but not yet production-grade** identity provider.
This file is deliberately honest about the gap: everything marked below as a
P0 was found by reading the code, and none of it should be a surprise to anyone
deciding whether to point real traffic at this.

## Done

- OIDC: `/authorize`, `/token` (authorization_code + refresh_token, PKCE),
  `/userinfo`, `/jwks.json`, `/introspect`, `/revoke`, discovery
- SAML 2.0 (v1 profile): SP-initiated Web Browser SSO, redirect binding in,
  POST binding out, signed Response + Assertion, SP registry, IdP metadata,
  request-signature verification, `ForceAuthn`
- Password (scrypt; PBKDF2 legacy hashes upgrade on login) plus optional per-user TOTP MFA, backup codes, trusted
  devices, and an option to require MFA for everyone
- Flat groups, each **static** (assigned members) or **dynamic** (attribute
  rules built in the admin UI, resolved everywhere membership matters),
  multi-domain UPNs, HR attributes exposed as claims
- **Directory schemas**: named attribute vocabularies per object type (Basic
  default, FlareID HR provided), admin + API CRUD, and conforming on schema
  change (same-named attributes carry over, with a preview of what's cleared)
- **User lifecycle**: accounts are created disabled and activated explicitly;
  admins can reset passwords to a chosen value or a generated one
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
  migrations, plus CI (210 tests at v3.0.0)
- **v3.0.0:** outbound email with self-service password recovery and
  invitations; RP-initiated logout (`end_session_endpoint`); consent screen and
  per-client trusted flag; public/native clients (PKCE-only); per-client claim
  allowlist; `auth_time`, `acr`, `at_hash`, `prompt`, `max_age`; a scripted
  OIDC conformance check (`npm run oidc:conformance`); SCIM 2.0 *server* for
  inbound provisioning; CSV import in the admin console; self-service profile
  editing with per-attribute permissions in the schema; SAML encrypted
  assertions, Single Logout and SP metadata import; edge rate limits on every
  anonymous route; and the fixes from the second (deep) security audit

## P0 - before pointing anything that matters at this

1. ~~**No automated tests at all.**~~ Done - 73 tests covering the crypto
   primitives, the OIDC flows and the whole provisioning API.
2. ~~**A shipped administrator with a committed password hash.**~~ Done - the
   migrations seed no users.
3. ~~**Password hashing is below current guidance.**~~ Done - scrypt
   (N=2^13, r=8, p=10) as self-describing PHC strings, legacy PBKDF2 upgraded
   at sign-in. PBKDF2 could not simply be raised: Workers caps it at 100,000
   iterations in production (local dev does not). `PASSWORD_HASHER=pbkdf2`
   remains for the Workers Free plan, whose CPU limit can't fit scrypt.
4. ~~**No CSRF defence on state-changing forms.**~~ Done - every browser POST
   is verified against `Origin` / `Sec-Fetch-Site` / `Referer` and refused
   unless it comes from this origin, sibling subdomains included.
5. ~~**No security headers.**~~ Done - HSTS, `X-Frame-Options`,
   `Referrer-Policy`, COOP, `Permissions-Policy`, and a CSP that allows only
   FlareID's own inline scripts, by hash. Inline event handlers are gone.
6. ~~**Expired state is never garbage-collected.**~~ Done - an hourly Cron
   Trigger purges expired codes, tokens, sessions and devices, and audit
   entries past a configurable retention (default 365 days).
7. ~~**PKCE is optional and `plain` is accepted.**~~ Done for `plain` - S256
   only. Mandatory PKCE arrives with public clients (item 14); every client
   today is confidential.
8. ~~**Refresh tokens never expire and are never rotated.**~~ Done - 30-day
   expiry, rotation on every use, and reuse detection that revokes the family.

## P1 - to call it a real identity provider

Items 9-17, 19 (scripted check), 20 and most of 21 shipped in v3.0.0 (see Done).
Still open:

12. **Front-channel logout** to relying parties (RP-initiated logout is done).
18. **WebAuthn / passkeys.** Phishing-resistant MFA is table stakes now.
19. **The OpenID Foundation's official suite** in CI against a disposable
    deployment (today: `npm run oidc:conformance`, a scripted check of the
    Basic OP rules, run against `idp.tmesandbox.com` at 61/0).
21. **SAML v2 saml2int items:** metadata-driven SP registry refresh,
    `subject-id`/`pairwise-id`, the full published-metadata requirements.
22. **Large-directory performance:** a group's member picker still lists every
    user, and listing groups resolves each dynamic group with a full users scan
    (bounded per request, flagged by the audit as needing validation at scale).

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
    member checklist will not survive ten thousand users - and documented,
    tested ceilings.
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
