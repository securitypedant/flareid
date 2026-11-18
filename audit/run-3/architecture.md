# FlareID architecture and trust-boundary summary (run-3, deep, whole-codebase)

## Product
FlareID is a single-tenant OpenID Connect identity provider running as one Cloudflare Worker
(Hono 4 + TypeScript) on D1 (persistent state), KV (sessions/flows), optional R2 (backup
snapshots), Workers rate-limit bindings, Analytics Engine, and send_email. It also implements
SAML 2.0 IdP, an LDAPv3/AD-emulation read directory over Spectrum-terminated TCP, SCIM 2.0
client+server, inbound OIDC+SAML federation, and Shared Signals (SSF) transmitter+receiver.
Personal project deployed to the TME Sandbox account; treat deployment-dependent facts
(Access app attachment, mTLS on zone, Spectrum apps, notification destinations) as
needs-validation.

## Principals and authority
- Anonymous internet caller: discovery, /setup (pre-setup bootstrap-gated), /login + factors,
  /authorize flow start, /saml/sso request parse, /federation callbacks, recovery/invite,
  /device approval, /connect/register (open DCR), /ssf/receive (signature-authed),
  /token (client-auth), /api/v1/openapi.json.
- Bootstrap token (env secret): full admin on /api/v1 pre-setup; post-setup only break-glass
  routes (/api/v1/recovery/admin-reset, /api/v1/backup/restore).
- API-key holders (flareid_sk_, scoped): /api/v1 + /scim/v2; non-admin keys barred from
  admin-role holders/groups via guards + grantsAdminRoleGroup.
- Signed-in user: /account/* per grants; SSO reuse at /authorize + /saml/sso.
- Group manager: member changes + access-request decisions for own groups only.
- Admin-role holder: /admin/* via PATH_AREAS map (unmapped = super-only) + 10-min step-up on
  every POST under /admin.
- OIDC clients: secret or private_key_jwt; public clients PKCE-only. Dynamic clients: hashed
  registration_access_token for RFC 7592 self-management.
- SAML SPs: redirect-binding signature (optional per-SP) + registered ACS allowlist; POST
  binding refused.
- Upstream IdPs: OIDC (KV state+PKCE+nonce+JWKS) or SAML response signature vs configured cert.
- LDAP: service binds (flareid_ldap_ secrets, per-app scoped views) + user binds (shared web
  lockout, TOTP-in-password) + anonymous root-DSE only.
- SSF transmitters: registered issuer+JWKS; verified SETs can revoke sessions/tokens and flag
  users on the risk watchlist.

## Data classes
Password hashes; TOTP seeds; WebAuthn credentials; sealed secrets (KEY_ENCRYPTION_KEY) for
client secrets, SCIM bearer secrets, CF API token, email keys; signing keys (RS256/ES256) sealed
in D1; sessions + refresh-token families; audit log (hash-chained); whole-DB backup bundles;
HR attributes incl. custom schema-mapped claims.

## Cross-cutting controls
4 MiB declared-length body cap; edge rate limits (AUTH 120/min, API 600/min, IP-keyed) on named
route groups; CSRF origin checks on browser mounts only (machine mounts precede it
intentionally); security headers with frame-ancestors escape hatches for /check_session and
frontchannel; step-up freshness on /admin POSTs and sensitive /account actions; privilege
guards making dynamic-group rules unable to grant admin roles to non-privileged writers;
audit on all API calls and mutations; per-request bound-principal revalidation on LDAP;
revocation cascades (sessions+tokens+passkeys) on deactivation, password change, SCIM
disable, SSF session-revoked.

## Outbound fetch inventory (SSRF-relevant)
SCIM-out targets (admin-set), SSF stream endpoints (admin-set), SSF transmitter JWKS
(caller-registered), client jwks_uri (self-registered via DCR), federation issuer discovery +
token + JWKS (admin-set issuer, fetched-doc endpoints), SAML SP metadata_url (admin-set, https,
no-redirect, 10s, 256KB cap), SCIM photo URL (provisioner-controlled — weakest guard), Turnstile
siteverify, pwnedpasswords, Cloudflare API (metrics/cfone), backchannel logout URIs.

## Deployment-dependent (needs_validation)
Zone-level Access app + AUD enforcement; mTLS (request.cf.tlsClientAuth); Spectrum apps for
LDAPS; Workers notification destinations; strength/secrecy of env secrets; optional
AUTH_LIMITER/API_LIMITER bindings; EMAIL binding; issuer resolution before setup (request-origin
derived).

## Run-3 scope notes
Two prior runs exist: run-1 deep whole-repo @v3.9.0 (83 records), run-2 LDAP-scoped @d6bcebd
(14 records). Both refs are ancestors of HEAD (0972885); all 97 records cite changed source —
every one is a revalidation lead, none are carried confirmations. New since run-1: SSF
transmitter+receiver, Cloudflare One integration (Access JWT gate, posture, watchlist, list
sync), backup/restore, audit chain, DCR+private_key_jwt, session mgmt, backchannel logout,
3rd-party-init, e2e rig — all first-pass review territory.
