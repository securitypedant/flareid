# Architecture

One Hono Worker, one D1 database, one KV namespace. No build step, no
client-side framework, no server to run. Everything the browser sees is HTML
rendered by a template function in `src/lib/html.ts`.

## Request path

```
src/index.ts
  ├── GET /health                      ─ before everything, no DB read
  ├── /api/v1/*        routes/api.ts   ─ bearer auth, JSON
  │                                      mounted before the appName middleware:
  │                                      these are the only routes that work on
  │                                      an instance with no users in it
  ├── middleware: resolve the admin-configurable app name once per request
  ├── /.well-known/…   routes/discovery.ts
  ├── /jwks.json       routes/discovery.ts
  ├── /authorize       routes/authorize.ts
  ├── /login, /logout  routes/login.ts
  ├── /token           routes/token.ts
  ├── /introspect      routes/introspect.ts
  ├── /revoke          routes/introspect.ts
  ├── /userinfo        routes/userinfo.ts
  ├── /account/*       routes/account.ts   ─ requireSession
  └── /admin/*         routes/admin.ts     ─ requireSession + requireAdmin
```

## Storage

| Data | Where | Why there |
|---|---|---|
| Users, groups, membership, domains | D1 | Relational, queried by several dimensions, has to be listable and auditable |
| OIDC clients | D1 | Secrets stored as SHA-256; redirect URIs as a JSON array |
| Authorization codes, access and refresh tokens | D1 | Single-use and revocable, so they need a durable record rather than a signature |
| Sessions, trusted devices, backup codes | D1 | All of these have to be listable and revocable from a UI |
| API keys | D1 | Same |
| Settings, audit log | D1 | Settings are read on nearly every request; the table is tiny and D1 caches it well |
| Login-flow state, pending MFA, rate-limit counters | KV | Short-lived, write-heavy, and nothing is lost if it disappears |

Access tokens are deliberately **opaque**, not JWTs: the only thing they
authorize is a call to `/userinfo`, and a database row means revocation is
immediate rather than eventual. The `id_token` is a signed JWT, because that is
what relying parties verify offline.

## Authentication

### Sessions

A `__Host-flareid_session` cookie holding a random 32-byte id, matched against
a row in `sessions`. Server-tracked rather than a self-contained signed cookie,
so that "sign out everywhere" and admin-forced logout are real rather than
advisory. 12-hour lifetime, checked against `created_at` on every read.

`__Host-` is a host-only cookie prefix with no `Domain` attribute, so a sibling
subdomain cannot set it. It is still *same-site* for `SameSite` purposes, which
is why the missing CSRF defence in ROADMAP.md matters.

### Passwords

PBKDF2-HMAC-SHA256 via Web Crypto, per-row salt, and the iteration count stored
alongside the hash so it can be raised later without invalidating what is
already there. Comparison is constant-time-ish over the hex digest.

### MFA

RFC 6238 TOTP, implemented by hand - HMAC-SHA1, 6 digits, 30-second step, one
step of drift tolerated either way. Hand-rolled because it is about sixty lines
and the alternative is a dependency in the authentication path. Verified
against the RFC's own test vectors in `test/totp.test.ts`.

Backup codes are hashed like passwords and consumed on use. Trusted devices are
a separate cookie plus a `trusted_devices` row, letting a user skip the
challenge on a device they have already proved, without disabling MFA.

### The login flow

`/authorize` does not post a form directly. It stores the pending OIDC request
in KV behind a random `flow_id`, renders the login form carrying that id, and
`POST /login` resumes whatever the flow says. The indirection is what lets the
same login page serve an OIDC authorization, a direct `/account` visit, a
forced MFA enrolment and an MFA challenge - and it is the extension point a
future SAML binding would use, as a second `kind` alongside `"oidc"` and
`"direct"`.

## Authorization

`/admin` is gated on membership of the **Super Admins** group, not on a column.
It is an ordinary group, managed like any other, which means there is one
mechanism for "who is allowed to do what" rather than two. The `users.is_admin`
column still exists and is still written, but only because SCIM payloads read
it; it is not consulted for access control.

The provisioning API has its own axis: a bearer token with scopes, which is not
a user at all. Actions taken that way appear in the audit log with a null
`actor_user_id` and the key's name in `actor_upn`.

## Signing keys

An RS256 keypair. The private half is the `SIGNING_KEY_PKCS8` secret; the
public half is a non-secret `var`, because it is exactly what `/jwks.json`
publishes. They are generated together by `scripts/generate-keypair.mjs` and
must stay in step.

Rotation publishes both keys for a window: set `SIGNING_PUBLIC_JWK_PREVIOUS`
and `SIGNING_KEY_ID_PREVIOUS` to the outgoing key so tokens signed moments
before the rotation stay verifiable until they expire.

Keys living in environment variables is a known limitation - rotation needs a
redeploy. ROADMAP.md item 24 moves them into storage.

## Provisioning

Two ways in, deliberately:

- **A browser**, for a human: `/admin/setup` and the admin pages.
- **`/api/v1`**, for everything else.

The API is not a thin wrapper over the UI; the directory import in particular
has semantics the form does not - upsert by username, explicit group membership,
two-pass manager resolution, per-record error reporting. The reasoning is in
[api.md](api.md), and the short version is that a bundle should produce exactly
the directory it describes.

A fresh instance has no users, so the first call cannot be authenticated by a
password. `BOOTSTRAP_TOKEN`, a Worker secret, fills that gap and retires itself
when setup completes.

## Testing

`@cloudflare/vitest-plugin` runs the tests **inside the Workers runtime**, with
a local D1 and KV, so a test can drive the whole Worker over `SELF.fetch` and
assert on real HTTP responses. The database is migrated from the actual
migration files rather than a fixture schema, so there is no second copy of the
schema to drift.

`test/helpers.ts` has a `resetDatabase()` that drops every table found in
`sqlite_master` - in reverse creation order, because foreign keys point
backwards along it - and re-applies the migrations. Tests therefore depend on
their own setup rather than on the runner's storage isolation, which has
changed shape twice across versions of the Workers Vitest integration.

## What is not here

- **No SAML.** [../SAML-implementation.md](../SAML-implementation.md) is the
  plan, including why it is achievable and why it is not next.
- **No scheduled handler.** Expired tokens and sessions are not collected;
  ROADMAP.md item 6.
- **No per-client claim filtering.** Every relying party receives the same
  claim set; ROADMAP.md item 15.
- **No inbound SCIM.** FlareID pushes to a SCIM server but cannot be
  provisioned by one; ROADMAP.md item 16.
