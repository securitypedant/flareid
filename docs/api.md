# The provisioning API

Everything the admin UI does, without a browser: create the first
administrator, set the primary domain, import users and groups, register
relying parties, configure SCIM.

It exists because the alternative was a deploy script holding a cookie jar,
regexing a `flow_id` out of the login page and parsing a client secret out of a
`<code>` block in the response. That worked until a heading moved.

**Reference:** every operation, with its permission, parameters, request body
and responses, is in [api-reference.md](api-reference.md), generated from the
OpenAPI 3.1 document [openapi.json](openapi.json). Every deployment also serves
that document at `GET /api/v1/openapi.json` (no token needed - it describes
routes, never data), so a client generator or an API explorer can point at it.
Both files are generated from the route definitions with `npm run docs:api`;
the test suite fails if they are stale, and fails if a console action has no
API operation (`test/api-parity.test.ts`).

Base path: `/api/v1`. JSON in, JSON out. Every mutation is idempotent and is
recorded in the audit log against the token that made it. Every authenticated
call, reads included, is also logged as `api.request` with its method, path and
response status; a presented key that is unknown, revoked or expired is logged as
`api.auth_failed` with only its non-secret prefix. Admin → Log → "API keys"
shows both.

## Authentication

`Authorization: Bearer <token>`, where the token is one of two things.

### The bootstrap token

`BOOTSTRAP_TOKEN`, a Worker secret set at deploy time. (The browser page at
`/setup` takes the same token in a form and runs the same setup as
`POST /api/v1/setup` with `complete: true`.) Values starting `replace-me` - the
placeholders in `.dev.vars.example` - are never accepted.

A freshly migrated FlareID has no users and no default password, so there is
nothing to log in as - this is the only way in. It is accepted for every
endpoint **until setup completes**, and after that only by
`POST /api/v1/recovery/admin-reset`.

**Marking setup complete retires it, so `complete: true` must be the last call
a provisioning run makes.** Sending it early means the next request arrives
with a token FlareID stopped accepting one request ago. Leaving setup
incomplete on failure is deliberate: the token still works, so re-running
resumes.

To close the door entirely:

```bash
npx wrangler secret delete BOOTSTRAP_TOKEN
```

### API keys

Minted from **Admin → Integrations → API keys**, or from
`POST /api/v1/api-keys`. Shown once, stored only as a SHA-256 hash. Use these
for anything ongoing.

Permissions are the same ones admin roles use (Security → Roles): one per
area, `<area>:read` or `<area>:write` (write implies read), and `*` for
everything. The areas are `users`, `groups`, `domains`, `schemas`, `import`
(write only), `oidc`, `saml`, `scim`, `email`, `api_keys`, `security`,
`branding`, `signing_keys`, `roles`, `audit` and `performance` (both read
only). Each operation names the permission it needs as `x-permission` in the
spec, and in the reference.

The original scopes keep working, as shorthand:

| Scope | Stands for |
|---|---|
| `directory:read` | `users:read`, `groups:read`, `domains:read`, `schemas:read`, `oidc:read`, `saml:read` |
| `directory:write` | `users:write`, `groups:write`, `domains:write`, `import:write`, and reading clients, SAML apps and schemas |
| `clients:write` | `oidc:write`, `saml:write` |
| `settings:write` | `security:write`, `branding:write`, `email:write`, `scim:write`, `schemas:write` |
| `admin` | `*`: everything, plus minting further keys |

Some actions need `*` whatever else a key holds, because they reach an
administrator: creating or resetting an administrator in `/setup`, granting
`super_admin` or an admin role group through an import, acting on an account
that holds an admin role (update, delete, password or MFA reset, invite),
changing an admin role group or its members, moving every UPN to another
domain, and resetting every password to the default. A role can only be given
permissions the calling key holds itself, and `*` only by a `*` key.

A failure answers `401` (unknown, revoked or expired token) or `403` (the token
is valid but lacks the scope), with a `message` explaining which.

## Endpoints

The sections below cover the original endpoints in depth, with the scope names
they were written for (still accepted); the exact permission of every route is
in the reference. The API also covers everything else the console
does - in summary:

| Area | Endpoints |
|---|---|
| Users | `POST /users`, `GET`/`PATCH`/`DELETE /users/{username}`, `POST .../reset-password`, `POST .../reset-mfa`, `GET`/`DELETE .../sessions`, `GET .../passkeys`, `DELETE .../passkeys/{credential_id}`, `GET .../apps`, `DELETE .../apps/{client_id}` |
| Groups | `POST /groups`, `GET`/`PATCH`/`DELETE /groups/{id}` (members paged, `?search=`), `POST .../freeze`, `POST .../members`, `DELETE .../members/{username}` |
| OIDC clients | `GET`/`PATCH`/`DELETE /clients/{client_id}`, `POST .../rotate-secret` |
| SAML, SCIM | `GET /saml/service-providers/{id}`, `GET /scim/config` |
| Domains | `DELETE /domains/{domain}`, `PUT /domains/{domain}/brand` |
| API keys | `GET /api-keys` (never tokens or hashes), `DELETE /api-keys/{id}` |
| Email | `GET`/`PUT /email`, `POST /email/enabled`, `POST /email/test` |
| Branding | `GET`/`PATCH /branding` (default brand, `custom_css` included), `PUT`/`DELETE /branding/logo`, `GET`/`POST /branding/brands`, `GET`/`PATCH`/`DELETE /branding/brands/{id}`, `PUT`/`DELETE /branding/brands/{id}/logo`, `GET /branding/email-templates`, `PUT`/`DELETE /branding/email-templates/{key}` - see [branding.md](branding.md) |
| Security | `GET /security`, `PUT /security/password-policy`, `.../rate-limit`, `.../session-limits`, `.../audit-retention`, `.../new-user-password`, `.../require-mfa`, `.../breached-passwords`, `.../turnstile`, `POST /security/new-user-password/apply-to-all`; authentication policies (`/security/policies`), factors (`/security/factors`, security questions at `/security/security-questions`), roles (`/security/roles`) and signing keys (`/security/signing-keys`, `POST .../{alg}/rotate`) |
| Monitoring | `GET /audit` (the console's log filters), `GET /stats` (the overview), `GET /performance` (`configured: false` until `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN` are set) |

Second factors: `GET /security/factors` lists `totp`, `passkey`,
`email_otp` (email one-time codes) and `security_questions`, each with
`enabled` (the switch) and `usable` (switched on and able to work - email
codes also need email to be configured). `PUT /security/factors/email_otp`
with `{"enabled": true}` is a `400` until email is configured, and
`PUT /security/factors/security_questions` a `400` while fewer questions are
enabled than each person must set. Users carry `email_otp_enabled` and
`security_questions_enabled` next to `mfa_enabled` (the authenticator app),
and `POST /users/{username}/reset-mfa` clears all three. `second_factors`
lists every factor a user has enrolled (`totp`, `passkey` - at least one -
`email_otp`, `security_questions`); `GET /stats` counts users with any of them
in `counts.mfa_enrolled` and per factor in `second_factors`.

Security questions: `GET /security/security-questions` returns the settings
(`required`: how many each person sets, default 3; `asked`: how many are
asked at sign-in, default 2) and the catalogue of questions people choose
from; `PUT` changes the settings, and `POST .../questions`,
`PATCH .../questions/{id}` (`{"enabled": false}`) and
`DELETE .../questions/{id}` manage the catalogue (`security:write`). A question
someone has answered cannot be deleted, only disabled; answers are never
exposed (they are stored only as salted hashes).

Breached passwords and bot protection: `GET /security` includes
`breached_password_check` (on by default; `PUT /security/breached-passwords`
with `{"enabled": false}` turns it off) and `turnstile` (`mode`, `active`,
`site_key`, `secret_set`, `secret_from_env`). `PUT /security/turnstile` takes
`mode` (`off` / `on`), `site_key` and `secret`; fields not given keep their
values, the secret is write-only and never returned, and `mode: "on"` is a
`400` until a site key and a secret (or the `TURNSTILE_SECRET_KEY` Worker
secret) are present. A password set through the API that is in a breach is a
`400` naming how often it appeared.

Request bodies are validated against the schema in the spec: a wrong type is a
`400` with `error: "invalid_request"` and a `message` naming the field.

### `GET /status`

Scope: `directory:read`.

```json
{
  "service": "flareid-idp",
  "api_version": 1,
  "issuer": "https://idp.example.com",
  "app_name": "FlareID",
  "setup_completed": true,
  "default_domain": "example.com",
  "counts": { "users": 31, "groups": 8, "oidc_clients": 1, "domains": 1 }
}
```

### `POST /setup`

Scope: `settings:write` for the settings fields; the `admin` block additionally
requires the `admin` scope (it creates or resets a Super Admin), and is checked
before anything is applied. Every field is optional; only what is present is
applied, in a fixed order - settings, then the administrator, then the
completion flag. That order matters: the account is created using whatever
`new_user_password_mode` and `default_password` say, so applying those
afterwards would mint an administrator with the wrong credential.

```json
{
  "domain": "example.com",
  "admin": {
    "username": "admin",
    "password": "optional - generated and returned if omitted",
    "display_name": "Administrator",
    "given_name": "Administrator",
    "family_name": ""
  },
  "default_password": "",
  "new_user_password_mode": "random",
  "app_name": "FlareID",
  "login_subtitle": "Sign in to continue.",
  "login_gradient": { "from": "#f7b733", "to": "#f6821f" },
  "require_mfa": false,
  "password_policy": {
    "minLength": 8,
    "requireUppercase": false,
    "requireLowercase": false,
    "requireNumber": false,
    "requireSymbol": false
  },
  "rate_limit": { "max_attempts": 5, "window_minutes": 15 },
  "cursor_trail": { "enabled": true, "characters": "" },
  "session_limits": { "max_hours": 12, "idle_minutes": 0 },
  "complete": false
}
```

`cursor_trail.characters` empty means the default symbols; otherwise its
characters (spaces dropped, at most 64) are cycled in order on the sign-in page.
`session_limits.max_hours` is 1-720; `idle_minutes` is 0 (no inactivity limit)
or 5-10080. Both apply to existing sessions immediately. For either object, an
omitted field keeps its current value.

Answers with what it applied, and the administrator's generated password if one
was generated:

```json
{
  "ok": true,
  "applied": ["domain=example.com", "admin=admin@example.com"],
  "setup_completed": false,
  "admin": { "upn": "admin@example.com", "password": "K7mq..." }
}
```

The administrator is placed in `Super Admins` and kept active explicitly -
imported and admin-created users are `disabled` until activated.

### `POST /directory/import`

Scope: `directory:write`. The main event.

```json
{
  "version": 1,
  "mode": "merge",
  "domain": "example.com",
  "groups": [
    { "name": "Engineering", "description": "Everyone in Engineering" },
    {
      "name": "All Employees",
      "description": "Every employee - dynamic",
      "rule": "{\"all\":[{\"field\":\"employment_type\",\"op\":\"eq\",\"value\":\"full_time\"}]}"
    }
  ],
  "users": [
    {
      "username": "ada.kowalski",
      "display_name": "Ada Kowalski",
      "given_name": "Ada",
      "family_name": "Kowalski",
      "password": null,
      "groups": ["Engineering"],
      "job_title": "Staff Engineer",
      "department": "Engineering",
      "employee_number": "E0007",
      "hire_date": "2021-03-01",
      "employment_status": "active",
      "employment_type": "full_time",
      "location": "London",
      "manager": "nikita.chapman",
      "status": "active",
      "schema": "FlareID HR",
      "attributes": { "cost_center": "CC-100" },
      "super_admin": false
    }
  ]
}
```

The important property of the format: **users carry no domain**. Each one is
identified by `username` - the local part - and the UPN is composed
server-side as `username@domain`, taking `domain` from the bundle or the
instance default. That is what makes one bundle importable onto any deployment.

Other things worth knowing:

- **Imported users land `disabled` by default.** Set `status: "active"` on
  each user you want to be able to sign in straight away.
- **`schema` names the schema the user conforms to** (a `user` schema from
  `GET /schemas`, e.g. `"FlareID HR"`); it defaults to the deployment's
  default schema (`Basic` out of the box). `attributes` sets schema-defined
  attribute values - names matching built-in fields write to those columns;
  anything else becomes a custom attribute. Import merges custom attributes
  rather than clearing ones the schema doesn't define; use
  `POST /schemas/:id/apply` to conform everyone.
- **A group is static or dynamic, never both.** A group listed with a `rule`
  is dynamic: the JSON rule (`{"all":[{"schema","field","op","value"}]}`, ops
  `eq`/`ne`, every condition must match) is evaluated at read time, and its
  membership is exactly the matching users. `schema` is optional and only
  labels where the attribute came from. Explicit members are removed when a
  group becomes dynamic, and a user listing a dynamic group in `groups` is
  reported in `errors` and skipped. `Super Admins` can never be dynamic. For
  static groups, omit `groups` on a user to leave membership alone; send `[]`
  to clear it.
- **Groups are upserted**, whether they appear in `groups` or only as a
  membership, so a bundle does not have to declare the same thing twice.
- `manager` names another user's `username`, resolved in a second pass - so a
  manager may appear later in the bundle, or in an earlier chunk, or already be
  in the database.
- `password` is only used when creating an account. Omitting it on re-import
  leaves whatever the user has chosen since, which is the only safe default.
- `mode: "replace"` deletes every user who is not a Super Admin, and every
  group except the two built-ins, before importing.
- **Maximum 100 users per request.** Each distinct password costs a scrypt
  hash (~100 ms of CPU): a chunk of 100 users with generated passwords takes
  around ten seconds, while 100 users sharing a default password hash it once.
  Chunk; the import is idempotent by username, so chunking is safe.
- With the breached-password check on (the default), explicit passwords are
  checked against Have I Been Pwned (only a 5-character hash prefix is sent)
  when the request carries at most 200 of them - every request, at the current
  cap - and a breached one is reported in `errors` like a policy failure. If
  the service cannot be reached, the passwords are allowed.

```json
{
  "domain": "example.com",
  "mode": "merge",
  "users": { "created": 30, "updated": 0, "skipped": 0 },
  "groups": { "created": 6, "updated": 0 },
  "generated_passwords": { "ada.kowalski@example.com": "..." },
  "managers_resolved": 29,
  "errors": []
}
```

`errors` is per-record and non-fatal: one bad row is reported, the other
ninety-nine still land.

### `POST /directory/reset`

Scope: `directory:write`. `mode: "replace"` with an empty bundle - removes
everything except the administrators and the two built-in groups.

When outbound SCIM is configured, every removed user and group is queued for
deletion at the SCIM target in the same transaction as the local delete, and a
bounded batch is sent straight away; the rest (and any failure) is retried by
every sync and the hourly cron. The response includes `scim` with the counts
and `deprovision_pending`.

### `POST /users/{username}/invite`

Scope: `directory:write`. Emails the user a single-use link: an **invitation**
(7 days; sets a password and activates the account) when the account is not
active, otherwise a **password reset** link (1 hour). Sending a new link voids
every earlier one for that user. Answers `{ "ok": true, "kind": "invite" |
"reset", "to": "<address>" }`; `409` when email is not configured; `403` for a
Super Admin target unless the key has the `admin` scope. The recipient is the
user's `email` if set, otherwise their UPN.

### `GET /users`, `GET /groups`

Scope: `directory:read`. `?limit=` (max 500) and `?offset=`. Users come back
with resolved `manager_upn` and `groups`, and explicitly without
`password_hash`, `password_salt` or `totp_secret`.

### `GET /domains`, `POST /domains`

Scope: `directory:read` / `directory:write`.

```json
{ "domain": "example.com", "set_default": true }
```

### `POST /domains/{domain}/default`

Scope: `directory:write`. Makes an existing domain the default. `404` if it is
not registered.

### `POST /domains/{domain}/apply-to-all`

Scope: **`admin`** (since v3: it rewrites Super Admin UPNs too, and recovery
mail follows the UPN). Rewrites every user's UPN onto this domain, keeping
the local part, and voids outstanding invitation and reset links for the
moved accounts. Answers `{ "updated": n, "conflicts": [...] }`, where a
conflict is two accounts whose local parts would collide.

Rarely needed now that imports take the domain as a parameter, but kept for an
already-provisioned instance that has to move.

### `GET /clients`, `POST /clients`

Scope: `directory:read` / `clients:write`.

```json
{
  "name": "Cloudflare Access",
  "redirect_uris": ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
  "client_id": "optional",
  "client_secret": "optional, at least 24 characters",
  "client_type": "confidential | public",
  "trusted": true,
  "allowed_claims": ["profile", "email", "groups"],
  "post_logout_redirect_uris": ["https://app.example.com/signed-out"],
  "frontchannel_logout_uri": "https://app.example.com/logout/frontchannel"
}
```

- `client_type: "public"` registers a native/SPA client with no secret (omit
  `client_secret`); it must use PKCE (S256) and may redirect to any port on a
  registered loopback URI (RFC 8252).
- `trusted: false` shows the user a consent screen before the first code; a
  user's consent is remembered per scope and withdrawn when they revoke the app.
- `allowed_claims` limits which claim groups the client can ever receive
  (`profile`, `email`, `groups`, `hr`, `custom`); the id_token and `/userinfo`
  release the intersection of the requested scopes and this list. Omitted or
  `null` means every group (the pre-v3 behaviour).
- `post_logout_redirect_uris` are exact-match targets for RP-initiated logout
  at `/oidc/logout` (the discovery document's `end_session_endpoint`); each
  must be `https`, or `http` on a loopback host.
- `frontchannel_logout_uri` (https) is loaded in a hidden iframe, with `iss`
  and `sid`, when a user who signed in to this client signs out of FlareID
  (OpenID Connect Front-Channel Logout 1.0).

Supplying `client_id` and `client_secret` is what makes a single-pass Terraform
apply possible: Terraform needs the credential to create the Access identity
provider, and cannot read a value out of an application it has not deployed
yet. So it generates the pair, passes it in, and nothing has to flow back.

Both must be present together, and a secret shorter than 24 characters is a
`400`. It used to be silently replaced with a generated one, which left Access
holding a credential FlareID had never heard of and every login failing with
nothing to explain why.

Re-registering the same `client_id` updates it rather than colliding, so
provisioning converges on re-runs. A generated `client_secret` is returned
once; a supplied one is not echoed back.

### `GET /saml/service-providers`, `POST /saml/service-providers`, `DELETE /saml/service-providers/{id}`

Scope: `directory:read` / `clients:write`.

Registers a SAML 2.0 service provider - an application allowed to sign users
in via `/saml/sso`. Keyed on `entity_id`, so re-running provisioning updates
the existing row rather than colliding on the unique index; fields not
supplied keep their values.

```json
{
  "entity_id": "https://team.cloudflareaccess.com",
  "name": "Cloudflare Access",
  "acs_urls": ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
  "default_acs_url": "optional - used when the request omits one",
  "nameid_format": "transient | emailAddress | persistent",
  "attribute_map": { "email": "email", "groups": "groups" },
  "sign_response": true,
  "sign_assertion": true,
  "want_authn_requests_signed": false,
  "signing_certs": ["PEM blocks, or bare base64 DER"],
  "slo_url": "https://sp.example.com/saml/slo",
  "encrypt_assertions": false,
  "encryption_cert": "PEM, required when encrypt_assertions is true",
  "subject_id": "'' | subject-id | pairwise-id"
}
```

`slo_url` (https) enables SAML Single Logout at `/saml/slo` (HTTP-Redirect,
signed LogoutRequests only, bound to the browser's session by SessionIndex).
With `encrypt_assertions`, the signed assertion is encrypted to
`encryption_cert` (AES-256-GCM, RSA-OAEP).

`subject_id` releases the SAML subject identifier attribute: `pairwise-id`
(different for every SP) or `subject-id` (the same for every SP), both scoped
to the user's UPN domain.

`POST /saml/service-providers/import-metadata` with `{ "xml": "<EntityDescriptor ...>",
"name": "optional" }`, or `{ "url": "https://..." }` to register the SP's
published metadata (re-read daily), creates or updates the SP from its metadata: entity ID,
HTTP-POST ACS URLs, SLO URL, signing and encryption certificates. Answers
`{ "ok": true, "id", "entity_id", "acs_urls", "slo_url", "encryption" }`.

`attribute_map` maps a SAML attribute name onto a user field; an empty object
falls back to `{"email","name","given_name","family_name","groups"}`.
`want_authn_requests_signed` requires at least one entry in `signing_certs`,
any of which may have signed the request - register two during certificate
rollover.

`DELETE` takes the numeric `id` from the list response, not the entity_id:
entity IDs are URLs and cannot ride inside a path segment.

### `GET /schemas`, `POST /schemas`, `PATCH /schemas/:id`, `DELETE /schemas/:id`, `POST /schemas/:id/apply`

Reads carry `directory:read`; writes carry `settings:write`.

A schema names the attribute vocabulary an object type (`user` or `group`)
conforms to. A fresh deployment ships three provided schemas: user `Basic`
(identity fields only - the default for new users), user `FlareID HR` (the
full built-in HR set), and group `Basic` (the default for new groups). The
list response marks the default with `"default": true`. Provided schemas are
editable but not deletable.

Moving an object to a schema **conforms** it: attributes the target schema
defines keep their values (matched by name, so same-named attributes carry
over), and everything else is cleared. Identity fields (names, UPN) are on
every object and are never cleared. Deleting a schema moves its objects to
the default schema the same way.

```json
// POST /schemas
{
  "object_type": "user",
  "name": "Contractor",
  "description": "Engagement fields for non-employees",
  "attributes": [
    { "name": "cost_center", "label": "Cost center", "type": "string" },
    { "name": "end_date", "label": "Contract end", "type": "date" },
    { "name": "sponsor", "label": "Sponsor", "type": "reference", "ref_object": "user", "required": true }
  ]
}
```

Attribute `type` is `string` (default), `number`, `date`, `boolean`, or
`reference` (with `ref_object`, currently `user`). Names must match
`^[a-z][a-z0-9_]*$` and may not be a claim the IdP asserts itself (`email`,
`groups`, `id`, `name`, `preferred_username`, ...).

`"user_editable": true` lets users change the attribute themselves on
My account. It is refused for references, for `manager`, and for any attribute
a dynamic group's rule matches on (otherwise users could choose their own
groups); the reverse also holds - a rule may not match on an editable
attribute. Attribute names matching
built-in user fields (`job_title`, `department`, `employee_number`,
`hire_date`, `employment_status`, `employment_type`, `location`, and the name
fields) map onto those columns; anything else is stored as a custom
attribute. `PATCH` accepts `name`, `description` and a full `attributes`
replacement. `POST /:id/apply` conforms every object of that type to the
schema (see above) and returns `{ "applied": <count> }`.

Users and groups in `GET /users` / `GET /groups` now include `schema_name`,
`attributes` (the custom-attribute map), and - for groups - `rule`,
`member_count` (rule matches for a dynamic group, assigned members for a
static one) and `explicit_member_count` (always 0 for a dynamic group).

### `POST /scim/config`, `POST /scim/test`, `POST /scim/sync`

Scope: `settings:write`.

```json
{
  "endpoint": "https://api.cloudflare.com/client/v4/accounts/<id>/access/scim/v2",
  "secret": "...",
  "scope": { "mode": "all", "group_ids": [] }
}
```

`POST /scim/sync` runs a full sync in batches of 200 users per call, then the
groups. The response carries `complete` and `remainingUsers`: call it again
until `complete` is `true` (the hourly cron also carries an unfinished sync on).

### SCIM 2.0 server (`/scim/v2`)

FlareID also *accepts* provisioning: an HR system or upstream IdP can manage
users and groups over SCIM 2.0 at `/scim/v2` (`Users`, `Groups`,
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`), authenticated with an
API key - `directory:read` for reads, `directory:write` for writes. Filters
support `userName`/`externalId`/`displayName eq "..."`; `PATCH` follows
RFC 7644 and is all-or-nothing. Super Admins (the users and their group
memberships) need an `admin`-scoped key. Every inbound change is passed on to
the outbound SCIM target when one is configured.

### `POST /api-keys`

Scope: `admin`.

```json
{ "name": "terraform", "scopes": ["directory:write", "clients:write"] }
```

The response is the only time the token is returned.

### `POST /recovery/admin-reset`

**Bootstrap token only**, and the one route it still answers after setup is
complete. Re-creates or re-enables a Super Admin and resets their password,
loudly, in the audit log.

```json
{ "username": "admin", "password": "optional - generated if omitted" }
```

It exists because the alternative, for a locked-out deployment, is hand-editing
D1. Delete the `BOOTSTRAP_TOKEN` secret if you would rather it did not.

## A complete provisioning run

Note the ordering: `complete` last.

```bash
BASE=https://idp.example.com
TOKEN=$BOOTSTRAP_TOKEN

# 1. Domain, administrator, settings - but NOT complete.
curl -sS -X POST "$BASE/api/v1/setup" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","admin":{"username":"admin"},
       "default_password":"a-shared-demo-password","new_user_password_mode":"default"}'

# 2. The directory, in chunks of 100.
curl -sS -X POST "$BASE/api/v1/directory/import" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @directory.json

# 3. A relying party.
curl -sS -X POST "$BASE/api/v1/clients" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Cloudflare Access",
       "redirect_uris":["https://team.cloudflareaccess.com/cdn-cgi/access/callback"]}'

# 4. A long-lived key for later, while the bootstrap token still works.
curl -sS -X POST "$BASE/api/v1/api-keys" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"ci","scopes":["directory:write"]}'

# 5. Last.
curl -sS -X POST "$BASE/api/v1/setup" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"complete":true}'
```

A worked implementation of exactly this, including chunking and the error
handling, is in the ai-horizon repository as
`scripts/bootstrap-flareid.mjs` and `scripts/lib/flareid-api.mjs`.
