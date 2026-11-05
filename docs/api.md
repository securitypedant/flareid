# The provisioning API

Everything the admin UI does, without a browser: create the first
administrator, set the primary domain, import users and groups, register
relying parties, configure SCIM.

It exists because the alternative was a deploy script holding a cookie jar,
regexing a `flow_id` out of the login page and parsing a client secret out of a
`<code>` block in the response. That worked until a heading moved.

Base path: `/api/v1`. JSON in, JSON out. Every mutation is idempotent and is
recorded in the audit log against the token that made it.

## Authentication

`Authorization: Bearer <token>`, where the token is one of two things.

### The bootstrap token

`BOOTSTRAP_TOKEN`, a Worker secret set at deploy time.

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

Scopes:

| Scope | Allows |
|---|---|
| `directory:read` | Read users, groups, domains, clients, status |
| `directory:write` | Create and update users and groups, manage domains; cannot grant `super_admin`, add members to `Super Admins`, or overwrite an existing `Super Admins` member |
| `clients:write` | Register OIDC relying parties |
| `settings:write` | Settings, branding, SCIM configuration, setup; cannot create or reset an administrator |
| `admin` | All of the above, plus minting further keys |

A failure answers `401` (unknown, revoked or expired token) or `403` (the token
is valid but lacks the scope), with a `message` explaining which.

## Endpoints

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
  "complete": false
}
```

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

Scope: `directory:write`. Rewrites every user's UPN onto this domain, keeping
the local part. Answers `{ "updated": n, "conflicts": [...] }`, where a
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
  "client_secret": "optional, at least 24 characters"
}
```

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
  "signing_certs": ["PEM blocks, or bare base64 DER"]
}
```

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
`reference` (with `ref_object`, currently `user`). Attribute names matching
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
