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
| `directory:write` | Create and update users and groups, manage domains |
| `clients:write` | Register OIDC relying parties |
| `settings:write` | Settings, branding, SCIM configuration, setup |
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

Scope: `settings:write`. Every field is optional; only what is present is
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

The administrator is placed in `Super Admins` and deliberately **not** in
`All Employees` - a service account that administers the directory is not a
person, and `All Employees` is the intended target for access policies and SCIM
sync scope.

### `POST /directory/import`

Scope: `directory:write`. The main event.

```json
{
  "version": 1,
  "mode": "merge",
  "domain": "example.com",
  "groups": [
    { "name": "Engineering", "description": "Everyone in Engineering" }
  ],
  "users": [
    {
      "username": "ada.kowalski",
      "display_name": "Ada Kowalski",
      "given_name": "Ada",
      "family_name": "Kowalski",
      "password": null,
      "groups": ["All Employees", "Engineering"],
      "job_title": "Staff Engineer",
      "department": "Engineering",
      "employee_number": "E0007",
      "hire_date": "2021-03-01",
      "employment_status": "active",
      "employment_type": "full_time",
      "location": "London",
      "manager": "nikita.chapman",
      "status": "active",
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

- **Group membership is explicit.** The admin form auto-joins new accounts to
  `All Employees`, because a human filling in a form should not have to
  remember. An import does not: it produces exactly the directory it describes,
  so a group that is not listed is a group the person is not in. Omit `groups`
  entirely to leave existing membership alone; send `[]` to clear it.
- **Groups are upserted**, whether they appear in `groups` or only as a
  membership, so a bundle does not have to declare the same thing twice.
- `manager` names another user's `username`, resolved in a second pass - so a
  manager may appear later in the bundle, or in an earlier chunk, or already be
  in the database.
- `password` is only used when creating an account. Omitting it on re-import
  leaves whatever the user has chosen since, which is the only safe default.
- `mode: "replace"` deletes every user who is not a Super Admin, and every
  group except the two built-ins, before importing.
- **Maximum 100 users per request.** Each new account costs a PBKDF2 hash, and
  a few hundred of those in one request finds the Worker CPU limit. Chunk;
  the import is idempotent by username, so chunking is safe.

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
