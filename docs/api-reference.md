# FlareID provisioning API reference

Generated from the route definitions by `npm run docs:api`; do not edit by hand.
The same document is served by every deployment at `GET /api/v1/openapi.json` (no token needed), and is in [openapi.json](openapi.json).
See [api.md](api.md) for authentication, permissions and worked examples.

API version 3.7.0.

## Contents

- [Status](#status) - Instance status and first-run setup.
- [Users](#users) - People in the directory.
- [Groups](#groups) - Static and dynamic (rule-based) groups.
- [Directory](#directory) - Bulk import and reset.
- [Domains](#domains) - UPN domains.
- [Schemas](#schemas) - User and group attribute schemas.
- [OIDC clients](#oidc-clients) - OpenID Connect relying parties.
- [SAML](#saml) - SAML service providers.
- [SCIM](#scim) - Outbound SCIM provisioning (FlareID as a SCIM client).
- [Email](#email) - Outbound email settings and templates.
- [API keys](#api-keys) - Bearer tokens for this API.
- [Branding](#branding) - The default brand and per-domain brands: app name, logo, sign-in page colours, custom CSS, email accent; email templates.
- [Security](#security) - Password, session, rate-limit and audit settings; authentication policies and factors.
- [Roles](#roles) - Admin roles: permission sets granted to groups.
- [Signing keys](#signing-keys) - Token signing keys (public parts only).
- [Monitoring](#monitoring) - Overview statistics, performance and the audit log.
- [Recovery](#recovery) - Break-glass administrator reset (bootstrap token only).

## Status

Instance status and first-run setup.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/status` | `directory:read` | Instance status and directory counts |
| `POST` | `/api/v1/setup` | `settings:write` | Configure the instance (first run, or re-run to converge) |

### `GET /api/v1/status`

Instance status and directory counts.

Permission: `directory:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `service` | string | yes |  |
| `api_version` | number | yes |  |
| `issuer` | string | yes |  |
| `app_name` | string | yes |  |
| `setup_completed` | boolean | yes |  |
| `default_domain` | string \| null | yes |  |
| `counts` | object { users, groups, oidc_clients, domains } | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/setup`

Configure the instance (first run, or re-run to converge).

Applies settings, then creates or resets the administrator (needs `*`), then marks setup complete when `complete` is true - which retires the bootstrap token, so send it last.

Permission: `settings:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `domain` | string | no |  |
| `admin` | object { username, password, display_name, given_name, family_name } | no |  |
| `default_password` | string | no |  |
| `app_name` | string | no |  |
| `login_subtitle` | string | no |  |
| `login_gradient` | object { from, to } | no |  |
| `require_mfa` | boolean | no |  |
| `new_user_password_mode` | "default" \| "random" | no |  |
| `password_policy` | PasswordPolicy | no |  |
| `rate_limit` | object { max_attempts, window_minutes } | no |  |
| `cursor_trail` | object { enabled, characters } | no |  |
| `session_limits` | object { max_hours, idle_minutes } | no |  |
| `complete` | boolean | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `applied` | string[] | yes |  |
| `setup_completed` | boolean | yes |  |
| `admin` | object { upn, password } | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Users

People in the directory.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `POST` | `/api/v1/users` | `users:write` | Create a user |
| `GET` | `/api/v1/users` | `users:read` | List users |
| `GET` | `/api/v1/users/{username}` | `users:read` | Get a user |
| `PATCH` | `/api/v1/users/{username}` | `users:write` | Update a user |
| `DELETE` | `/api/v1/users/{username}` | `users:write` | Delete a user |
| `POST` | `/api/v1/users/{username}/reset-password` | `users:write` | Set or generate a password |
| `POST` | `/api/v1/users/{username}/reset-mfa` | `users:write` | Reset multi-factor authentication |
| `GET` | `/api/v1/users/{username}/sessions` | `users:read` | List active sessions |
| `DELETE` | `/api/v1/users/{username}/sessions` | `users:write` | Sign out everywhere |
| `GET` | `/api/v1/users/{username}/passkeys` | `users:read` | List passkeys |
| `DELETE` | `/api/v1/users/{username}/passkeys/{credential_id}` | `users:write` | Remove a passkey |
| `GET` | `/api/v1/users/{username}/apps` | `users:read` | List the OIDC apps holding tokens for a user |
| `DELETE` | `/api/v1/users/{username}/apps/{client_id}` | `users:write` | Revoke an app's access |
| `POST` | `/api/v1/users/{username}/invite` | `users:write` | Email an invitation or a password reset link |

### `POST /api/v1/users`

Create a user.

New accounts are inactive unless `status` is `active`. Without `password`, the new-account password setting applies and the generated password is returned once. Giving someone an admin role group needs `*`.

Permission: `users:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `given_name` | string | yes |  |
| `family_name` | string | no |  |
| `email` | string \| null | no | Where email for the account goes, when not the UPN; null or empty clears it. |
| `schema_id` | integer | no |  |
| `schema` | string | no | The user schema, by name (alternative to schema_id). |
| `attributes` | map of string | no | Schema attribute values by name. On PATCH, merged into the current values. |
| `groups` | string[] | no | Static groups, by name. On PATCH, the complete set. |
| `status` | "active" \| "disabled" | no |  |
| `username` | string | yes |  |
| `domain` | string | no | Defaults to the default domain. |
| `password` | string | no |  |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `upn` | string | yes |  |
| `username` | string | yes |  |
| `password` | string | no |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `GET /api/v1/users`

List users.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `limit` | query | no | Page size (default 100, at most 500). |
| `offset` | query | no | Rows to skip. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `total` | number | yes |  |
| `limit` | number | yes |  |
| `offset` | number | yes |  |
| `users` | User[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/users/{username}`

Get a user.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

`User`:

| Field | Type | Required | Description |
|---|---|---|---|
| `upn` | string | yes |  |
| `username` | string | yes |  |
| `email` | string \| null | yes |  |
| `display_name` | string | yes |  |
| `given_name` | string | yes |  |
| `family_name` | string | yes |  |
| `external_id` | string | yes |  |
| `status` | "active" \| "disabled" | yes |  |
| `mfa_enabled` | boolean | yes | An authenticator app (TOTP) is enrolled. Only that factor: see second_factors for all of them. |
| `email_otp_enabled` | boolean | yes | Email one-time codes are enrolled as a second factor. |
| `security_questions_enabled` | boolean | yes | Security questions are set as a second factor. |
| `second_factors` | "totp" \| "passkey" \| "email_otp" \| "security_questions"[] | yes | Every second factor enrolled: an authenticator app, at least one passkey, email codes, security questions (which do not count for administrators). Empty when there is none. |
| `job_title` | string | yes |  |
| `department` | string | yes |  |
| `employee_number` | string | yes |  |
| `hire_date` | string | yes |  |
| `employment_status` | string | yes |  |
| `employment_type` | string | yes |  |
| `location` | string | yes |  |
| `manager_external_id` | string \| null | yes |  |
| `manager_upn` | string \| null | yes |  |
| `schema_id` | number \| null | yes |  |
| `schema_name` | string \| null | yes |  |
| `attributes` | map of string | yes |  |
| `groups` | string[] | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/users/{username}`

Update a user.

Fields not supplied keep their values. Moving to another schema keeps attributes with the same name and clears the rest. `status: disabled` signs them out everywhere and ends their tokens. An administrator's account needs `*`.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | no |  |
| `domain` | string | no |  |
| `given_name` | string | no |  |
| `family_name` | string | no |  |
| `email` | string \| null | no | Where email for the account goes, when not the UPN; null or empty clears it. |
| `schema_id` | integer | no |  |
| `schema` | string | no | The user schema, by name (alternative to schema_id). |
| `attributes` | map of string | no | Schema attribute values by name. On PATCH, merged into the current values. |
| `groups` | string[] | no | Static groups, by name. On PATCH, the complete set. |
| `status` | "active" \| "disabled" | no |  |

Response `200`:

`User`:

| Field | Type | Required | Description |
|---|---|---|---|
| `upn` | string | yes |  |
| `username` | string | yes |  |
| `email` | string \| null | yes |  |
| `display_name` | string | yes |  |
| `given_name` | string | yes |  |
| `family_name` | string | yes |  |
| `external_id` | string | yes |  |
| `status` | "active" \| "disabled" | yes |  |
| `mfa_enabled` | boolean | yes | An authenticator app (TOTP) is enrolled. Only that factor: see second_factors for all of them. |
| `email_otp_enabled` | boolean | yes | Email one-time codes are enrolled as a second factor. |
| `security_questions_enabled` | boolean | yes | Security questions are set as a second factor. |
| `second_factors` | "totp" \| "passkey" \| "email_otp" \| "security_questions"[] | yes | Every second factor enrolled: an authenticator app, at least one passkey, email codes, security questions (which do not count for administrators). Empty when there is none. |
| `job_title` | string | yes |  |
| `department` | string | yes |  |
| `employee_number` | string | yes |  |
| `hire_date` | string | yes |  |
| `employment_status` | string | yes |  |
| `employment_type` | string | yes |  |
| `location` | string | yes |  |
| `manager_external_id` | string \| null | yes |  |
| `manager_upn` | string \| null | yes |  |
| `schema_id` | number \| null | yes |  |
| `schema_name` | string \| null | yes |  |
| `attributes` | map of string | yes |  |
| `groups` | string[] | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}`

Delete a user.

Removes the account, its memberships, sessions and tokens, and deprovisions it over SCIM. An administrator's account needs `*`.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/users/{username}/reset-password`

Set or generate a password.

A supplied password must meet the policy; without one, a password is generated and returned once. Every session and token ends.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `password` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `password` | string | no |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/users/{username}/reset-mfa`

Reset multi-factor authentication.

Clears the authenticator, backup codes, email one-time codes, security questions and remembered devices; they enrol again at next sign-in. Passkeys are kept (remove them with the passkeys operations).

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/users/{username}/sessions`

List active sessions.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `sessions` | Session[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}/sessions`

Sign out everywhere.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `revoked` | number | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/users/{username}/passkeys`

List passkeys.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `passkeys` | object[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}/passkeys/{credential_id}`

Remove a passkey.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |
| `credential_id` | path | yes | The passkey's credential id, as listed. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/users/{username}/apps`

List the OIDC apps holding tokens for a user.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `apps` | object[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}/apps/{client_id}`

Revoke an app's access.

Its access tokens are deleted and refresh tokens revoked; they sign in to it again.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |
| `client_id` | path | yes | The OIDC client_id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/users/{username}/invite`

Email an invitation or a password reset link.

An inactive account gets an invitation (choosing a password activates it); an active one a reset link. Needs email configured. An administrator's account needs `*`.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `kind` | "invite" \| "reset" | yes |  |
| `to` | string | yes |  |

Errors: `400`, `401`, `403`, `404`, `409`, `502` (`{ "error", "message" }`).

## Groups

Static and dynamic (rule-based) groups.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `POST` | `/api/v1/groups` | `groups:write` | Create a group |
| `GET` | `/api/v1/groups` | `groups:read` | List groups |
| `GET` | `/api/v1/groups/{id}` | `groups:read` | Get a group and a page of its members |
| `PATCH` | `/api/v1/groups/{id}` | `groups:write` | Update a group |
| `DELETE` | `/api/v1/groups/{id}` | `groups:write` | Delete a group |
| `POST` | `/api/v1/groups/{id}/freeze` | `groups:write` | Convert a dynamic group to static |
| `POST` | `/api/v1/groups/{id}/members` | `groups:write` | Add members to a static group |
| `DELETE` | `/api/v1/groups/{id}/members/{username}` | `groups:write` | Remove a member from a static group |

### `POST /api/v1/groups`

Create a group.

With `rule`, a dynamic group (no explicit members); otherwise static, optionally with `members`. A name that grants an admin role needs `*`.

Permission: `groups:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `rule` | GroupRule | no | A dynamic group's membership rule: every condition must hold. |
| `members` | string[] | no | Usernames, for a static group. |
| `description` | string | no |  |
| `schema_id` | integer | no |  |
| `schema` | string | no | The group schema, by name (alternative to schema_id). |
| `attributes` | map of string | no | Group schema attribute values; on PATCH, merged into the current ones. |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `id` | number | yes |  |
| `name` | string | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `GET /api/v1/groups`

List groups.

Permission: `groups:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `groups` | Group[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/groups/{id}`

Get a group and a page of its members.

Members are the assigned ones for a static group and the rule's matches for a dynamic one; `search` filters them by name, UPN or username.

Permission: `groups:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |
| `search` | query | no | string |
| `limit` | query | no | Default 100, at most 500. |
| `offset` | query | no | string |

Response `200`:

`any`

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/groups/{id}`

Update a group.

Fields not supplied keep their values. A dynamic group's `rule` can be replaced, but the type cannot change: a static group never becomes dynamic, and a dynamic one becomes static only through POST /api/v1/groups/{id}/freeze. Members are managed with the members endpoints. An admin role group needs `*`.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `rule` | GroupRule | no | A dynamic group's membership rule: every condition must hold. |
| `description` | string | no |  |
| `schema_id` | integer | no |  |
| `schema` | string | no | The group schema, by name (alternative to schema_id). |
| `attributes` | map of string | no | Group schema attribute values; on PATCH, merged into the current ones. |

Response `200`:

`Group`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `description` | string \| null | yes |  |
| `rule` | string | yes | Rule JSON (see GroupRule), or empty for a static group. |
| `schema_id` | number \| null | yes |  |
| `schema_name` | string \| null | yes |  |
| `attributes` | map of string | yes |  |
| `member_count` | number | yes |  |
| `explicit_member_count` | number | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `DELETE /api/v1/groups/{id}`

Delete a group.

Super Admins cannot be deleted; an admin role group needs `*`.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/groups/{id}/freeze`

Convert a dynamic group to static.

The rule's current matches become assigned members and the rule is removed.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `members` | number | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/groups/{id}/members`

Add members to a static group.

People already in the group are left as they are.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `usernames` | string[] | yes |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `added` | number | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/groups/{id}/members/{username}`

Remove a member from a static group.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |
| `username` | path | yes | string |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Directory

Bulk import and reset.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `POST` | `/api/v1/directory/import` | `import:write` | Import users and groups |
| `POST` | `/api/v1/directory/reset` | `import:write` | Remove every user and group except the administrators and their groups |

### `POST /api/v1/directory/import`

Import users and groups.

Idempotent. `super_admin`, admin role group membership and overwriting an administrator need `*`.

Permission: `import:write`

Request body:

`DirectoryBundle`:

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | number | no |  |
| `mode` | "merge" \| "replace" | no |  |
| `passwords` | "default" \| "none" | no |  |
| `domain` | string | no |  |
| `groups` | object[] | no |  |
| `users` | object[] | no |  |

Response `200`:

`ImportResult`:

| Field | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes |  |
| `mode` | "merge" \| "replace" | yes |  |
| `users` | object { created, updated, skipped } | yes |  |
| `groups` | object { created, updated } | yes |  |
| `generated_passwords` | map of string | yes |  |
| `managers_resolved` | number | yes |  |
| `errors` | object[] | yes |  |
| `scim` | map of any | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/directory/reset`

Remove every user and group except the administrators and their groups.

Permission: `import:write`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `domain` | string | yes |  |
| `scim` | map of any | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Domains

UPN domains.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `DELETE` | `/api/v1/domains/{domain}` | `domains:write` | Remove a domain |
| `GET` | `/api/v1/domains` | `domains:read` | List domains |
| `POST` | `/api/v1/domains` | `domains:write` | Add a domain (idempotent) |
| `PUT` | `/api/v1/domains/{domain}/brand` | `domains:write` | Choose the brand a domain's people see |
| `POST` | `/api/v1/domains/{domain}/default` | `domains:write` | Make a domain the default |
| `POST` | `/api/v1/domains/{domain}/apply-to-all` | `domains:write` | Move every user onto this domain |

### `DELETE /api/v1/domains/{domain}`

Remove a domain.

Refused while it is the last domain or any user's UPN is on it.

Permission: `domains:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `domain` | path | yes | The domain name. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `GET /api/v1/domains`

List domains.

Permission: `domains:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `domains` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/domains`

Add a domain (idempotent).

Permission: `domains:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes |  |
| `set_default` | boolean | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `domain` | string | yes |  |
| `is_default` | boolean | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/domains/{domain}/brand`

Choose the brand a domain's people see.

`brand_id` null is the default brand. The sign-in pages, My account and emails follow the person's UPN domain (see Branding).

Permission: `domains:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `domain` | path | yes | The domain name. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `brand_id` | integer \| null | yes |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `domain` | string | yes |  |
| `brand_id` | number \| null | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/domains/{domain}/default`

Make a domain the default.

Permission: `domains:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `domain` | path | yes | The domain name. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `default_domain` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/domains/{domain}/apply-to-all`

Move every user onto this domain.

Also needs `*`: it rewrites Super Admin UPNs, and recovery mail follows the UPN.

Permission: `domains:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `domain` | path | yes | The domain name. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `updated` | number | yes |  |
| `conflicts` | string[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Schemas

User and group attribute schemas.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/schemas` | `schemas:read` | List schemas |
| `POST` | `/api/v1/schemas` | `schemas:write` | Create a schema |
| `PATCH` | `/api/v1/schemas/{id}` | `schemas:write` | Update a schema |
| `DELETE` | `/api/v1/schemas/{id}` | `schemas:write` | Delete a schema |
| `POST` | `/api/v1/schemas/{id}/apply` | `schemas:write` | Move every user (or group) onto this schema |

### `GET /api/v1/schemas`

List schemas.

Permission: `schemas:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `object_type` | query | no | "user" \\| "group" |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `schemas` | Schema[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/schemas`

Create a schema.

Permission: `schemas:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `object_type` | "user" \| "group" | no |  |
| `name` | string | yes |  |
| `description` | string | no |  |
| `attributes` | object[] | no |  |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `PATCH /api/v1/schemas/{id}`

Update a schema.

`attributes`, when given, replaces the attribute list.

Permission: `schemas:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `description` | string | no |  |
| `attributes` | object[] | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/schemas/{id}`

Delete a schema.

Objects on it move to the default schema. Provided schemas cannot be deleted.

Permission: `schemas:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/schemas/{id}/apply`

Move every user (or group) onto this schema.

Permission: `schemas:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `applied` | number | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## OIDC clients

OpenID Connect relying parties.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/clients/{client_id}` | `oidc:read` | Get an OIDC client |
| `PATCH` | `/api/v1/clients/{client_id}` | `oidc:write` | Update an OIDC client |
| `DELETE` | `/api/v1/clients/{client_id}` | `oidc:write` | Delete an OIDC client |
| `POST` | `/api/v1/clients/{client_id}/rotate-secret` | `oidc:write` | Rotate a confidential client's secret |
| `GET` | `/api/v1/clients` | `oidc:read` | List OIDC clients |
| `POST` | `/api/v1/clients` | `oidc:write` | Register an OIDC client (idempotent on a supplied client_id) |

### `GET /api/v1/clients/{client_id}`

Get an OIDC client.

Never includes the secret.

Permission: `oidc:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `client_id` | path | yes | The OIDC client_id. |

Response `200`:

`OidcClient`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `client_id` | string | yes |  |
| `name` | string | yes |  |
| `client_type` | "confidential" \| "public" | yes |  |
| `redirect_uris` | string[] | yes |  |
| `post_logout_redirect_uris` | string[] | yes |  |
| `frontchannel_logout_uri` | string \| null | yes |  |
| `trusted` | boolean | yes |  |
| `allowed_claims` | array \| null | yes | Claim groups released to this client; null = every group. |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | yes | How this client's id_tokens are signed. |
| `created_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/clients/{client_id}`

Update an OIDC client.

Fields not supplied keep their values. The client id, type and secret are not changed here (see rotate-secret).

Permission: `oidc:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `client_id` | path | yes | The OIDC client_id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `redirect_uris` | string[] | no |  |
| `trusted` | boolean | no |  |
| `allowed_claims` | array \| null | no | Claim groups this client may receive; null = every group. |
| `post_logout_redirect_uris` | string[] | no |  |
| `frontchannel_logout_uri` | string | no | https URL; empty clears it. |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | no | How this client's id_tokens are signed. |

Response `200`:

`OidcClient`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `client_id` | string | yes |  |
| `name` | string | yes |  |
| `client_type` | "confidential" \| "public" | yes |  |
| `redirect_uris` | string[] | yes |  |
| `post_logout_redirect_uris` | string[] | yes |  |
| `frontchannel_logout_uri` | string \| null | yes |  |
| `trusted` | boolean | yes |  |
| `allowed_claims` | array \| null | yes | Claim groups released to this client; null = every group. |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | yes | How this client's id_tokens are signed. |
| `created_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/clients/{client_id}`

Delete an OIDC client.

With every code, token and consent issued to it.

Permission: `oidc:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `client_id` | path | yes | The OIDC client_id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/clients/{client_id}/rotate-secret`

Rotate a confidential client's secret.

The new secret is returned once; the old one stops working immediately.

Permission: `oidc:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `client_id` | path | yes | The OIDC client_id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `client_id` | string | yes |  |
| `client_secret` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/clients`

List OIDC clients.

Permission: `oidc:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `clients` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/clients`

Register an OIDC client (idempotent on a supplied client_id).

Supply `client_id` and `client_secret` (24+ characters) together to seed known credentials; omit both to have them generated (the secret is returned once).

Permission: `oidc:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `redirect_uris` | string[] | yes |  |
| `client_id` | string | no |  |
| `client_secret` | string | no |  |
| `client_type` | "confidential" \| "public" | no |  |
| `trusted` | boolean | no |  |
| `allowed_claims` | array \| null | no |  |
| `post_logout_redirect_uris` | string[] | no |  |
| `frontchannel_logout_uri` | string | no |  |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | no | How this client's id_tokens are signed (default RS256). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `created` | boolean | yes |  |
| `id` | number | yes |  |
| `client_id` | string | yes |  |
| `client_secret` | string | no |  |
| `client_type` | string | no |  |
| `redirect_uris` | string[] | yes |  |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## SAML

SAML service providers.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/saml/service-providers/{id}` | `saml:read` | Get a service provider |
| `DELETE` | `/api/v1/saml/service-providers/{id}` | `saml:write` | Delete a service provider |
| `GET` | `/api/v1/saml/service-providers` | `saml:read` | List SAML service providers |
| `POST` | `/api/v1/saml/service-providers` | `saml:write` | Register or update a service provider (keyed on entity_id) |
| `POST` | `/api/v1/saml/service-providers/import-metadata` | `saml:write` | Register or update a service provider from its metadata |

### `GET /api/v1/saml/service-providers/{id}`

Get a service provider.

Update with POST /api/v1/saml/service-providers (keyed on entity_id).

Permission: `saml:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`SamlServiceProvider`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `entity_id` | string | yes |  |
| `name` | string | yes |  |
| `acs_urls` | string[] | yes |  |
| `default_acs_url` | string \| null | yes |  |
| `nameid_format` | string | yes |  |
| `attribute_map` | map of string | yes |  |
| `sign_response` | boolean | yes |  |
| `sign_assertion` | boolean | yes |  |
| `want_authn_requests_signed` | boolean | yes |  |
| `signing_certs` | string[] | yes |  |
| `slo_url` | string \| null | yes |  |
| `encryption_cert` | string \| null | yes |  |
| `encrypt_assertions` | boolean | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/saml/service-providers/{id}`

Delete a service provider.

Permission: `saml:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/saml/service-providers`

List SAML service providers.

Permission: `saml:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `service_providers` | SamlServiceProvider[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/saml/service-providers`

Register or update a service provider (keyed on entity_id).

On update, fields not supplied keep their values; on create, the documented defaults apply.

Permission: `saml:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `entity_id` | string | yes |  |
| `name` | string | no |  |
| `acs_urls` | string[] | no |  |
| `default_acs_url` | string | no |  |
| `nameid_format` | string | no |  |
| `attribute_map` | map of string | no |  |
| `sign_response` | boolean | no |  |
| `sign_assertion` | boolean | no |  |
| `want_authn_requests_signed` | boolean | no |  |
| `signing_certs` | string[] | no |  |
| `slo_url` | string \| null | no |  |
| `encryption_cert` | string \| null | no |  |
| `encrypt_assertions` | boolean | no |  |
| `subject_id` | "" \| "subject-id" \| "pairwise-id" | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `created` | boolean | yes |  |
| `id` | number | yes |  |
| `entity_id` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/saml/service-providers/import-metadata`

Register or update a service provider from its metadata.

Pasted `xml`, or a `url` that is fetched now and re-read daily.

Permission: `saml:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `xml` | string | no |  |
| `url` | string | no |  |
| `name` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `id` | number | yes |  |
| `entity_id` | string | yes |  |
| `acs_urls` | string[] | yes |  |
| `slo_url` | string \| null | yes |  |
| `encryption` | boolean | yes |  |
| `subject_id` | string \| null | yes |  |
| `refresh` | boolean | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## SCIM

Outbound SCIM provisioning (FlareID as a SCIM client).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/scim/config` | `scim:read` | Read the SCIM configuration |
| `POST` | `/api/v1/scim/config` | `scim:write` | Set the SCIM endpoint, secret and scope |
| `POST` | `/api/v1/scim/test` | `scim:write` | Test the SCIM connection |
| `POST` | `/api/v1/scim/sync` | `scim:write` | Push the next batch of users, then the groups |

### `GET /api/v1/scim/config`

Read the SCIM configuration.

Whether a secret is set, never the secret.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | yes |  |
| `secret_set` | boolean | yes |  |
| `scope` | object { mode, group_ids } | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/config`

Set the SCIM endpoint, secret and scope.

A changed scope re-evaluates everything already pushed, after the response.

Permission: `scim:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | no |  |
| `secret` | string | no |  |
| `scope` | object { mode, group_ids } | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/test`

Test the SCIM connection.

Permission: `scim:write`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | boolean | yes |  |
| `status` | number | no |  |
| `error` | string | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/sync`

Push the next batch of users, then the groups.

Call again until `complete` is true.

Permission: `scim:write`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | boolean | yes |  |
| `complete` | boolean | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Email

Outbound email settings and templates.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/email` | `email:read` | Read the email settings |
| `PUT` | `/api/v1/email` | `email:write` | Set the From address and name |
| `POST` | `/api/v1/email/enabled` | `email:write` | Switch email on or off |
| `POST` | `/api/v1/email/test` | `email:write` | Send a test email |

### `GET /api/v1/email`

Read the email settings.

`sending` is true when the binding, a From address and the switch are all in place.

Permission: `email:read`

Response `200`:

`EmailSettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `binding` | boolean | yes |  |
| `sending` | boolean | yes |  |
| `from_address` | string | yes |  |
| `from_name` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/email`

Set the From address and name.

The address must be on a domain onboarded to Cloudflare Email Sending.

Permission: `email:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `from_address` | string | yes |  |
| `from_name` | string | no |  |

Response `200`:

`EmailSettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `binding` | boolean | yes |  |
| `sending` | boolean | yes |  |
| `from_address` | string | yes |  |
| `from_name` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/email/enabled`

Switch email on or off.

Off stops all sending and hides recovery and invitations, keeping the From address and name.

Permission: `email:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |

Response `200`:

`EmailSettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `binding` | boolean | yes |  |
| `sending` | boolean | yes |  |
| `from_address` | string | yes |  |
| `from_name` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/email/test`

Send a test email.

Permission: `email:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `to` | string | yes |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `to` | string | yes |  |

Errors: `400`, `401`, `403`, `502` (`{ "error", "message" }`).

## API keys

Bearer tokens for this API.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/api-keys` | `api_keys:read` | List API keys |
| `POST` | `/api/v1/api-keys` | `admin` | Mint an API key |
| `DELETE` | `/api/v1/api-keys/{id}` | `api_keys:write` | Revoke an API key |

### `GET /api/v1/api-keys`

List API keys.

Never the tokens or their hashes.

Permission: `api_keys:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `api_keys` | ApiKey[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/api-keys`

Mint an API key.

`scopes` are permissions (`users:read`, `oidc:write`, `*`) or the legacy scopes; omit for an admin key. The token is returned once.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `scopes` | string[] | no |  |
| `expires_at` | string \| null | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `id` | number | yes |  |
| `name` | string | yes |  |
| `scopes` | string[] | yes |  |
| `token` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `DELETE /api/v1/api-keys/{id}`

Revoke an API key.

Anything using it stops working immediately. Cannot be undone.

Permission: `api_keys:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Branding

The default brand and per-domain brands: app name, logo, sign-in page colours, custom CSS, email accent; email templates.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/branding` | `branding:read` | Read the default brand |
| `PATCH` | `/api/v1/branding` | `branding:write` | Change the default brand |
| `PUT` | `/api/v1/branding/logo` | `branding:write` | Upload the default brand's logo |
| `DELETE` | `/api/v1/branding/logo` | `branding:write` | Remove the default brand's logo |
| `GET` | `/api/v1/branding/brands` | `branding:read` | List the brands attached to domains |
| `POST` | `/api/v1/branding/brands` | `branding:write` | Create a brand |
| `GET` | `/api/v1/branding/brands/{id}` | `branding:read` | Read a brand |
| `PATCH` | `/api/v1/branding/brands/{id}` | `branding:write` | Change a brand |
| `DELETE` | `/api/v1/branding/brands/{id}` | `branding:write` | Delete a brand |
| `PUT` | `/api/v1/branding/brands/{id}/logo` | `branding:write` | Upload a brand's logo |
| `DELETE` | `/api/v1/branding/brands/{id}/logo` | `branding:write` | Remove a brand's logo |
| `GET` | `/api/v1/branding/email-templates` | `branding:read` | List the email templates |
| `PUT` | `/api/v1/branding/email-templates/{key}` | `branding:write` | Replace an email template |
| `DELETE` | `/api/v1/branding/email-templates/{key}` | `branding:write` | Reset an email template to the default |

### `GET /api/v1/branding`

Read the default brand.

Permission: `branding:read`

Response `200`:

`Branding`:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | yes |  |
| `login_subtitle` | string | yes |  |
| `login_gradient` | object { from, to } | yes |  |
| `cursor_trail` | object { enabled, characters } | yes |  |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `css_url` | string \| null | yes | Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null. |
| `preview_url` | string | yes | The sign-in page in this brand, for a signed-in administrator with branding:read. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PATCH /api/v1/branding`

Change the default brand.

Fields not supplied keep their values. Colours are #rrggbb. An empty `login_subtitle` shows no message; empty cursor-trail `characters` uses the default symbols. `custom_css` (at most 20 KB; empty removes it) is refused if it contains `</style`, `@import`, `expression(`, `javascript:` or a `url(` that is not a same-origin path or a data: URL - the page's Content-Security-Policy blocks remote fonts and images anyway.

Permission: `branding:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | no |  |
| `login_subtitle` | string | no |  |
| `login_gradient` | object { from, to } | no |  |
| `cursor_trail` | object { enabled, characters } | no |  |
| `email_accent` | string | no |  |
| `custom_css` | string | no |  |

Response `200`:

`Branding`:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | yes |  |
| `login_subtitle` | string | yes |  |
| `login_gradient` | object { from, to } | yes |  |
| `cursor_trail` | object { enabled, characters } | yes |  |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `css_url` | string \| null | yes | Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null. |
| `preview_url` | string | yes | The sign-in page in this brand, for a signed-in administrator with branding:read. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/branding/logo`

Upload the default brand's logo.

Shown on the sign-in pages, the top bar and emails. Replaces (and deletes) the previous upload.

Permission: `branding:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `data` | string | yes | The image, base64-encoded (a `data:image/...;base64,` prefix is accepted). PNG or JPEG, at most 256 KB, recognised by its bytes; SVG is refused. |

Response `200`:

`Branding`:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | yes |  |
| `login_subtitle` | string | yes |  |
| `login_gradient` | object { from, to } | yes |  |
| `cursor_trail` | object { enabled, characters } | yes |  |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `css_url` | string \| null | yes | Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null. |
| `preview_url` | string | yes | The sign-in page in this brand, for a signed-in administrator with branding:read. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `DELETE /api/v1/branding/logo`

Remove the default brand's logo.

FlareID's own mark is shown again.

Permission: `branding:write`

Response `200`:

`Branding`:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | yes |  |
| `login_subtitle` | string | yes |  |
| `login_gradient` | object { from, to } | yes |  |
| `cursor_trail` | object { enabled, characters } | yes |  |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `css_url` | string \| null | yes | Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null. |
| `preview_url` | string | yes | The sign-in page in this brand, for a signed-in administrator with branding:read. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/branding/brands`

List the brands attached to domains.

The default brand is `GET /api/v1/branding`.

Permission: `branding:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `brands` | Brand[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/branding/brands`

Create a brand.

`name` is required and unique. Fields left out or null use the default brand's value. `custom_css` follows the rules of `PATCH /api/v1/branding`.

Permission: `branding:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `app_name` | string \| null | no |  |
| `login_subtitle` | string \| null | no |  |
| `login_gradient` | object \| null { from, to } | no |  |
| `email_accent` | string \| null | no |  |
| `custom_css` | string \| null | no |  |
| `domains` | string[] | no | Replaces the set of domains using this brand; a domain moves from any brand it was on. |

Response `201`:

`Brand`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `app_name` | string \| null | yes | null: the default brand's. |
| `login_subtitle` | string \| null | yes | null: the default brand's; empty: no message. |
| `login_gradient` | object \| null { from, to } | yes | null: the default brand's. |
| `email_accent` | string \| null | yes | null: the default brand's. |
| `logo_url` | string \| null | yes | This brand's own upload; null uses the default brand's logo. |
| `custom_css` | string | yes | Empty uses the default brand's stylesheet. |
| `domains` | string[] | yes | The domains whose people see this brand. |
| `effective` | object { app_name, login_subtitle, login_gradient, email_accent, logo_url, css_url } | yes | What the pages and emails actually use, with the default brand filling the gaps. |
| `preview_url` | string | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `GET /api/v1/branding/brands/{id}`

Read a brand.

Permission: `branding:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Brand`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `app_name` | string \| null | yes | null: the default brand's. |
| `login_subtitle` | string \| null | yes | null: the default brand's; empty: no message. |
| `login_gradient` | object \| null { from, to } | yes | null: the default brand's. |
| `email_accent` | string \| null | yes | null: the default brand's. |
| `logo_url` | string \| null | yes | This brand's own upload; null uses the default brand's logo. |
| `custom_css` | string | yes | Empty uses the default brand's stylesheet. |
| `domains` | string[] | yes | The domains whose people see this brand. |
| `effective` | object { app_name, login_subtitle, login_gradient, email_accent, logo_url, css_url } | yes | What the pages and emails actually use, with the default brand filling the gaps. |
| `preview_url` | string | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/branding/brands/{id}`

Change a brand.

Fields not supplied keep their values; null resets one to the default brand's.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `app_name` | string \| null | no |  |
| `login_subtitle` | string \| null | no |  |
| `login_gradient` | object \| null { from, to } | no |  |
| `email_accent` | string \| null | no |  |
| `custom_css` | string \| null | no |  |
| `domains` | string[] | no | Replaces the set of domains using this brand; a domain moves from any brand it was on. |

Response `200`:

`Brand`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `app_name` | string \| null | yes | null: the default brand's. |
| `login_subtitle` | string \| null | yes | null: the default brand's; empty: no message. |
| `login_gradient` | object \| null { from, to } | yes | null: the default brand's. |
| `email_accent` | string \| null | yes | null: the default brand's. |
| `logo_url` | string \| null | yes | This brand's own upload; null uses the default brand's logo. |
| `custom_css` | string | yes | Empty uses the default brand's stylesheet. |
| `domains` | string[] | yes | The domains whose people see this brand. |
| `effective` | object { app_name, login_subtitle, login_gradient, email_accent, logo_url, css_url } | yes | What the pages and emails actually use, with the default brand filling the gaps. |
| `preview_url` | string | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `DELETE /api/v1/branding/brands/{id}`

Delete a brand.

Its domains go back to the default brand; its logo is deleted.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PUT /api/v1/branding/brands/{id}/logo`

Upload a brand's logo.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `data` | string | yes | The image, base64-encoded (a `data:image/...;base64,` prefix is accepted). PNG or JPEG, at most 256 KB, recognised by its bytes; SVG is refused. |

Response `200`:

`Brand`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `app_name` | string \| null | yes | null: the default brand's. |
| `login_subtitle` | string \| null | yes | null: the default brand's; empty: no message. |
| `login_gradient` | object \| null { from, to } | yes | null: the default brand's. |
| `email_accent` | string \| null | yes | null: the default brand's. |
| `logo_url` | string \| null | yes | This brand's own upload; null uses the default brand's logo. |
| `custom_css` | string | yes | Empty uses the default brand's stylesheet. |
| `domains` | string[] | yes | The domains whose people see this brand. |
| `effective` | object { app_name, login_subtitle, login_gradient, email_accent, logo_url, css_url } | yes | What the pages and emails actually use, with the default brand filling the gaps. |
| `preview_url` | string | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/branding/brands/{id}/logo`

Remove a brand's logo.

The brand uses the default brand's logo again.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Brand`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `app_name` | string \| null | yes | null: the default brand's. |
| `login_subtitle` | string \| null | yes | null: the default brand's; empty: no message. |
| `login_gradient` | object \| null { from, to } | yes | null: the default brand's. |
| `email_accent` | string \| null | yes | null: the default brand's. |
| `logo_url` | string \| null | yes | This brand's own upload; null uses the default brand's logo. |
| `custom_css` | string | yes | Empty uses the default brand's stylesheet. |
| `domains` | string[] | yes | The domains whose people see this brand. |
| `effective` | object { app_name, login_subtitle, login_gradient, email_accent, logo_url, css_url } | yes | What the pages and emails actually use, with the default brand filling the gaps. |
| `preview_url` | string | yes |  |
| `created_at` | string | yes |  |
| `updated_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/branding/email-templates`

List the email templates.

Keys: invitation, password_reset, email_otp. Text fields take {{placeholders}}; the layout is FlareID's own.

Permission: `branding:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `accent` | string | yes |  |
| `templates` | any[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/branding/email-templates/{key}`

Replace an email template.

Fields not supplied take the default wording. Subject and heading cannot be empty.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `key` | path | yes | "invitation" \\| "password_reset" \\| "email_otp" |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `subject` | string | no |  |
| `heading` | string | no |  |
| `body` | string | no |  |
| `action` | string | no |  |
| `footer` | string | no |  |

Response `200`:

`any`

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/branding/email-templates/{key}`

Reset an email template to the default.

Permission: `branding:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `key` | path | yes | "invitation" \\| "password_reset" \\| "email_otp" |

Response `200`:

`any`

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Security

Password, session, rate-limit and audit settings; authentication policies and factors.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/security` | `security:read` | Read the security settings |
| `PUT` | `/api/v1/security/password-policy` | `security:write` | Set the password policy |
| `PUT` | `/api/v1/security/breached-passwords` | `security:write` | Switch the breached-password check on or off |
| `PUT` | `/api/v1/security/turnstile` | `security:write` | Configure bot protection (Cloudflare Turnstile) |
| `PUT` | `/api/v1/security/rate-limit` | `security:write` | Set the sign-in rate limit |
| `PUT` | `/api/v1/security/session-limits` | `security:write` | Set the session limits |
| `PUT` | `/api/v1/security/audit-retention` | `security:write` | Set how long the audit log is kept |
| `PUT` | `/api/v1/security/new-user-password` | `security:write` | Set what password new accounts get |
| `POST` | `/api/v1/security/new-user-password/apply-to-all` | `admin` | Set every account's password to the default password |
| `PUT` | `/api/v1/security/require-mfa` | `security:write` | Require a second factor for everyone (legacy switch) |
| `GET` | `/api/v1/security/policies` | `security:read` | List authentication policies |
| `POST` | `/api/v1/security/policies` | `security:write` | Create an authentication policy |
| `PATCH` | `/api/v1/security/policies/{id}` | `security:write` | Update an authentication policy |
| `DELETE` | `/api/v1/security/policies/{id}` | `security:write` | Delete an authentication policy |
| `GET` | `/api/v1/security/factors` | `security:read` | List second factors |
| `PUT` | `/api/v1/security/factors/{key}` | `security:write` | Turn a second factor on or off |
| `GET` | `/api/v1/security/security-questions` | `security:read` | Read the security-questions settings and catalogue |
| `PUT` | `/api/v1/security/security-questions` | `security:write` | Change how many security questions are set and asked |
| `POST` | `/api/v1/security/security-questions/questions` | `security:write` | Add a security question |
| `PATCH` | `/api/v1/security/security-questions/questions/{id}` | `security:write` | Enable or disable a security question |
| `DELETE` | `/api/v1/security/security-questions/questions/{id}` | `security:write` | Delete a security question |

### `GET /api/v1/security`

Read the security settings.

Permission: `security:read`

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/password-policy`

Set the password policy.

Omitted rules are off; minLength defaults to 8.

Permission: `security:write`

Request body:

`PasswordPolicy`:

| Field | Type | Required | Description |
|---|---|---|---|
| `minLength` | integer | no |  |
| `requireUppercase` | boolean | no |  |
| `requireLowercase` | boolean | no |  |
| `requireNumber` | boolean | no |  |
| `requireSymbol` | boolean | no |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/breached-passwords`

Switch the breached-password check on or off.

When on (the default), passwords people choose - self-service changes, invitations, resets, passwords set by administrators and imported passwords (imports with up to 200 explicit passwords) - are refused if they appear in Have I Been Pwned's breach corpus. Only the first 5 characters of the password's SHA-1 hash are sent (k-anonymity). If the service cannot be reached the password is allowed.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/turnstile`

Configure bot protection (Cloudflare Turnstile).

Fields not supplied keep their values; an empty or omitted `secret` keeps the saved one. The secret is write-only. `mode: on` needs a site key and a secret (or the TURNSTILE_SECRET_KEY Worker secret) and protects the password sign-in and password-recovery forms; passkey sign-in is not challenged.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | "off" \| "on" | no |  |
| `site_key` | string | no |  |
| `secret` | string | no |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/rate-limit`

Set the sign-in rate limit.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `max_attempts` | integer | yes |  |
| `window_minutes` | integer | yes |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/session-limits`

Set the session limits.

`max_hours` 1-720; `idle_minutes` 5-10080, or 0 for no idle limit. Out-of-range values are clamped. Applies to existing sessions at once.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `max_hours` | number | yes |  |
| `idle_minutes` | number | yes |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/audit-retention`

Set how long the audit log is kept.

30-3650 days, clamped.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `days` | number | yes |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/new-user-password`

Set what password new accounts get.

`mode: default` gives new accounts the shared `default_password` (generated if none is set); `random` generates one per account.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | "default" \| "random" | no |  |
| `default_password` | string | no |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/security/new-user-password/apply-to-all`

Set every account's password to the default password.

Administrators' accounts included, so it needs `*`. Optionally sets `default_password` first. Refused (0 changed) when no default is set.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `default_password` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `updated` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/require-mfa`

Require a second factor for everyone (legacy switch).

Authentication policies are the finer-grained control.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `required` | boolean | yes |  |

Response `200`:

`SecuritySettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `password_policy` | PasswordPolicy | yes |  |
| `rate_limit` | object { max_attempts, window_minutes } | yes |  |
| `session_limits` | object { max_hours, idle_minutes } | yes |  |
| `audit_retention_days` | number | yes |  |
| `new_user_password` | object { mode, default_password_set } | yes |  |
| `require_mfa` | boolean | yes |  |
| `breached_password_check` | boolean | yes | New passwords found in Have I Been Pwned's breach corpus are refused. |
| `turnstile` | TurnstileSettings | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/security/policies`

List authentication policies.

Permission: `security:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `policies` | AuthPolicy[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/security/policies`

Create an authentication policy.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `description` | string | no |  |
| `requirement` | "password" \| "mfa" | no | Password alone, or password plus a second factor; a passkey satisfies either. |
| `priority` | integer | no | 1-1000; lower wins when several policies match. |
| `groups` | string[] | no | Group names the policy applies to. |

Response `201`:

`AuthPolicy`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `description` | string | yes |  |
| `requirement` | "password" \| "mfa" | yes |  |
| `priority` | number | yes |  |
| `is_default` | boolean | yes |  |
| `groups` | string[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PATCH /api/v1/security/policies/{id}`

Update an authentication policy.

Fields not supplied keep their values. `make_default: true` makes it the policy for everyone no other policy matches.

Permission: `security:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `make_default` | boolean | no |  |
| `description` | string | no |  |
| `requirement` | "password" \| "mfa" | no | Password alone, or password plus a second factor; a passkey satisfies either. |
| `priority` | integer | no | 1-1000; lower wins when several policies match. |
| `groups` | string[] | no | Group names the policy applies to. |

Response `200`:

`AuthPolicy`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `description` | string | yes |  |
| `requirement` | "password" \| "mfa" | yes |  |
| `priority` | number | yes |  |
| `is_default` | boolean | yes |  |
| `groups` | string[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/security/policies/{id}`

Delete an authentication policy.

The default policy cannot be deleted.

Permission: `security:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/security/factors`

List second factors.

Permission: `security:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `factors` | Factor[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/factors/{key}`

Turn a second factor on or off.

At least one factor must stay on while a policy requires a second factor. Email one-time codes (email_otp) are off on a fresh install and can be switched on only once email is configured. Security questions (security_questions) are off on a fresh install and need at least as many enabled questions as each person sets (see /api/v1/security/security-questions).

Permission: `security:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `key` | path | yes | "totp" \\| "passkey" \\| "email_otp" \\| "security_questions" |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `factors` | Factor[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/security/security-questions`

Read the security-questions settings and catalogue.

Answers are never exposed: they are stored only as salted hashes.

Permission: `security:read`

Response `200`:

`SecurityQuestions`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes | The factor's switch (PUT /api/v1/security/factors/security_questions). |
| `required` | number | yes | How many questions each person sets. |
| `asked` | number | yes | How many of them are asked, picked at random, at each sign-in. |
| `questions` | SecurityQuestion[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/security/security-questions`

Change how many security questions are set and asked.

`required` is 1-10 and at most the number of enabled questions; `asked` is 1 to `required`. Fields left out keep their value.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `required` | integer | no |  |
| `asked` | integer | no |  |

Response `200`:

`SecurityQuestions`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes | The factor's switch (PUT /api/v1/security/factors/security_questions). |
| `required` | number | yes | How many questions each person sets. |
| `asked` | number | yes | How many of them are asked, picked at random, at each sign-in. |
| `questions` | SecurityQuestion[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/security/security-questions/questions`

Add a security question.

5-200 characters; a question already in the list (ignoring case) is a 409.

Permission: `security:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes |  |

Response `201`:

`SecurityQuestion`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `text` | string | yes |  |
| `enabled` | boolean | yes | Offered when people choose their questions. Answers to a disabled question keep working. |
| `answered_by` | number | yes | How many people answered it. A question with answers cannot be deleted. |
| `created_at` | string | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `PATCH /api/v1/security/security-questions/questions/{id}`

Enable or disable a security question.

At least as many questions as each person sets must stay enabled.

Permission: `security:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |

Response `200`:

`SecurityQuestion`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `text` | string | yes |  |
| `enabled` | boolean | yes | Offered when people choose their questions. Answers to a disabled question keep working. |
| `answered_by` | number | yes | How many people answered it. A question with answers cannot be deleted. |
| `created_at` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/security/security-questions/questions/{id}`

Delete a security question.

Only a question nobody has answered (409 otherwise: disable it instead).

Permission: `security:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

## Roles

Admin roles: permission sets granted to groups.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/security/roles` | `roles:read` | List roles |
| `POST` | `/api/v1/security/roles` | `roles:write` | Create a role |
| `PATCH` | `/api/v1/security/roles/{id}` | `roles:write` | Update a role |
| `DELETE` | `/api/v1/security/roles/{id}` | `roles:write` | Delete a role |

### `GET /api/v1/security/roles`

List roles.

Permission: `roles:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `roles` | Role[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/security/roles`

Create a role.

Permission: `roles:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `description` | string | no |  |
| `permissions` | string[] | no | Permissions (`users:read`, `oidc:write`, `signin`, `account:write`, `*`). None beyond what the calling token holds; `*` only with `*`. |
| `groups` | string[] | no | Group names the role is granted to (ignored for a default role, which applies to everyone). |

Response `201`:

`Role`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `description` | string | yes |  |
| `builtin` | boolean | yes |  |
| `is_default` | boolean | yes |  |
| `permissions` | string[] | yes |  |
| `groups` | string[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PATCH /api/v1/security/roles/{id}`

Update a role.

Fields not supplied keep their values. Super Admin cannot be changed; a built-in role keeps its name.

Permission: `roles:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `description` | string | no |  |
| `permissions` | string[] | no | Permissions (`users:read`, `oidc:write`, `signin`, `account:write`, `*`). None beyond what the calling token holds; `*` only with `*`. |
| `groups` | string[] | no | Group names the role is granted to (ignored for a default role, which applies to everyone). |

Response `200`:

`Role`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `description` | string | yes |  |
| `builtin` | boolean | yes |  |
| `is_default` | boolean | yes |  |
| `permissions` | string[] | yes |  |
| `groups` | string[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/security/roles/{id}`

Delete a role.

Built-in roles cannot be deleted.

Permission: `roles:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Signing keys

Token signing keys (public parts only).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/security/signing-keys` | `signing_keys:read` | List token signing keys |
| `POST` | `/api/v1/security/signing-keys/{alg}/rotate` | `signing_keys:write` | Rotate the signing key for an algorithm |

### `GET /api/v1/security/signing-keys`

List token signing keys.

Public parts only.

Permission: `signing_keys:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `keys` | SigningKey[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/security/signing-keys/{alg}/rotate`

Rotate the signing key for an algorithm.

The old key is retired but stays published for 24 hours so tokens it signed still verify.

Permission: `signing_keys:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `alg` | path | yes | "RS256" \\| "ES256" |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `alg` | string | yes |  |
| `kid` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Monitoring

Overview statistics, performance and the audit log.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/stats` | `performance:read` | Overview statistics |
| `GET` | `/api/v1/performance` | `performance:read` | Request volume, errors and latency |
| `GET` | `/api/v1/audit` | `audit:read` | Read the audit log |

### `GET /api/v1/stats`

Overview statistics.

The numbers on the console's overview: directory counts, second-factor enrolment, the last 24 hours and the last 30 days of sign-in activity (from the audit log). `counts.mfa_enrolled` is the number of users with any second factor (authenticator app, passkey, email codes or security questions); `second_factors` breaks it down.

Permission: `performance:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `counts` | map of number | yes |  |
| `second_factors` | SecondFactorCounts | yes |  |
| `last_24h` | map of number | yes |  |
| `last_30d` | object { sign_ins, failed_sign_ins, sign_ins_by_day, outcomes, top_actions, top_users } | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/performance`

Request volume, errors and latency.

From Workers Analytics Engine. Without CF_ACCOUNT_ID and CF_ANALYTICS_TOKEN the answer is `configured: false` (still 200), so a dashboard can say what to set up; a failed query is `configured: true, ok: false` with the error.

Permission: `performance:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `range` | query | no | "1h" \\| "24h" \\| "7d" |
| `endpoint` | query | no | One route family, e.g. token. |

Response `200`:

`Performance`:

| Field | Type | Required | Description |
|---|---|---|---|
| `configured` | boolean | yes |  |
| `ok` | boolean | no |  |
| `error` | string | no |  |
| `message` | string | no |  |
| `range` | string | yes |  |
| `bucket_minutes` | number | yes |  |
| `endpoint` | string \| null | yes |  |
| `points` | object[] | no |  |
| `families` | object[] | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/audit`

Read the audit log.

Newest first, with the console's filters. actor: people, api, system; category: login, user, group, directory, api, api_key, oidc, oauth, saml, scim, settings, domain, schema, idp; from/to are whole UTC days (YYYY-MM-DD, inclusive).

Permission: `audit:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `search` | query | no | Matches actor, action, target, details or IP. |
| `actor` | query | no | string |
| `category` | query | no | string |
| `from` | query | no | string |
| `to` | query | no | string |
| `limit` | query | no | Default 100, at most 500. |
| `offset` | query | no | string |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `total` | number | yes |  |
| `limit` | number | yes |  |
| `offset` | number | yes |  |
| `entries` | AuditEntry[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Recovery

Break-glass administrator reset (bootstrap token only).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `POST` | `/api/v1/recovery/admin-reset` | `bootstrap-token` | Re-mint a Super Admin (break-glass) |

### `POST /api/v1/recovery/admin-reset`

Re-mint a Super Admin (break-glass).

Only the BOOTSTRAP_TOKEN secret is accepted, before or after setup. Loudly audited.

Permission: `bootstrap-token`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes |  |
| `password` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `upn` | string | yes |  |
| `password` | string | yes |  |

Errors: `400`, `403` (`{ "error", "message" }`).

