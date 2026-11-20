# FlareID provisioning API reference

Generated from the route definitions by `npm run docs:api`; do not edit by hand.
The same document is served by every deployment at `GET /api/v1/openapi.json` (no token needed), and is in [openapi.json](openapi.json).
See [api.md](api.md) for authentication, permissions and worked examples.

API version 4.7.0.

## Contents

- [Status](#status) - Instance status and first-run setup.
- [Users](#users) - People in the directory.
- [Groups](#groups) - Static and dynamic (rule-based) groups.
- [Access](#access) - Access requests and certification campaigns over group membership.
- [Directory](#directory) - Bulk import and reset.
- [Domains](#domains) - UPN domains.
- [Schemas](#schemas) - User and group attribute schemas.
- [OIDC clients](#oidc-clients) - OpenID Connect relying parties.
- [SAML](#saml) - SAML service providers.
- [App catalog](#app-catalog) - Templates for well-known applications: browse, read the setup instructions, and create the client or service provider filled in.
- [SCIM](#scim) - Outbound SCIM provisioning (FlareID as a SCIM client).
- [LDAP](#ldap) - The read-only LDAP interface: app registrations and directory settings.
- [Mappings](#mappings) - Attribute flows: inbound and outbound mapping rules evaluated by the expression engine, and the collision policy.
- [Federation](#federation) - Inbound federation: upstream identity providers people sign in through (FlareID as the relying party).
- [Cloudflare One](#cloudflare-one) - The Cloudflare One (Zero Trust) connection, gateway-list sync and the risk watchlist.
- [Signals](#signals) - Shared Signals Framework: outbound CAEP/RISC streams and trusted inbound transmitters.
- [Email](#email) - Outbound email settings and templates.
- [API keys](#api-keys) - Bearer tokens for this API.
- [Branding](#branding) - The default brand and per-domain brands: app name, logo, sign-in page colours, custom CSS, email accent; email templates.
- [Security](#security) - Password, session, rate-limit and audit settings; authentication policies and factors.
- [Roles](#roles) - Admin roles: permission sets granted to groups.
- [Signing keys](#signing-keys) - Token signing keys (public parts only).
- [Monitoring](#monitoring) - Overview statistics, performance and the audit log.
- [Backup](#backup) - Whole-database export and restore for disaster recovery (docs/dr.md).
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
| `require_mfa` | boolean | no | Make the default policy (everyone no other policy matches) require a second factor, or not. |
| `admin_mfa` | boolean | no | Require a second factor for administrators (default: a fresh install does). true keeps Super Admins in the "Password and a second factor" policy; false takes them out of every policy that requires one and makes "Password only" the default, so the first administrator signs in with the password alone. Omitted leaves the policies as they are. false needs the `admin` scope; false with require_mfa: true is a 400. |
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
| `GET` | `/api/v1/users/{username}/photo` | `users:read` | Get the profile photo |
| `PUT` | `/api/v1/users/{username}/photo` | `users:write` | Set the profile photo |
| `DELETE` | `/api/v1/users/{username}/photo` | `users:write` | Remove the profile photo |
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
| `emails` | object[] | no | The complete contact-address list (work/home/aliases), replacing what is there; the marked or first entry is the primary that `email` claims and mail goes to. Takes precedence over `email`. |
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
| `emails` | object[] | yes | Every contact address on the account; the primary is what `email` and mail deliveries use. |
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
| `emails` | object[] | no | The complete contact-address list (work/home/aliases), replacing what is there; the marked or first entry is the primary that `email` claims and mail goes to. Takes precedence over `email`. |
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
| `emails` | object[] | yes | Every contact address on the account; the primary is what `email` and mail deliveries use. |
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

### `GET /api/v1/users/{username}/photo`

Get the profile photo.

The stored image as base64 - the same bytes the console's /account/photo route serves browsers.

Permission: `users:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `content_type` | string | yes |  |
| `photo` | string | yes | Base64 image data. |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PUT /api/v1/users/{username}/photo`

Set the profile photo.

Base64 PNG, JPEG, WebP or GIF, at most 1 MB decoded. Refused while `photo` is mastered by inbound provisioning.

Permission: `users:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `photo` | string | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}/photo`

Remove the profile photo.

Refused while `photo` is mastered by inbound provisioning.

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
| `POST` | `/api/v1/groups/bulk` | `groups:write` | Apply an action to many groups at once |
| `POST` | `/api/v1/groups/{id}/freeze` | `groups:write` | Convert a dynamic group to static |
| `POST` | `/api/v1/groups/{id}/members` | `groups:write` | Add members to a static group |
| `DELETE` | `/api/v1/groups/{id}/members/{username}` | `groups:write` | Remove a member from a static group |
| `POST` | `/api/v1/groups/{id}/managers` | `groups:write` | Name group managers |
| `DELETE` | `/api/v1/groups/{id}/managers/{username}` | `groups:write` | Remove a group manager |

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
| `requestable` | boolean | no | Whether people may ask for membership on My account; only a static group can be. |
| `cf_list_sync` | boolean | no | Keep the member emails in a Cloudflare One gateway list (the Cloudflare One connection must be configured). |
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
| `requestable` | boolean | no | Whether people may ask for membership on My account; only a static group can be. |
| `cf_list_sync` | boolean | no | Keep the member emails in a Cloudflare One gateway list (the Cloudflare One connection must be configured). |
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
| `requestable` | boolean | yes | Whether people may ask for membership on My account (static groups only). |
| `cf_list_sync` | boolean | yes | Member emails are kept in a Cloudflare One gateway list. |

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

### `POST /api/v1/groups/bulk`

Apply an action to many groups at once.

Only static groups are ever touched - a dynamic group's membership follows its rule, so it lands in `skipped` (as does an admin role group when the token lacks `*`). `requestable_on`/`requestable_off` toggles membership requests on My account; `add_members` adds `usernames` to each group.

Permission: `groups:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `group_ids` | integer[] | yes |  |
| `action` | "requestable_on" \| "requestable_off" \| "add_members" | yes |  |
| `usernames` | string[] | no | Required for add_members. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `applied` | string[] | yes |  |
| `skipped` | string[] | yes |  |
| `added` | number | no |  |

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

### `POST /api/v1/groups/{id}/managers`

Name group managers.

A static group's managers can change its members and answer its access requests from My account. A dynamic group's membership follows its rule, so it takes none. An admin role group needs `*`.

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

### `DELETE /api/v1/groups/{id}/managers/{username}`

Remove a group manager.

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

## Access

Access requests and certification campaigns over group membership.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/access/requests` | `groups:read` | List access requests |
| `POST` | `/api/v1/access/requests` | `groups:write` | File an access request |
| `POST` | `/api/v1/access/requests/{id}` | `groups:write` | Approve or deny an access request |
| `POST` | `/api/v1/access/requests/{id}/cancel` | `groups:write` | Withdraw a pending access request |
| `GET` | `/api/v1/access/campaigns` | `groups:read` | List certification campaigns |
| `POST` | `/api/v1/access/campaigns` | `groups:write` | Start a certification campaign |
| `GET` | `/api/v1/access/campaigns/{id}` | `groups:read` | Get a campaign and its review items |
| `POST` | `/api/v1/access/campaigns/{id}/close` | `groups:write` | Close a campaign |
| `POST` | `/api/v1/access/campaigns/{id}/items/{item_id}` | `groups:write` | Certify or revoke a membership under review |

### `GET /api/v1/access/requests`

List access requests.

Defaults to requests still waiting; `status` filters, `all` lists every request, `search` matches the person, group or reason.

Permission: `groups:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `status` | query | no | "pending" \\| "approved" \\| "denied" \\| "cancelled" \\| "all" |
| `search` | query | no | string |
| `limit` | query | no | Default 100, at most 500. |
| `offset` | query | no | string |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `requests` | AccessRequest[] | yes |  |
| `total` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/access/requests`

File an access request.

Requests `group_id` for `username` - the same flow the My account requester follows: the group must be requestable and static, the user must not already belong or have a pending ask, and their own managed groups are refused.

Permission: `groups:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes |  |
| `group_id` | integer | yes |  |
| `reason` | string | no |  |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `request` | AccessRequest | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `POST /api/v1/access/requests/{id}`

Approve or deny an access request.

An approval adds the requester to the group exactly like a membership edit does. Touching an admin role group needs `*`.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `decision` | "approved" \| "denied" | yes |  |
| `note` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `request` | AccessRequest | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `POST /api/v1/access/requests/{id}/cancel`

Withdraw a pending access request.

Cancels a request still waiting for a decision. Withdrawing another user's request needs `*` (an admin key).

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `request` | AccessRequest | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `GET /api/v1/access/campaigns`

List certification campaigns.

Permission: `groups:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `campaigns` | AccessCampaign[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/access/campaigns`

Start a certification campaign.

Every assigned membership of the named groups becomes a review item, snapshotted at creation. Dynamic groups in scope contribute nothing.

Permission: `groups:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `group_ids` | integer[] | yes |  |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `campaign` | AccessCampaign | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/access/campaigns/{id}`

Get a campaign and its review items.

Permission: `groups:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `campaign` | AccessCampaign | yes |  |
| `items` | AccessCertItem[] | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/access/campaigns/{id}/close`

Close a campaign.

Items still pending keep their membership and count as unreviewed.

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

### `POST /api/v1/access/campaigns/{id}/items/{item_id}`

Certify or revoke a membership under review.

`revoke` removes the member from the group immediately. Touching an admin role group needs `*`.

Permission: `groups:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric campaign id. |
| `item_id` | path | yes | Numeric review item id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `decision` | "certify" \| "revoke" | yes |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `item` | AccessCertItem | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

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
| `assigned_groups` | number[] | yes | Group ids whose members may see and sign in to this app; [] = everyone. |
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
| `backchannel_logout_uri` | string | no | https URL; empty clears it. |
| `initiate_login_uri` | string | no | https URL; empty clears it. |
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
| `assigned_groups` | number[] | yes | Group ids whose members may see and sign in to this app; [] = everyone. |
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
| `backchannel_logout_uri` | string | no |  |
| `initiate_login_uri` | string | no |  |
| `id_token_signed_response_alg` | "RS256" \| "ES256" | no | How this client's id_tokens are signed (default RS256). |
| `assigned_groups` | array \| null | no | Group ids whose members may see and sign in to this app; empty or null = everyone. On update, omitted keeps the current restriction. |

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
| `assigned_groups` | number[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## SAML

SAML service providers.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/saml/service-providers/{id}` | `saml:read` | Get a service provider |
| `DELETE` | `/api/v1/saml/service-providers/{id}` | `saml:write` | Delete a service provider |
| `GET` | `/api/v1/saml/service-providers` | `saml:read` | List SAML service providers |
| `POST` | `/api/v1/saml/service-providers` | `saml:write` | Register or update a service provider (keyed on entity_id) |
| `GET` | `/api/v1/saml/settings` | `saml:read` | Read the instance SAML settings |
| `PUT` | `/api/v1/saml/settings` | `saml:write` | Set the SAML algorithm deny list |
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
| `nameid_format` | string | yes | transient, emailAddress, persistent - or "none": the Subject carries no <saml:NameID>. |
| `attribute_map` | map of string | yes |  |
| `attribute_definitions` | SamlAttributeDefinition[] | yes | Released attributes with arbitrary Name/NameFormat; overrides attribute_map when non-empty. |
| `sign_response` | boolean | yes |  |
| `sign_assertion` | boolean | yes |  |
| `want_authn_requests_signed` | boolean | yes |  |
| `signing_certs` | string[] | yes |  |
| `slo_url` | string \| null | yes |  |
| `encryption_cert` | string \| null | yes |  |
| `encrypt_assertions` | boolean | yes |  |
| `assigned_groups` | number[] | yes | Group ids whose members may see and SSO into this app; [] = everyone. |
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
| `nameid_format` | string | no | transient, emailAddress, persistent - or "none" to omit <saml:NameID> from the Subject entirely. |
| `attribute_map` | map of string | no |  |
| `attribute_definitions` | array \| null | no | Released attributes with an arbitrary SAML Name and optional NameFormat per entry; replaces attribute_map when non-empty. null clears it back to the map. |
| `sign_response` | boolean | no |  |
| `sign_assertion` | boolean | no |  |
| `want_authn_requests_signed` | boolean | no |  |
| `signing_certs` | string[] | no |  |
| `slo_url` | string \| null | no |  |
| `encryption_cert` | string \| null | no |  |
| `encrypt_assertions` | boolean | no |  |
| `encryption_policy` | object \| null { content, transport, digest, mgf } | no |  |
| `subject_id` | "" \| "subject-id" \| "pairwise-id" | no |  |
| `assigned_groups` | array \| null | no | Group ids whose members may see and SSO into this app; empty or null = everyone. On update, omitted keeps the current restriction. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `created` | boolean | yes |  |
| `id` | number | yes |  |
| `entity_id` | string | yes |  |
| `assigned_groups` | number[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/saml/settings`

Read the instance SAML settings.

Permission: `saml:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `disabled_algorithms` | string[] | yes | Instance-wide algorithm deny list (IIP-ALG08): full URIs or short tokens (aes256-cbc, rsa-oaep-mgf1p, sha1). A denied algorithm cannot be selected on a service provider and fails closed at emission. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/saml/settings`

Set the SAML algorithm deny list.

Entries are XML Encryption URIs or short tokens, matched against content, key-transport, OAEP digest and MGF choices alike (a URI's #-fragment counts too). Replaces the whole list. A service provider whose encryption policy resolves to a denied algorithm cannot be saved, and one already stored fails closed at emission.

Permission: `saml:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `disabled_algorithms` | string[] | yes | Instance-wide algorithm deny list (IIP-ALG08): full URIs or short tokens (aes256-cbc, rsa-oaep-mgf1p, sha1). A denied algorithm cannot be selected on a service provider and fails closed at emission. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `disabled_algorithms` | string[] | yes | Instance-wide algorithm deny list (IIP-ALG08): full URIs or short tokens (aes256-cbc, rsa-oaep-mgf1p, sha1). A denied algorithm cannot be selected on a service provider and fails closed at emission. |

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

## App catalog

Templates for well-known applications: browse, read the setup instructions, and create the client or service provider filled in.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/app-catalog` | `oidc:read or saml:read` | List the app catalog |
| `GET` | `/api/v1/app-catalog/{slug}` | `oidc:read or saml:read` | Read a catalog entry |
| `POST` | `/api/v1/app-catalog/{slug}/apply` | `oidc:write or saml:write` | Create an app from a catalog entry |

### `GET /api/v1/app-catalog`

List the app catalog.

Templates for well-known applications: the placeholders each entry needs, ready for POST .../apply.

Permission: `oidc:read or saml:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `entries` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/app-catalog/{slug}`

Read a catalog entry.

The entry's setup instructions with the deployment's own values already substituted ({idp_*} tokens resolved); app-side placeholders stay wrapped in braces until apply supplies them. `saml`/`oidc` is the raw template the apply operation feeds.

Permission: `oidc:read or saml:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `slug` | path | yes | slug |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes |  |
| `name` | string | yes |  |
| `protocol` | "saml" \| "oidc" | yes |  |
| `website` | string | yes |  |
| `logo_url` | string | yes | This deployment's URL for the entry's icon; applying the entry sets it as the created record's logo. |
| `placeholders` | string[] | yes | The {name} tokens the caller supplies at apply time. |
| `instructions` | object { app, flareid } | yes |  |
| `saml` | map of any | no |  |
| `oidc` | map of any | no |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/app-catalog/{slug}/apply`

Create an app from a catalog entry.

Builds the SAML service provider or OIDC client the entry templates - saml:write for a SAML entry, oidc:write for OIDC. `values` must fill every placeholder the entry lists. A confidential OIDC client's `client_secret` is returned once, here only.

Permission: `oidc:write or saml:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `slug` | path | yes | slug |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `values` | map of string | no | {placeholder} names to values; every name the entry lists is required. |

Response `201`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `protocol` | "saml" \| "oidc" | yes |  |
| `id` | number | yes |  |
| `client_id` | string | no |  |
| `client_secret` | string | no | Only for a confidential OIDC client, and only in this response. |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

## SCIM

Outbound SCIM provisioning (FlareID as a SCIM client).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/scim/config` | `scim:read` | Read the first SCIM target's configuration |
| `POST` | `/api/v1/scim/config` | `admin` | Set the first SCIM target's endpoint, secret, scope and tuning |
| `GET` | `/api/v1/scim/targets` | `scim:read` | List outbound SCIM targets |
| `POST` | `/api/v1/scim/targets` | `admin` | Add an outbound SCIM target |
| `GET` | `/api/v1/scim/targets/{id}` | `scim:read` | Read one SCIM target |
| `PATCH` | `/api/v1/scim/targets/{id}` | `admin` | Change a SCIM target |
| `DELETE` | `/api/v1/scim/targets/{id}` | `scim:write` | Remove a SCIM target |
| `POST` | `/api/v1/scim/test` | `scim:write` | Test a SCIM connection |
| `POST` | `/api/v1/scim/sync` | `admin` | Push the next batch of users, then the groups |
| `GET` | `/api/v1/scim/mappings` | `scim:read` | List inbound attribute mappings |
| `PUT` | `/api/v1/scim/mappings` | `scim:write` | Replace the inbound attribute mappings |
| `GET` | `/api/v1/scim/correlation` | `scim:read` | List the inbound correlation keys |
| `PUT` | `/api/v1/scim/correlation` | `scim:write` | Replace the inbound correlation keys |
| `GET` | `/api/v1/scim/mastering` | `scim:read` | List the fields mastered by inbound provisioning |
| `PUT` | `/api/v1/scim/mastering` | `scim:write` | Replace the mastered field list |

### `GET /api/v1/scim/config`

Read the first SCIM target's configuration.

The legacy single-target view: the first target in the list. Whether a secret is set, never the secret. `/api/v1/scim/targets` lists them all.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | yes |  |
| `secret_set` | boolean | yes |  |
| `scope` | object { mode, group_ids } | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/config`

Set the first SCIM target's endpoint, secret, scope and tuning.

The legacy single-target view: updates the first target (creating one named Default when none exists). `POST /api/v1/scim/targets` and `/api/v1/scim/targets/{id}` manage them all. A changed scope re-evaluates everything already pushed, after the response. `tuning` controls how hard the client pushes: pace_ms between requests, members_per_request per group PATCH, and sync_batch users per sync call.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoint` | string | no |  |
| `secret` | string | no |  |
| `scope` | object { mode, group_ids } | no |  |
| `tuning` | object { pace_ms, members_per_request, sync_batch } | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/scim/targets`

List outbound SCIM targets.

One row per downstream SCIM server, each with its own endpoint, credential (write-only), scope and tuning.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `targets` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/targets`

Add an outbound SCIM target.

One target per downstream SCIM server. `name` is unique; `secret` is write-only.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `endpoint` | string | yes |  |
| `secret` | string | no |  |
| `scope` | object { mode, group_ids } | no |  |
| `tuning` | object { pace_ms, members_per_request, sync_batch } | no |  |
| `enabled` | boolean | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `GET /api/v1/scim/targets/{id}`

Read one SCIM target.

Permission: `scim:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `endpoint` | string | yes |  |
| `secret_set` | boolean | yes |  |
| `scope` | object { mode, group_ids } | yes |  |
| `tuning` | object { pace_ms, members_per_request, sync_batch } | yes |  |
| `enabled` | boolean | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/scim/targets/{id}`

Change a SCIM target.

Fields not supplied keep their values; a blank secret keeps the stored credential. A changed scope re-evaluates everything already pushed, after the response.

Permission: `admin`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `endpoint` | string | no |  |
| `secret` | string | no |  |
| `scope` | object { mode, group_ids } | no |  |
| `tuning` | object { pace_ms, members_per_request, sync_batch } | no |  |
| `enabled` | boolean | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/scim/targets/{id}`

Remove a SCIM target.

Links, push state and queued deprovisions go with it; the objects already created downstream are left there.

Permission: `scim:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/scim/test`

Test a SCIM connection.

`target_id` picks the target; without it the first enabled one.

Permission: `scim:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `target_id` | integer | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | boolean | yes |  |
| `status` | number | no |  |
| `error` | string | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/scim/sync`

Push the next batch of users, then the groups.

Call again until `complete` is true. `target_id` picks the target; without it the first enabled one.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `target_id` | integer | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | boolean | yes |  |
| `complete` | boolean | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/scim/mappings`

List inbound attribute mappings.

The expressions that rewrite fields on users an upstream provisioner creates or updates over the SCIM server API. Fields with no mapping keep the standard SCIM attribute mapping.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `mappings` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/scim/mappings`

Replace the inbound attribute mappings.

The whole set at once, in evaluation order. Each `target` is a user field: a column name (display_name, department, ...), `upn`, `active`, `manager`, `emails`, or `custom.<key>`. An expression yielding nothing clears its field on PUT and leaves it alone on PATCH.

Permission: `scim:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `mappings` | object[] | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/scim/correlation`

List the inbound correlation keys.

Ordered match keys tried when an inbound create's userName is new - the first key matching one existing user adopts the account instead of conflicting. Valid keys: upn, employee_number, emails, source_id.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `keys` | string[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/scim/correlation`

Replace the inbound correlation keys.

The ordered list, empty to refuse every duplicate. Valid keys: upn, employee_number, emails, source_id.

Permission: `scim:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `keys` | string[] | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/scim/mastering`

List the fields mastered by inbound provisioning.

Mastered fields belong to the upstream provisioner: inbound SCIM writes change them, the console shows them read-only, and the admin API rejects them. Valid fields: upn, emails, given_name, family_name, display_name, job_title, department, employee_number, hire_date, employment_status, employment_type, location, manager, photo, or custom.<key> for a custom attribute.

Permission: `scim:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `fields` | string[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/scim/mastering`

Replace the mastered field list.

The whole set, empty to unmaster everything. Valid fields: upn, emails, given_name, family_name, display_name, job_title, department, employee_number, hire_date, employment_status, employment_type, location, manager, photo, or custom.<key>.

Permission: `scim:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `fields` | string[] | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## LDAP

The read-only LDAP interface: app registrations and directory settings.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/ldap/apps` | `ldap:read` | List LDAP apps |
| `POST` | `/api/v1/ldap/apps` | `ldap:write` | Create or update an LDAP app (upsert by slug) |
| `POST` | `/api/v1/ldap/apps/{slug}/rotate` | `ldap:write` | Rotate an app's bind secret |
| `POST` | `/api/v1/ldap/apps/{slug}/reveal` | `ldap:write` | Reveal an app's current bind secret |
| `DELETE` | `/api/v1/ldap/apps/{slug}` | `ldap:write` | Revoke an LDAP app |
| `GET` | `/api/v1/ldap/settings` | `ldap:read` | Read the LDAP settings |
| `POST` | `/api/v1/ldap/settings` | `ldap:write` | Update the LDAP settings |

### `GET /api/v1/ldap/apps`

List LDAP apps.

Secrets are never returned - only the prefix for identification.

Permission: `ldap:read`

Response `200`:

`LdapApp[]`

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ldap/apps`

Create or update an LDAP app (upsert by slug).

Idempotent: the same body re-applied updates the app. The `secret` field appears only on create; rotate to get a new one.

Permission: `ldap:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes | Lowercase letters, digits and dashes; also the DN branch: ou=<slug>,<base>. |
| `name` | string | yes |  |
| `user_groups` | string[] | no | Group names whose members may bind; omit/empty = all users. |
| `exposed_groups` | string[] | no | Group names visible to this app; omit/empty = all groups. |
| `mfa_mode` | "password" \| "otp_if_enrolled" \| "otp_required" | no | password \| otp_if_enrolled (default) \| otp_required |
| `include_disabled` | boolean | no |  |

Response `200`:

`any`

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ldap/apps/{slug}/rotate`

Rotate an app's bind secret.

Permission: `ldap:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `slug` | path | yes | slug |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes |  |
| `secret` | string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `POST /api/v1/ldap/apps/{slug}/reveal`

Reveal an app's current bind secret.

Returns the KEK-sealed secret. 409 when the app predates secret sealing - rotate once to enable reveal.

Permission: `ldap:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `slug` | path | yes | slug |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

### `DELETE /api/v1/ldap/apps/{slug}`

Revoke an LDAP app.

Sets revoked_at; binds and searches fail immediately. Idempotent.

Permission: `ldap:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `slug` | path | yes | slug |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `GET /api/v1/ldap/settings`

Read the LDAP settings.

Permission: `ldap:read`

Response `200`:

`LdapSettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `hostname` | string | yes |  |
| `base_dn` | string | yes |  |
| `netbios_name` | string | yes |  |
| `unscoped_bind_app` | string | yes |  |
| `posix_uid_base` | number | yes |  |
| `posix_gid_base` | number | yes |  |
| `posix_default_gid` | number | yes |  |
| `posix_shell` | string | yes |  |
| `posix_home` | string | yes |  |
| `idle_timeout_minutes` | number | yes |  |
| `otp_rebind_seconds` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ldap/settings`

Update the LDAP settings.

Only the fields sent change. `enabled: true` also generates the domain SID and GUID namespace on first use.

Permission: `ldap:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | no |  |
| `hostname` | string | no |  |
| `base_dn` | string | no | '' = derive dc=… from the default domain. |
| `netbios_name` | string | no | '' = uppercased first label of the default domain. |
| `unscoped_bind_app` | string | no | Slug that unattributed user binds land on; '' = deny them. |
| `posix_uid_base` | integer | no |  |
| `posix_gid_base` | integer | no |  |
| `posix_default_gid` | integer | no |  |
| `posix_shell` | string | no |  |
| `posix_home` | string | no | Template; {username} is substituted. |
| `idle_timeout_minutes` | integer | no |  |
| `otp_rebind_seconds` | integer | no |  |

Response `200`:

`LdapSettings`:

| Field | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes |  |
| `hostname` | string | yes |  |
| `base_dn` | string | yes |  |
| `netbios_name` | string | yes |  |
| `unscoped_bind_app` | string | yes |  |
| `posix_uid_base` | number | yes |  |
| `posix_gid_base` | number | yes |  |
| `posix_default_gid` | number | yes |  |
| `posix_shell` | string | yes |  |
| `posix_home` | string | yes |  |
| `idle_timeout_minutes` | number | yes |  |
| `otp_rebind_seconds` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Mappings

Attribute flows: inbound and outbound mapping rules evaluated by the expression engine, and the collision policy.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/mappings` | `schemas:read` | List a channel's attribute mappings |
| `PUT` | `/api/v1/mappings` | `admin` | Replace a channel's attribute mappings |
| `GET` | `/api/v1/mappings/collisions` | `schemas:read` | Read the collision policy |
| `PUT` | `/api/v1/mappings/collisions` | `admin` | Set the collision policy |

### `GET /api/v1/mappings`

List a channel's attribute mappings.

The mapping rows for one flow: `channel` is scim-in, jit, scim-out, oidc; `owner` scopes it (an upstream IdP id for jit, a SCIM target id for scim-out, a client_id for oidc, empty for the channel's defaults and for scim-in). Each row's `expression` is evaluated over the source document - the SCIM body, the IdP's claims, or the FlareID user.

Permission: `schemas:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `channel` | query | yes | string |
| `owner` | query | no | string |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `mappings` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/mappings`

Replace a channel's attribute mappings.

The whole set for (channel, owner) at once - the same surface as the console's Flows editor, which is Super-Admin-gated for the same reason: the rows rewrite what every sign-in and provisioning write carries. `/api/v1/scim/mappings` remains the delegable (scim:write) view of the scim-in channel.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `channel` | string | yes |  |
| `owner` | string | no |  |
| `resource` | string | no |  |
| `mappings` | object[] | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/mappings/collisions`

Read the collision policy.

What inbound writes do when an identity collides: `username` is increment (append a counter), pattern (evaluate `username_pattern` over {local, n, domain, email} until free), or fail; `email` is skip (don't attach) or fail.

Permission: `schemas:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes |  |
| `username_pattern` | string | yes |  |
| `email` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/mappings/collisions`

Set the collision policy.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | no |  |
| `username_pattern` | string | no |  |
| `email` | string | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes |  |
| `username_pattern` | string | yes |  |
| `email` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Federation

Inbound federation: upstream identity providers people sign in through (FlareID as the relying party).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/federation/idps` | `federation:read` | List upstream identity providers |
| `POST` | `/api/v1/federation/idps` | `admin` | Add an upstream identity provider |
| `GET` | `/api/v1/federation/idps/{id}` | `federation:read` | Read one upstream identity provider |
| `PATCH` | `/api/v1/federation/idps/{id}` | `admin` | Change an upstream identity provider |
| `DELETE` | `/api/v1/federation/idps/{id}` | `admin` | Remove an upstream identity provider |

### `GET /api/v1/federation/idps`

List upstream identity providers.

Providers people can sign in through - FlareID as the relying party. `config` never carries the client secret, only whether one is stored.

Permission: `federation:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `idps` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/federation/idps`

Add an upstream identity provider.

FlareID as the relying party. OIDC `config`: issuer, client_id, client_secret (write-only), scopes. SAML `config`: sso_url, certificate (PEM or base64), idp_entity_id, nameid_format, attr_map. `jit` creates an account on first sign-in when no local user matches; `jit_groups` lists the groups every such account joins. Registering an IdP trusts its claims for every account here, so this needs an admin-scoped key - not delegated federation write.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `protocol` | "oidc" \| "saml" | yes |  |
| `enabled` | boolean | no |  |
| `jit` | boolean | no |  |
| `jit_domain` | string | no |  |
| `jit_groups` | integer[] | no | Group ids every JIT-provisioned account joins at creation. A group may grant a read-only admin role; one granting a write-capable role is refused. |
| `config` | map of string \| map of string | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `409` (`{ "error", "message" }`).

### `GET /api/v1/federation/idps/{id}`

Read one upstream identity provider.

Permission: `federation:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `protocol` | "oidc" \| "saml" | yes |  |
| `enabled` | boolean | yes |  |
| `jit` | boolean | yes |  |
| `jit_domain` | string \| null | yes |  |
| `jit_groups` | number[] | yes | Group ids every JIT-provisioned account joins at creation. |
| `config` | map of string \| boolean \| map of string | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `PATCH /api/v1/federation/idps/{id}`

Change an upstream identity provider.

Fields not supplied keep their values; `config` keys merge onto the stored config, and an omitted client_secret keeps the stored credential.

Permission: `admin`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `protocol` | "oidc" \| "saml" | no |  |
| `enabled` | boolean | no |  |
| `jit` | boolean | no |  |
| `jit_domain` | string | no |  |
| `jit_groups` | integer[] | no | Group ids every JIT-provisioned account joins at creation. A group may grant a read-only admin role; one granting a write-capable role is refused. |
| `config` | map of string \| map of string | no |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/federation/idps/{id}`

Remove an upstream identity provider.

Its sign-in button and linked identities go with it; the accounts themselves are kept.

Permission: `admin`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Cloudflare One

The Cloudflare One (Zero Trust) connection, gateway-list sync and the risk watchlist.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/integrations/cloudflare-one` | `cfone:read` | Read the Cloudflare One connection and sync status |
| `PUT` | `/api/v1/integrations/cloudflare-one` | `cfone:write` | Configure the Cloudflare One connection |
| `POST` | `/api/v1/integrations/cloudflare-one/sync` | `cfone:write` | Run the list sync now |
| `PUT` | `/api/v1/users/{username}/watch` | `cfone:write` | Flag a user on the risk watchlist |
| `DELETE` | `/api/v1/users/{username}/watch` | `cfone:write` | Clear a user from the risk watchlist |

### `GET /api/v1/integrations/cloudflare-one`

Read the Cloudflare One connection and sync status.

Permission: `cfone:read`

Response `200`:

`CloudflareOne`:

| Field | Type | Required | Description |
|---|---|---|---|
| `configured` | boolean | yes |  |
| `account_id` | string | yes | The Cloudflare account Zero Trust lives in. |
| `team` | string | yes | Zero Trust team name - the Access tenant https://{team}.cloudflareaccess.com. |
| `access_aud` | string | yes | AUD tag of the Access application protecting the admin console; empty disables the JWT check. |
| `api_token_set` | boolean | yes | Whether an API token is stored; the token itself is never returned. |
| `lists` | string[] | yes | The list syncs that run (see /sync for per-group syncs). |
| `list_status` | object[] | yes |  |
| `watchlist` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/integrations/cloudflare-one`

Configure the Cloudflare One connection.

An empty `api_token` keeps the stored one; `lists` names the reusable-list syncs to run (watchlist, deprovisioned, managed-domains, auth-fail-ips). Clearing `account_id` disconnects and stops the Access-JWT check.

Permission: `cfone:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `account_id` | string | yes | Empty disconnects. |
| `api_token` | string | no | Zero Trust Read/Write token; omit to keep the stored one. |
| `team` | string | no |  |
| `access_aud` | string | no |  |
| `lists` | "watchlist" \| "deprovisioned" \| "managed-domains" \| "auth-fail-ips"[] | no |  |

Response `200`:

`CloudflareOne`:

| Field | Type | Required | Description |
|---|---|---|---|
| `configured` | boolean | yes |  |
| `account_id` | string | yes | The Cloudflare account Zero Trust lives in. |
| `team` | string | yes | Zero Trust team name - the Access tenant https://{team}.cloudflareaccess.com. |
| `access_aud` | string | yes | AUD tag of the Access application protecting the admin console; empty disables the JWT check. |
| `api_token_set` | boolean | yes | Whether an API token is stored; the token itself is never returned. |
| `lists` | string[] | yes | The list syncs that run (see /sync for per-group syncs). |
| `list_status` | object[] | yes |  |
| `watchlist` | object[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/integrations/cloudflare-one/sync`

Run the list sync now.

Also runs the watchlist sweep (lapsed flags drop out). The scheduled job does the same on its own cadence.

Permission: `cfone:write`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `synced` | string[] | yes |  |
| `failed` | map of string | yes |  |
| `swept` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PUT /api/v1/users/{username}/watch`

Flag a user on the risk watchlist.

The watchlist is a system group whose member emails Cloudflare One can consume (list sync or a SCIM target). `ttl_hours` 0 means the flag stays until cleared.

Permission: `cfone:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | string | yes |  |
| `ttl_hours` | number | no |  |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `watched` | true | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

### `DELETE /api/v1/users/{username}/watch`

Clear a user from the risk watchlist.

Permission: `cfone:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `username` | path | yes | The username (the UPN's local part, unique across every domain). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `watched` | false | yes |  |

Errors: `400`, `401`, `403`, `404` (`{ "error", "message" }`).

## Signals

Shared Signals Framework: outbound CAEP/RISC streams and trusted inbound transmitters.

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/ssf/streams` | `signals:read` | List outbound signal streams |
| `POST` | `/api/v1/ssf/streams` | `signals:write` | Register an outbound stream |
| `PATCH` | `/api/v1/ssf/streams/{id}` | `signals:write` | Update an outbound stream |
| `DELETE` | `/api/v1/ssf/streams/{id}` | `signals:write` | Delete an outbound stream |
| `POST` | `/api/v1/ssf/outbox/drain` | `signals:write` | Retry undelivered events now |
| `GET` | `/api/v1/ssf/transmitters` | `signals:read` | List trusted inbound transmitters |
| `POST` | `/api/v1/ssf/transmitters` | `admin` | Trust an inbound transmitter |
| `DELETE` | `/api/v1/ssf/transmitters/{id}` | `admin` | Stop trusting a transmitter |

### `GET /api/v1/ssf/streams`

List outbound signal streams.

Permission: `signals:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `streams` | SsfStream[] | yes |  |
| `events_supported` | string[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ssf/streams`

Register an outbound stream.

A receiver endpoint we push signed SETs to (application/secevent+jwt). `events` selects which of the supported CAEP/RISC URIs it gets; an empty list means all.

Permission: `signals:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `endpoint_url` | string | yes |  |
| `aud` | string | no |  |
| `events` | "https://schemas.openid.net/secevent/caep/event-type/session-revoked" \| "https://schemas.openid.net/secevent/caep/event-type/credential-change" \| "https://schemas.openid.net/secevent/risc/event-type/account-disabled" \| "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"[] | no |  |

Response `201`:

`SsfStream`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `endpoint_url` | string | yes |  |
| `aud` | string | yes | Audience the receiver expects in the SET; empty uses the endpoint's host. |
| `events` | string[] | yes | Event URIs this stream gets; empty means all supported. |
| `disabled` | boolean | yes |  |
| `created_at` | string | yes |  |
| `last_push_at` | string \| null | yes |  |
| `last_error` | string \| null | yes |  |
| `queued` | number | yes | Undelivered events waiting in the outbox. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PATCH /api/v1/ssf/streams/{id}`

Update an outbound stream.

Permission: `signals:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | no |  |
| `endpoint_url` | string | no |  |
| `aud` | string | no |  |
| `events` | "https://schemas.openid.net/secevent/caep/event-type/session-revoked" \| "https://schemas.openid.net/secevent/caep/event-type/credential-change" \| "https://schemas.openid.net/secevent/risc/event-type/account-disabled" \| "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"[] | no |  |
| `disabled` | boolean | no |  |

Response `200`:

`SsfStream`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `endpoint_url` | string | yes |  |
| `aud` | string | yes | Audience the receiver expects in the SET; empty uses the endpoint's host. |
| `events` | string[] | yes | Event URIs this stream gets; empty means all supported. |
| `disabled` | boolean | yes |  |
| `created_at` | string | yes |  |
| `last_push_at` | string \| null | yes |  |
| `last_error` | string \| null | yes |  |
| `queued` | number | yes | Undelivered events waiting in the outbox. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `DELETE /api/v1/ssf/streams/{id}`

Delete an outbound stream.

Queued undelivered events for the stream go with it.

Permission: `signals:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ssf/outbox/drain`

Retry undelivered events now.

The outbox drains on emit and on the hourly cron; this forces a pass - useful after fixing a receiver that was down.

Permission: `signals:write`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `sent` | number | yes |  |
| `failed` | number | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/ssf/transmitters`

List trusted inbound transmitters.

Permission: `signals:read`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `transmitters` | SsfTransmitter[] | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/ssf/transmitters`

Trust an inbound transmitter.

An issuer whose SETs we accept at POST /ssf/receive, verified against `jwks_url`. A `session-revoked` event for a user's email kills their sessions; a credential/risk event flags them on the risk watchlist for 24h.

Permission: `admin`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `issuer` | string | yes |  |
| `jwks_url` | string | yes |  |

Response `201`:

`SsfTransmitter`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | number | yes |  |
| `name` | string | yes |  |
| `issuer` | string | yes |  |
| `jwks_url` | string | yes |  |
| `created_at` | string | yes |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `DELETE /api/v1/ssf/transmitters/{id}`

Stop trusting a transmitter.

Permission: `admin`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

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
| `PATCH` | `/api/v1/api-keys/{id}` | `api_keys:write` | Rename an API key or change its permissions |
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

### `PATCH /api/v1/api-keys/{id}`

Rename an API key or change its permissions.

Takes effect on the key's next request. The token itself never changes - rotate by revoking and minting a new one. Revoked keys are read-only.

Permission: `api_keys:write`

| Parameter | In | Required | Description |
|---|---|---|---|
| `id` | path | yes | Numeric id. |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `scopes` | string[] | yes |  |

Response `200`:

`Ok`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |

Errors: `400`, `401`, `403`, `404`, `409` (`{ "error", "message" }`).

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
| `default_language` | string | yes | The sign-in pages' language when the browser asks for none FlareID has (no ?lang=, language cookie, OIDC ui_locales or supported Accept-Language). One of `available_languages`. |
| `available_languages` | object[] | yes | The languages the sign-in pages are translated into (locales/*.json). |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `console_timezone` | string | yes | The timezone console pages display dates in. Empty for each browser's own zone; otherwise "UTC" or an IANA name like Europe/London. |
| `css_url` | string \| null | yes | Where that stylesheet is served (`/brand/css/default-<hash>.css`), or null. |
| `preview_url` | string | yes | The sign-in page in this brand, for a signed-in administrator with branding:read. |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `PATCH /api/v1/branding`

Change the default brand.

Fields not supplied keep their values. Colours are #rrggbb. An empty `login_subtitle` shows no message; empty cursor-trail `characters` uses the default symbols; `default_language` must be one of `available_languages`. `custom_css` (at most 20 KB; empty removes it) is refused if it contains `</style`, `@import`, `expression(`, `javascript:` or a `url(` that is not a same-origin path or a data: URL - the page's Content-Security-Policy blocks remote fonts and images anyway.

Permission: `branding:write`

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | no |  |
| `login_subtitle` | string | no |  |
| `login_gradient` | object { from, to } | no |  |
| `cursor_trail` | object { enabled, characters } | no |  |
| `default_language` | string | no |  |
| `email_accent` | string | no |  |
| `custom_css` | string | no |  |
| `console_timezone` | string | no |  |

Response `200`:

`Branding`:

| Field | Type | Required | Description |
|---|---|---|---|
| `app_name` | string | yes |  |
| `login_subtitle` | string | yes |  |
| `login_gradient` | object { from, to } | yes |  |
| `cursor_trail` | object { enabled, characters } | yes |  |
| `default_language` | string | yes | The sign-in pages' language when the browser asks for none FlareID has (no ?lang=, language cookie, OIDC ui_locales or supported Accept-Language). One of `available_languages`. |
| `available_languages` | object[] | yes | The languages the sign-in pages are translated into (locales/*.json). |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `console_timezone` | string | yes | The timezone console pages display dates in. Empty for each browser's own zone; otherwise "UTC" or an IANA name like Europe/London. |
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
| `default_language` | string | yes | The sign-in pages' language when the browser asks for none FlareID has (no ?lang=, language cookie, OIDC ui_locales or supported Accept-Language). One of `available_languages`. |
| `available_languages` | object[] | yes | The languages the sign-in pages are translated into (locales/*.json). |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `console_timezone` | string | yes | The timezone console pages display dates in. Empty for each browser's own zone; otherwise "UTC" or an IANA name like Europe/London. |
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
| `default_language` | string | yes | The sign-in pages' language when the browser asks for none FlareID has (no ?lang=, language cookie, OIDC ui_locales or supported Accept-Language). One of `available_languages`. |
| `available_languages` | object[] | yes | The languages the sign-in pages are translated into (locales/*.json). |
| `email_accent` | string | yes |  |
| `logo_url` | string \| null | yes | Path of the uploaded logo (`/brand/logo/<id>-<hash>.png\|jpg`, cached as immutable), or null for FlareID's own mark. |
| `custom_css` | string | yes | The custom stylesheet for the sign-in, second-step, consent, recovery and setup pages (never the admin console). Empty for none. |
| `console_timezone` | string | yes | The timezone console pages display dates in. Empty for each browser's own zone; otherwise "UTC" or an IANA name like Europe/London. |
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
| `device_cert` | boolean | no | Sign-in needs a verified WARP device certificate (request.cf.tlsClientAuth) - the zone must enforce mTLS. |
| `max_risk` | "" \| "low" \| "medium" | no | Deny sign-in when the user's Cloudflare ZT risk score is above this level; empty checks nothing. |

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
| `device_cert` | boolean | yes |  |
| `max_risk` | string | yes |  |

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
| `device_cert` | boolean | no | Sign-in needs a verified WARP device certificate (request.cf.tlsClientAuth) - the zone must enforce mTLS. |
| `max_risk` | "" \| "low" \| "medium" | no | Deny sign-in when the user's Cloudflare ZT risk score is above this level; empty checks nothing. |

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
| `device_cert` | boolean | yes |  |
| `max_risk` | string | yes |  |

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

At least one factor must stay on while a policy requires a second factor, and one of totp, passkey and email_otp while a policy requires one of an administrator (security questions never count for administrators). Email one-time codes (email_otp) are off on a fresh install and can be switched on only once email is configured. Security questions (security_questions) are off on a fresh install and need at least as many enabled questions as each person sets (see /api/v1/security/security-questions).

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
| `GET` | `/api/v1/audit/verify` | `audit:read` | Verify the audit log's tamper-evident chain |
| `GET` | `/api/v1/audit/export` | `audit:read` | Export the audit log |

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

Newest first, with the console's filters. actor: people, api, system; category: login, user, group, directory, api, api_key, oidc, oauth, saml, scim, ldap, settings, domain, schema, idp; from/to are whole UTC days (YYYY-MM-DD, inclusive).

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

### `GET /api/v1/audit/verify`

Verify the audit log's tamper-evident chain.

Every audit row stores a SHA-256 chain over the previous row's hash and its own contents. This recomputes the chain and reports `ok`, `fork` (two rows share a parent - possible under concurrent writes), or `broken` (a row was altered or removed). Rows written before chaining was introduced are skipped and counted in `unchained`.

Permission: `audit:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `limit` | query | no | How many of the newest rows to check, at most 10,000 (default). |

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `checked` | number | yes |  |
| `unchained` | number | yes |  |
| `status` | "ok" \| "empty" \| "broken" \| "fork" | yes |  |
| `at_id` | number | no |  |
| `message` | string | no |  |

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `GET /api/v1/audit/export`

Export the audit log.

The same filters as GET /api/v1/audit, as a download instead of a page. `format` is `ndjson` (default, one entry per line) or `csv`. `chain_hash` is included so the export can be re-verified offline. At most 100,000 rows per call.

Permission: `audit:read`

| Parameter | In | Required | Description |
|---|---|---|---|
| `format` | query | no | "ndjson" \\| "csv" |
| `search` | query | no | string |
| `actor` | query | no | string |
| `category` | query | no | string |
| `from` | query | no | string |
| `to` | query | no | string |

Response `200`:

`string`

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

## Backup

Whole-database export and restore for disaster recovery (docs/dr.md).

| Method | Path | Permission | Summary |
|---|---|---|---|
| `GET` | `/api/v1/backup` | `admin` | Export the whole database |
| `POST` | `/api/v1/backup/restore` | `bootstrap-token` | Restore a backup bundle |

### `GET /api/v1/backup`

Export the whole database.

A JSON bundle `{ version: 1, at, tables: { name: [rows] } }` covering every table except the migration ledger. It contains everything an attacker would want - password hashes, encrypted secrets, session state - so it needs an `admin` permission key and should be handled like the database itself. Restore with POST /api/v1/backup/restore (bootstrap token only).

Permission: `admin`

Response `200`:

`map of any`

Errors: `400`, `401`, `403` (`{ "error", "message" }`).

### `POST /api/v1/backup/restore`

Restore a backup bundle.

Bootstrap token only. Body is the bundle from GET /api/v1/backup plus `confirm: true`. **Wipes every table and rewrites it** - the bundle's tables and columns are validated against this schema before the first delete, so a bundle from a newer schema aborts cleanly. Apply the target's migrations first.

Permission: `bootstrap-token`

Request body:

`map of any`

Response `200`:

| Field | Type | Required | Description |
|---|---|---|---|
| `ok` | true | yes |  |
| `restored` | number | yes |  |
| `tables` | number | yes |  |

Errors: `400`, `403` (`{ "error", "message" }`).

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

