# Provisioning API

Everything the admin console does is also available over a JSON API at `https://<your hostname>/api/v1`. Use it for scripts, CI pipelines, Terraform or onboarding automation.

The [API reference](/docs/api/reference) lists every operation, generated from the running code. The same description is available as an OpenAPI 3.1 document at `/api/v1/openapi.json`, for client generators and API explorers.

## API keys

Every request needs a bearer token:

```sh
curl https://idp.example.com/api/v1/users -H "Authorization: Bearer flareid_sk_..."
```

To create a key:

1. Go to **Integrations → API keys → + New key**.
2. Enter a name that says what uses it, such as `HR sync`. It appears in the audit log against everything the key does.
3. Choose its **Permissions**, or **Start from a role**.
4. Copy the key. It's shown only once.

You can change a key's permissions later, or revoke it, from the same page.

## Permissions

Keys use the same permissions as [admin roles](roles.md): read or write for each area, such as `users:write` or `audit:read`, or `*` for everything. Each operation in the reference shows the permission it needs.

A few shorthand scopes cover common jobs:

| Scope | Covers |
|---|---|
| `directory:read` | Reading users, groups, domains, schemas, OIDC clients and SAML apps. |
| `directory:write` | Changing users, groups and domains, and importing. Also what the [SCIM server](scim.md#inbound-scim-server) needs. |
| `clients:write` | OIDC clients, SAML apps and federation. |
| `settings:write` | Security, branding, email, SCIM and schemas. |
| `admin` | Everything, including creating further keys. |

Anything that touches an administrator's account needs `admin`.

## Requests and errors

- Send and receive JSON. Changes are recorded in the [audit log](monitoring.md#audit-log), as is every authenticated call.
- Errors return a status code and `{ "error": "...", "message": "..." }`:

| Status | Meaning |
|---|---|
| `400` | The request is invalid. The message names the field. |
| `401` | The key is missing, unknown, revoked or expired. |
| `403` | The key doesn't have the permission. |
| `404` | No such object. |
| `409` | It conflicts with something that already exists. |

## Example: create a user

```sh
curl -X POST https://idp.example.com/api/v1/users \
  -H "Authorization: Bearer $FLAREID_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "username": "ada", "given_name": "Ada", "family_name": "Lovelace", "status": "active", "groups": ["Engineering"] }'
```

## Setting up a new deployment

Before setup is complete, the `BOOTSTRAP_TOKEN` secret works as a key for every operation, so you can set up FlareID entirely from a script: `POST /api/v1/setup` creates the first administrator and domain, `POST /api/v1/directory/import` loads people and groups, and `POST /api/v1/api-keys` mints a key for later. Send `"complete": true` to `/setup` last: it retires the bootstrap token.

## Emergency access

If every administrator is locked out, `POST /api/v1/recovery/admin-reset` with the bootstrap token re-creates or re-enables a Super Admin and resets their password. It's the only thing the bootstrap token can do after setup. Delete the `BOOTSTRAP_TOKEN` secret if you'd rather it couldn't.
