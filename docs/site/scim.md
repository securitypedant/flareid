# SCIM provisioning

SCIM keeps other systems' user lists in step with FlareID. It works in two directions:

- **Outbound**: FlareID pushes users and groups to other systems, such as Cloudflare Access or a SaaS app.
- **Inbound**: an HR system or another identity provider pushes users and groups into FlareID.

## Outbound: add a target

A target is one system FlareID pushes to.

1. In the other system, turn on SCIM and copy its **SCIM endpoint** and **secret** (bearer token).
2. In FlareID, go to **Integrations → SCIM provisioning → + New target**.
3. Enter a name, the **SCIM endpoint (base URL)** and the **SCIM secret**, and save.
4. On the target's page, select **Test connection**, then **Sync all now**.

From then on, changes are pushed as they happen, whether they're made in the console, by import, over the API, or by inbound SCIM.

| In FlareID | On the target |
|---|---|
| A user is created or edited | Created or updated |
| A user is made inactive | Set inactive |
| A user is deleted | Deleted (retried until it succeeds) |
| Group membership changes, including dynamic groups | Membership updated |
| A group is renamed or deleted | Renamed or deleted |

## Sync scope

Under **Sync scope**, push everyone, or only members of specific groups. Users and groups that fall out of scope are removed from the target. Start with specific groups if your directory has test accounts.

## Sync tuning

Some SCIM servers, including Cloudflare Access, reject large or rapid requests. If syncs report errors, lower **Members per group request** and **Users per sync batch**, or raise **Pause between requests**. A large directory syncs over several runs; the hourly job carries on where the last one stopped.

The **Sync log** on the target's page shows what happened in recent syncs.

## Inbound SCIM server

FlareID is also a SCIM 2.0 server at `https://<your hostname>/scim/v2`. To let an HR system or another identity provider provision FlareID:

1. Create an [API key](api.md#api-keys) with `directory:write`.
2. In the other system, enter the SCIM base URL above and the API key as the bearer token.

Changes that arrive this way flow on to your outbound targets. On the **SCIM provisioning** page you can also set:

- **Inbound attribute mapping**: change how incoming SCIM fields map onto FlareID attributes.
- **Correlation**: match an incoming user to an existing account (for example by employee number) instead of refusing a duplicate.
- **Field mastering**: make fields owned by the provisioner read-only everywhere else, so HR data like job title can't drift.

Accounts that hold an admin role can only be changed by a key with `admin` permission.
