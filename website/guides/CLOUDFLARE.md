# FlareID with Cloudflare One (OIDC sign-in and SCIM provisioning)

This guide connects FlareID to a Cloudflare One (Zero Trust) account as an
identity provider:

- **OIDC** signs your users in to Access applications, Gateway and the
  Cloudflare One Client, with their groups in the token.
- **SCIM** keeps Cloudflare One's user registry in step with FlareID: new
  people appear, removed people are deprovisioned, and group names show up in
  the policy builder.

You need a running FlareID (for example `https://idp.example.com`), a Super
Admin account on it, and a Cloudflare account with Zero Trust enabled.

Throughout, replace:

| Placeholder | Example | Where to find it |
|---|---|---|
| `<flareid>` | `https://idp.example.com` | Your FlareID issuer URL |
| `<team>` | `acme` | Cloudflare dashboard → **Zero Trust** → **Settings** → **Team name and domain** |

---

## Part 1: Sign-in with OIDC

### 1.1 Create the OIDC client in FlareID

1. Sign in to FlareID as a Super Admin and open **Admin → Integrations → OIDC
   clients → + New client**.
2. Fill in:
   - **Name**: `Cloudflare One`
   - **Redirect URIs**: `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`
   - **Client type**: Confidential (a server that can keep a secret)
   - **Trusted first-party app**: ticked, so users are not shown a consent
     screen for your own Zero Trust login
   - **Claims this app may receive**: keep **Email address**, **Name and
     username** and **Group memberships** ticked. Untick **Job title,
     department and manager** and **Custom attributes** unless your policies
     need them.
3. Select **Create client**. Copy the **Client ID** and **Client secret** now:
   the secret is shown only once. The client page also lists the Auth, Token
   and Certificate URLs, each with a copy button.

### 1.2 Add FlareID as an identity provider in Cloudflare One

1. In the [Cloudflare dashboard](https://dash.cloudflare.com/), go to
   **Zero Trust → Integrations → Identity providers**.
2. Select **Add new identity provider → OpenID Connect**.
3. Fill in:

   | Cloudflare field | Value |
   |---|---|
   | **Name** | `FlareID` |
   | **App ID** | the Client ID from step 1.1 |
   | **Client secret** | the Client secret from step 1.1 |
   | **Auth URL** | `<flareid>/authorize` |
   | **Token URL** | `<flareid>/token` |
   | **Certificate URL** | `<flareid>/jwks.json` |
   | **Proof Key for Code Exchange (PKCE)** | On (FlareID supports S256) |

4. Under **Optional configurations**:
   - **OIDC Claims**: add `groups`, and any others your policies use, for
     example `job_title` or `department` (these need **Job title, department
     and manager** ticked on the FlareID client).
   - **Email claim**: leave as `email`.
   - **Scopes**: `openid email profile groups`.
5. Leave SCIM off for now; Part 2 turns it on. Select **Save**.

### 1.3 Test the connection

Back on **Integrations → Identity providers**, select **Test** next to
FlareID and sign in with a FlareID account. The test page should show the
user's `email`, `name` and `groups`.

If the test fails:

- **"redirect_uri is not registered"** on the FlareID page: the redirect URI
  on the FlareID client must match `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`
  exactly.
- **Signed in but no `groups`**: check that `groups` is in the scopes and the
  OIDC claims on the Cloudflare side, and that **Group memberships** is ticked under
  **Claims this app may receive** on the FlareID client.
- **Asked for a code you don't have**: the user's authentication policy in
  FlareID (**Admin → Security**) needs a second factor. They can enrol an
  authenticator app or a passkey under **My account → Security**.

### 1.4 Use it in Access policies

- Enable FlareID as a login method on your Access applications (or under
  **Settings → Authentication** for the Cloudflare One Client).
- In an Access policy, use the **Login Methods** selector for FlareID, then
  match on **Emails**, **Emails ending in**, or **OIDC Claims** with claim
  name `groups` and a FlareID group name (for example `Engineering`).

Access evaluates groups from the token at sign-in, so OIDC alone is enough
for group-based policies. SCIM (Part 2) adds readable group names in the
policy builder, deprovisioning, and up-to-date identities for Gateway.

---

## Part 2: Provisioning with SCIM

FlareID pushes users and groups to Cloudflare One's SCIM endpoint. Cloudflare
One is the SCIM server; FlareID is the client.

### 2.1 Enable SCIM in Cloudflare One

1. In **Zero Trust → Integrations → Identity providers**, find FlareID and
   select **Edit**.
2. Turn on **Enable SCIM**.
3. Choose the options you want:
   - **Enable user deprovisioning**: revoke a user's Access sessions when
     FlareID deactivates or deletes them. Recommended.
   - **Remove user seat on deprovision**: free the user's seat at the same time.
   - **SCIM identity update behavior**: *Automatic identity updates* keeps
     Gateway and device profiles current; *Group membership change
     reauthentication* also signs the user out of Access when their groups
     change.
4. Select **Regenerate Secret**, then copy the **SCIM Endpoint** and
   **SCIM Secret**. Select **Save**.

### 2.2 Point FlareID at it

1. In FlareID, open **Admin → Integrations → SCIM provisioning**.
2. Paste:
   - **SCIM endpoint (base URL)**: the SCIM Endpoint, exactly as Cloudflare
     shows it
   - **SCIM secret**: the SCIM Secret
3. Select **Save**, then **Test connection**. A successful test lists the
   request FlareID made and the status Cloudflare returned.
4. Under **Sync scope**, choose who is provisioned:
   - **All groups**: every user and group, or
   - **Specific groups only**: only members of the groups you pick, and
     those groups. Start here if your directory is large or contains test accounts.
5. Select **Sync all now**. FlareID pushes users in batches of 200 per run.
   For a large directory, the hourly maintenance job carries on from where
   the last batch stopped; selecting **Sync all now** again continues it too.

### 2.3 What stays in sync

From then on, FlareID pushes changes as they happen, from the console, the
API, CSV imports and its own inbound SCIM server:

| In FlareID | In Cloudflare One |
|---|---|
| A user is created or edited (in scope) | The user is created or updated |
| A user is deactivated | The user is set inactive; with deprovisioning on, their sessions end |
| A user is deleted | The user is deleted (queued and retried if Cloudflare is unreachable) |
| A user's group membership changes, including through a dynamic group's rule | Group membership is updated |
| A group is renamed or deleted | The group is renamed or deleted |
| The sync scope changes | Users and groups now out of scope are removed |

Deletions that fail (for example during an outage) wait in a queue and are
retried by every sync and by the hourly job.

### 2.4 Check it worked

- **Zero Trust → Team & Resources → Users** lists the provisioned people,
  and the policy builder offers FlareID's group names.
- FlareID's **Admin → Log** records each sync and any SCIM failure, and the
  **Overview** dashboard counts SCIM failures and queued deletions for the
  last 24 hours.

---

## Doing it all over the API

Everything above can be scripted. FlareID's provisioning API (see
`docs/api.md`) creates the OIDC client and sets the SCIM connection:

```bash
# FlareID: an OIDC client for Cloudflare One, with a secret you choose
curl -s "<flareid>/api/v1/clients" -H "Authorization: Bearer $FLAREID_API_KEY" \
  -H "Content-Type: application/json" -d '{
    "name": "Cloudflare One",
    "client_id": "cloudflare-one",
    "client_secret": "'"$CLIENT_SECRET"'",
    "redirect_uris": ["https://<team>.cloudflareaccess.com/cdn-cgi/access/callback"],
    "trusted": true,
    "allowed_claims": ["email", "profile", "groups"]
  }'

# FlareID: the SCIM connection, then a full sync
curl -s "<flareid>/api/v1/scim/config" -H "Authorization: Bearer $FLAREID_API_KEY" \
  -H "Content-Type: application/json" -d '{
    "endpoint": "'"$CF_SCIM_ENDPOINT"'",
    "secret": "'"$CF_SCIM_SECRET"'",
    "scope": { "mode": "all", "group_ids": [] }
  }'
curl -s -X POST "<flareid>/api/v1/scim/sync" -H "Authorization: Bearer $FLAREID_API_KEY"
```

The FlareID key needs the `clients:write` and `settings:write` scopes. On the
Cloudflare side, the identity provider can be created with the
[Identity Providers API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/create/)
or the `cloudflare_zero_trust_access_identity_provider` Terraform resource
(type `oidc`, with `pkce_enabled = true`, `claims = ["groups"]` and
`scopes = ["openid", "email", "profile", "groups"]`). Supplying your own
`client_id` and `client_secret` to FlareID is what lets a single Terraform
apply create both sides.
