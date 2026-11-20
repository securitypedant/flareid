# Cloudflare Access

This guide adds FlareID as an identity provider in Cloudflare Zero Trust, so people sign in to Access applications, Gateway and the Cloudflare One Client with their FlareID account and groups.

Replace `<flareid>` with your issuer URL (such as `https://idp.example.com`), and `<team>` with your Zero Trust team name.

## 1. Create the client in FlareID

1. Go to **Applications → New OIDC client** (or pick **Cloudflare Access** from **Applications → App catalog** to have the fields prefilled).
2. Fill in:
   - **Name**: `Cloudflare Access`
   - **Client type**: Confidential
   - **Redirect URIs**: `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`
   - **Trusted first-party app**: ticked
   - **Claims this app may receive**: email, name and group memberships
3. Select **Create client**, and copy the **Client ID** and **Client secret**.

## 2. Add FlareID in Cloudflare

1. In the Cloudflare dashboard, go to **Zero Trust → Integrations → Identity providers → Add new → OpenID Connect**.
2. Fill in:

   | Cloudflare field | Value |
   |---|---|
   | **App ID** | The Client ID |
   | **Client secret** | The Client secret |
   | **Auth URL** | `<flareid>/authorize` |
   | **Token URL** | `<flareid>/token` |
   | **Certificate URL** | `<flareid>/jwks.json` |
   | **PKCE** | On |
   | **Scopes** | `openid email profile groups` |
   | **OIDC Claims** | `groups` |

3. Select **Save**, then **Test**. The test page should show the person's email, name and groups.

## 3. Use it in policies

Enable FlareID as a login method on your Access applications. In a policy, match on **Emails**, or on **OIDC Claims** with the claim name `groups` and a FlareID group name.

## 4. Optional: provision with SCIM

SCIM keeps Cloudflare's user list in step with FlareID: new people appear, and people you disable lose access straight away.

1. In Cloudflare, edit the FlareID identity provider, turn on **Enable SCIM** and **Enable user deprovisioning**, and copy the **SCIM Endpoint** and **SCIM Secret**.
2. In FlareID, go to **Integrations → SCIM provisioning → + New target** and paste them.
3. Select **Test connection**, then **Sync all now**.

See [SCIM provisioning](scim.md) for scope and tuning.

## Also see

- [Cloudflare One](cloudflare-one.md): sync gateway lists, check device posture and risk scores at sign-in, and protect the admin console with Access.
- [SAML apps](saml.md): use SAML with Access instead of OIDC.
