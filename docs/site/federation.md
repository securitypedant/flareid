# Federation

Federation lets people sign in to FlareID *through* another identity provider, such as Entra ID, Okta or Google Workspace. Each provider gets a **Continue with ...** button on the sign-in page. FlareID still issues the tokens your applications receive, and still applies groups, branding and SCIM.

Manage providers under **Integrations → Federation**.

## Add an OIDC provider

1. In the upstream provider, register an app with this redirect URI: `https://<your hostname>/federation/oidc/callback`. Copy its client ID and secret.
2. In FlareID, go to **Integrations → Federation → + New provider** and choose OIDC.
3. Enter:
   - **Name**: shown on the button, such as `Entra ID`
   - **Issuer URL**: the provider's issuer, such as `https://login.microsoftonline.com/<tenant>/v2.0`
   - **Client ID** and **Client secret**
   - **Scopes** (optional): the default is `openid profile email`
4. Select **Create provider**.

## Add a SAML provider

1. In FlareID, go to **Integrations → Federation → + New provider** and choose SAML.
2. Enter the provider's **SSO URL (HTTP-Redirect)** and **Signing certificate**, and optionally its entity ID and NameID format.
3. Select **Create provider**. The provider's page shows FlareID's **SP entity ID** and **ACS URL**.
4. In the upstream provider, register FlareID as a SAML app with that entity ID and ACS URL.

## How accounts are linked

The first time someone signs in through a provider, FlareID links their upstream identity to an account:

- **By email address**: if an active account here has the same address, it's linked.
- **Just-in-time provisioning**: if ticked, someone with no account here gets one, on the **JIT domain** (or their email domain, if it's one of yours).
- Otherwise, sign-in is refused.

After that, they always land on the same account. The provider's page lists **Linked identities** and when each last signed in.

## Disable a provider

Untick **Enabled** to remove the button from the sign-in page without losing the links.
