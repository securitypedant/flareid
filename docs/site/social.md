# Social sign-in

Social sign-in puts **Continue with Google**, **Continue with GitHub** and other consumer-provider buttons on the sign-in page. Each provider is a normal [upstream provider](federation.md) under the hood — the same JIT provisioning, claim mappings and linked identities — with its protocol details already filled in.

Manage providers under **Integrations → Social sign-in**.

## Providers

| Provider | Protocol | Notes |
|---|---|---|
| Google | OIDC | Gmail and Google Workspace accounts. |
| Microsoft | OIDC | Set **Directory (tenant)** to restrict to one organisation, or leave `common` for any Microsoft account. |
| Apple | OIDC | Sign in with Apple. Instead of a client secret, provide the Team ID, Key ID and the Sign in with Apple **.p8 key** — FlareID signs the required client-secret JWT for each sign-in. |
| Facebook | OIDC | Facebook Login with OpenID Connect. |
| LinkedIn | OIDC | Needs the "Sign In with LinkedIn using OpenID Connect" product on the app. |
| Slack | OIDC | |
| Yahoo | OIDC | |
| Twitch | OIDC | |
| LINE | OIDC | |
| Salesforce | OIDC | For a My Domain org, edit the issuer on the provider's Federation page after setup. |
| GitLab | OIDC | gitlab.com, or a self-managed instance by editing the issuer. |
| GitHub | OAuth 2.0 | No OIDC — FlareID reads the profile, and the primary *verified* email when the profile hides it. |
| Discord | OAuth 2.0 | |
| X (Twitter) | OAuth 2.0 | X never returns an email address — accounts link by username, and JIT-provisioned accounts have no email. |

Any other OIDC or SAML provider can be added by hand under **Integrations → Federation**.

## Set up a provider

1. Register an OAuth app with the provider — its docs link is on the provider's page — using this redirect URI:
   `https://<your hostname>/federation/oidc/callback`
2. On the provider's page under **Integrations → Social sign-in**, enter the client ID and secret (or Apple's key material).
3. Optionally tick **Just-in-time provisioning** so people with no account here get one — see [how accounts are linked](federation.md#how-accounts-are-linked).
4. Save. The button appears on the sign-in page straight away.

## Disable or remove

Untick **Enabled** to hide the button without losing linked identities. **Remove** deletes the provider and forgets its links — the accounts themselves are kept.

## Claims and mapping

Each provider's sign-in claims run through the same [JIT mapping rules](mappings.md) as federation: **Flows → Federation sign-in**. The OAuth 2.0 adapters (GitHub, Discord, X) synthesize OIDC-shaped claims — `sub`, `name`, `preferred_username`, `picture`, and `email` where the provider offers one.
