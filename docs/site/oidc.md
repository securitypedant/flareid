# OIDC clients

An OIDC client is an application that signs people in with FlareID over OpenID Connect, such as Cloudflare Access, a web app or a mobile app. Manage them under **Applications** (see [the applications page](applications.md)).

## Register a client

1. Go to **Applications → New OIDC client**.
2. Enter a name, and choose the client type:
   - **Confidential**: a server that can keep a secret, such as Cloudflare Access or a web backend.
   - **Public**: a single-page or native app. It has no secret and must use PKCE.
3. Add the app's **Redirect URIs**, one per line. They must match exactly what the app sends.
4. Select **Create client**, then copy the **Client ID** and **Client secret**. The secret is shown only once.

The client's page lists the URLs the app needs, each with a copy button.

## Settings

| Setting | What it does |
|---|---|
| **Redirect URIs** | Where FlareID may send people after sign-in. |
| **Post-logout redirect URIs** | Where FlareID may send people after the app signs them out. |
| **ID token signing algorithm** | `RS256` works everywhere. Choose `ES256` only if the app supports it. |
| **Front-channel logout URI** | Loaded in a hidden frame when someone signs out, so the app can end its session too. |
| **Restrict to groups** | Only members of the chosen groups see the app on their My account launchpad and may sign in to it. Empty means everyone. |
| **Trusted first-party app** | Skips the consent screen. Untick it for third-party apps. |
| **Claims this app may receive** | Limits what the app can learn about people. |

Lost the secret? Use **Rotate secret** on the client's page. The old secret stops working straight away.

## Endpoints

Most apps only need the issuer URL and find everything else automatically:

| Endpoint | URL |
|---|---|
| Issuer | `https://<your hostname>` |
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/authorize` |
| Token | `/token` |
| UserInfo | `/userinfo` |
| Signing keys (JWKS) | `/jwks.json` |
| Logout | `/oidc/logout` |

## Claims

An app receives a claim only when it asks for the scope **and** the client is allowed it:

| Scope | Claims |
|---|---|
| `openid` | `sub` (always required) |
| `email` | `email`, `email_verified` |
| `profile` | `name`, `given_name`, `family_name`, `preferred_username`, `job_title`, `department`, `manager`, `employee_number`, and `custom` for your own [schema](schemas.md) attributes |
| `groups` | `groups`: the names of the person's groups |
| `address`, `phone` | `address`; `phone_number` |
| `offline_access` | A refresh token, so the app can stay signed in |

## Troubleshooting

- **"redirect_uri is not registered"**: the app sent a redirect URI that isn't on the client exactly, including the path and trailing slash.
- **No groups in the token**: the app must request the `groups` scope, and **Group memberships** must be ticked under **Claims this app may receive**.
- **People see a consent screen**: tick **Trusted first-party app**.
- **People are asked for a code they don't have**: their [authentication policy](policies.md) requires a second factor.
