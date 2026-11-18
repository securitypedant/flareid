# FlareID documentation

FlareID is an identity provider that runs on Cloudflare Workers. It signs people in to your applications with OpenID Connect, SAML or LDAP, keeps a directory of users and groups, and pushes that directory to other systems with SCIM.

These guides are for the IT administrators who run it. Each one covers what a capability does and how to set it up from the admin console at `/admin`.

## Where to start

1. [Deploy FlareID and run first-time setup](deploy.md).
2. Add people: [create them one by one](users.md), or [import a CSV](importing.md).
3. Connect an application: [OIDC](oidc.md), [SAML](saml.md) or [LDAP](ldap.md). Using Cloudflare Zero Trust? Follow [Cloudflare Access](cloudflare-access.md).
4. Decide how people sign in: [authentication policies and second factors](policies.md).

## What FlareID does

| Capability | What it gives you |
|---|---|
| [Users](users.md) and [groups](groups.md) | A directory with HR attributes, static and rule-based groups, group managers and access reviews. |
| [OIDC](oidc.md) and [SAML](saml.md) | Single sign-on for web apps, Cloudflare Access and SaaS. |
| [LDAP](ldap.md) | A read-only LDAPS directory for apps that only speak LDAP. |
| [SCIM](scim.md) | Push users and groups to other systems, or let an HR system provision FlareID. |
| [Federation](federation.md) | Let people sign in through another identity provider such as Entra ID or Okta. |
| [Policies](policies.md) | Per-group sign-in rules: passwords, authenticator apps, passkeys, email codes. |
| [Branding](branding.md) | Your logo, colours and wording, per email domain. |
| [Provisioning API](api.md) | Everything the console does, over a JSON API. |

## Key terms

- **UPN**: a person's sign-in name, such as `ada@example.com`. The part before `@` is their *username*, unique across every domain.
- **Issuer**: the URL FlareID identifies itself as, such as `https://idp.example.com`. Applications trust it, so it never changes after setup.
- **Admin console** (`/admin`): where administrators manage everything. What each administrator can see depends on their [role](roles.md).
- **My account** (`/account`): where people manage their own password, second factors and sessions. See [My account](my-account.md).

> Every page in the admin console has a **?** link next to its title that opens the matching guide here.
