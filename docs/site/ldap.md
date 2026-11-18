# LDAP

FlareID can serve the directory over LDAP, for applications that only speak LDAP, such as Grafana, GitLab, Jenkins, sssd or network devices. It's read-only and LDAPS-only (TCP 636, and the Global Catalog on 3269).

Each application gets its own service account and its own view of the directory, with its own rules for who can sign in.

## Before you start

LDAP traffic reaches the Worker through Cloudflare Spectrum. You need:

- a Spectrum plan with Worker origins enabled on your account
- a hostname for LDAP, such as `ldap.example.com`, with an Advanced or custom edge certificate (Universal SSL doesn't work with Spectrum)
- a Spectrum application on `tcp/636` (and optionally `tcp/3269`) with your FlareID Worker as the origin and TLS set to *flexible*

## Turn on LDAP

1. Go to **Integrations → LDAP**.
2. Select **Enable LDAP**.
3. Check the **Hostname** (your Spectrum hostname) and the **Base DN**, such as `dc=example,dc=com`, and select **Save settings**.

Changing the base DN later changes every bind DN, so set it once.

## Add an LDAP app

1. Select **+ New LDAP app**.
2. Enter a **Name** and a **Slug**, such as `grafana`. The slug becomes part of every DN for this app and can't be changed.
3. Choose who the app sees:
   - **Bindable users**: members of these groups can sign in and are visible. Leave empty for everyone.
   - **Exposed groups**: the groups the app can see. Leave empty for all.
4. Choose the **Second factor**:
   - **Password only**
   - **Password + OTP when the user has one** (recommended)
   - **Always password + OTP**
5. Select **Create LDAP app**, then copy the secret. It's shown only once.

The next page lists the connection details, and ready-made configs for ldapsearch, Grafana, sssd, GitLab and Jenkins.

## Connection details

| Setting | Value |
|---|---|
| Server | `ldaps://<hostname>:636` |
| Bind DN | `cn=<slug>,ou=services,<base DN>` |
| User search base | `ou=people,ou=<slug>,<base DN>` |
| Group search base | `ou=groups,ou=<slug>,<base DN>` |
| User filter | `(&(objectClass=inetOrgPerson)(uid=%s))` |

## Signing in with a second factor

When an app requires a one-time code, people type it after their password, separated by a comma: `password,123456`.

## Managing apps

On an app's page you can change who it sees, **Reveal secret**, **Rotate secret** (the old one stops working straight away), or **Revoke app**.
