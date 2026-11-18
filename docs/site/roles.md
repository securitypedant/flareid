# Admin roles

Roles decide what administrators can see and do in the admin console. A role is a set of permissions, given to one or more groups. Everyone's access is the **default role** plus the roles of their groups.

Manage roles under **Security → Roles**.

## Built-in roles

| Role | Can do |
|---|---|
| **User** (default) | Sign in and manage their own account. Applies to everyone. |
| **Super Admin** | Everything, including roles, security settings and API keys. Held by the **Super Admins** group, and can't be changed. |
| **Directory Admin** | Users, groups, domains, schemas and CSV import. |
| **Application Admin** | OIDC clients, SAML apps, SCIM provisioning and email. |
| **Auditor** | Read-only access to the directory, integrations, the overview and the log. |

## Create a role

1. Go to **Security → Roles → + New role**.
2. Enter a name and description.
3. Under **Permissions**, choose **Read** or **Write** for each area. Write includes read.
4. Under **Granted to**, pick the groups that get the role.
5. Save.

To make someone an administrator, add them to a group that has a role.

## Permission areas

| Group | Areas |
|---|---|
| Directory | Users, Groups, Domains, Schemas, Import and reset |
| Applications | OIDC clients, SAML apps, SCIM provisioning, LDAP apps, Federation, Email, Cloudflare One, Shared signals |
| Platform | API keys, Security settings and policies, Branding, Signing keys, Roles |
| Monitoring | Log, Overview and performance (read only) |

[API keys](api.md#api-keys) use the same permissions.

## Safeguards

- Only a Super Admin can change an account or group that holds an admin role, so nobody can promote themselves.
- The **Administrators** card on the Roles page lists everyone with more than the default role, what they can do, and whether they have a second factor.
