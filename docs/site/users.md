# Users

The **Users** page lists everyone in the directory. Each person has a UPN they sign in with, a status, profile attributes, and group memberships.

## Add a user

1. Go to **Users → + New user**.
2. Enter a first name, last name and UPN. The domain list comes from [Domains](domains.md).
3. Choose a [schema](schemas.md) if you use more than one, and fill in any attributes.
4. Add them to static groups. Dynamic groups pick people up from their attributes automatically.
5. Choose how they get a password:
   - **Email them an invitation**: they choose their own password from a link. Needs [email](email.md).
   - **Set a password of your own**, or leave it blank to generate one.

New accounts start **inactive**. Activate them from their page once they're ready to sign in.

To add many people at once, see [Importing users](importing.md).

## Edit a user

Select a person to open their page. From there you can:

- edit their name, attributes and email addresses (people can sign in and recover with any address on their account; the primary one gets invitations and reset links)
- change their static groups, and see the dynamic groups their attributes put them in
- switch them between **Active** and **Inactive**
- **Reset password**, **Reset MFA** (their second factors), or **Send reset link**
- see their active sessions and connected apps, and **Sign out everywhere**
- view the **Raw record**: the user exactly as the API and SCIM see it

Fields marked *mastered by provisioning* are owned by an upstream system over [SCIM](scim.md#inbound-scim-server) and can't be edited here.

## Disable or delete

- **Inactive** stops sign-ins but keeps the account, its groups and its history. Use this when someone leaves.
- **Delete** removes the account, its group memberships and any tokens issued for it. It can't be undone.

Both are pushed to your [SCIM](scim.md) targets.

## Administrators

Administrator access comes from group membership: the **Super Admins** group, or a group with an [admin role](roles.md). Only a Super Admin can change an account that holds an admin role.
