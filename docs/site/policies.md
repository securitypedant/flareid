# Policies and second factors

**Security → Policies** decides what each person must present to sign in. **Security → Factors** decides which second factors people can use.

## Authentication policies

A policy requires either:

- **Password (or a passkey)**, or
- **Password + second factor (or a passkey)**

A passkey satisfies every policy on its own, because it's already multi-factor.

Each policy applies to the groups you choose. Someone in several policies' groups gets the one with the lowest **Priority** number. Anyone not covered gets the **default** policy.

FlareID starts with two policies, *Password only* and *Password and a second factor*. On a fresh install, Super Admins are in the second one.

### Where a policy applies

A policy governs two things:

- **FlareID sign-in** — the built-in application everyone can log in to (the console and My account). Each person's policy resolves from their groups and the default.
- **Applications** — an app can bind a policy on its **Policies** tab (Applications → app → Policies). Signing in to that app then must satisfy the policy: a *second factor* requirement steps the session up, while a device-certificate or risk condition denies the sign-in outright. Bound apps appear in each policy's **Applies to** column next to its groups.

### Create a policy

1. Go to **Security → Policies**.
2. Under **New policy**, enter a name and choose what it **Requires**.
3. Set a **Priority** (lower wins) and pick the groups it applies to.
4. Optionally, with [Cloudflare One](cloudflare-one.md#sign-in-checks) connected, set a **Cloudflare risk cap** or **Require a WARP device certificate**.
5. Select **Create policy**.

> The Policies page warns you while any administrator can sign in with a password alone.

## Second factors

Turn factors on or off under **Security → Factors**:

| Factor | Notes |
|---|---|
| **Authenticator app** | Six-digit codes from an app such as 1Password, Google Authenticator or Authy. |
| **Passkeys** | Face ID, Touch ID, Windows Hello or a security key. Counts as both factors. |
| **Backup codes** | Single-use recovery codes shown once and stored as hashes. A user can hold them on their own or next to other factors. |
| **Email one-time code** | A six-digit code by email. Needs [email](email.md). Off by default. |
| **Security questions** | The weakest option. Never accepted for administrators. Off by default. |

Turning a factor off stops it counting toward a policy and hides it from My account. FlareID won't let you turn off the last factor a policy depends on.

For security questions, set **Questions each person sets** and **Questions asked at sign-in**, and manage the list of questions people choose from.

## What people see

When a policy requires a second factor and someone hasn't set one up, they're asked to set one up the next time they sign in. People manage their factors under **My account → Security**. See [My account](my-account.md).

To clear someone's factors, use **Reset MFA** on their page under [Users](users.md).
