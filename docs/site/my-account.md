# Signing in and My account

This page covers what the people in your directory see, so you can support them.

## Signing in

People sign in at `/login` with their username or full UPN and their password, or with a passkey. Depending on their [authentication policy](policies.md), they're then asked for a second factor:

- a code from an authenticator app
- a single-use backup code
- a code sent by email
- answers to their security questions

A passkey counts as both steps at once. People can tick **Remember this device** to skip the second step on that browser for a while.

Forgot their password? The **Forgot your password?** link emails a reset link, once [email](email.md) is set up.

## My account

Everyone can manage their own account at `/account`:

| Page | What people can do |
|---|---|
| **Account** | Edit the profile fields their schema allows, and upload a photo. |
| **Applications** | A launchpad of the apps they may use — every app, or only the ones assigned to them or their groups when an app restricts access. Each app opens from its card. |
| **Security** | Change their password; set up an authenticator app, passkeys, email codes or security questions (a backup-code set is issued with the first factor); see active sessions, remembered devices and connected apps, and sign any of them out. |
| **Access** | See their groups, request access to requestable groups and applications from one picker, and manage groups they're a [manager](groups.md#group-managers) of. |

## When someone is locked out

From their page under **Users** you can:

- **Reset password**: set a new one, or generate one.
- **Send reset link**: email them a link to choose their own.
- **Reset MFA**: clear their authenticator, backup codes, email codes, security questions and remembered devices. They enrol again at next sign-in.
- **Sign out everywhere**: end all their sessions.

Too many failed attempts lock an account temporarily. The limit is under [Security settings](security.md#login-rate-limiting).
