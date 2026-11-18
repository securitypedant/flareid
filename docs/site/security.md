# Security settings

**Security → Settings** holds the instance-wide rules for passwords, sessions and sign-in attempts. Rules about *what people must present* to sign in are per group, under [Policies](policies.md).

## Passwords

| Setting | What it does |
|---|---|
| **New account password** | What a new account, or a manual reset, gets: the **default password**, or a **randomly generated** one. Random is safer. |
| **Default password** | The password used when the setting above is *default*. **Apply default password to all accounts** resets every account to it, so use it with care. |
| **Password complexity policy** | Minimum length, and whether uppercase, lowercase, numbers and symbols are required. |
| **Breached passwords** | Refuses passwords found in known data breaches (Have I Been Pwned), without sending the password anywhere. On by default. |

## Bot protection (Turnstile)

Cloudflare Turnstile checks that a person, not a script, is using the password sign-in and password-recovery forms.

1. In the Cloudflare dashboard, create a Turnstile widget for your FlareID hostname.
2. Enter its **Site key** and **Secret key**, and turn protection on.

Passkey sign-in is never challenged.

## Session limits

- **Maximum session length (hours)**: how long a sign-in lasts, however active someone is.
- **Sign out after inactivity (minutes)**: how long a session can sit idle.

## Login rate limiting

Locks out an account from an IP address after too many failed password or code attempts. The default is 5 attempts in 15 minutes. People can try again once the window has passed.

**Edge flood limits** also cap requests per IP address to every page that doesn't need sign-in. They're set in the Worker's configuration.

## Audit log retention

How many days to keep [audit log](monitoring.md#audit-log) entries. Older entries are deleted by the hourly cleanup.

## Re-authentication

Sensitive actions in the admin console, such as changing security settings or resetting someone's credentials, ask you to confirm your password and second factor if you haven't signed in recently. What you were doing then carries on.
