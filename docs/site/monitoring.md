# Monitoring and the audit log

FlareID shows how it's being used on the **Overview**, and records every sign-in and change in the **Log**.

## Overview

The **Overview → Dashboard** shows, for the last few weeks:

- successful sign-ins per day, and sign-in outcomes (success, wrong password, locked out)
- the most active accounts
- directory activity: users and groups created, changed or deleted
- posture: how many people have a second factor, plus SCIM failures and queued deletions

## Performance

**Overview → Performance** shows request volume, errors and latency for every endpoint, a live view of the last 30 minutes, and where the time goes inside requests.

To turn it on:

1. Create a Cloudflare API token with **Account Analytics: Read**.
2. Set it as the `CF_ANALYTICS_TOKEN` secret on the Worker, and set the `CF_ACCOUNT_ID` variable to your account ID.

## Audit log

**Log** lists everything that happened, newest first: sign-ins, admin changes, self-service changes, API calls, token grants, SCIM syncs and LDAP binds. Each entry records who did it, what they changed, when, and from which IP address.

- **Filter** by category (such as Sign-ins, Users or API requests), by who did it, by date, or by text.
- **Export** downloads the filtered entries as NDJSON, ready for a SIEM. The API can also export CSV.
- **Verify integrity** checks the log hasn't been tampered with. Each entry is chained to the one before it, so a deleted or edited entry shows up.

Entries are kept for the number of days set under [Security settings](security.md#audit-log-retention).

## Alerts and health checks

- Point an uptime monitor at `GET /health`. It returns `200` when the Worker is running.
- Set up Cloudflare notifications (**Notifications → Add**) for Worker errors and usage spikes.
- Worker logs are on by default under **Workers & Pages → your Worker → Logs**. Scheduled jobs log a message when they fail.
