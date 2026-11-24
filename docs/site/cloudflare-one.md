# Cloudflare One

Connect FlareID to your Cloudflare One (Zero Trust) account to share identity signals both ways: keep Gateway lists in step with the directory, use Cloudflare's risk scores at sign-in, and protect the admin console with Access.

For signing people in to Access applications, see [Cloudflare Access](cloudflare-access.md).

## Connect

1. In the Cloudflare dashboard, create an API token with **Zero Trust: Edit** on the account.
2. In FlareID, go to **Integrations → Cloudflare One**.
3. Enter the **Account ID** and **API token**, and save.

## List sync

FlareID can keep Cloudflare Gateway lists up to date, so Gateway and Access policies can use them. Tick the lists you want:

| List | Contents |
|---|---|
| **FlareID risk watchlist** | Email addresses of people on the risk watchlist. |
| **FlareID deprovisioned** | Email addresses of disabled accounts. |
| **FlareID managed domains** | Your UPN domains, for example as trusted senders in Email Security. |
| **FlareID sign-in failures** | IP addresses with repeated recent sign-in failures. |

You can also sync any group's members to a list: turn it on from the group's page under **Groups**. Lists update on the hourly schedule, or select **Sync now**.

## Access applications

FlareID can pull your account's Cloudflare Access applications (read-only — it never writes Access configuration). FlareID refreshes the mirror hourly (or on demand with **Sync applications now**). Map each app to the static group whose membership grants it:

- **Launchpad**: members of the granting group see the app on their **Applications** page, linked to its protected hostname.
- **Self-service**: switch **Requestable** on and people can ask for the app from **My account → Access**. An approved request simply adds them to the granting group — Access's own policies do the enforcement, so an Access policy should *Include* that group (or a reusable Access group containing it).

When a synced app's Allow policies already select a FlareID group — by IdP group claim (`groups`) or via a reusable Access group — the page names it as a suggestion under **Policies name**. Apps removed from the account drop out on the next sync, along with their pending requests - as does the whole mirror if the connection is re-pointed or disconnected.

This pairs naturally with [Cloudflare Access](cloudflare-access.md): FlareID stays the authority for who people are and which groups they belong to, and Access stays the authority for what they can reach.

## Risk watchlist

People on the watchlist are members of the **Risk watchlist** group, so you can sync it to a Cloudflare list or a SCIM target and tighten their inspection. People are added:

- by hand, from their page under **Users**
- automatically for 24 hours after a burst of failed sign-ins
- by a security signal from a trusted transmitter (see [Shared Signals](shared-signals.md))

Clear an entry from the watchlist on the **Cloudflare One** page.

## Sign-in checks

With the connection set up, an [authentication policy](policies.md) can also:

- **Cloudflare risk cap**: refuse sign-in when Cloudflare's user risk score is above *low* or *medium*. If the check can't run, sign-in isn't blocked.
- **Require a WARP device certificate**: only allow sign-in from devices that present a client certificate. This needs mTLS enforced on the zone.

## Protect the admin console with Access

Put the admin console behind a Cloudflare Access application, then enter your **Zero Trust team name** and that application's **Access application AUD**. From then on, every admin console page checks the Access token, and requests that bypass Access are refused.

> Open the console through the Access-protected hostname before saving, or you could lock yourself out.
