# Demo deployment: Cloudflare-federated read-only admins

Stand up a fresh FlareID instance where **anyone who can pass your Cloudflare
Zero Trust tenant's login** (e.g. every `@cloudflare.com` identity) is
provisioned just-in-time into a group carrying a read-only admin role — they
can sign in and browse the whole console without changing anything.

Uses two features: inbound OIDC federation with JIT, and the provider's
**JIT groups** policy (v4.6.0+) — configured groups that provisioned accounts
join at creation. Write-capable role groups are refused at save time;
read-only ones are exactly what this demo is for.

## 1. Deploy the instance

```sh
npm install
export CLOUDFLARE_ACCOUNT_ID=<account>        # the account to deploy to
npx wrangler d1 create flareid-db            # copy the id into wrangler.jsonc
npx wrangler kv namespace create SESSIONS    # copy the id
npx wrangler deploy
npx wrangler d1 execute flareid-db --remote --file migrations/all.sql   # or each migration in order
```

Set the required secrets (`npx wrangler secret put ...`) and the issuer/custom
hostname per `docs/deploy.md`. Put the Worker on a public hostname in a zone
you control — federation callbacks need a stable URL. Optionally apply
`terraform/` for the WAF/API Shield edge (`docs/secure-edge.md`).

Open `https://<idp>/setup` and create the first Super Admin (that's you).

## 2. Cloudflare side — an Access for SaaS OIDC app

In **Zero Trust → Access → SaaS applications → Add application → OIDC**:

- **Redirect URL**: `https://<idp>/federation/oidc/callback`
- **Policy**: `Emails ending in @cloudflare.com` (or whatever identifies your
  team — an IdP group works too)
- Save; copy the **Client ID** and **Client secret**.

The app's OIDC issuer is
`https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<clientID>` —
it serves `/.well-known/openid-configuration` on that path, which is all
FlareID needs.

## 3. FlareID side

1. **Directory → Domains → + New domain** — add a domain for JIT usernames
   (e.g. `cf.demo`; it only mints `user@cf.demo` usernames — emails keep their
   real `@cloudflare.com` addresses).
2. **Directory → Groups → + New group** — `Demo Observers` (static, no rule).
3. **Security → Roles → + New role** — e.g. `Read-only Admin`. Tick **Read**
   on *every* permission area (leave every Write unticked), and keep **Sign
   in** ticked. Attach the `Demo Observers` group.

   With every Read granted, viewers see the *entire* console — every nav
   section, every page, dropdown and option, all directory data. The
   permission model gates on method: GET needs only `:read`, so nothing is
   hidden; every POST is refused with "Your role can view this but not
   change it." The only pages a non-Super Admin can never reach are writes
   anyway (`/admin/setup`, federation/transmitter/SCIM-target saves,
   `apply-to-all`).
4. **Integrations → Federation → + New provider → OIDC**:
   - **Name**: `Cloudflare`
   - **Issuer URL**: `https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<clientID>`
   - **Client ID** / **Client secret**: from step 2
   - **JIT provisioning**: on · **JIT domain**: `cf.demo`
   - **Groups JIT accounts join**: `Demo Observers`
   — saving validates that none of the JIT groups grant write roles.
5. Save. The sign-in page now shows **Continue with Cloudflare**.

## 4. What a coworker experiences

1. Opens `https://<idp>` → **Continue with Cloudflare** → your tenant's Access
   login (their normal corporate SSO).
2. Access returns them with email/name claims; FlareID provisions an account
   on the JIT domain, links the upstream identity, adds them to
   `Demo Observers`.
3. They land in `/account` and can open `/admin` — every area is visible,
   every write control is absent or refused (`*:read` permissions only).

## 5. Hardening notes

- **Admin-plane Access gate** (optional, recommended): set the Cloudflare One
  connection's **team + Access AUD** so `/admin` also requires a valid
  `CF_Authorization` JWT — nobody reaches the console without passing Access
  twice. (Integrations → Cloudflare One.)
- `workers.dev` stays behind Access as the ops backdoor.
- Read-only viewers can still *see* user data — demo on seeded/fake users,
  not a production directory.
- The JIT safeguard in `federation.ts` still refuses rule-matched admin
  groups; `jit_groups` is the only sanctioned JIT→role path, and only for
  read-only roles.

## Cleanup / teardown

Disable the provider to revoke future JIT sign-ins instantly; linked accounts
stay but lose the Access path. Delete the SaaS app in Zero Trust to cut the
upstream. `wrangler delete` removes the instance.
