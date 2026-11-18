# Deploy and first-time setup

FlareID runs as a single Cloudflare Worker with a D1 database and a KV namespace. A new deployment has no users and no default password: you create the first administrator yourself, with a one-time bootstrap token.

## Deploy

1. Select **Deploy to Cloudflare** on the [FlareID GitHub page](https://github.com/securitypedant/flareid) and sign in to Cloudflare.
2. Keep the suggested names for the Worker, D1 database and KV namespace, or choose your own.
3. Enter the two secrets, and keep a copy of both:
   - `BOOTSTRAP_TOKEN`: a long random string (`openssl rand -hex 32`). You enter it once, on the setup page.
   - `KEY_ENCRYPTION_KEY`: from `openssl rand -base64 48`. It encrypts the signing keys. **Never change it.**
4. Select **Deploy**.

Prefer a terminal? Clone the repository, then run `npm install` and `npm run deploy:cli`.

## Choose your hostname first

The address you complete setup on becomes the **issuer**, and every application trusts it from then on. If you want FlareID on your own hostname, such as `idp.example.com`, add it now: **Workers & Pages → your Worker → Settings → Domains & Routes → Add → Custom domain**.

> Some accounts protect every `*.workers.dev` hostname with Cloudflare Access. People must be able to reach the identity provider *before* they are signed in, so use a custom domain, or add an Access bypass for the hostname.

## Run setup

1. Open `https://<your hostname>/setup`.
2. Enter the bootstrap token, your primary domain (`example.com` gives people names like `ada@example.com`), and the first administrator's username, name and password.
3. Keep **Require a second factor for administrators** ticked.
4. Select **Create administrator and finish setup**, then sign in. You'll be asked to set up a second factor.

Once setup is complete, the bootstrap token stops working everywhere except the emergency administrator reset in the [API](api.md).

## Optional next steps

| Feature | What to do |
|---|---|
| Email (invitations, password recovery, email codes) | Onboard a sending domain, then set a From address. See [Email](email.md). |
| SAML | Run `npm run saml:keygen` and set the two secrets it prints. See [SAML apps](saml.md). |
| Bot protection | Turn on Turnstile under **Security**. See [Security settings](security.md). |
| Performance dashboard | Set the `CF_ACCOUNT_ID` variable and a `CF_ANALYTICS_TOKEN` secret. See [Monitoring](monitoring.md). |

## Workers plan

Password hashing uses about 100 ms of CPU per sign-in, which needs the Workers Paid plan. On the Free plan, set the `PASSWORD_HASHER` variable to `pbkdf2`.
