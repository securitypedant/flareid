# Testing against real applications

`e2e/compose.yml` stands FlareID up next to real products that consume its
OIDC, SAML, SCIM and LDAP surfaces. `e2e/real-apps.mjs` seeds the IdP (users,
groups, clients, SP registration) and writes the per-app config under
`e2e/state/`.

```sh
docker compose -f e2e/compose.yml up -d --build   # flareid + core OIDC apps
node e2e/real-apps.mjs                            # seed; writes e2e/state/
docker compose -f e2e/compose.yml restart oauth2-proxy grafana bookstack
```

Two issuers are in play: the **browser** reaches FlareID at
`http://localhost:8787` and the **app containers** reach it at
`http://flareid:8787` (compose network) — OIDC endpoints are therefore split:
browser-facing `auth_url` uses localhost, server-side `token`/`userinfo` calls
use `flareid:8787`. The issuer in tokens is `ISSUER_URL`; keep both URLs' host
reachable from the browser for redirects.

## OIDC consumers (core profile)

| App | URL | What it exercises | Login |
| --- | --- | --- | --- |
| oauth2-proxy | http://localhost:4180 | Discovery, auth-code flow, `id_token` validation, email/profile/groups claims, upstream header pass-through | any lab user |
| Grafana OSS | http://localhost:3000 | Generic OAuth plugin: discovery-lite manual endpoints, `userinfo` claims, `groups` claim → role mapping (`Grafana Admins` → Admin) | `grace` → Admin; `ada`/`linus` → Viewer |
| BookStack | http://localhost:6875 | Discovery-driven OIDC config, `groups` claim → role sync, JIT provisioning | `ada` gets `BookStack Editors` role |

All three are configured purely from `e2e/state/*.env` — re-running the seed
rotates client secrets and rewrites the files; `restart` the consumers.

## SAML SPs (`--profile saml`)

SAML needs two things the OIDC apps don't:

- **IdP signing secrets.** Pass `SAML_SIGNING_CERT` + `SAML_SIGNING_KEY_PKCS8`
  to the flareid service (`npm run saml:keygen` writes `.saml-*.pem` files —
  feed them via an env file or `-e` flags).
- **https ACS URLs.** FlareID refuses to register `http://` assertion consumer
  endpoints. The `saml` profile runs `caddy` with `tls internal` as an
  https-terminating proxy; trust its root CA once per browser:
  `docker compose -f e2e/compose.yml exec caddy cat /data/caddy/pki/authorities/local/root.crt`

| App | URL | What it exercises |
| --- | --- | --- |
| SimpleSAMLphp | https://localhost:8443/simplesaml | Canonical SP: IdP-initiated + SP-initiated SSO, attribute rendering, SLO |
| Zabbix web | (extras profile) | Native SAML login incl. JIT user creation via `username_attribute` |
| BookStack | flip `AUTH_METHOD` to `saml2` | onelogin/php-saml consumer — a second, independent SAML stack |

## SCIM

**Inbound** — FlareID is the service provider at `/scim/v2`, authenticated with
an API key carrying `directory:read`/`directory:write`. `scim2-tester` (PyPI)
is a real compliance harness:

```sh
pipx run scim2-tester --url http://localhost:8787/scim/v2 --header "Authorization: Bearer <lab-key>"
```

**Outbound** — FlareID pushes to registered targets
(`POST /api/v1/scim/targets`). Apache Syncope (`--profile scim`,
http://localhost:9080/syncope) is a real IdM with a SCIM service provider;
enable its SCIM extension per its docs, then register
`http://syncope:9080/syncope/scim` as a target and watch the next sync window.

## LDAP

FlareID is the LDAP server (see LDAP.md). Any LDAP client verifies it — the
quickest is `ldapsearch` from a debian container:

```sh
docker run --rm --network flareid-lab debian:bookworm-slim sh -c \
  "apt-get update -qq && apt-get install -y -qq ldap-utils >/dev/null && \
   ldapsearch -x -H ldap://flareid:389 -D '<service bind dn>' -w '<secret>' -b 'dc=example,dc=com'"
```

Heavier LDAP consumers in the matrix below (Gitea, Nextcloud, Jenkins) all
speak LDAP natively too.

## The wider matrix — manual / heavier

Container-friendly but not wired into compose yet (all documented upstream):

| App | Protocol | Notes |
| --- | --- | --- |
| Gitea | OIDC + LDAP | `gitea admin auth add-oauth` inside the container |
| Nextcloud | OIDC + SAML + LDAP | `extras` profile; enable `user_oidc` / `user_saml` / `user_ldap` apps |
| Vault | OIDC + LDAP | `extras` profile; `vault auth enable oidc` + CLI role mapping |
| Jenkins | OIDC + SAML | install `oic-auth` / `saml` plugins |
| MinIO | OIDC | env-configured console SSO |
| Keycloak | SAML + OIDC broker | FlareID as upstream IdP via identity brokering |
| Moodle | SAML2 plugin | another php-saml consumer |
| Apache APISIX / nginx | OIDC | gateway-level auth offload |

SaaS receivers that can't be containerized — a once-a-quarter manual pass with
free tiers is the practical coverage:

| Service | Protocol | Free path |
| --- | --- | --- |
| Okta | OIDC + SAML + SCIM-in | Integrator Free account |
| Microsoft Entra | SAML + SCIM-in | non-gallery app needs a P1 trial |
| Google Workspace | SAML + SCIM-in | 14-day trial |
| JumpCloud | SAML + OIDC | free up to 10 users |
| OneLogin | SAML + OIDC | developer account |
| Slack | SAML | needs a paid workspace |
| GitHub | SAML + SCIM-in | needs Enterprise Cloud EMU |
| Atlassian | SAML | needs Atlassian Access |

## What to verify per app (checklist)

1. **SSO in** — unauthenticated visit redirects to FlareID, password sign-in
   returns to the app logged in as the right user.
2. **Claims** — name/email land correctly; `groups` claim maps to app roles
   where supported (Grafana role attribute, BookStack role sync).
3. **JIT provisioning** — first login creates the user; attribute changes on
   the next login propagate.
4. **Logout** — app logout ends the FlareID session (or at least the app's);
   re-login requires fresh auth, not a cached assertion.
5. **Wrong-user denial** — a user outside the app's expected groups is handled
   sanely (denied or least-privilege role).
6. **Deprovisioning** — disable the user in FlareID → next login is refused;
   where SCIM is wired, the downstream account is disabled too.
