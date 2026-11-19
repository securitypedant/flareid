# End-to-end testing

Three layers, fastest first:

| Layer | Command | What it proves |
| --- | --- | --- |
| Vitest (in-runtime) | `npm test` | Services, routes and middleware against local D1 — the unit/integration suite |
| Container smoke | `node e2e/smoke.mjs` | The real HTTP surface: bootstrap, setup, login UX, a full OIDC flow, audit chain, backup, SSF |
| Real browser | `node e2e/ux.spec.mjs` | Rendering and interaction in Chromium |
| Real apps | `e2e/compose.yml` | Third-party products consuming FlareID — see [real-apps.md](real-apps.md) |

## The e2e container

`e2e/Dockerfile` packages the Worker exactly as it deploys: `wrangler dev`
serves it on port 8787 against a local D1 with every migration applied, local
KV, and throwaway secrets generated at boot.

```sh
docker build -f e2e/Dockerfile -t flareid-e2e .
docker run --rm -p 8787:8787 flareid-e2e
```

Knobs (env on `docker run`):

- `BOOTSTRAP_TOKEN` — defaults to `e2e-bootstrap-token`.
- `SAML_SIGNING_CERT` / `SAML_SIGNING_KEY_PKCS8` — PEM strings; without them the
  SAML endpoints answer 503. Generate a pair with `npm run saml:keygen` (it
  writes `.saml-cert.pem` / `.saml-key.pem`) and pass them with `--env-file`.
- `PORT` — dev-server port inside the container.

Mount a volume on `/app/.wrangler` to keep D1/KV state across restarts;
without one every run starts empty.

## Smoke test

`e2e/smoke.mjs` is a zero-dependency driver over plain `fetch`. Against a fresh
container it runs the whole product once:

bootstrap → `POST /api/v1/setup` → create users/groups → browser-style login
for a user and the admin (real `flow_id` scrape, form POST, session cookie) →
admin console pages → OIDC discovery → register a client → `authorization_code`
→ `token` → `userinfo` → `introspect` → audit-chain verify + export → backup →
SSF discovery + stream registration.

```sh
node e2e/smoke.mjs                      # 26 checks, exits non-zero on failure
BASE=http://localhost:9999 node e2e/smoke.mjs
```

It also runs against `npm run dev` or a deployed instance (set `BASE` and
`BOOTSTRAP_TOKEN` accordingly; on a deployed instance the bootstrap token is
already retired, so mint a key beforehand or run setup first locally).

## Browser test

`e2e/ux.spec.mjs` drives real Chromium — a starter spec covering the login
card, both user roles, and locale switching:

```sh
npm i -D playwright && npx playwright install chromium
node e2e/smoke.mjs   # first, so the users exist
node e2e/ux.spec.mjs
```

## Third-party RP check

`e2e/proxy-check.mjs` drives the compose lab's oauth2-proxy leg end to end —
unauthenticated request to the protected upstream, bounce through FlareID's
sign-in, and back to the upstream asserting it received
`X-Forwarded-Email`/`X-Forwarded-Groups`. Needs the lab up and seeded:

```sh
docker compose -f e2e/compose.yml up -d flareid
node e2e/smoke.mjs && node e2e/real-apps.mjs
docker compose -f e2e/compose.yml up -d oauth2-proxy whoami
node e2e/proxy-check.mjs
```

## In CI

The `e2e` job in `.github/workflows/ci.yml` runs all of the above on every
push and pull request: container build → smoke → Chromium spec → lab seed →
oauth2-proxy flow. `smoke.mjs` saves its minted admin key to
`e2e/state/lab-key.json` so `real-apps.mjs` can reuse it after `/setup`
retires the bootstrap token.

The dispatch-only `integration-verification` workflow runs the same battery
plus the heavier legs: the `saml` profile with real generated signing material
(caddy + SimpleSAMLphp) and **SCIM Verify** (`e2e/scim-verify-run.mjs`, config
`e2e/scim-verify.config.yaml`, declared divergences in
`e2e/scim-verify-expected.txt`). Run it from the Actions tab when protocol
code changes or before a release.

## Caveats

- `wrangler dev` prints `Unable to fetch the Request.cf object` behind some
  proxies; it falls back to a placeholder — harmless, but `cf.tlsClientAuth`
  policy conditions will see `certVerified: "NONE"`.
- Miniflare stubs outbound fetch targets (`api.pwnedpasswords.com`, the CF API,
  Access JWKS); nothing real leaves the box.
- The container uses `PASSWORD_HASHER=pbkdf2`; argon2id works too — override if
  you want to exercise it.
