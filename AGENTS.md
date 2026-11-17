# FlareID agent notes

## Deployment account

The live deployment is the `flareid-idp` worker in the **Cloudflare TME
Sandbox** account: `f36003e36a2151b8607ef11a5665e16a` (also in
`wrangler.jsonc` as the `CF_ACCOUNT_ID` var).

The deploy token can see multiple accounts. **Always set
`CLOUDFLARE_ACCOUNT_ID` explicitly on every wrangler command** — deploy,
`d1 execute`, `secret`, `tail` — or wrangler silently picks the first
account it can see, which is *Cloudflare Demo (TME)*
(`d6850012d250c1600028b55d1d879b16`). Deploys have already been lost to
that account once.

```sh
export CLOUDFLARE_ACCOUNT_ID=f36003e36a2151b8607ef11a5665e16a
npx wrangler deploy
npx wrangler d1 execute flareid-db --remote --file migrations/NNNN_*.sql
```

Sanity-check after deploying: `wrangler deployments list` should show the
new version under the TME Sandbox account.

## Verify

```sh
npx tsc --noEmit
npx vitest run test/ldap.test.ts   # LDAP only
npx vitest run                     # full suite (~4 min)
```

## Releasing

- Version lives in **two** places: `package.json` and `src/version.ts`
  (`VERSION`, rendered in the authenticated nav bar). Bump both — a test
  (`test/ui-feedback.test.ts`) keeps them equal. Releases are tagged
  (`v3.10.0`); changelog sections are `## [x.y.z] - YYYY-MM-DD`.
- Deploy only *after* the version bump is committed, or the live nav bar
  shows the previous version.

## Gotchas

- `workers.dev` (`flareid-idp.tmesandbox.workers.dev`) sits behind
  Cloudflare Access — direct curls return `403 error code: 1050`. Test
  through the configured custom domain / LDAP hostname instead.
- `scripts/deploy.mjs` intentionally rewrites `wrangler.jsonc` (D1/KV ids,
  name, issuer) — a dirty working tree after it runs is expected.
