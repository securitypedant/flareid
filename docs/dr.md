# Backup, restore and disaster recovery

Everything FlareID owns lives in one D1 database (KV holds only short-lived
login state; Worker secrets hold deploy-time material). A backup is therefore
one JSON file, and a restore is a redeploy plus one API call.

## What's in a backup

`GET /api/v1/backup` returns `{ version: 1, at, tables: { name: [rows] } }` -
every table except the migration ledger, including:

- users, credentials, groups, sessions, signing keys, settings
- encrypted secrets (SCIM/API tokens, SMTP, Cloudflare One) - still encrypted
  under `KEY_ENCRYPTION_KEY`, useless without it
- password hashes - **treat the bundle like the database itself**

The endpoint needs an `admin`-permission API key (or the bootstrap token) and
audits every download (`backup.exported`). Curl it:

```sh
curl -H "Authorization: Bearer $KEY" https://idp.example.com/api/v1/backup -o backup.json
```

## Scheduled snapshots (optional)

Uncomment `r2_buckets` in `wrangler.jsonc`, create the bucket and redeploy:

```sh
wrangler r2 bucket create flareid-backups
npm run deploy
```

The hourly cron writes `backups/YYYY-MM-DD.json` once a day (idempotent -
re-runs skip a day that already has an object). Retention is a bucket
lifecycle policy in the R2 console if you want one.

## Restoring

On the target deployment (fresh or existing):

1. **Deploy the same version and apply migrations.** `wrangler d1 migrations
   apply flareid-db --remote`. A bundle from a newer schema is refused -
   restore validates every table and column *before* deleting anything.
2. **Set the secrets** the deployment needs (`BOOTSTRAP_TOKEN`,
   `KEY_ENCRYPTION_KEY`, SAML keys if used). `KEY_ENCRYPTION_KEY` must be the
   *same* value as the source, or every encrypted secret restores unreadable.
3. **Restore:**

```sh
curl -X POST -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq '. + {confirm: true}' backup.json)" \
  https://idp.example.com/api/v1/backup/restore
```

`confirm: true` is required - restore **wipes every table** on the target
(even ones the bundle doesn't mention) and rewrites it. It returns
`{ ok, restored, tables }` and audits itself (`backup.restored`).

## DR checklist

| Failure | Recovery |
| --- | --- |
| Worker deleted/broken | Redeploy; D1 is untouched. |
| D1 data lost/corrupted | Fresh D1 → apply migrations → restore latest bundle. |
| Wrong region / whole account loss | New account: deploy, set secrets, restore bundle. RTO = deploy + one POST. |
| `KEY_ENCRYPTION_KEY` lost | All encrypted secrets must be re-entered; users must reset passwords is **not** needed (hashes are unencrypted) but SCIM/API/SMTP credentials are unrecoverable. |
| `BOOTSTRAP_TOKEN` lost | Set a new one (`wrangler secret put`); it's the only thing that gates restore and break-glass admin reset. |

RPO is one day with the R2 binding, or whenever you last pulled
`/api/v1/backup` without it. For a tighter RPO, call the endpoint on a
schedule from wherever you keep backups - it's a plain GET.
