# Backup and restore

Everything FlareID stores lives in one D1 database, so a backup is one JSON file and a restore is one API call.

> A backup contains password hashes and encrypted secrets. Store it as carefully as the database itself.

## Take a backup

Use an [API key](api.md#api-keys) with `admin` permission:

```sh
curl -H "Authorization: Bearer $KEY" https://idp.example.com/api/v1/backup -o backup.json
```

Every download is recorded in the [audit log](monitoring.md#audit-log).

## Scheduled backups

To keep a daily copy in R2:

1. Create a bucket: `npx wrangler r2 bucket create flareid-backups`.
2. Uncomment the `r2_buckets` section in `wrangler.jsonc` and redeploy.

FlareID writes `backups/YYYY-MM-DD.json` once a day. Use an R2 lifecycle rule to delete old copies.

## Restore

Restoring **replaces everything** in the target database.

1. Deploy the same FlareID version and apply the database migrations.
2. Set the Worker secrets. `KEY_ENCRYPTION_KEY` must be the **same** as the original, or stored secrets can't be read.
3. Send the backup with the bootstrap token and `confirm: true`:

```sh
curl -X POST https://idp.example.com/api/v1/backup/restore \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq '. + {confirm: true}' backup.json)"
```

## Recovery checklist

| Problem | Fix |
|---|---|
| Worker deleted or broken | Redeploy. The database is untouched. |
| Database lost or corrupted | Create a new database, apply migrations, restore the latest backup. |
| Locked out of every admin account | Use the emergency administrator reset in the [API](api.md#emergency-access) with the bootstrap token. |
| `BOOTSTRAP_TOKEN` lost | Set a new one with `npx wrangler secret put BOOTSTRAP_TOKEN`. |
| `KEY_ENCRYPTION_KEY` lost | Passwords still work, but stored credentials, such as SCIM secrets and the Cloudflare One API token, must be entered again. |
