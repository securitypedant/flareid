# Upgrading

FlareID is upgraded by deploying a newer version of the code. Database changes are applied automatically as migrations.

## Deployed with the button

Your copy of FlareID lives in a GitHub or GitLab repository in your account, and Cloudflare redeploys it on every push.

1. Pull the latest changes from the [FlareID repository](https://github.com/securitypedant/flareid) into your copy (for example with GitHub's **Sync fork**, or `git pull upstream main`).
2. Push. The build applies the migrations and deploys.

## Deployed from a terminal

```sh
git pull
npm install
npm run deploy
```

`npm run deploy` applies any new migrations, then deploys the Worker.

## Before you upgrade

- [Take a backup](backup.md).
- Read the changelog for the versions between yours and the new one. The version you're running is shown in the admin console's top bar.
- Never change `KEY_ENCRYPTION_KEY`.

## After you upgrade

Check the version in the top bar, sign in, and look at the [audit log](monitoring.md#audit-log) and Worker logs for errors.
