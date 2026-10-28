# Contributing

Thanks for looking. A few things worth knowing before you spend time on a
change.

## What this project is, and is not

FlareID is a small OIDC identity provider for Cloudflare Workers. It was built
because workshops and demos need a real identity provider and often cannot have
one, and it is being made genuinely deployable rather than only demonstrable.

[ROADMAP.md](ROADMAP.md) is the honest version: what works, what is missing,
and a short list of things that are deliberately out of scope - self-service
signup, nested groups, multi-tenancy, and several SAML bindings nobody deploys.
If your change is on that out-of-scope list, please open an issue first rather
than a pull request; the reasoning is recorded there and I would rather discuss
it than reject working code.

The P0 section is where help is most useful.

## Getting set up

```bash
npm install
npm run keygen                     # once
npm run db:migrations:local
npm run dev                        # http://localhost:8790
```

`.dev.vars` (gitignored):

```
COOKIE_ENCRYPTION_KEY=<any random string>
SIGNING_KEY_PKCS8="<private key PEM from npm run keygen>"
BOOTSTRAP_TOKEN=<any random string>
```

A fresh database has no users, so create the first administrator through the
API - see [docs/api.md](docs/api.md).

## Before you open a pull request

```bash
npm run typecheck     # src and test
npm test
```

Both run in CI along with a `wrangler deploy --dry-run`, which catches the
thing a typecheck cannot: a module that does not bundle for the Workers
runtime.

**New behaviour needs a test.** This project went a long time with none, and
that is the single biggest reason not to trust it; please do not add to the
pile. The suite runs inside the Workers runtime against a local D1 migrated
from the real migration files, so a test can exercise the whole Worker end to
end - see `test/oidc.test.ts`, which drives a full authorization-code flow and
verifies the resulting `id_token` against `/jwks.json`.

## House style

A couple of conventions that are not obvious from the code:

**Comments explain why, not what.** There are some long ones. They are long
because they record a decision or a failure that cost something to find - the
ordering constraint on `complete` in the provisioning API, or why
`resetDatabase` drops tables in reverse creation order. If you remove a comment
like that, the next person re-learns it the hard way. If you find one that is
now wrong, fixing it is as valuable as fixing code.

**Migrations are append-only.** The chain was squashed once, deliberately and
disruptively, to get a workshop's seed data out of it (see
[docs/upgrading.md](docs/upgrading.md)). That is not a thing to do again. Add a
new numbered file.

**No seed data, and no default credentials.** A deployment starts empty on
purpose. Anything that needs sample users should go through the provisioning
API, not a migration.

**Prose in docs uses ` - ` rather than em dashes**, to match what is already
there.

## Commits and pull requests

Small, focused commits with messages that say why. A pull request description
that explains the problem is worth more than one that lists the files changed.

If a change affects how a deployment is operated - a new secret, a new setting,
a migration - please update the relevant doc in the same pull request.

## Licence

By contributing you agree that your contribution is licensed under the Apache
License 2.0, the same as the rest of the project. There is no CLA.
