# Sign-in identifiers (design)

Status: agreed design, not yet implemented. Written after the run-5 security
audit; implementation follows it.

Today every account has a UPN (`local@domain`, unique) **and** a `username`
(the local part, unique across all domains so bare names always resolve to
exactly one account). That second uniqueness is the thing this design removes:
it forbids `simon@d1.com` and `simon@d2.com` coexisting, and it can't express
accounts whose identity isn't an email at all - a GitHub handle, or a phone
number.

## The model

`users.upn` stays the single UNIQUE canonical sign-in identifier, but its
grammar widens from "UPN only" to three shapes plus the federated-handle
convention:

| Form | Shape | Example | Minted by |
| --- | --- | --- | --- |
| UPN | `local@domain` | `simon@d1.com`, `simon@d2.com` | admin / API / CSV import; federated JIT verbatim (managed **or** unmanaged domain) |
| Native handle | `^[a-z0-9][a-z0-9._-]{1,63}$`, at least one non-digit | `simon` | admin / API / import; zero-domain deployments |
| Federated handle | `{handle}-{idp-slug}` | `simon-github`, `simon-gitlab` | social / federation JIT when the upstream identity is a bare handle |
| Phone | `^\+[1-9]\d{6,14}$` (E.164) | `+15551234567` | admin / API / import; SCIM |

So one directory can hold all of these at once:

```
simon            = native SSO account, no domain (or zero-domain install)
simon-github     = GitHub-federated account whose upstream handle is simon
simon-gitlab     = GitLab-federated account whose upstream handle is simon
simon@d1.com     = SSO account for d1.com
simon@d2.com     = SSO account for d2.com
+15551234567     = phone-number account
```

`users.username` loses its UNIQUE constraint (a table-rebuild migration, same
style as migration 0057 for `access_requests`). It keeps its meaning - the
local part / display short name - and becomes a *resolution candidate* rather
than a uniqueness invariant. Handle and phone accounts store `username = upn`.

The suffixed federated handle is **just a name, never parsed**. Nothing splits
`simon-dev-github` back into parts: provenance lives in
`federated_identities.idp_id`, a real foreign key. `-` is the separator
precisely because it carries no meaning to the system. The suffix is the
normalized name of the IdP record (`github`, `gitlab`, `acme-ad` for "Acme AD") -
not a hardcoded provider type - so enterprise IdPs get the same readable
provenance.

## Resolution

`getUserByLoginIdentifier` becomes shape-aware:

1. **`@`-form input** - exact `upn`, then `getUserByAnyEmail` (contact aliases
   still sign in). Unchanged.
2. **`+`-form input** - normalize to E.164 (strip spaces, dashes, parens;
   `+` required), exact `upn`, then a new `user_phones` table lookup.
3. **Bare input** - **exact `upn` first** (this is where handles resolve: the
   bare string `securitypedant` is literally the GitHub account's identifier,
   so it always wins its own name even when `securitypedant@company.com` and
   `securitypedant@partner.com` exist). Then `username` local-part candidates:
   - exactly one match - that user
   - more than one, or none - **resolve as "no user"** (see ambiguity below)

The same resolver serves LDAP binds (`uid=` goes through it instead of querying
`username` directly) and account recovery.

## Ambiguity: resolve to "no user"

When bare input has no exact identifier match and hits the local part of
multiple accounts (`simon@d1.com` + `simon@d2.com`, no handle `simon`), the
resolver returns *no account*. The sign-in then follows the existing
unknown-identifier path - dummy hash verification, identical generic "sign-in
failed" error, identical timing, the normal rate-limit key. It leaks nothing:
a colliding name is indistinguishable from a wrong password.

The one place the collision *is* visible is the server-side audit trail:
`login.failed` carries `reason: "ambiguous_identifier"` so an admin can see a
real user failing because their bare name collides, and tell them to use their
full address. No default-domain preference, no account chooser (a chooser
leaks which names exist).

Consequence worth documenting: a bare local part only signs in while it is
globally unique across handles **and** local parts. The moment a second
`simon@` exists, bare `simon` silently stops working and both users need their
full address. The audit reason is what makes that debuggable.

## Normalization and validation

New `lib/identifier.ts`:

```ts
parseIdentifier(raw) -> { kind: "upn" | "handle" | "phone", normalized }
```

Shape detection by first character class: `+` -> phone, contains `@` -> UPN,
else handle.

- **UPN**: lowercase; local part keeps the existing `USERNAME_PATTERN`; the
  domain must be a managed domain **for native accounts only**.
- **Handle**: `^[a-z0-9][a-z0-9._-]{1,63}$`, at least one non-digit, lowercase.
  All-digit bare names are reserved so a handle can never shadow a phone
  number. No `@`, no `+`.
- **Phone**: stored and matched in strict `+E.164` (`^\+[1-9]\d{6,14}$`).
  Input may carry spaces/dashes/parens and is stripped; no national-format
  guessing.

## Namespace and collision rules

- `upn` UNIQUE (the DB constraint covers all four shapes).
- UPN-form `upn` must not equal any `user_emails`/`users.email` row, and vice
  versa (existing clash checks, kept).
- New `user_phones` table mirroring `user_emails`: multiple E.164-normalized
  numbers per account, resolvable at sign-in like aliases; a phone row must not
  equal another account's `upn` or another account's phone row.
- Handle vs phone collision is structurally impossible (`+` is not a handle
  character; all-digit handles are refused).
- A federated handle that collides (`simon-github` already taken, or GitHub's
  own `simon-github` minting `simon-github-github`) falls to the standard
  collision policy.

## JIT minting (federation + social)

The managed-domain rewrite goes away for federated accounts:

- Upstream identity is `@`-form (email/UPN claim) -> mint it **verbatim**,
  even when the domain is unmanaged. The managed-domain rule only constrains
  native accounts; a federated UPN is a name, not an address we serve mail
  for. This is what lets `simonsmith01@gmail.com` (social) coexist with
  `simonsmith01@company.com` (native).
- Upstream identity is a bare handle (GitHub-style) -> mint
  `{handle}-{idp-slug}`. Every federated handle gets the suffix, so no
  first-come advantage and the account's source is readable in user lists and
  audit output. A GitHub user literally named `simon-github` mints
  `simon-github-github` - harmless, never parsed.
- Either form collides -> the existing collision policy (counter / pattern /
  refuse). `{idp}` becomes a pattern variable so policies can mint their own
  provenance shapes.
- `jit_domain` stays as the fallback when the profile supplies no usable
  identifier at all.

## Zero-domain deployments

A directory with no managed domains is just handles and phones - no special
mode. Every bare name is globally unique, so ambiguity can't arise and
sign-in UX is maximal. Degradations, all graceful:

- Recovery links, invitations and email OTP need a `user_emails` address;
  accounts without one see "no contact address" rather than silent failure.
- Domain-branded sign-in pages don't apply.
- Setup and the admin create form treat domains as optional.

## Write paths

- `createUser` / `updateUser` / CSV import gain an `identifier` input
  accepting any shape; `username` + `domain` remains the UPN shorthand. The
  uniqueness check becomes `upn = ?` (plus the email/phone clash checks).
- SCIM `userName` accepts all shapes; `user_phones` maps to the SCIM
  `phoneNumbers` attribute.
- `social.ts` providers mint handles (`{handle}-{provider}`) or verbatim UPNs.
- Admin UI: an identifier-type picker (UPN + domain dropdown when domains
  exist / handle / phone); "Username" labels become "Sign-in name".

## Perimeter notes

- **OIDC/SAML claims**: `preferred_username` keeps emitting `username`;
  `email` claims come from `users.email`/`user_emails` (a handle account can
  still assert an email). `sub`/`external_id` are already immutable UUIDs -
  nothing identity-critical keys on the mutable name.
- **LDAP**: attributed `uid=` binds follow the same resolver including the
  ambiguity-as-not-found rule; docs recommend UPN binds for multi-domain
  installs.
- **Dynamic group rules**: `username` now repeats across domains - rules
  needing precision should use `upn`.
- **`user_emails` clash check**: the `username` clause is dead (aliases are
  always `@`-form) - simplify to upn/email.

## Phasing

1. **Foundation** - `user_phones` table, username-UNIQUE-drop rebuild
   migration, `lib/identifier.ts`, resolver rewrite (+ audit reason), LDAP
   bind via the resolver, write paths, UI labels.
2. **JIT / social** - verbatim UPN minting, `{handle}-{idp}` minting,
   collision-policy `{idp}` variable.
3. **Polish** - phone sign-in UX, docs, optional later: home-realm discovery
   (identifier-first routing of federated-only accounts to their IdP) and an
   opt-in ambiguity chooser.

## Explicitly not in scope

- Phone as a *factor* (SMS OTP) - this is phone as identifier only.
- Interactive "which account?" chooser - enumeration risk; revisit only as an
  opt-in setting.
- National-format phone guessing - `+E.164` is required, no default country.
