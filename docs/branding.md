# Branding

Admin → Branding sets how the pages people sign in through, and the email they
get, look. Everything here has an API twin under `/api/v1/branding` (see
[api-reference.md](api-reference.md#branding)); `branding:read` sees it,
`branding:write` changes it.

## The default brand and per-domain brands

The **default brand** is Branding → Settings: the app name, the sign-in
message, the sign-in gradient, the logo, the custom CSS, and (under Email
templates) the email accent colour. Everyone sees it unless their domain has a
brand of its own. The admin console, the issuer, and the names in the OIDC
discovery document and SAML metadata always use it.

A **brand** (Branding → Brands) is attached to one or more UPN domains, from
the brand's page or from the Domains page (`PUT /api/v1/domains/{domain}/brand`).
Each field a brand leaves empty - app name, sign-in message, gradient, email
accent, logo, custom CSS - falls back to the default brand's. The cursor trail
and the email template wording are shared by every brand (`{{app_name}}` is
the recipient's brand's app name). Deleting a brand returns its domains to the
default brand and deletes its logo.

## Which brand a page uses

The sign-in page does not know who is signing in until they type a UPN, so the
brand is decided like this (`brandFor` and `requestBrandDomain` in
`src/lib/brands.ts`):

1. **Once the person is known** - the second step (authenticator, email code,
   passkey, security questions), the OIDC consent page, the sign-out
   confirmation, My account (name and logo in the top bar), the password-reset
   and invitation link pages, and every email sent to them (invitation, reset,
   sign-in code): the brand of their UPN's domain.
2. **Before that**, on the sign-in and recovery pages, a hint:
   - the OIDC `login_hint` sent to `/authorize` - its part after the last `@`
     (`alice@acme.com` → `acme.com`; a bare `acme.com` works too);
   - `/login?domain=acme.com` or `/login?login_hint=alice@acme.com`, for links
     you hand out.

   The hint is carried in the sealed sign-in flow, so the error pages that
   follow a wrong password keep the brand. It only chooses a look: it never
   pre-selects an account or changes how the UPN is resolved.
3. **Else the hostname** the page was opened on, when it is a branded domain
   or a subdomain of one (`login.acme.com` → `acme.com`, the most specific
   match first). The issuer's own hostname never counts: it serves every
   domain, so a brand attached to the domain it happens to sit under must not
   become everyone's sign-in page.
4. **Else the default brand.** SAML AuthnRequests carry no hint FlareID reads,
   so a SAML sign-in uses the hostname or the default brand until the person
   is identified.

## Logos

PNG or JPEG, at most 256 KB, recognised by the file's first bytes (a `.png`
name or an `image/png` type is not enough). The console uploads a file; the
API takes it base64-encoded in JSON (`PUT /api/v1/branding/logo`,
`PUT /api/v1/branding/brands/{id}/logo`, `{"data": "<base64>"}` - a
`data:image/png;base64,` prefix is accepted).

**SVG is refused.** An SVG is an XML document that can carry script and
external references; serving one safely needs its own locked-down
Content-Security-Policy and must never be inlined, and even then most email
clients (Gmail, Outlook) do not display SVG, so a logo that only works on the
web pages would be a half-feature. PNG and JPEG work everywhere.

Logos are stored in D1 (`brand_assets`, base64) - no R2 bucket is needed - and
served from `GET /brand/logo/<id>-<hash>.<png|jpg>`: the name carries the
content hash and an asset never changes (a new upload is a new asset), so it is
cached for a year as `immutable`, with `X-Content-Type-Options: nosniff`. A
name whose hash is not the asset's is a 404. A replaced or removed logo is
deleted, so an old email's image stops loading. Emails reference the logo by
absolute URL (`${ISSUER_URL}/brand/logo/...`, only when the issuer is https);
an email in a brand without an uploaded logo carries no image at all.

## Custom CSS

Each brand can have a stylesheet (at most 20 KB). It is applied to the
sign-in, second-step, consent, sign-out, password-recovery, invitation and
setup pages - **never to the admin console or My account**, so a stylesheet
that breaks a page cannot lock administrators out of fixing it.

- It is served as its own file, `GET /brand/css/<default|id>-<hash>.css`
  (`text/css`, `nosniff`, cached as immutable by hash), and linked with
  `<link rel="stylesheet">`. It is never inlined into a page.
- The page's Content-Security-Policy is unchanged (`style-src 'self'
  'unsafe-inline'`, `img-src 'self' data:`, fonts `'self'`): fonts and images
  from other sites are blocked whatever the CSS says. So that this is reported
  when the CSS is saved rather than silently ignored by the browser, saving
  refuses `</style` or `<script`, `@import`, `url()` pointing anywhere but a
  path on this site (`/...`) or a `data:` URL, remote URLs in strings
  (`image-set()`, `@font-face`), `expression(`, `javascript:`,
  `-moz-binding` and `behavior`. The checks run after removing comments and
  decoding CSS escapes, so `\75 rl(` is `url(`.
- **Escape hatch:** `/login?nocustom=1` (or the same on any of those pages)
  switches custom CSS off in that browser - a session cookie, so the sign-in
  posts that follow stay unstyled - until `?nocustom=0`. It removes styling
  only, so anyone may use it.

Stable selectors to style: `.auth-brand` (logo and name), `.auth-brand img`,
`.auth-brand span`, `.center-wrap .card`, `button.primary`, `p.sub`,
`.auth-foot`, `.auth-lang` (the language picker). Keep text readable when
you restyle: the sign-in pages are built to WCAG 2.2 AA contrast (links and
primary buttons use `--fi-accent: #c2410c`, 5.2:1 on white), and a custom
stylesheet is the one thing that can undo that. For example, a logo that
already contains the name:

```css
.auth-brand span { display: none; }
.auth-brand img { height: 56px; }
```

## Language

Branding → Settings → **Language** sets the sign-in pages' default language -
the one shown when the browser asks for none FlareID has. It is the same for
every brand. People can pick another from the sign-in page's footer. See
[i18n.md](i18n.md) for the full order and for adding a language.

## Preview

Each brand's page has **Preview the sign-in page**:
`/login?brand_preview=<id>` (or `default`). It renders the sign-in page in
that brand for a signed-in, active account holding `branding:read`, even
though they are signed in; for anyone else the parameter does nothing.
