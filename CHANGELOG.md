# Changelog

Notable changes to FlareID. This project follows [semantic
versioning](https://semver.org/) from v1.0.0 onward; until then, minor versions
may break things.

## [Unreleased]

### Security

- **Step-up re-authentication asks for an emailed code** when email codes are
  someone's second factor (no authenticator app): "Confirm it's you" now
  offers **Email me a code** and needs it with the password, instead of the
  password alone - weaker than their sign-in. A passkey still confirms on its
  own; security questions never do. Audited as `admin.step_up_code_sent` and
  `admin.step_up` with `method: "password+email_otp"`.

## [3.6.0] - 2026-11-12

Every release is treated as a fresh install for now. Migrations `0021`-`0025`
(signing keys, secure defaults, roles as data, email codes, security
questions). Also in this release: secure defaults (the second-factor policy
always applies to Super Admins and is the default on a fresh install), roles
as data with a default User role and one permissions model shared by roles
and API keys (Security > Roles), and the GitHub link beside the tagline.
OpenID Foundation Basic OP plan against the live instance: 1,720 conditions
passed; the only failures are the two screenshot-only error-page tests, plus
the deliberate email-in-id_token and profile-claims warnings.

### Added

- **Breached-password check** (Have I Been Pwned's Pwned Passwords,
  k-anonymity): a password someone chooses is refused with "This password has
  appeared in a data breach N times; choose another." if it is in the breach
  corpus - on self-service changes (My account), invitation acceptance,
  password-reset links, passwords an administrator sets (console and
  `POST /api/v1/users`, `POST /api/v1/users/{username}/reset-password`) and
  imported passwords (when the import carries at most 200 explicit passwords;
  each distinct password is asked about once). Generated passwords are not
  checked. Only the first 5 hex characters of the password's SHA-1 hash are
  sent, with `Add-Padding: true`; the suffixes are compared locally. On a
  timeout (3 s) or network error the check fails open and a warning (with no
  password or hash) goes to the Worker log. **On by default on a fresh
  install**; switched under Security > Settings > Breached passwords or
  `PUT /api/v1/security/breached-passwords`, audited as
  `settings.breached_password_check_changed`; `GET /api/v1/security` reports
  `breached_password_check`.
- **Bot protection with Cloudflare Turnstile** on the password sign-in form
  (`/login`, also when reached from `/authorize` or SAML SSO) and the
  password-recovery request (`/forgot-password`). Off by default; set under
  Security > Settings > Bot protection (site key, write-only secret key, mode
  off / on) or `PUT /api/v1/security/turnstile` (`GET /api/v1/security`
  returns `turnstile` with `secret_set`, never the secret). An optional
  `TURNSTILE_SECRET_KEY` Worker secret overrides the stored secret. The widget
  is rendered explicitly (light theme) and the token is redeemed with
  Siteverify - with `remoteip` from `CF-Connecting-IP` and an idempotency
  key, retried once on a network or internal error - before any account
  lookup, password hash, rate-limit count or email; the `hostname` must be
  the issuer host and the `action` the form's (`login` / `recovery`). A
  refusal shows "Please complete the check and try again.", is not audited
  and does not count against the account's sign-in limit (so a bot cannot
  lock out its victim); Siteverify being unreachable refuses (fails closed).
  Passkey sign-in is not challenged. The Content-Security-Policy admits
  `https://challenges.cloudflare.com` in `script-src` and `frame-src` only on
  the responses that render the widget, and only while it is on. Audited as
  `settings.turnstile_changed` (never with the secret).

- **Security questions as a second factor**, completing the initial set
  (password, authenticator app, passkeys, email codes, security questions).
  Off on a fresh install; switched on under Security > Factors, whose new
  **Security questions** page holds the settings (how many questions each
  person sets, default 3, and how many are asked at sign-in, default 2) and
  the catalogue people choose from (ten seeded; administrators add, disable
  and delete unanswered ones). People set theirs in My account > Security >
  Security questions (changing or removing them takes the current password,
  within the step-up attempt budget) or on the forced-enrolment page, which
  then resumes the sign-in with amr `kba`/`mfa`. Answers must be 3-100
  characters, for different questions, different from each other and from
  the username; they are normalised (Unicode NFKC, trimmed, whitespace
  collapsed, case-insensitive) and hashed with the password KDF and a salt of
  their own, and never stored, logged or audited in clear. At sign-in the
  second step offers **Answer security questions** (or asks them straight
  away when they are the only method): the questions are picked at random and
  bound to the pending step, so refreshing cannot re-roll them; all must be
  right, and wrong answers count against the per-user MFA attempt limit. A
  correct set signs in with amr `["pwd","kba","mfa"]` and counts toward
  policies that require a second factor and the last-factor guard. Because
  they are the weakest factor, the Factors page says so and recommends
  keeping a stronger one on, and **a Super Admin whose sign-in used security
  questions must re-authenticate on `/admin/reauth`** (password plus
  authenticator, or a passkey - never the questions) before sensitive console
  actions. Admin > Users shows whether they are set; **Reset MFA** (console
  and `POST /api/v1/users/{username}/reset-mfa`) and user deletion remove
  them. API: users gain `security_questions_enabled`; `PUT
  /api/v1/security/factors/security_questions`; `GET`/`PUT
  /api/v1/security/security-questions` and `POST`/`PATCH`/`DELETE
  .../questions[/{id}]` for the catalogue (`security:write`). Audited as
  `user.security_questions_enabled`/`_changed`/`_disabled`,
  `login.mfa_failed` with `method: "security_questions"`,
  `settings.security_question*`. Migration `0025_security_questions.sql`.
- **Email one-time codes as a second factor.** Switched on under Security >
  Factors (off on a fresh install, and only possible once email is
  configured; the page says why otherwise). People turn them on in My account
  > Security > Email codes by entering a code sent to their address, or on the
  forced-enrolment page, which then resumes the sign-in. At sign-in the second
  step offers **Email me a code** (alongside the authenticator app and
  passkeys, or on its own); codes are six random digits sent with the
  customisable Sign-in code template, stored hashed in KV for ten minutes,
  single use, and invalidated after five wrong guesses; sends are limited to
  five per user per 15 minutes. A verified code signs in with amr
  `["pwd","otp","mfa"]` and counts toward any policy that requires a second
  factor, including the "last factor on" guard. Turning email codes off takes
  a fresh code. Admin > Users shows whether they are enrolled, and **Reset
  MFA** (and `POST /api/v1/users/{username}/reset-mfa`) clears them. Users in
  the API gain `email_otp_enabled`; factors gain `usable`. Sends, failures,
  enrolment and removal are audited (`login.email_otp_sent`,
  `login.mfa_failed` with `method: "email_otp"`, `user.email_otp_enabled`,
  `user.email_otp_disabled`, ...); the code itself is never logged. Migration
  `0024_email_otp.sql`.
- Every `/login/...` endpoint now counts toward the edge "auth" rate limit
  (the passkey second step was missing).
- **The provisioning API covers everything the admin console does.** New
  endpoints for users (get, update - attributes, schema, email, status -
  delete, password and MFA resets, sessions, passkeys, connected apps),
  groups (create, get with paged and searchable members, update, delete,
  freeze, add and remove members), OIDC clients (get, update, rotate secret,
  delete), SAML service providers (get), API keys (list, revoke), domains
  (remove), SCIM (read configuration), email (settings, switch, test),
  branding and email templates, security settings, authentication policies,
  factors, roles, signing keys (list, rotate), the audit log, the overview
  statistics and performance. See `docs/api.md` for a summary.
- **An OpenAPI 3.1 document**, generated from the route definitions and served
  without a token at `GET /api/v1/openapi.json`. Every operation names the
  permission it needs (`x-permission`). `npm run docs:api` writes it to
  `docs/openapi.json` with a readable `docs/api-reference.md`.
- A parity test fails when a console action has no API operation, when an API
  route is missing from the spec, or when the committed spec is stale.
- **Security > Signing keys** in the console: every token signing key (kid,
  algorithm, status, created, retired, published until) with the active key
  per algorithm highlighted, and a step-up protected **Rotate** per algorithm
  (audited `signing_key.rotated`, shared with the API's rotate operation).
  Retired keys stay in `/jwks.json` for 24 hours so tokens they signed still
  verify, and the hourly cron now removes them afterwards. No redeploy needed.
- **Branding > Email templates** in the console: edit the subject, heading,
  body, button label and footer of the invitation, password reset and
  sign-in code emails, with their `{{placeholders}}` listed, a live preview
  (rendered subject, HTML and plain text with sample values) that updates as
  you type, **Reset to default** (confirmed), and the accent colour every email
  shares. Changes are audited (`settings.email_template_changed`,
  `settings.email_template_reset`, `settings.email_accent_changed`) and share
  their implementation with the API's email-template and branding operations.
- **Per-client ID token signing algorithm** (RS256 default, or ES256) on the
  OIDC client create and edit forms, and as `id_token_signed_response_alg` on
  `POST /api/v1/clients`, `PATCH /api/v1/clients/{client_id}` and the client
  read and list responses (anything other than RS256 or ES256 is a 400).

### Changed

- API routes require the granular permission for their area (`users:read`,
  `oidc:write`, ...), so keys minted with per-area permissions work across the
  API. Keys with the original scopes keep exactly the access they had.
- API request bodies are validated against the documented schemas: a wrong
  type is a `400 invalid_request` naming the field.
- `POST /api/v1/users/{username}/invite` now needs `*` for any account holding
  an admin role, not only Super Admins, as the console already required.
- `POST /api/v1/scim/config` with a new scope re-evaluates what was already
  pushed, as the console does.
- Console and API share one implementation per action (`src/services`), so the
  two cannot drift.

## [3.5.0] - 2026-11-11

Migrations `0019` (admin role groups) and `0020` (step-up).

### Added

- **Granular admin roles**, held through built-in groups like Super Admins:
  - **Directory Admins**: users, groups, domains, schemas and CSV import.
  - **Application Admins**: OIDC clients, SAML apps, SCIM provisioning, email.
  - **Auditors**: read-only access to everything above, the overview and the log.

  Security settings, branding, setup and API keys stay Super Admin only. Below
  Super Admin nobody can change a role group, act on an account that holds a
  role, or grant a role through a form or a CSV import. The sidebar shows only
  what a role can reach.
- **Step-up re-authentication** for sensitive admin actions (API keys, client
  secret rotation and deletion, password and MFA resets, user deletion,
  security settings, setup, the SCIM secret): unless the admin signed in or
  confirmed within the last 10 minutes, they confirm with their password (and
  code) or a passkey first.

### Changed

- Replace-mode imports and the sample-directory wipe keep the admin role
  groups and everyone holding a role.

## [3.4.0] - 2026-11-11

Migration `0018`.

### Added

- **Email on/off switch** (Admin → Integrations → Email): stops all sending
  and hides recovery and invitations, keeping the From address and name.
- **The OIDC `claims` request parameter** (Core 5.5): claims asked for the
  id_token or /userinfo are released there, within the client's allowlist.

### Security

- **Reusing an authorization code revokes the tokens it issued** (RFC 6749
  4.1.2): redeemed codes are kept, marked used, until they expire.

### Changed

- **Large directories:** people pickers (group members, manager and other
  references) search on the server as you type instead of loading every user;
  a 10,000-user group page went from about 2 MB to under 80 KB. SCIM group
  sync resolves all groups from one load of the directory.
- OpenID Foundation Basic OP plan: all conditions pass except the two
  screenshot-only error-page tests, the email-in-id_token and profile-claims
  warnings (kept deliberately, see `conformance/expected-failures.json`), and
  the two re-login tests that need screenshots uploaded by hand.

## [3.3.2] - 2026-11-11

### Added

- **Sync log** on Admin → Integrations → SCIM provisioning: a line for every
  batch of users and for the groups as a full sync runs (counts, timings and
  the first failures with their HTTP status), and the recent SCIM events when
  the page loads. The groups are now their own step of a full sync.

## [3.3.1] - 2026-11-11

### Fixed

- **"Sync all now" pushed only the first 200 users and no groups** on a large
  directory: a full sync runs in batches, and the rest waited for the hourly
  job. The button now runs every batch in turn, showing progress, and finishes
  with the groups. `POST /api/v1/scim/sync` reports `complete` and
  `remainingUsers` so scripts can do the same.

## [3.3.0] - 2026-11-11

Migration `0017` adds authentication policies. The old "Require MFA for every
account" setting becomes the choice of default policy, so behaviour is unchanged
on upgrade.

### Added

- **Authentication policies** (Admin → Security → Policies): "Password only"
  and "Password and a second factor" to start, assigned to groups with a
  priority, plus a default for everyone else. A passkey satisfies every policy.
- **Factors** (Admin → Security → Factors): turn the authenticator app and
  passkeys on or off, with enrolment counts; email one-time codes and
  security questions are listed as planned.
- **A passkey as the second factor.** Someone with only a passkey who signs in
  with their password is asked for the passkey, not sent to set up an
  authenticator app; forced enrolment offers a passkey too.
- **Performance dashboard** (Overview → Performance): requests, latency (p50,
  p95) and 5xx graphs over the last hour, day or week, per endpoint, from
  Workers Analytics Engine.
- **OIDC:** `POST /authorize` and `POST /userinfo` (with the token in the
  header or a form body), as OpenID Connect Core requires; request objects are
  refused with `request_not_supported` instead of being ignored. Found by the
  OpenID Foundation's suite.
- Security → Settings shows the edge flood limits.
- `website/guides/CLOUDFLARE.md`: connecting FlareID to Cloudflare One with
  OIDC and SCIM.

### Changed

- **My account** is grouped into Security (MFA, password, passkeys) and
  Sessions and devices (sessions, remembered devices, connected apps).
- The "use these values" panels on the OIDC client and SAML SP pages follow
  the theme (they stayed light in dark mode).
- "Sync all now" continues an unfinished large SCIM sync instead of restarting.

## [3.2.0] - 2026-11-11

Migrations `0013` to `0016`. Applying `0013` forgets remembered devices once
(they are now stored hashed), so affected users answer one MFA prompt.

### Added

- **Passkeys (WebAuthn).** Add them on My account; "Sign in with a passkey" on
  the login page needs no username. A passkey sign-in is multi-factor
  (`amr` `hwk`+`mfa`) and satisfies the require-MFA setting. Sign counters that
  do not advance are refused.
- **Front-channel logout** (OpenID Connect Front-Channel Logout 1.0): clients
  may register a `frontchannel_logout_uri`, loaded with `iss` and `sid` when
  the user signs out of FlareID.
- **OpenID Foundation conformance suite** as a CI workflow (manual and weekly)
  against a deployed instance: Basic OP, Config OP and RP-initiated logout.
- **SAML saml2int:** SP metadata registered from a URL and refreshed daily;
  `subject-id` and `pairwise-id` attributes (chosen per SP, or from the SP's
  `subject-id:req`); IdP metadata with `validUntil`, `cacheDuration`,
  `shibmd:Scope`, `mdui:DisplayName` and a technical contact.

### Security

- OAuth back-channel rate limits (`/token`, `/introspect`, `/revoke`) are keyed
  per client as well as per address, so relying parties behind a shared egress
  cannot throttle each other.
- Trusted-device cookies are stored hashed.
- The client address comes only from `CF-Connecting-IP`.
- Imported passwords must meet the password policy.
- CI actions are pinned to commit SHAs.

### Changed

- A full SCIM sync runs in batches of 200 users per invocation; the hourly
  cron finishes an unfinished one.

## [3.1.2] - 2026-11-11

### Changed

- The group members search box uses the same field styling as the rest of the
  console (it was an unstyled search input).
- "Convert to static" sits with Delete group, Cancel and Save.

## [3.1.1] - 2026-11-11

### Changed

- **Group page**: name, description and Membership come first again, with the
  members list below. For a static group, Membership is now only where you add
  people; current members are removed from the members list. "Convert to
  static" sits in Membership for a dynamic group.
- The groups list toolbar (search, type, page size, Import CSV, New group)
  stays on one row.
- The top bar links to the GitHub repository.
- Sign-in pages always use the light, branded theme.

### Fixed

- **Sign out appeared to hang** in Chrome: the `Clear-Site-Data: "cache"`
  header could stall the navigation. It is gone; signed-in pages are already
  sent `Cache-Control: no-store`.

## [3.1.0] - 2026-11-11

### Added

- **Group members panel**: every group's page lists its current members
  (assigned, or rule matches for a dynamic group) 30 per page, with a search
  by name or UPN to check whether a person is in the group.
- **Convert a dynamic group to static**, keeping today's matches as assigned
  members. A group's type is otherwise fixed at creation: a static group cannot
  become dynamic, so assigned members are never silently dropped.
- **Overview**: active accounts, SAML apps, active API keys, live refresh
  grants, and a last-24-hours panel (sign-ins, failures, rate-limited sign-ins,
  failed step-up checks, API calls, rejected keys, SCIM failures and queued
  deletions).
- **IdP performance** on the overview: requests, 5xx rate and p50/p95 latency
  per endpoint family, from Workers Analytics Engine. Every request now writes
  one data point to the `METRICS` dataset (no D1 or KV write); reading them back
  needs the `CF_ACCOUNT_ID` var and a `CF_ANALYTICS_TOKEN` secret (Account
  Analytics: Read).
- **Groups CSV import** at Admin → Groups → Import CSV.
- **Dark mode**: follows the system setting, with a Theme toggle in the top
  bar (auto, dark, light) remembered per browser.
- The top bar shows the deployed version.

### Changed

- Admin pages use the full window width.
- The CSV import page is laid out as file drop zones, password choices and a
  progress panel.
- README opens with a screenshot.

## [3.0.0] - 2026-11-11

Migrations `0008` to `0012` (account tokens, OIDC clients, self-service
profile, SAML v3, SCIM deprovision queue). On deploy, **every live session is
revoked once**: id_tokens issued before this release carried the raw session id
(see Security). Users simply sign in again.

### Security

Fixes from the second, deep security audit (66 coverage units, 41 candidates
independently verified - 36 confirmed, 5 needing deployment facts; report in
the audit run directory). Each has a regression test (`test/audit-v3.test.ts`,
`test/scim-scope.test.ts`).

- **High - id_token `sid` was the session cookie.** It is now a one-way
  derivation; RP-initiated logout matches the derivation.
- **High - `directory:write` to Super Admin takeover.** Applying a domain to all
  users (which rewrites Super Admin UPNs, and recovery mail follows the UPN)
  now needs the `admin` scope.
- Fresh-login requirements (`ForceAuthn`, `ForceAuthn="1"`, `prompt=login`,
  `max_age`) can no longer be satisfied through the MFA-enrolment resume page.
- MFA enrolment ends every other session; pending enrolment secrets are per
  session; backup-code regeneration needs a current factor; account step-up
  checks (current password, MFA disable/regenerate) share the login attempt
  budget; backup and authorization codes are consumed atomically.
- Every password change, admin reset, recovery reset and import password set
  revokes OAuth tokens, codes and outstanding links; deactivation voids
  invitation links; a new link voids all earlier ones, and changing a user's
  email or UPN voids links sent to the old address.
- SCIM: Super Admin memberships and the "Super Admins" name are guarded on the
  SCIM server (the console can no longer rename or delete the group);
  inbound changes reach the outbound target; group PATCH is all-or-nothing;
  deletions are queued durably and retried; removed members and scope changes
  are re-evaluated; a self-heal never recreates a deleted user.
- SAML Single Logout requires SessionIndex, a fresh IssueInstant, the right
  Destination, and refuses replays. `/oidc/logout` without a session sets no
  cookie.
- Rate limits: the edge limiter classifies the decoded path, IPv6 is keyed per
  /64, the per-IP login bucket counts failures only, the lockout message no
  longer reveals which accounts exist, sign-in inputs and audit targets are
  bounded, and passwordless accounts cost the same verify time as misses.
- Claim and schema hygiene: IdP-asserted claim names cannot be overridden or
  reused as attributes; schema names are validated for every writer; `manager`
  is never user-editable; dynamic-group rule guards share the evaluator's
  parser; rules are normalised and size-capped, and an unparseable stored rule
  matches nobody instead of breaking requests. Groups over 100 members work
  (one `json_each` parameter instead of one per member).
- Plus the remaining v2 audit items: same-origin `/login?next=`, empty or
  malformed API-key scopes and expiry rejected, validated login gradient,
  `Cache-Control: no-store` on dynamic pages, constant-time sign-in for unknown
  accounts, import SCIM deprovisioning, and keys kept out of the repo on a
  failed deploy. `npm audit` is clean.

### Added

- **Outbound email** (Cloudflare Email Sending) with **password recovery**
  ("Forgot your password?", one-hour single-use links) and **invitations**
  that set a password and activate the account. Admin → Integrations → Email;
  `POST /api/v1/users/{username}/invite`.
- **OIDC:** per-client claim allowlist, consent screen for untrusted clients,
  public/native clients (PKCE-only, loopback redirects), RP-initiated logout
  (`end_session_endpoint`), `auth_time`, `acr`, `at_hash`, `prompt` and
  `max_age`; `WWW-Authenticate` on `/userinfo` errors. A scripted conformance
  check, `npm run oidc:conformance`.
- **SCIM 2.0 server** at `/scim/v2` for inbound provisioning.
- **CSV import** in the admin console (users and groups), load-tested with
  10,000 users; `npm run test-data` generates a large test directory.
- **Self-service profile editing**, with a per-attribute "User can edit"
  permission in the schema.
- **SAML:** encrypted assertions, Single Logout (`/saml/slo`), and SP metadata
  import in the console and API.
- **Edge rate limits** in front of every anonymous route, counted in memory so
  a refused request costs no storage write; `GET /login`, `/authorize` and
  `/saml/sso` no longer write to KV.

- **Session limits** in Admin → Security (and `session_limits` on
  `POST /api/v1/setup`): a maximum session length (1-720 hours, default 12)
  and an optional inactivity timeout. Checked on every request, so changes
  apply to sessions that already exist.
- **Cursor trail controls** in Admin → Branding (and `cursor_trail` on
  `POST /api/v1/setup`): switch the sign-in page's drifting characters off, or
  give them your own characters - a company name spells itself out. On by
  default, as before.
- **API key activity in the log.** Every authenticated API call is recorded as
  `api.request` (method, path, status); failed key attempts as
  `api.auth_failed` with only the key's prefix. The API keys page links each
  key to its activity.
- **Log filters**: by actor (people, API keys, anonymous and system), action
  family, and date range, alongside the search.

### Changed

- **Integrations split into four pages** - OIDC clients, SAML apps, API keys
  and SCIM provisioning - listed under Integrations in the admin sidebar while
  you are in that section. `/admin/integrations` is now an overview summarising
  every configured client, app, key and the SCIM connection; `/admin/clients`
  and `/admin/scim` redirect.
- The admin sidebar has an **Overview** link to the dashboard.
- **A backup code can disable MFA**, so someone who lost their authenticator
  and signed in with a backup code can enrol a new one.
- **Sign-in errors are branded pages** (an expired sign-in, an MFA challenge
  for an account deactivated mid-login, an app misconfiguration) instead of
  plain text. Errors an app's configuration causes have no "sign in again"
  button, because retrying cannot fix them.
- Sign-in page logo: the mark is drawn at its own proportions with its
  off-white background removed (`public/FlareID_Mark.png`), closer to the name.

### Fixed

- The hourly cleanup compared rate-limit window starts (epoch milliseconds)
  with an ISO date string, which SQLite always orders after numbers, so every
  run deleted every lockout counter instead of only week-old ones.

## [2.0.1] - 2026-11-05

### Security

Fixes from the v2.0.0 independent security audit (all confirmed findings of
medium severity and above; migration `0007` adds the `rate_limits` table and
`users.totp_last_counter`):

- **API scope boundaries.** `directory:write` keys can no longer grant
  `super_admin`, add members to `Super Admins`, or overwrite an existing Super
  Admin through the import; `settings:write` keys can no longer create or
  reset an administrator through `POST /api/v1/setup` after setup. Both were
  effectively admin.
- **Mandatory MFA enforced at issuance.** A password-only session minted
  before forced enrolment no longer produces OIDC codes or SAML assertions at
  the SSO endpoints - the request is parked at enrolment and resumed
  afterwards.
- **Lifecycle consistency.** Deactivating a user (console or import) now
  revokes their sessions *and* token grants immediately; `/introspect` reports
  a deactivated user's tokens inactive; the MFA step re-checks account status
  so a pending challenge cannot complete for a disabled account; password
  change and admin reset sign out the user's other sessions.
- **SAML request handling.** `/saml/complete` only redeems flows bound to the
  user who just finished login+enrolment, so an ambient session alone cannot
  answer a `ForceAuthn` request. Inflated `SAMLRequest`s are capped at 64 KB
  before any DOM parsing.
- **Login rate limiting rewritten.** Attempts are counted atomically in D1
  (the KV read-modify-write could lose increments under bursts), keyed on the
  resolved account rather than the submitted spelling, the MFA bucket moved to
  a namespace password-step input cannot reach, and the shared per-IP budget
  raised to 20x so colleagues behind one egress address can't lock each other
  out.
- **TOTP replay.** A code already accepted cannot be used again inside its
  validity window, for login or for disabling MFA.

## [2.0.0] - 2026-11-03

### Added

- **Directory schemas.** Named attribute vocabularies per object type at
  Admin → Schemas and `/api/v1/schemas` (list, create, update, delete,
  `POST /:id/apply`). Ships two provided user schemas - "Basic" (identity
  fields only, the default for new objects) and "FlareID HR" (the full
  built-in HR set) - plus a Basic group schema. Attribute names matching
  built-in fields map to columns; everything else lives in
  `custom_attributes`. Moving an object to a schema conforms it: same-named
  attributes carry over, the rest are cleared (the admin UI previews the move
  and lists what will be cleared before you save). Custom attributes reach
  SAML SPs via `attribute_map` and OIDC clients under the `custom` claim.
  Attributes are edited as add/remove rows.
- **Dynamic groups.** A group is static (assigned members) or dynamic (rule
  matches only). Rules are built in the admin UI as rows of schema ›
  attribute, `=`/`!=`, value - with suggestions drawn from values already in
  the directory - and stored as
  `{"all":[{"schema":"FlareID HR","field":"department","op":"eq","value":"Sales"}]}`.
  Membership resolves everywhere: claims, SAML attributes, SCIM pushes,
  admin pages and the API. Import bundles accept `rule` on groups.
  `Super Admins` can never be dynamic.
- **Admin console redesign.** Navigation is a left sidebar (Schemas after
  Security; breadcrumbs kept). Users list gains a Schema column and filter
  and a row menu (Edit / Delete). The user page has an Active switch in the
  header that applies immediately and signs the user out when switched off,
  attributes in two columns, a searchable manager picker that never offers
  the user themselves, a Groups section listing assigned and dynamic
  membership separately, and a reorganised Security section. Groups list
  shows Static/Dynamic with a type filter; dynamic groups list their computed
  members. You cannot deactivate or delete your own account.
- **Chosen passwords on reset.** The admin reset form accepts an optional
  password (policy-validated); blank still generates one.
- **Branding page.** App name, sign-in message and login gradient moved from
  /admin/security to their own /admin/branding tab.
- **`GET /saml/cert.pem`** downloads the IdP signing certificate - the file
  SPs like Salesforce ask to upload - linked from the SP admin pages.
- 8 new tests covering schemas, conforming, and dynamic groups (98 total).
- **SAML 2.0 service-provider-initiated SSO.** `/saml/sso` accepts
  HTTP-Redirect AuthnRequests (unsigned, or signed per the SP's registered
  certificates - including mid-rollover), and answers with an HTTP-POST
  Response carrying a signed Assertion in a signed Response. Per-SP registry
  in Admin → Integrations and `/api/v1/saml/service-providers`: ACS URL
  allowlist, NameID format (transient / emailAddress / persistent), attribute
  mapping, signing policy. IdP metadata at `/saml/metadata`; request IDs are
  single-use, `ForceAuthn` is honoured, and POSTed AuthnRequests are rejected
  by design (see SAML-implementation.md §4). Responses and Assertions are
  signed "canonically by construction" - the emitted XML is already
  exclusive-C14N form, verified in tests against `xml-crypto`.
- **`npm run saml:keygen`** (`scripts/generate-saml-cert.mjs`) mints the
  RSA-3072 self-signed certificate + PKCS8 key the endpoints need
  (`SAML_SIGNING_CERT` var, `SAML_SIGNING_KEY_PKCS8` secret); `npm run deploy`
  generates them automatically when absent.
- 16 new tests covering the metadata endpoint, the full login and SSO paths,
  signature verification, `ForceAuthn`, NameID formats, the ACS allowlist,
  request replay, signed-request verification, and the SP provisioning API.

### Changed

- **Users are created disabled.** New accounts - from the admin form or the
  import API - cannot sign in until activated via the Active control on the
  user page or `status: "active"` in the bundle. The setup/admin-reset
  administrator stays explicitly active.
- **The seeded "All Employees" group is gone.** A bare install ships only
  Super Admins. Deployments that want a company-wide group define it as a
  dynamic group (e.g. `employment_type = full_time`), which also keeps
  membership correct as attributes change. The admin form's auto-join is
  gone with it.
- **Admin layout** spans the window with the topbar's gutter, so the sidebar
  sits under the logo at every width. After creating a user you can replace
  the temporary password with one of your own (policy-checked).
- **Refresh tokens rotate.** Each use returns a new refresh token; clients
  must store it. Presenting an old one revokes the whole family.

### Security

- **Password hashing moves to scrypt** (N=2^13, r=8, p=10, ~100 ms CPU per
  hash), stored as PHC strings. Legacy PBKDF2 hashes keep working and are
  upgraded at the next sign-in. Workers caps PBKDF2 at 100,000 iterations in
  production - a limit local dev doesn't enforce - so raising it wasn't an
  option. Set `PASSWORD_HASHER=pbkdf2` on the Workers Free plan.
- **CSRF defence**: browser POSTs are verified against `Origin` /
  `Sec-Fetch-Site` / `Referer` and refused unless same-origin - sibling
  subdomains included, which `SameSite=Lax` alone allowed.
- **Security headers and CSP**: HSTS, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, COOP, `Permissions-Policy`, and a CSP that
  allows only FlareID's own inline scripts by SHA-256 hash. Inline event
  handlers are replaced by `data-` attributes.
- **Refresh-token lifecycle**: 30-day expiry, rotation on use, reuse
  detection (RFC 9700) that revokes the family; `/revoke` ends the family.
- **PKCE is S256-only**; `plain` and challenges without a method are refused.
- **Hourly cleanup** (Cron Trigger) of expired codes, tokens, sessions and
  trusted devices, and audit entries past a configurable retention (Admin →
  Security, default 365 days).

### Fixed

- **Dynamic groups never reached tokens or SAML assertions.** Group
  resolution loaded only the user's id before evaluating rules, so sign-ins
  carried no dynamic groups even though the admin UI listed the members.
- **Stored XSS in the multi-select**: chip labels (user and group names,
  which the import API and SCIM can set) were inserted with `innerHTML`.
- 23 new tests (121 total).

## [0.1.0] - 2026-10-28

First release as a standalone project. FlareID previously lived inside a
workshop repository, and most of this release is the work of getting it out.

### Added

- **Provisioning API** at `/api/v1`: status, first-run setup, domains,
  bulk directory import, OIDC client registration, SCIM configuration, API key
  management, and a break-glass administrator reset. Documented in
  [docs/api.md](docs/api.md).
- **API keys**, managed from Admin → Integrations, stored as SHA-256 hashes and
  scoped (`directory:read`, `directory:write`, `clients:write`,
  `settings:write`, `admin`).
- **`BOOTSTRAP_TOKEN`**, a deploy-time Worker secret that configures a brand
  new instance and then retires itself once setup completes.
- **A test suite**: 73 tests running inside the Workers runtime against a local
  D1 migrated from the real migration files - the password KDF, TOTP against
  the RFC 6238 vectors, the full authorization-code and PKCE flow with
  `id_token` verification against `/jwks.json`, the refresh grant,
  introspection and revocation, and the whole provisioning API.
- **CI**: typecheck, tests, and a `wrangler deploy --dry-run` build check.
- **`npm run deploy`** (`scripts/deploy.mjs`): creates the D1 database and KV
  namespace, applies migrations, generates a signing keypair, sets the secrets,
  picks an issuer, attaches a custom domain when given a zone, and prints the
  one call needed to create the first administrator.
- **[SAML-implementation.md](SAML-implementation.md)**: a full feasibility
  assessment and implementation plan for SAML 2.0, including a correction to
  the previous claim that XML signing was impractical on Workers.
- **[docs/upgrading.md](docs/upgrading.md)**, for existing deployments.

### Changed

- **The migration chain was squashed from sixteen files to two.** Several
  existed only to seed a workshop's thirty fictional employees, its
  `company.com` domain, and an administrator whose password hash was committed.
  **This will not apply cleanly over a database built by the old chain** - see
  [docs/upgrading.md](docs/upgrading.md).
- **A deployment now starts empty**: no users, no domain row, no default
  password. The first administrator is created over the API.
- `default_password` starts unset, and unset now means "generate a random
  password per account and return it once" rather than falling back to a
  built-in string. `applyDefaultPasswordToAllUsers()` refuses when no default
  is configured, instead of blanking every password in the directory.
- `wrangler.jsonc` ships with placeholder resource ids and a localhost issuer;
  `npm run deploy` fills them in.
- `nodejs_compat` and a current `compatibility_date` are now set.
- The default login subtitle is generic, and is settable through the API.

### Removed

- **Every trace of the demo suite**: the thirty seeded users, the seeded
  administrator and its published password hash, the `company.com` domain row,
  the app launcher linking to five sibling demo applications, the "demo
  application with fake data" footer, and the `ROOT_DOMAIN` binding that
  existed to support the launcher.
- `scripts/generate-seed.mjs` and `npm run seed:generate`, which read another
  repository's migrations to emit a FlareID migration.

### Security

- No credential of any kind is shipped in this repository, other than a
  deliberately committed test-only signing key at `test/fixtures/signing-key.ts`
  (see [SECURITY.md](SECURITY.md)).
- `GET /api/v1/users` selects columns explicitly so that password and TOTP
  material cannot leave the database, and there is a test asserting it.
- Registering an OIDC client with a seeded secret shorter than 24 characters is
  now a `400`. It used to be silently replaced with a generated one, which left
  the relying party holding a credential FlareID had never heard of.
