# Changelog

Notable changes to FlareID. This project follows [semantic
versioning](https://semver.org/) from v1.0.0 onward; until then, minor versions
may break things.

## [Unreleased]

**Migration `0043_client_grant_types.sql`** - `oauth_clients.grant_types` and
`oauth_clients.registered_scope`, persisting the RFC 7591 `grant_types` and
`scope` metadata dynamic clients register, enforced at `/token` (NULL keeps
the old "every grant" behaviour for admin-created rows).

**Migration `0034_scim_targets.sql`** - `scim_targets` (one row per downstream
SCIM server) plus the per-target link tables `scim_user_links` /
`scim_group_links`; the existing single-target settings and `scim_id` columns
seed the first target, and `scim_group_state`, `scim_group_members` and
`scim_deprovision_queue` are rebuilt keyed by target.
**Migration `0035_scim_mappings.sql`** - `scim_mappings`, the inbound
attribute-mapping rules for the SCIM server API.
**Migration `0036_user_source_id.sql`** - `users.source_id`, the
provisioner's own stable id (SCIM `externalId`), unique when present.
**Migration `0037_upstream_idps.sql`** - `upstream_idps` (one row per
upstream identity provider) and `federated_identities`, the links binding an
upstream subject to a local account; the new `federation` permission area is
granted to every role already managing SAML or clients.
**Migration `0038_access_governance.sql`** - `groups.requestable` plus
`access_requests`, `cert_campaigns` and `cert_items`, the tables behind
access requests and membership reviews.
**Migration `0039_managers_and_photos.sql`** - `group_managers` (the named
people who run a static group's members and requests without holding
`groups:write`) and `user_photos` (profile image bytes, uploaded on My
account or written by inbound provisioning).
**Migration `0040_cloudflare_one.sql`** - `auth_policies.device_cert` and
`auth_policies.max_risk` (the posture conditions below), `groups.system`
and `groups.cf_list_sync`, and the `user_watch` / `cf_lists` tables behind
the risk watchlist and gateway-list sync.
**Migration `0041_audit_chain_and_ssf.sql`** - `audit_log.chain_hash` (the
tamper-evident chain below), and the `ssf_streams` / `ssf_outbox` /
`ssf_transmitters` tables behind Shared Signals.
**Migration `0042_oidc_profiles.sql`** - `oauth_clients` gains
`backchannel_logout_uri`, `initiate_login_uri`, `registration_token_hash`,
`jwks` and `jwks_uri` - the columns behind back-channel logout,
third-party-initiated login and dynamic client registration.

### Added

- **The remaining OIDC OP conformance profiles.** The OIDF workflow now runs
  all nine OP profiles a code-only provider can be certified for (the four
  implicit/hybrid profiles need response types FlareID does not issue):

  - *Form Post OP*: `response_mode=form_post` auto-submits the authorization
    response to the redirect URI, including through the MFA and
    trusted-device resume steps and on errors.
  - *Session Management OP*: authorize responses carry `session_state`, and
    `/check_session` serves the spec's postMessage iframe, advertised as
    `check_session_iframe` in discovery.
  - *Back-Channel OP*: sessions ending (logout, expiry sweep, admin revoke)
    POST a signed `logout_token` to every participating client's
    `backchannel_logout_uri` - `src/lib/backchannel.ts`, settable per client
    like the front-channel URI.
  - *3rd Party-Init OP*: `GET /oidc/init-login?iss=<client_id>` starts a
    normal authorization request aimed at the client's `initiate_login_uri`,
    passing `login_hint` and `target_link_uri` through.
  - *Dynamic OP*: `POST /connect/register` creates clients from RFC 7591
    metadata (redirect URIs, logout/init URIs, `jwks`/`jwks_uri`,
    `id_token_signed_response_alg`, grant types) and returns
    `registration_client_uri` + `registration_access_token`; GET/PUT on the
    client URI reads and updates per RFC 7592. Clients registered with a
    `jwks` or `jwks_uri` authenticate at `/token` with `private_key_jwt`
    assertions (RFC 7523), at every client-authenticated endpoint.

- **`address` and `phone` claim groups.** The OIDC `address` and `phone`
  scopes now resolve to the standard claims (`address` object,
  `phone_number`, `phone_number_verified`) from user schema attributes;
  discovery advertises them and consent lists them.

- **Containerized e2e rig** (`e2e/`, docs/e2e.md). One Dockerfile runs
  `wrangler dev` against local D1 in a clean container; `e2e/smoke.mjs`
  drives 26 checks over setup, users, logins, the OIDC code flow, audit
  export/verify, backup and SSF. `e2e/compose.yml` adds a local app lab
  (Grafana + SimpleSAMLphp + a TLS sidecar) for real-app OIDC/SAML testing
  per docs/real-apps.md, seeded by `e2e/real-apps.mjs`.

- **Audit export and tamper-evidence.** Every audit row now carries a
  `chain_hash` - SHA-256 over the previous row's hash plus its own
  contents - so editing or deleting a written row breaks the chain after
  it. `GET /api/v1/audit/verify` recomputes it (or the Log page's "Verify
  integrity" link; concurrent writers can fork, which it reports
  separately). `GET /api/v1/audit/export` and the Log page's "Export"
  stream the filtered view as NDJSON (or `?format=csv`) including
  `chain_hash` for offline re-verification.

- **Backup, restore and DR** (docs/dr.md). `GET /api/v1/backup` downloads
  every table as one JSON bundle (admin scope; it contains password hashes
  and encrypted secrets, so treat it like the database itself).
  `POST /api/v1/backup/restore` - bootstrap token only, `confirm: true`
  required - validates every bundled table and column against the schema
  before wiping and rewriting, parents-before-children by the schema's
  own foreign keys. Uncomment `r2_buckets` in wrangler.jsonc for daily
  snapshots to R2 in the cron.

- **Shared Signals Framework** (Integrations → Signals, a new `signals`
  permission area, and `/api/v1/ssf/*`). Outbound: registered streams get
  signed SETs (`application/secevent+jwt`, keys at `/jwks.json`) on
  session revokes, credential changes, account disables and new risk
  flags; delivery queues in `ssf_outbox` and retries hourly, per-stream
  status on the page. Inbound: trusted transmitters (issuer + JWKS URL)
  push SETs to `POST /ssf/receive`; a verified session-revoked kills the
  person's sessions and credential/risk events flag them on the risk
  watchlist for 24h. Discovery at `/.well-known/ssf-configuration`.

- **Observability runbook** (docs/observability.md): what already emits
  (Analytics Engine metrics, the audit log, structured cron events,
  `/health`), which Workers notifications to configure for alerting, and
  the queries worth keeping.

- **Cloudflare One integrations** (Integrations → Cloudflare One, a new
  `cfone` permission area, and `/api/v1/integrations/cloudflare-one`).
  One connection - account id, a Zero Trust API token, and optionally the
  team name + Access application AUD - feeds four things:

  - *Access JWT for the admin plane*: once a team and AUD are set, every
    console request must carry a valid Access JWT (`Cf-Access-Jwt-Assertion`
    or the `CF_Authorization` cookie) verified against the team's JWKS -
    reaching the Worker origin directly stops working, exactly as a
    service-token bypass would want it not to.
  - *Sign-in posture on authentication policies*: a policy can now require
    a verified WARP device certificate (`request.cf.tlsClientAuth`, when
    the zone enforces mTLS) and cap the user's Cloudflare ZT risk score
    (`zt_risk_scoring`). Posture failures deny sign-in with their own
    messages; an unconfigured or failing risk API never blocks anyone.
  - *The risk watchlist*: a system group whose membership code maintains
    (`user_watch`) - flag people from the Cloudflare One page, the user
    page, or `PUT|DELETE /api/v1/users/{username}/watch`, and failed
    sign-in bursts (10+/h) flag them automatically for 24h. The group
    syncs downstream like any group, so a SCIM target or a Cloudflare
    email list sees it.
  - *Reusable list sync*: the scheduled job full-replaces gateway lists -
    watchlist, deprovisioned users, managed domains, source IPs with
    repeated recent sign-in failures, and any group's member emails via
    its own "Sync member emails" switch (`cf_list_sync`, also on
    `PATCH /api/v1/groups/{id}`). A remotely deleted list recreates
    itself on the next run.

- **Delegated group management.** An admin can name managers on any static
  group (a card on its console page, `POST|DELETE
  /api/v1/groups/{id}/managers`); a manager then runs the group from My
  account → Groups → Manage - adding and removing members and approving or
  denying its access requests - without holding `groups:write`. Dynamic
  groups take no managers (a rule assigns their members) and admin role
  groups take none either, since their membership is itself an admin grant.
  Membership changes made this way flow through the same guards, audit
  events and SCIM pushes as a console edit. Approval is never circular: a
  group drops out of the request picker for its managers, and nobody can
  decide their own request - on the console queue or the managed-group
  page, whichever surface the POST comes from.

- **My account is three pages.** The top bar's menu under your name
  (Account, Groups, Security - Sign out moved inside) splits what was one
  long page: Account holds profile and photo,
  Groups holds memberships, the searchable request form, request history
  and any groups you manage, and Security holds factors, password,
  sessions, devices and connected apps.

- **Notifications.** A bell in the top bar drops down the work waiting on
  you - pending access requests for an administrator, the ones waiting on
  the groups you manage for a group manager - and the admin's left nav
  shows the queue size as a count on Groups/Access.

- **Profile photos.** A photo can be uploaded on My account (PNG, JPG,
  WebP or GIF, 1 MB, stored in `user_photos` and served to signed-in users
  at `/account/photo/{id}`), or arrive with provisioning: the SCIM `photos`
  attribute takes a `data:` URI or an `https://` URL fetched server-side,
  and `photo` is a mastered field, so an HR-managed photo hides the upload
  form. Avatars appear in the admin user and access-request lists and on
  managed-group pages; a user with no photo shows their initials in a
  tinted circle (the photo <img> covers them when it loads), and the
  top-bar menu button shows the same.

- **Role visibility on groups.** The groups list names each group's admin
  roles in a Role column ("-" for plain member groups) and can be filtered
  to role-bearing groups only; the request-access picker on My account
  labels them too, with each role's description alongside the group's.



- **Access requests and certification campaigns.** A static group can be
  marked requestable (a checkbox in the group editor, `requestable` in the
  API): it then appears on My account, where anyone can ask for membership
  with a reason, and a groups admin approves or denies from the new Groups →
  Access queue - an approval writes the membership exactly like editing the
  group does, so SCIM pushes and the admin-role-group guards ride along.
  Reviews certify assigned membership periodically: a campaign snapshots the
  chosen groups' explicit members and asks an admin to keep or revoke each
  one, closing with the undecided left as they were. Dynamic groups are
  neither requestable nor reviewable - their membership follows a rule, not
  a grant, so change the rule instead. API: `GET|POST
  /api/v1/access/requests/{id}`, `GET` the queue, and `GET|POST
  /api/v1/access/campaigns` plus `/{id}`, `/{id}/close` and
  `/{id}/items/{item_id}`.

- **Inbound federation.** People can sign in *through* an upstream identity
  provider - FlareID as the OIDC relying party and SAML service provider,
  the reverse of the OIDC clients and SAML service providers it already
  serves. Each enabled provider puts a "Continue with ..." button on the
  sign-in page. OIDC providers run the authorization-code flow with PKCE and
  verify the `id_token` against the provider's JWKS; SAML providers send an
  AuthnRequest (HTTP-Redirect) and verify the response signature against the
  configured IdP certificate - never one embedded in the document - plus
  audience, recipient, issuer and validity-window checks. The first sign-in
  links the upstream identity to a local account: a stored link, adoption by
  UPN or contact address, or just-in-time provisioning when the provider has
  it switched on (`jit` + an optional `jit_domain`; usernames get a numeric
  suffix on collision). The round trip rides a one-shot KV state that
  carries the original login flow, so an OIDC authorization request or SAML
  login completes exactly as a password sign-in would - MFA gates and all.
  Managed on Integrations → Federation and over `GET|POST
  /api/v1/federation/idps` and `GET|PATCH|DELETE
  /api/v1/federation/idps/{id}` (a new `federation` permission area, also
  granted by the `clients:write` scope).

- **Correlation rules for inbound creates.** An upstream POST whose
  `userName` is new no longer has to be a conflict: ordered match keys
  (`upn`, `emails`, `employee_number`, `source_id`) are tried in turn, the
  first key matching one account adopts it and the write applies there, and
  a key matching several accounts answers 409 rather than merging two
  people. Rehires and feeds re-pointed at FlareID attach to the account they
  mean. Managed on the SCIM page and over `GET|PUT
  /api/v1/scim/correlation`; empty keeps the refuse-everything default.
  Inbound `externalId` is now stored on the account (`source_id`), echoed in
  user resources, usable as a mapping target, and resolved in `manager`
  references - a manager can be named by FlareID UUID, source id, UPN, or
  contact address.

- **Inbound attribute mapping for SCIM provisioning.** Upstream provisioners
  whose dialect doesn't match FlareID's fields can be translated instead of
  forked: each mapping row feeds one user field (`upn`, the profile columns,
  `active`, `manager`, `emails`, or `custom.<key>`) from an expression over
  the incoming SCIM body - attribute paths, filters like
  `emails[type eq "work"].value`, URN extension attributes, `+`
  concatenation, and `lower upper trim concat join coalesce first split eq
  ne if`. So `upn` can be `lower(name.givenName + "." + name.familyName) +
  "@example.com"`, and `active` can key off an enterprise extension value.
  PATCH evaluates each expression against the patch merged onto the current
  resource, and an expression yielding nothing leaves the field alone there
  but clears it on PUT. Managed on the Integrations → SCIM page and over
  `GET|PUT /api/v1/scim/mappings`.

- **Field mastering.** HR-owned fields can be declared mastered so only
  inbound SCIM writes change them: the console user editor renders them
  read-only, the self-service profile hides them, the admin API refuses a
  write that names one (`400`), and other channels keep the existing value
  rather than clearing it when the field is absent. Masterable fields are
  the profile columns, `upn`, `emails`, `manager`, and `custom.<key>` for
  custom attributes. Managed on the Integrations → SCIM page and over
  `GET|PUT /api/v1/scim/mastering`.

- **Outbound SCIM is multi-target.** FlareID can push users and groups to
  several SCIM servers at once - Cloudflare Access and Google Workspace side
  by side, or a second Access account for a different org slice - each with
  its own name, endpoint, write-only credential, sync scope and push tuning,
  the same shape the OIDC client and SAML service-provider lists already
  have. The Integrations → SCIM page becomes a target list with per-target
  detail pages (connection, scope, tuning, test & sync, delete), and the API
  gains `GET|POST /api/v1/scim/targets` and `GET|PATCH|DELETE
  /api/v1/scim/targets/{id}`; `POST /api/v1/scim/config` keeps working as the
  single-target view over the first target. Test and sync take an optional
  `target_id`, syncs stay single-flight per target, and pushes fan out: every
  enabled target gets the write, each paced by its own tuning. Deletion queues
  a downstream deprovision per target the object was linked to; deleting a
  target drops its links and queue but leaves the remote objects.

### Fixed

- **A stale push can no longer resurrect a deleted object.** With the move to
  per-target link tables (cascaded on delete), a push working from a row
  captured before a deletion now verifies the user or group still exists
  before creating it downstream.

- **API-key scope self-escalation.** `PATCH /api/v1/api-keys/{id}` applied
  the requested scopes without the cap the console has always enforced - a
  key holding only `api_keys:write` could rewrite its own scopes to
  `admin`. Both the PATCH and `POST /api/v1/api-keys` now refuse scopes the
  calling token does not itself hold.

- **Delegated federation write was a whole-directory takeover.**
  `federation:write` (handed out by `clients:write` and delegable to
  non-admin roles) could register or reconfigure an upstream identity
  provider - whose verified-but-unauthenticated claims then adopt *any*
  account by address match, including Super Admins. Registering, changing
  and removing upstream IdPs now needs an admin-scoped API key and Super
  Admin in the console; `federation:read` stays delegated.

- **SCIM custom-attribute writes bypassed the admin-role guard.** Inbound
  mapping writes to `custom_attributes` merged *after* the
  no-admin-role-grant check ran, so a `directory:write` key could set an
  attribute a role-linked dynamic group's rule matches and land the user
  in an admin group. The merge now happens before the check sees the row,
  on the correlate, PUT and PATCH paths (create already checked the
  merged set).

- **JIT provisioning skipped the admin-role guard.** A federated sign-in
  creating an account never checked the post-insert row against role
  linked dynamic-group rules - the only user-creation path that didn't -
  so upstream-controlled claim fields could place the new account in an
  admin group. It is checked now, like every other creator.

- **Authorization responses identify the issuer (RFC 9207).** Success and
  error redirects from `/authorize` (query and `form_post`) now carry
  `iss`, which the OIDF conformance suite requires.

- **The medium- and low-severity audit backlog is remediated.** The follow-up
  sweep from the third codebase-wide security audit:

  - Replay and one-shot hardening: `private_key_jwt` client assertions must
    carry `exp`/`iat`/`jti` and a seen jti is refused (RFC 7523); inbound SSF
    SETs need an `aud` naming this receiver, a fresh `iat`, and an unseen
    `jti`; KV get-then-delete one-shots (SAML/OIDC states, passkey and
    enrolment challenges, step-up actions, consent, device codes) now claim
    atomically in D1 so a replay inside KV's propagation window gets nothing.
  - Secret parity: `cfone.api_token`, `scim_targets.secret`,
    `upstream_idps` client secrets, LDAP service secrets and TOTP seeds seal
    at rest like the other credentials - out of backup bundles and snapshots.
  - Guard coverage: Cloudflare One watch actions pass `assertMayTouchUser`;
    system groups refuse SCIM/directory-import writes; the LDAP HTTP API
    checks the `ldap` permission area (not legacy scopes), `userinfo` and
    `introspect` honour the sign-in permission, and IdP/user-email writes
    reject alias/UPN collisions.
  - Session hygiene: browser logout notifies back-channel clients before the
    front-channel pass deletes `session_clients`, and device-grant approvals
    record their `session_clients` row so revocation reaches them.
  - Denial-of-service surface: edge rate limiting covers the previously
    unlisted auth-adjacent routes and charges the client dimension by a hash
    (DCR can no longer mint fresh client_ids to reset it), IPv6 `/48`
    rate-limit keys refund on failure, failed-login counting no longer
    scans the audit table, LDAP binds pad the timing gap and cap open
    connections, photo fetch redirects/timeouts/streaming are bounded, SAML
    SP metadata cert growth is capped, and API bodies are validated against
    their declared schemas.

- **The deferred validation items are resolved.** Placeholder secrets can no
  longer serve as the login-flow HMAC key; the conformance-export scrub
  catches base64/urlencoded/HTTP-Basic renderings of secrets, not only the
  literal strings; upstream IdP discovery and token-exchange fetches (and the
  jose remote-JWKS fetches behind them) carry timeouts, and discovery failures
  negative-cache for a minute; request bodies without Content-Length are
  buffered under the same 4 MiB ceiling as declared ones; managed domains must
  be syntactic DNS names (a suffix like "com" can no longer capture brand
  resolution or escape the delete-time LIKE); Analytics Engine queries time
  out instead of pinning admin pages; SAML ACS/SLO URLs are https-checked
  again at use time; and dynamically registered clients keep the grants and
  scope they declared (new `oauth_clients.grant_types`/`registered_scope`
  columns).

## [4.0.0] - 2026-11-17

**Migration `0032_user_emails.sql`** - `user_emails`, the per-account contact
address list; existing `users.email` values are backfilled as work primaries.
**Migration `0033_device_flow.sql`** - `device_codes` for the device
authorization grant.

### Added

- **OAuth `client_credentials` (service-account tokens).** Confidential
  clients can exchange their credentials directly at `/token` for a signed
  access token carrying `openid`/`email`/`profile`/`groups` claims about the
  client itself - machine-to-machine calls no longer need an API key or a
  signed-in user. Discovery advertises the grant, and `/introspect` reads the
  service JWTs too.
- **Device Authorization Grant (RFC 8628).** `POST /device_authorization`
  hands a device code and a short user code; the person approves at
  `/device` after signing in, and the device polls `/token` with
  `urn:ietf:params:oauth:grant-type:device_code` (honouring `interval`,
  `slow_down` and `authorization_pending`) until it is approved, denied or
  expires. Codes are single-use, hashed at rest, and swept by the hourly
  cleanup.
- **Multiple contact addresses per account.** `user_emails` holds the full
  list (work/home/anything) that SCIM `emails` carries; the primary is
  mirrored to `users.email` so every existing read path - LDAP `mail`, the
  `email` claim, invitations and reset links, email codes - keeps working.
  An address can only belong to one account, and people can sign in or
  recover with any listed address, not just the UPN. The user page gains an
  addresses editor, the API accepts and returns `emails` on user resources,
  and the raw JSON card on the user page shows the whole record minus
  credential material.
- **Outbound SCIM pacing and request sizing.** Group membership changes go
  as chunked `members` PATCH operations - never one giant PUT full of
  members - and full-sync PUT/POST bodies carry identity only, with the
  member set appended in pieces. Every remote call is paced. The receiver's
  limits are tunable under Integrations → SCIM (or `tuning` on
  `POST /api/v1/scim/config`): milliseconds between requests, member
  references per PATCH, and users per sync batch - for receivers bounded by
  per-request document limits.

### Fixed

- **A Terraform example** (`examples/terraform-access/`) that wires the
  Cloudflare Access integration in one apply: it generates the client
  credential, registers it over the API, creates the Generic OIDC identity
  provider with SCIM enabled, and points FlareID's outbound SCIM at the
  generated endpoint. Optional demo application included.
- **Sub-request performance telemetry.** A second Analytics Engine dataset
  (`flareid_spans`, binding `METRICS_SPANS`) records what inside a request
  costs time - password verification and hashing, token signing, the LDAP
  directory snapshot, outbound SCIM calls and email sends - and every audited
  action doubles as a counted event. The performance page gains a
  "Where the time goes" table, a security-events table, and a live strip of
  per-minute requests that refreshes every ten seconds.
- **A structured access log.** Every HTTP request logs one JSON line
  (`msg: "http.request"`, family, method, status, ms) to Workers Logs, so
  `wrangler tail` and Logpush see machine-readable traffic.

### Changed

- **Step-up re-authentication resumes the interrupted action.** A sensitive
  POST that needs a fresh sign-in is stashed server-side; completing the
  check replays it automatically instead of dropping the admin back on an
  emptied form. The stash is bound to the session, single-use, and expires
  inside the step-up window.
- **Console layout and density.** Card pairs in `two-col` grids now match
  heights; chart and ranked-bar labels render at the stat-label size
  everywhere (charts take a width matching their card so the SVG no longer
  upscales its text); the theme toggle shows icons instead of "Theme: x"
  text; `/admin/users` shows the filtered count in its heading; and more
  forms lay related fields out in pairs (`field-row`, which now stacks on
  small screens) - the SAML default-ACS/NameID pair, setup wizard, password
  policy checkboxes, Turnstile keys and the LDAP app name/slug.
- **Dashboard "IdP performance" card** also shows the busiest endpoint and
  the slowest endpoint p95, and non-link stat cards no longer get the
  hover highlight that implied they were clickable.
- **Spanish sign-in pages.** `es` joins `en`, `fr` and `de`, negotiated the
  same way (`?lang=`, cookie, `ui_locales`, Accept-Language or the instance
  default). The language links in the auth footer are now a compact dropdown
  with flags, which scales as more locales arrive.
- **Four more sign-in locales:** Brazilian Portuguese (`pt-br`), Simplified
  Chinese (`zh-cn`), Japanese (`ja`) and Italian (`it`), each flagged
  machine-assisted pending a native review. Locale matching also falls back
  across regions now - a browser asking for `pt-PT` gets `pt-br` rather than
  the instance default.
- **API keys are editable.** An existing key's name and permission set can be
  changed from its console edit page or `PATCH /api/v1/api-keys/{id}` -
  changes apply on the key's next request and the token itself never
  changes. The same holder-permission clamp as creation applies.
- **Failed sign-ins on the dashboard chart** are drawn as a red line on a
  right-hand axis instead of being invisible next to successful sign-ins.
- Charts fill their cards at any window width, ranked-bar labels are the
  same size as other body text, and the OIDC client form pairs its two
  URI lists and its two logout/algorithm fields in `field-row`s.
- The Groups list shows the filtered count in its heading, like Users.

### Fixed

- **SCIM `emails` writes validate before anything is stored.** A malformed
  address answers `400 invalidValue`, and an address held by another account
  answers `409 uniqueness` (checked before the user row is created on POST,
  so a conflict can't strand a half-written user). Previously a bad write
  could surface as a 500.
- The email-template form carries the accent colour too, so the page has one
  Save button; the preview script reads it off the same form.
- Multi-card columns in a `two-col` grid (the brand edit page) keep each
  card at natural height again - the equal-height rule only applies to a
  pair of cards, not to a column of several.
- The failed-sign-ins line and the p95 latency line draw a card-coloured
  halo under the stroke, so the line stays readable where it crosses a bar.
- **Directory writes no longer wait on the SCIM remote.** Creating, editing,
  or deleting a user or group used to await the outbound provisioning pushes
  - one call for the object, then one per affected group - so a slow or
  overloaded SCIM endpoint could hold a save open for tens of seconds. The
  pushes are post-response work now (`executionCtx.waitUntil`), the same
  pattern the inbound SCIM server already used, and anything missed is still
  reconciled by the hourly sync.

### Security

- **Remaining run-2 audit findings closed.**
  - The LDAP frame reader accumulates chunks and joins once per frame - a
    peer pacing writes can no longer inflate per-frame CPU quadratically.
  - The search deadline is checked per candidate (not only after a match)
    and applies a 30s server cap when the client sets no `timeLimit`, so a
    non-matching scan can no longer run unbounded; DN-valued filter
    comparisons parse each stored DN at most once per entry.
  - Critical controls are honoured per RFC 4511 - an unsupported critical
    control fails the whole op with `unavailableCriticalExtension`, and a
    malformed paged-results control refuses instead of silently running
    unpaged.
  - Schema attributes can no longer be defined under names the LDAP
    directory asserts itself (`memberof`, `objectguid`, ...), and stored
    custom attributes are never emitted under reserved names - a
    group-less user's `memberOf` is no longer forgeable.
  - Failed LDAP user binds now pay a uniform verification cost across hash
    formats, closing the legacy-format timing oracle.
  - LDAP console pages join the `ldap` admin area (`ldap:read` /
    `ldap:write`); every unmapped `/admin` path now fails closed to Super
    Admin instead of failing open to any admin role.

## [3.10.0] - 2026-11-16

**Migration `0030_ldap.sql`** - `ldap_apps` and the `ldap_*` settings.
**Migration `0031_ldap_secret_reveal.sql`** - `ldap_apps.secret_enc`.

### Added

- **An LDAP interface.** FlareID now answers LDAPv3 over TCP - a read-only,
  LDAPS-only view of the directory, delivered to the Worker's `connect()`
  handler by Spectrum's Worker origin (ports 636 and 3269). The design and
  rationale are in [LDAP.md](LDAP.md).
  - **Per-app branches.** Every registered LDAP app gets its own subtree
    (`ou=<slug>,<base>`), its own service bind DN
    (`cn=<slug>,ou=services,<base>`) and its own policy: bindable groups,
    exposed groups, disabled-user visibility and MFA mode.
  - **Binds.** Service binds authenticate apps; user binds resolve DNs, UPNs,
    `NETBIOS\user` and bare usernames, share the web sign-in lockout buckets
    and dummy-hash timing, and take TOTP in the password field as
    `<password>,<code>` per the app's MFA mode (with a short re-bind window
    for clients that open a fresh connection per operation).
  - **Search, compare, whoami and RFC 2696 paging** over a snapshot refreshed
    every 30s; entries cover inetOrgPerson/posixAccount plus the AD surface
    (sAMAccountName, objectGUID/objectSid, memberOf, userAccountControl,
    objectCategory matching) so AD-shaped filters work against Grafana,
    GitLab, sssd and friends. Ranged retrieval (`member;range=L-H`) and the
    RFC 2891 server-side sort control are supported for AD-style clients.
  - **Password Modify (RFC 3062).** User-bound connections can rotate their
    own password with `oldPasswd` verified against the live credential;
    a change runs the same compromise response as the account page
    (sessions revoked, tokens revoked, passkeys dropped).
  - **Admin and API.** Integrations → LDAP manages settings and apps (the
    secret is shown once, with generated client configs for Grafana, sssd,
    GitLab, Jenkins and ldapsearch); `/api/v1/ldap/apps` and
    `/api/v1/ldap/settings` provision the same. Binds and admin actions join
    the audit log under the new `ldap` family; searches stay out of it and
    are counted in Workers logs. App secrets are stored KEK-sealed, so the
    console's Reveal and `POST /api/v1/ldap/apps/{slug}/reveal` can show the
    current secret without a rotation; reveals are audited.

### Security

- **LDAP bound state is re-validated per operation.** Settings are re-read
  on every op, so disabling LDAP disconnects in-flight connections on their
  next operation; service binds are disconnected when their app is revoked;
  user binds are re-checked for status and app group membership, and a
  disabled or de-grouped user drops to anonymous. Password Modify verifies
  `oldPasswd` against the live hash, not the bind-time snapshot.
- **A failed LDAP bind discards the previous authentication** (RFC 4511
  4.2.1) instead of retaining the prior principal.
- **User-bound scoping is per-entry.** A bound user sees only their own
  entry and the group entries they belong to (with `member` reduced to
  themselves), and compare gets the same authorisation as search - foreign
  entries return `noSuchObject` rather than answering as an oracle.
- **Partial LDAP app updates keep omitted policy fields.** `POST
  /api/v1/ldap/apps` on an existing slug no longer resets group
  restrictions, MFA mode or disabled-user policy to create defaults.
- **Passkey ceremonies work when a user scope is present.**
  `allowCredentials[].id` is now converted from base64url to BufferSource
  before `navigator.credentials.get`; the omission broke every user-scoped
  assertion (MFA step and step-up re-authentication).
- **Authorization scopes are bounded at intake.** `/authorize` caps the
  `scope` parameter at 512 characters before it is stored verbatim on grant
  rows. (Effective claims were already intersected with the client's
  `allowed_claims`; this is input hygiene, not a behavior change.)

## [3.9.3] - 2026-11-15

No migrations. The confirmed low-severity audit findings in one pass -
token and code lifecycle, SAML unlinkability, SCIM delta correctness,
input bounds and a login timing equalization - plus the audit's
remaining validation leads.

### Security

- **Revocation now covers every credential in a grant.** Revoking a
  connected app (self-service or admin) deletes its unredeemed
  authorization codes too, and `POST /revoke` on a refresh token
  invalidates the access tokens the grant issued - refresh-minted access
  tokens are linked to the family by `code_hash`, so reuse-detection
  revocation reaches them as well (RFC 7009 §2.1).
- **Sign-in permission is re-checked at credential minting.** The refresh
  grant and authorization-code redemption both refuse `invalid_grant`
  once the user's roles no longer include `signin`, and `/saml/complete`
  re-evaluates it at redemption rather than trusting the parked flow.
- **The passkey factor switch is a gate, not only UI.** Disabled passkeys
  cannot authenticate (`/login/passkey*`) or enrol (`/account/passkeys*`),
  matching the checks the MFA verification path already applied.
- **SAML transient identifiers are unlinkable across service providers.**
  The transient NameID and SessionIndex now derive from
  `sha256(session id | entity id)`, so two SPs can no longer correlate the
  pseudonym to link one user's sessions. Single-use AuthnRequest replay
  keys are namespaced per SP, and ACS/SLO endpoints must be `https://` on
  every registration path - admin form, metadata import and API upsert -
  with `default_acs_url` required to be a member of `acs_urls`.
- **SCIM outbound calls are bounded and deltas are complete.** `scimFetch`
  applies a 10-second timeout so one stalled remote cannot head-of-line
  block the sync, and a membership PATCH now removes a member's previous
  remote id when it rotates instead of leaving a stale reference in the
  remote group.
- **Input bounds tightened.** `GET /api/v1/audit` clamps `limit` into
  1..500 (a negative value was SQLite-unlimited); the default-brand
  `app_name` and `login_subtitle` enforce the documented 60/140-character
  caps on every write path; `logAudit` bounds `details` (4 KB) and
  `user_agent` (512) the way `target` already was; the console domain
  set-default refuses an unknown id instead of leaving zero defaults, and
  `deleteDomain`'s last-domain and in-use refusals are enforced inside the
  DELETE statement so concurrent writes cannot slip past the check.
- **Every refused sign-in costs a uniform verification.** Login failure
  now always pays one scrypt plus one PBKDF2 verification, so response
  time cannot distinguish an unknown username from an account on a legacy
  hash format.
- **Other hardening.** The `/admin` overview hides its audit-derived
  sections (most-active accounts, sign-in outcomes, directory activity)
  from roles holding neither `performance:read` nor `audit:read`, matching
  the API's bar for the same numbers; the hourly cleanup keeps
  rate-limit counters alive at least as long as the configured window;
  `replace` imports and the remove-sample-data wipe keep the `All
  Employees` built-in the docs promise; clearing a user-editable attribute
  named `constructor` actually removes it; Turnstile accepts a token
  solved on any hostname the deployment serves (e.g. a brand's custom
  domain), not only the issuer host; and the setup/helper scripts write
  credential-bearing files `0600`.
- **Email headers and anonymous bodies bounded.** `sendEmail` now
  enforces the contract at the `send_email` binding boundary: the
  recipient must be a single well-formed address, and CR/LF is stripped
  from the subject and display name, so a stored brand name or an
  imported contact address cannot inject header lines. A request
  declaring a body over 4 MB gets a 413 before the parser buffers it.
- **SAML default ACS and login-flow sealing.** `resolveAcsUrl` honours
  `default_acs_url` only while it is a registered ACS, so a stale or
  hand-edited row cannot redirect assertions outside the allowlist; and
  the sealed-flow MAC refuses placeholder-length secret material rather
  than deriving a forgeable key.
- **Conformance CI: secrets out of the artifact.** The exported suite
  results are scrubbed of the shared secrets they can embed - client
  secrets, the seeded user's password, the suite token - before the
  artifact upload (`conformance/redact-exports.mjs`).

## [3.9.2] - 2026-11-15

Migrations: `0028_consent_claim_groups.sql`, `0029_repairs.sql`. The rest of
the confirmed medium-severity audit findings: consent tracking, credential
lifecycle, policy-write safety, rate-limit dimensions, secret hygiene and
SCIM/SAML robustness.

### Security

- **OIDC `claims=` requests now share consent with the scopes they imply.**
  Consent was recorded per requested scope only, so a client holding consent
  for `openid` could add `claims={"id_token":{"department":...}}` and release
  attributes the user was never asked about. Consent now tracks the union of
  scopes and the claim groups the `claims` parameter resolves to, both at
  `/authorize` and in the OIDC session grant path (`0028`).
- **Password and passkey lifecycle fixes.** Changing your password rotates
  the session id (a cloned cookie dies with the old one), a completed
  password reset clears WebAuthn credentials (a passkey an attacker
  registered no longer survives the reset), and adding or removing a
  passkey now needs a fresh session or the current password within the
  step-up budget - a bare session cookie can no longer mint a standalone
  multi-factor credential. Removal goes through a confirmation page that
  asks for the password when the session is stale.
- **Identity and setup admission.** `users` writes reject UPNs that break
  the username pattern, duplicate another account's UPN, or name a domain
  the deployment does not serve; `POST /api/v1/setup` refuses
  domain/complete effects for non-privileged callers; the MFA gate no
  longer accepts a TOTP or passkey the account has disabled.
- **Policy-write guards.** Auth-policy writes that would require MFA while
  no usable factor exists are refused instead of locking every admin out
  (`assertFactorsExistForMfa`), and saving or applying the default
  password runs the breached-password check the single-user path already
  had.
- **Migration repairs for name-keyed bindings** (`0029_repairs.sql`):
  upgrades that bound admin roles or the admin MFA policy to objects by
  display name are re-bound by id - a renamed policy or group can no
  longer silently un-guard administrators or smuggle an admin grant in.
- **Rate-limit dimensions an attacker could mint are gone.** The edge
  limiter only keys `/token` per `client_id` for clients that actually
  exist (a made-up id no longer gets its own budget), and IPv6 sources are
  charged at both /64 and a shared /48 so rotating subnets cannot escape
  the budget.
- **`/jwks.json` can never republish private key material.** Env-supplied
  public JWKs (`SIGNING_PUBLIC_JWK`, `SIGNING_PUBLIC_JWK_PREVIOUS`) are
  stripped of private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`,
  `k`) at storage and again at publish time.
- **Scheduled SAML SP-metadata refresh may only strengthen trust
  configuration.** The unsigned remote document previously rewrote ACS
  allowlists, signing certs, signed-request and encryption requirements
  wholesale. A refresh now keeps registered ACS endpoints (never adds, and
  only narrows when the publisher withdraws), unions signing
  certificates, preserves `want_authn_requests_signed` and
  `encrypt_assertions` once enabled, applies https-only endpoints, logs a
  `saml.metadata_refresh_held` audit entry when it declines a change, and
  still tracks non-security fields. The fetch no longer follows redirects
  (the registered https URL is what authenticates the publisher) and the
  256 KB cap is enforced while the body streams in, not after buffering.
- **SCIM full sync is single-flight and creates are race-safe.** The
  console poller, `POST /api/v1/scim/sync` and the hourly cron can no
  longer run overlapping syncs (a DB lock coalesces the loser into a
  `busy` response). Link writes are guarded by `scim_id IS NULL` - a
  losing remote id is queued for deprovision instead of orphaned - and a
  409 from the remote resolves the existing object by `externalId`/
  `userName` and adopts it.
- **Conformance CI no longer runs mutable, unpinned code next to
  secrets.** The workflow clones the conformance suite at a pinned commit
  (the tag is verified, not trusted), installs Python deps from a
  hash-locked `conformance/requirements.txt`, scopes each secret to the
  step that needs it, keeps result artifacts 14 days, and the local
  conformance script redacts `code`/`state`/tokens from what it prints.
  `conformance-results/` is git-ignored for local runs.

## [3.9.1] - 2026-11-15

No migrations. Fixes from a deep security audit of the whole codebase: the
theme is delegated credentials (API keys, scoped admin roles, SCIM
provisioning) exceeding their intended authority at seams where a second
write path skipped an invariant the console enforced.

### Security

- **Admin roles can no longer be granted through dynamic-group attributes
  from a non-Super credential.** A group linked to an admin role with a
  dynamic rule (for example `department = "IT"`) was previously only safe
  against the console: a `users:write` API key could create or PATCH a
  user's attributes to match the rule, `import:write` could do the same
  through a directory bundle (and could overwrite or delete the role group
  itself, or write a rule against it), and `directory:write` SCIM keys
  could push members into it because the SCIM server only refused changes
  to a group literally named "Super Admins". Every write that could land a
  user in a group linked to an admin role now simulates the post-write
  user row against that group's rule and refuses the match (403 / bundle
  rejection) unless the actor is privileged - Super Admin or an `admin`
  API key - covering user create/update/status/invite, import bundles
  (rule fields are also restricted to the non-user-editable set on write),
  and the SCIM server, whose name-only guard is replaced by the real
  role-linked-group check for group renames, member replacement,
  membership deltas and deletes. The role name itself is no longer
  trusted as a marker: bindings are resolved by group id.
- **Step-up re-authentication is deny-by-default and id-safe.** The
  sensitive-path allowlist missed a number of admin mutations - including
  `POST /admin/users` and `/admin/users/:id/status`, so a stale admin
  session could create and activate a new Super Admin - and matched ids
  with `\d+`, which `+2`-style encodings slipped past. Every admin POST is
  now sensitive except the reauthentication endpoints themselves, and the
  non-super guard matches the full path-shape the routes declare instead
  of the digits.
- **The MFA gate can no longer be satisfied by enrolling into it.** When a
  session needed a second factor the middleware let `/account/mfa*` and
  `/account/passkeys*` through for both gate outcomes; a password-only
  session that was meant to sign in again could instead enrol a factor and
  upgrade its own `amr`. That path now revokes the untrusted session. The
  passkey ceremony also upgrades `amr` in the request that stores the
  credential (and `/account/passkeys-enrolled` only honours the session
  that ran the ceremony), so a fresh session is never killed mid-enrolment.
- **`apply-to-all` on domains is a Super-only action.** Rewriting every
  user's UPN to an attacker-registered domain (then harvesting a
  forgotten-password link) needed only `domains:write` in the console; the
  API already required `admin`. The console route and middleware now gate
  it on Super Admin, the button is hidden from other administrators, and
  the same-page validation requires the new UPN domain to be a registered
  domain.
- **Stored secrets are no longer rendered to read-only roles.**
  `/admin/integrations/scim` rendered the SCIM bearer secret and
  `/admin/security` rendered the shared default password into the page for
  any holder of `scim:read`/`security:read` (including Auditors), while
  the API never returned them. Both fields are now write-only - blank
  keeps the stored value, clearing the SCIM endpoint removes the
  credential - matching the existing Turnstile-secret convention.
- **The outbound SCIM endpoint is validated and the client is hardened.**
  A `scim:write` key could store an arbitrary URL and have the worker push
  the whole directory to it with the Bearer credential attached - an SSRF
  read primitive on top of exfiltration, since redirects were followed
  with credentials and downstream error bodies were returned to the
  caller. Endpoints must now be plain `https:` URLs (no credentials,
  query or fragment) whose host is not loopback, private, link-local,
  CGNAT, benchmarking or multicast space, in every spelling the URL
  parser normalizes (hex/integer IPv4, `*.localhost`, IPv4-mapped and
  unique-local IPv6); the setting is re-validated on every outbound call.
  Redirects are followed by hand and the credential is only resent while
  the target stays on the configured origin; downstream error bodies are
  bounded to 300 characters before they are logged or returned. The
  console POST surfaces a validation error inline instead of failing
  silently.

## [3.9.0] - 2026-11-12

No migrations.

### Changed

- **Administrators' second factor: secure by default, but changeable.**
  Whether an administrator needs a second factor is now decided by the
  authentication policy that applies to them, like everyone else, instead of
  being hard-coded. A fresh install still requires it: Super Admins are in
  "Password and a second factor", which is also the default policy. An
  instance can choose otherwise:
  - at setup, with the new **Require a second factor for administrators
    (recommended)** box on `/setup`, ticked by default, or `admin_mfa` on
    `POST /api/v1/setup` (omitted: the policies are left as they are, which on
    a fresh install means required). Unticked / `false` takes Super Admins out
    of every policy that requires a second factor and makes "Password only"
    the default, so the first administrator signs in with the password alone
    (`admin_mfa: false` needs the `admin` scope, and with `require_mfa: true`
    is a `400`). `true` puts
    Super Admins back in "Password and a second factor";
  - afterwards, under Security > Policies (a step-up-protected action):
    take the Super Admins group out of "Password and a second factor" (and
    make a password-only policy the default, if the default requires one).
    The edit form asks before saving the policy that makes administrators use
    a second factor (or before making a password-only policy the default
    while the default is what covers them), the Policies page warns, naming
    them, while any administrator can sign in with a password alone, and the
    Roles page says so per administrator. Changes that leave administrators
    newly without the requirement are audited with `admin_mfa_relaxed: true`
    and `admins_without_mfa` (`auth_policy.created`/`updated`/`deleted`,
    `role.created`/`updated`, `settings.require_mfa_changed`, and
    `idp.setup_completed`).

  When a policy does require a second factor of an administrator, the rules
  for its strength stay: security questions never count (not offered at
  sign-in or forced enrolment, a session that used them is bounced, and
  `/account/mfa/questions` refuses administrators), and Super Admin step-up
  never accepts them. The last of the authenticator app, passkeys and email
  codes can be switched off only while no policy requiring a second factor
  applies to an administrator; otherwise only the existing "a policy requires
  one" guard applies.

## [3.8.0] - 2026-11-12

Migrations `0026` (SCIM group state) and `0027` (brands). Branding (logo
upload, per-domain brands, custom CSS), the sign-in pages in English, French
and German with a WCAG 2.2 AA pass, SCIM group updates that send only the
change, group lists that read the directory once, and second-factor columns
that count every factor. Remaining roadmap items are GitHub issues #1-#8.

### Added

- **Languages.** The sign-in, second-step, consent, sign-out, recovery,
  reset, invitation, setup and sign-in error pages are translated: English
  (the source), French and German (machine-assisted, marked so in their files;
  review welcome). The strings are JSON resource files in `locales/`, bundled
  at build time, with `{placeholder}`s and `.one`/`.other` plural forms
  (`src/lib/i18n.ts`); a missing key falls back to English, and
  `test/i18n.test.ts` fails any locale whose keys or placeholders differ from
  `en.json`. The language is `?lang=` (remembered in a `flareid_lang` cookie),
  then that cookie, then the sign-in flow's language - carried in the sealed
  flow and the pending second step, and seeded from OIDC `ui_locales` - then
  `Accept-Language`, then a new **Default language** under Admin → Branding
  (`default_language` on `GET`/`PATCH /api/v1/branding`, which also lists
  `available_languages`). The sign-in page has a language picker
  (`/login/language`, which keeps the sign-in in progress); Turnstile is asked
  for the page's language. Pages set `<html lang>` and `dir` (a locale can
  declare `"dir": "rtl"`). See [docs/i18n.md](docs/i18n.md), and
  CONTRIBUTING.md, "Adding a language".
- **Accessibility (WCAG 2.2 AA) on the same pages.** One `<h1>` each (visually
  hidden on the sign-in page) and the card as the `<main>` landmark; errors in
  a `role="alert"` region, tied to the inputs they concern with
  `aria-invalid` and `aria-describedby`; password fields described by the
  policy text; `autocomplete="username"`/`current-password`/`new-password`/
  `one-time-code` throughout; every input, including "Remember this device",
  with a `<label for>`; a visible focus outline; the passkey status line a
  live region; the Turnstile widget a labelled group; "Sign in again"-style
  actions are styled links rather than a button inside a link; the second
  step's page titles name the method ("Check your email", "Security
  questions"); the cursor trail is `aria-hidden` and does not run at all under
  `prefers-reduced-motion: reduce`.

- **Logo upload.** Admin → Branding takes a logo (PNG or JPEG, at most
  256 KB, validated by its magic bytes - not its name or declared type) shown
  on the sign-in pages, in the top bar and at the top of emails (by absolute
  `${ISSUER_URL}/brand/logo/...` URL). Logos are stored in D1 (new migration
  `0027_brands.sql`: `brand_assets`, base64) and served from
  `GET /brand/logo/<id>-<hash>.png|jpg` with a year-long immutable cache
  lifetime; a replaced or removed logo is deleted, and "Remove logo" brings
  back FlareID's mark. **SVG is refused**: it can carry script, and most email
  clients do not display it anyway.
- **Per-domain branding.** Branding → Brands: brands with their own app name,
  sign-in message, gradient, email accent, logo and custom CSS, each falling
  back to the default brand's where left empty, attached to UPN domains from
  the brand's page or the Domains page (`brands` table, `domains.brand_id`).
  Before someone is identified the sign-in and recovery pages use the domain
  of the OIDC `login_hint` (or `/login?domain=` / `?login_hint=`), carried in
  the sealed flow, else the hostname when it is a branded domain or a
  subdomain of one - never the issuer's own hostname - else the default
  brand. Once they are identified - the second step, consent, sign-out
  confirmation, My account, reset and invitation link pages - and in every
  email to them (invitation, reset, sign-in code), their UPN's domain decides.
  The admin console, the issuer and the OIDC/SAML metadata keep the default
  brand. See [docs/branding.md](docs/branding.md).
- **Custom CSS.** Per brand, up to 20 KB, linked as a stylesheet from
  `GET /brand/css/<default|id>-<hash>.css` (`text/css`, `nosniff`, never
  inlined) on the sign-in, second-step, consent, recovery, invitation and setup
  pages only - never the admin console or My account, so a broken stylesheet
  cannot lock administrators out. Saving refuses `</style`, `@import`,
  `url()` other than same-origin paths and `data:` URLs, remote URLs in
  strings, `expression(`, `javascript:`, `-moz-binding` and `behavior` (checked
  after decoding CSS escapes); the Content-Security-Policy is unchanged and
  blocks remote fonts and images regardless. `?nocustom=1` on any of those
  pages switches custom CSS off for that browser until `?nocustom=0`.
- **Preview.** `/login?brand_preview=<id|default>` renders the sign-in page in
  a brand for a signed-in administrator with `branding:read`; linked from each
  brand's page. Ignored for anyone else.
- **API.** `GET`/`PATCH /api/v1/branding` gain `logo_url`, `custom_css`,
  `css_url` and `preview_url`; new `PUT`/`DELETE /api/v1/branding/logo`,
  `GET`/`POST /api/v1/branding/brands`,
  `GET`/`PATCH`/`DELETE /api/v1/branding/brands/{id}`,
  `PUT`/`DELETE /api/v1/branding/brands/{id}/logo` (logos as base64 JSON) and
  `PUT /api/v1/domains/{domain}/brand`; `GET /api/v1/domains` gains
  `brand_id`. Each console action is mapped in the API parity test.

### Changed

- **Contrast on the sign-in pages.** Their accent colour (links, primary
  buttons, focus) is `#c2410c` instead of Cloudflare orange `#f6821f`, whose
  white button text and links measured 2.6:1; the new one is 5.2:1 on white
  (WCAG 1.4.3 asks 4.5:1). Placeholders use the muted text colour (4.8:1). The
  admin console keeps its colours.
- Every page's `<html>` carries `lang` and `dir` (`page()` takes the language
  as its last argument; the console is `en`); the centred-card layout's
  wrapper is a `<main>`. `passwordPolicySummary`, `validatePassword`,
  `newPasswordError` and `breachMessage` take an optional locale (English
  wording unchanged); `loginForm`, `mfaForm` and `AuthMessage` take message
  keys (`msg()`, `fieldMsg()`) or text, and `LoginAppearance` has the page's
  `locale`.
- `sendEmailOtp` and `buildEmail` take the recipient's brand instead of an app
  name; `getLoginAppearance` takes a brand, and the auth-page views
  (`authPage`, `loginForm`, `mfaForm`, `authMessagePage`) read the app name
  from the appearance.
- **Group lists read the directory once.** `GET /api/v1/groups` and the SCIM
  server's `GET /scim/v2/Groups` resolve every listed group's members in one
  pass (`resolveManyGroupMemberUserIds`): one read of the users table for all
  dynamic groups instead of one per dynamic group (4 → 1 for a list with four
  dynamic groups), and one lookup for every member's SCIM reference on a
  page. A SCIM list asked to leave members out (`excludedAttributes=members`,
  or `attributes` without `members`) resolves none at all and omits the
  attribute.
- **SCIM group updates send only the change.** FlareID records what the SCIM
  server last accepted for each group (new migration
  `0026_scim_group_state.sql`: `scim_group_state` and `scim_group_members`)
  and updates an existing remote group with an RFC 7644 PATCH - `add` on
  `members` and `remove` on `members[value eq "…"]`, at most 1000 member
  references per request, `replace displayName` on a rename - instead of
  PUT-ing every member again; a group whose membership did not change is not
  sent at all. A full PUT is still sent when nothing is on file, when more
  than half the group changed, or when the server refuses the PATCH; a 404
  recreates the group. Full syncs (Sync now, the cron, a scope change) still
  PUT every group and refresh the record. A one-person import into a
  2,000-person sample directory went from three group PUTs (~164 KB, the
  whole of "All Employees" and "Everyone outside London") to none; moving one
  person between two large groups is two PATCHes of under 300 bytes. This
  is what made `scripts/oidc-suite-setup.mjs` take over a minute and a half:
  its conformance user sits in the dynamic groups its empty attributes match.
- **MFA columns count every factor.** "Has a second factor" now means an
  authenticator app, at least one passkey, email codes or security questions
  everywhere it is shown: the Users list's MFA column names them ("Authenticator
  app, Passkey") and its MFA filter ("Has a second factor" / "No second
  factor") uses the same SQL; the overview's "MFA enrolled" and coverage count
  anyone with a factor, with a per-factor breakdown; the user page lists each
  factor, including passkeys, and marks an administrator's security questions
  as not counting; My account says which second factors you have (those
  switched on), and its
  former "Two-factor authentication" card is now called "Authenticator app".
  API: user objects gain `second_factors` (`totp`, `passkey`, `email_otp`,
  `security_questions`) - `mfa_enabled` still means the authenticator app -
  and `GET /api/v1/stats` gains a `second_factors` breakdown, with
  `counts.mfa_enrolled` now counting any factor.
- **The CSRF refusal carries the security headers itself.** `csrfProtection`
  now runs the same header code as every response (`applySecurityHeaders`,
  factored out of `securityHeaders`) on its 403 - CSP, `X-Frame-Options`,
  `nosniff`, HSTS, `no-store` - instead of relying on the middleware mounted
  around it. (In the app as mounted, `securityHeaders` already wrapped it; the
  refusal no longer depends on that.)

### Security

- **Administrators cannot set security questions.** A direct
  `POST /account/mfa/questions` from anyone holding an admin role is refused
  (403, on the styled error page, audited as
  `user.security_questions_refused`), as the sign-in and forced-enrolment
  pages already did not offer them. My account shows the Security questions
  card without a form for administrators, with the reason - and the remove
  form if they set questions before the role was granted.

## [3.7.0] - 2026-11-12

Deployable from the **Deploy to Cloudflare** button, with first-run setup in
the browser; administrators always need a strong second factor; errors are
pages; step-up asks for an emailed code when that is the second factor.

### Added

- **Deploy to Cloudflare button.** The README has the button and a
  step-by-step walkthrough: Cloudflare copies the repository into your
  GitHub/GitLab, provisions D1 and KV, asks for the two secrets listed in the
  new `.dev.vars.example` (`BOOTSTRAP_TOKEN`, `KEY_ENCRYPTION_KEY`, described
  in `package.json` `cloudflare.bindings`), applies the migrations and
  deploys.
- **First-run setup in a browser at `/setup`**: the bootstrap token, the
  primary domain and the first Super Admin (username, display name,
  password - policy and breached-password check apply). It runs the same
  `runSetup()` as `POST /api/v1/setup` (now in `services/setup.ts`), then
  sends the administrator to sign in and enrol a second factor. Rate-limited,
  origin-checked like every form, audited (`via: "setup_page"`; a wrong token
  as `idp.setup_token_rejected`), and inert once setup is complete. `/` and
  `/login` send a visitor there while the instance has no one to sign in as.
  Unset or `replace-me` placeholder secrets get instructions instead, and the
  placeholders are never accepted as a bootstrap token by the API either.

### Changed

- **`ISSUER_URL` is empty by default and worked out at runtime**: before setup,
  the request's https origin (http only on localhost; other plain-http
  requests are refused); setup stores the issuer it completed on
  (`idp_settings.issuer_url`, from the console, the API or `/setup`) and it is
  fixed from then on, whatever Host a request arrives with. A non-empty
  `ISSUER_URL` still pins it. Add a custom domain before running setup.
- **`wrangler.jsonc` carries nothing of one deployment**: `ISSUER_URL` is
  `""`, and `SIGNING_PUBLIC_JWK`, `SIGNING_KEY_ID` and `SAML_SIGNING_CERT` are
  gone from vars. Signing keys are generated in D1 under `KEY_ENCRYPTION_KEY`;
  SAML needs `SAML_SIGNING_KEY_PKCS8` and `SAML_SIGNING_CERT` both set as
  secrets (`npm run saml:keygen` now writes them to a private temporary
  directory and prints the two `wrangler secret put` commands). Sealed login
  flows fall back to `KEY_ENCRYPTION_KEY` when neither `SIGNING_KEY_PKCS8` nor
  `COOKIE_ENCRYPTION_KEY` is set, so they stay free of KV writes.
- **`npm run deploy` is migrate-and-deploy** (`wrangler d1 migrations apply DB
  --remote && wrangler deploy`), as Workers Builds runs it. The terminal
  helper is now `npm run deploy:cli`; it sets `KEY_ENCRYPTION_KEY` (fresh
  installs only) and the SAML pair as secrets, no longer generates an RS256
  keypair or sets `COOKIE_ENCRYPTION_KEY`, deploys once, and points at
  `/setup`. The `db:migrations:*` scripts use the binding name.

- **Errors are pages, not bare text.** Every refused or failed action in the
  admin console (a duplicate group or schema name, a missing item, a role
  that cannot do this, an invalid form) now shows in the console with a
  title, the reason and **Go back**, which returns to the form with what was
  typed. My account, the admin access refusals, unknown addresses, server
  errors, the edge rate limit and the cross-site refusal do the same for
  browsers; API, SCIM and token endpoints still answer in their own formats.

### Security

- **Step-up re-authentication asks for an emailed code** when email codes are
  someone's second factor (no authenticator app): "Confirm it's you" now
  offers **Email me a code** and needs it with the password, instead of the
  password alone - weaker than their sign-in. A passkey still confirms on its
  own; security questions never do. Audited as `admin.step_up_code_sent` and
  `admin.step_up` with `method: "password+email_otp"`.
- **Administrators always need a strong second factor**, whatever the
  authentication policies say: anyone holding a role beyond the default User
  role must use the authenticator app, a passkey or email codes. Security
  questions never count for them (not offered at sign-in or forced enrolment,
  and a session that used them is bounced); a password-only session goes to
  `/account/mfa/setup`, or back to sign-in if they have a factor but did not
  use it. The last of those three factors cannot be switched off, and
  Security > Roles shows each administrator's second factor. Finishing a
  forced enrolment now re-checks the rule before resuming the app's sign-in.

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
