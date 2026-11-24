# FlareID security audit — run-4 report

## Run

- **Profile:** deep · **Scope:** whole codebase (`.`)
- **Source ref:** `f98ce6d` (v4.13.0 head, plus the remediation commits described below)
- **Execution:** source-level review by five hunter agents over disjoint units
  (auth/session surface, SAML surface, federation/social, API + scope boundaries,
  cross-cut: SSRF/secrets/rate-limits), triaged and fixed in-tree.
- **Prior runs:** run-3 (deep whole-repo, `0972885`, 57 records — all remediated).
  One run-3 `needs_validation` carryover was re-hunted: the declared
  `Content-Length` cap bypass — **confirmed at source and fixed** in this run.

## Results

**18 confirmed findings:** 1 high · 5 medium · 12 low. All remediated in the
same working tree (uncommitted at report time; the release below carries them).
Nine regression tests added (`test/audit-run5.test.ts` — named for the audit
session; covers the high and the highest-value mediums/lows end-to-end).

### Confirmed high

1. `saml:require-mfa-not-enforced-on-fresh-login` — `completeLoginFlow`
   (`src/routes/login.ts`) checked app assignment and posture but never
   `appRequiresMfa`/`amrSatisfiesMfa`. A fresh password login to an SP with
   `require_mfa` (or an `mfa`-requirement policy) was issued an assertion with
   `amr=["pwd"]` — reachable when the user had no factor enrolled, so the
   pending-MFA step silently downgraded. Fixed: the SAML branch now answers a
   signed `RequestDenied`, matching the OIDC path (`authorize.ts:84`).

### Confirmed mediums

1. `cfapp:granting-group-can-be-admin-role` — `configureAccessApp` accepted
   admin-role groups as the granting group; the queue hid approve from
   non-supers but showed no `Admin access` badge, so a `cfone:write` admin
   created a request path into e.g. Super Admins. Fixed: rejected like
   `addGroupManagers`; picker and badge updated (`cfone.ts`, `admin.ts`).
2. `api:access-request-decide-wrong-scope` — `POST /api/v1/access/requests/{id}`
   charged `groups:write` regardless of target; an approval writes the app's
   assignment, so app targets now charge `oidc:write`/`saml:write`
   (`api/access.ts`) — the console rule.
3. `saml:ispassive-enrol-gate-fallthrough` — `IsPassive` + unsatisfied
   enrolment gate fell through to an assertion; now answers `NoPassive`
   (`saml.ts`).
4. `federation:email-verified-ignored-on-adoption` — account adoption
   (linkIdentity by email match) trusted unverified upstream emails; now gated
   on a verified claim (`federation.ts` `profileFromClaims` /
   `resolveFederatedUser`).
5. `step-up:secret-fields-stashed-and-echoed` — `stashPendingAction` replayed
   arbitrary POST bodies into KV and the resume page; fields matching
   `password|secret|token|key|credential` now refuse the stash (admin retypes)
   (`step-up.ts`).

### Confirmed lows

- `access:group-swap-display` — request rows now snapshot the granting group id
  at request time (`TARGET_EXTRA`), so retargeting a group can't hide which
  group approval would write (`access.ts`).
- `access:assign-missing-touch-guard` — `assignUserToApp` gained
  `assertMayTouchUser` (`access.ts`).
- `api:cfapp-enum-missing` — `cfapp` added to `target_type` on the file-request
  route and schema (`api/access.ts`).
- `ssrf:outbound-follows-redirects` — `redirect: "error"` on request_uri,
  `sector_identifier_uri`, and federated token-exchange fetches (a 307/308
  would re-POST `code`+`client_secret`) (`request-object.ts`,
  `registration.ts`, `federation.ts`).
- `policy:dangling-policy-id` — `assertPolicyExists` wired into every
  `policy_id` writer; dangling ids now 400 (`auth-policy.ts` + call sites).
- `saml-inbound:conditions-scd-optional` — inbound federated assertions now
  require `Conditions` and `SubjectConfirmationData` and reject NaN
  timestamps (`federation.ts verifySamlResponse`).
- `scim:repoint-keeps-bearer` — repointing a target endpoint drops the sealed
  Bearer; supplying a fresh secret with the move is fine (`scim-targets.ts`).
- `account:password-reset-leaves-mfa` — self password change and
  `resetUserPassword` now clear all MFA material (totp, factor flags,
  questions, answers, backup codes, trusted devices), matching
  `resetUserMfa` compromise-response semantics (`account.ts`,
  `services/users.ts`).
- `backup-codes:regen-not-atomic` — regeneration is a single `batch`
  delete+insert; a concurrent regen can no longer interleave live codes
  (`backup-codes.ts`).
- `step-up:budget-on-success` — the step-up attempt budget is a read-only
  check plus a charge on each failure; a typoing user can no longer burn the
  admin's budget ahead of a successful verify (`account.ts`, `admin.ts`,
  `rate-limit.ts`).
- `admin:malformed-referer-500` — `new URL()` on `Referer` in step-up
  middleware is guarded (`admin.ts`).
- `index:content-length-nan` (run-3 carryover) — malformed/negative declared
  lengths are treated as undeclared → the buffered cap applies; the 4 MB
  buffer cap can no longer be skipped (`index.ts`).

### Design note (recorded, not changed)

KBA (security questions) satisfies a per-app `require_mfa` for regular users
but **not** for administrators — matching the admin bar `secondFactorGate`
already sets. `amrSatisfiesMfa` takes `{ admin }` and discounts `kba` for
admins; both OIDC and SAML paths call it with `isAdministrator` resolved.

## Verification

- `npx tsc --noEmit` clean; full suite **902/902** (incl. 9 new regressions).
- e2e smoke **26/26**, UX **5/5**, SCIM Verify green (1 declared
  upstream-expectation mismatch) — all against a container built from this tree.
- OIDC certification suite re-runs in CI against the live deploy.

## Files

`findings.json` — machine-readable records · `coverage-ledger.json` — unit
coverage · `architecture.md` — boundary map used by hunters.
