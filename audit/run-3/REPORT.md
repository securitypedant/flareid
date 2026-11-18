# FlareID security audit — run-3 report

## Run

- **Profile:** deep · **Scope:** whole codebase (`.`)
- **Source ref:** `0972885351591bd926e23ad14e61d729ed62065c` (v2.0 branch head at audit time)
- **Execution:** sandboxed source-and-local-only. No target code ran outside `env -i` +
  `sandbox-exec` deny-network or `docker --network none`; scratch files promoted through
  `promote.py` only. No live endpoints, production identities, or shared services touched.
- **Agents spent:** 4 recon + 11 wave-1 hunters + 3 wave-2 hunters + 2 critics + 4 verifiers
  = 24 (no budget set).
- **Prior runs:** run-1 (deep whole-repo, 83 records) and run-2 (LDAP-scoped, 14 records).
  Both refs are ancestors of the audit ref; **all 97 prior records cite changed source**, so
  every one was re-hunted as a revalidation lead — zero carried confirmations. The
  revalidation verdicts are the run's strongest evidence of remediation progress: the
  overwhelming majority are confirmed fixed (see "Prior revalidation" below).

## Results

**57 final records:** 48 confirmed · 8 needs_validation · 1 rejected.
Severity on confirmed: **4 high · 21 medium · 22 low · 1 informational**.
Independent verification (fresh agents, not the writers): 55 verified, 1 adjusted
(scope/line corrections applied), 1 rejected (`api-keys:users.ts removeUserPasskey guard` —
the claimed missing `assertMayTouchUser` exists at services/users.ts:480).

### Confirmed highs

1. `api-keys:patch-scope-no-held-permission-cap` — `PATCH /api/v1/api-keys/{id}` sets scopes
   with no held-permission cap; any `api_keys:write` key grants itself or a sibling `*`/`admin`.
   The console twin enforces the cap (admin.ts:3894/3954); the API omits it.
2. `federation:delegated-write-registers-adopting-idp-unverified-address` — `federation:write`
   (delegable, non-admin) registers an arbitrary upstream IdP; federated sign-in adopts
   accounts by unverified email/UPN claim — session as any user including Super Admin.
   Victim MFA is the only containment.
3. `federation:jit-insert-misses-admin-role-grant-check` — the JIT insert is the only
   user-creation writer missing `grantsAdminRoleGroup`; IdP-controlled claim fields can land
   the new account in a role-linked dynamic group.
4. `scim-server:custom-attr-merge-after-admin-role-grant-check` — SCIM PUT/PATCH/correlate
   merge custom attributes into the row *after* `assertNoAdminRoleGrant` ran; a
   `directory:write` key writes rule-matching attributes → admin-role group membership.

### Recurring systemic theme

Newest subsystems shipped with guard gaps relative to the codebase's own established
contracts: `assertMayTouchUser` absent on watch flag/unflag and LDAP reveal; `groups.system`
checks missing on SCIM/import/PATCH writers while 5 sibling mutators enforce it; sealed-at-rest
applied to LDAP secrets but not `cfone.api_token`, `scim_targets.secret`,
`upstream_idps.config` secrets, or `totp_secret`; replay protection absent on both new
signature surfaces (private_key_jwt: no `exp`/`jti`; SSF SETs: no `jti`/`aud` requirement;
KV `get`→`delete` one-shots replayable inside the ~60 s eventual-consistency window). Two
ordering/omission bugs break the logout contract: `frontchannelTargets()` deletes
`session_clients` before `notifySessionRevoked()` reads it, and the device grant never
creates `session_clients` at all — back-channel logout silently never delivers.

### Prior revalidation (97 records)

Hunters re-verified all prior records against current source. Confirmed **fixed**: the
step-up allowlist + digit-regex bypasses, enrolment-exemption MFA-gate bypass, SCIM
name-only admin guards, directory-import role-group grants, SCIM-out endpoint/fetch guards,
federation ACS/sig checks, passkey cross-session claim, audit unbounded details, CSV/formula
export (console side), Turnstile hostname pin, workflow mutable-tag/pip/artifact findings,
LDAP run-2 set (framereader, bound-principal revalidation, criticality, writeLdapApp,
schema reservation). Residuals became new findings where still real (LDAP bind timing
oracle — a regression *introduced by* the run-2 fix; client-dimension quota bypass —
partially mitigated but DCR supplies infinite client_ids).

### Coverage

49 ledger units, all `covered` (validator-clean). Wave-1: 37 units across every route,
subsystem, and lifecycle step. Critic pass found 12 orphan areas (issuer/discovery, email
pipeline, i18n/rendering, public misc, API schema drift, secret parity, admin-tier DoS,
identity collision, KV one-shot race, LDAP dn/ad, cron batch, group rename protection) —
all assigned and covered in wave-2. Final critic pass: see `agents/critic-final/`.

### Notable follow-ups (out of audit scope, flagged for the operator)

- `openid.net.env` + `conformance/suite-config.json` hold **live credentials** and are not
  `.dockerignore`d — the `flareid-e2e` image baked them in (h-infra-01). Rotate if the image
  ever left this machine.
- h-infra-02 (unscrubbed artifact upload) was fixed in flight at `ffb6db6`.
- Functional (non-security) regressions found incidentally: `attributes.ts` custom-attribute
  SP-mapping dead code; `schemas.ts` "manager" carve-out missing from the LDAP reservation.

## Files

- `findings.json` — 58 schema-validated records (`validate-findings.cjs` PASS)
- `FINDINGS-DETAIL.md` — prose detail for the 48 confirmed records
- `NEEDS-VALIDATION.md` — the 9 records awaiting external facts + validation plans
- `coverage-ledger.json` — 49 covered units (`validate-coverage-ledger.cjs` PASS)
- `architecture.md`, `prior-index.json`, `run-metadata.json`
- `agents/` — per-agent scratch + promoted artifacts (hunter unit verdicts, verifier results)

## Limits

Source/local only — deployment-dependent facts (Access app attachment, zone mTLS, Spectrum,
notification destinations, secret strength, platform body/fetch limits) are reported as
`needs_validation` with concrete plans, not assumed. One run does not exhaust the target.
