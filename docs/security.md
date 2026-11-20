# Security posture

FlareID is engineered as a **defensibly secure** IdP: every claim below is backed
by code, tests, conformance runs, or committed audit artifacts — not assertion.
The posture is three independent layers, each eliminating a class of attacks the
others can't.

## Layer 1 — the platform removes the infrastructure attack surface

- **V8 isolates, not servers**: no OS, SSH, containers, or patchable host. There
  is no host to land on, escalate from, or move laterally inside.
- **Managed state**: D1/KV/Secrets are injected as bindings — no self-hosted
  database to harden, no credentials on disk, no disk-encryption question.
- **The network absorbs availability attacks**: DDoS defense is inherent to the
  platform the IdP's availability depends on.
- **Zone security stack** (deployable via `terraform/`): custom WAF rules
  (admin ACL, cleartext deny, method allow-list, 4 MiB body cap), per-IP rate
  limits on login/token/SSO/SCIM, managed rulesets, API Shield OpenAPI schema
  validation on `/api` + `/scim`, TLS ≥1.2/1.3 — enforcement *below* the app, so
  an app bug can't expose an unfiltered edge. See `docs/secure-edge.md`.
- **Access on `workers.dev`**: the unshielded origin is locked behind Access;
  the public hostname is the only path in.

## Layer 2 — the application implements the protocols defensively

**Cryptography**

- SAML: exclusive C14N response signing (RS256/ES256), XSW-hardened
  verification on both bindings, namespace-decoy rejection, per-SP
  `encryption_policy` honoring SP `md:EncryptionMethod` (AES-GCM content,
  RSA-OAEP transport incl. manual wrap for MGF pairs WebCrypto can't express),
  `EncryptedKey Recipient` binding to the destination ACS.
- OIDC: JWKS rotation, pairwise `sub` + `sector_identifier_uri`, signed
  userinfo, JAR request objects, `private_key_jwt`.
- **Instance algorithm deny-list** (`disabled_algorithms`): configuration of a
  denied algorithm fails at write time and at emission — fail closed.

**Protocol correctness** (the subtle attack surface)

- Error responses carry no assertion; unsatisfiable requests get the spec'd
  status (`InvalidNameIDPolicy`, `NoAuthnContext`, `NoPassive`,
  `UnknownPrincipal`) instead of a misleading success.
- `RequestedAuthnContext` comparison matrix implemented (exact/minimum/
  maximum/better); `NameIDPolicy` format, `SPNameQualifier`, `SPProvidedID`,
  and request `Subject` are honored or refused per spec.
- ACS selection honors `isDefault`; registered endpoints can't be silently
  withdrawn by metadata refresh.
- Sessions: step-up/factor binding, `check_session` liveness via `oidc_sid`,
  back-channel logout fan-out ordering, DCR clients bounded to declared grants.

**Admin plane**

- Permission-area RBAC on every surface; system objects (groups, watchlist,
  `Risk watchlist` name) protected from upsert/squat; delegated tokens
  (`scim:write`, `signals:write`) cannot mint trusted transmitters or export
  the directory; `ensureDomain` validation, alias-namespace UPN checks.
- Audit chain with anchored verification — retention deletes can't falsify it.
- Secrets at rest sealed (`default_password`, `turnstile_secret`); dead
  credential classes migrated out; `.dockerignore` covers suite configs.

## Layer 3 — verifiability: the claims are checkable

- **Conformance suites, continuously**: OIDF (OIDC), SAMLscope (SAML),
  SCIM Verify (SCIM) — external tools regression-test security behavior
  (signature verification, assertion scoping, session binding), not just
  self-asserted tests. Artifacts under `conformance/`; methodology in
  `docs/conformance.md`.
- **Adversarial audits**: deep multi-phase audits (recon → parallel hunters →
  critic → validation → independent verification) with committed findings and
  revalidation of every prior record — including hunting *incomplete-fix
  variants*, the class most regressions hide in.
- **Test suite**: ~725 tests including negative/protocol-abuse cases;
  `npm run test` and the integration-verification workflow run every change.
- **OpenAPI-driven enforcement**: the same schema that documents `/docs/api`
  feeds API Shield — documentation and enforcement can't drift.

## Known limitations — published, not hidden

- Tracked in the audit `NEEDS-VALIDATION` list and `conformance/expected-*`
  files; the conformance page lists every `NOT_VERIFIED` case and why.
- The `workers.dev` origin relies on Access staying enabled — it's the ops
  backdoor by design; treat its loss as an incident.

## Operating it securely

1. Deploy the edge stack: `terraform/` + `docs/secure-edge.md`.
2. Keep Access on `workers.dev`; ACL or mTLS the admin plane.
3. Set `disabled_algorithms` to your policy (e.g. deny `sha1`, `rsa-1_5`).
4. Every release: `npm run docs:api` → `terraform apply` (schema stays current)
   → run the conformance + e2e suites against the shielded hostname.
5. Security contact/disclosure: `SECURITY.md`.
