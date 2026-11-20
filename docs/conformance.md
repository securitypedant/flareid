# Conformance testing

FlareID is exercised by three independent conformance harnesses. This page
records what each suite covers, where the evidence lives, and the current
results — including the failures, which are reported honestly rather than
suppressed.

| Harness | What it verifies | Where it runs | Latest result |
| --- | --- | --- | --- |
| OpenID Foundation conformance suite | OIDC OP behaviour across 9 certification plans | `.github/workflows/oidc-conformance.yml` | All plans green except declared expectations |
| SCIM Verify (`ghcr.io/limosa-io/scimverify`, pinned) | SCIM 2.0 provisioning API | `e2e/scim-verify-run.mjs`, CI | Green; 1 declared upstream-expectation mismatch |
| SAMLscope (Kantara IIP profile) | SAML 2.0 IdP conformance, case-level evidence | self-hosted suite, artifacts in `conformance/samlscope/` | 54 PASS / 33 WARNING / 4 FAIL / 70 NOT_VERIFIED |

## OpenID Connect — OpenID Foundation suite

The CI workflow runs nine OP certification plans against the deployed IdP
(`https://idp.tmesandbox.com`), using `conformance/suite-config.json` (plus the
front-channel and back-channel variants `fc-suite-config.json` /
`bc-suite-config.json`):

- `oidcc-basic-certification-test-plan` (discovery, static client)
- `oidcc-config-certification-test-plan`
- `oidcc-formpost-basic-certification-test-plan`
- `oidcc-dynamic-certification-test-plan` (dynamic registration)
- `oidcc-3rdparty-init-login-certification-test-plan`
- `oidcc-rp-initiated-logout-certification-test-plan`
- `oidcc-frontchannel-rp-initiated-logout-certification-test-plan`
- `oidcc-backchannel-rp-initiated-logout-certification-test-plan`
- `oidcc-session-management-certification-test-plan`

Results are exported by the suite and scrubbed of shared secrets by
`conformance/redact-exports.mjs` before being kept as CI artifacts.

**Declarations.** Two files carry the honest-expectations bookkeeping; the
runner fails on anything not declared, and also fails when a declaration stops
applying (so fixes can't silently accrete stale entries):

- `conformance/expected-failures.json` — conditions expected to warn or fail,
  each with a comment explaining why:
  - `EnsureIdTokenDoesNotContainEmailForScopeEmail` (warning): FlareID
    deliberately returns `email` in the id_token — Cloudflare Access and most
    relying parties read it there.
  - `VerifyScopesReturnedInUserInfoClaims` (warning): FlareID only releases
    claims the directory actually stores.
  - `OIDCCCheckDiscEndpointResponseTypesSupportedDynamic` /
    `...GrantTypesSupportedDynamic` (failure, `dynamic_client` variant only):
    the dynamic certification profile requires implicit response types /
    grant types in discovery; a code-only OP cannot truthfully advertise them.
  - `oidcc-refresh-token` WebRunner (failure): a known runner-side flake —
    the scripted browser intermittently lands on the wrong page mid-flow.
    Under investigation.
- `conformance/expected-skips.json` — modules that skip by design because
  FlareID deliberately does not advertise `none` signing:
  `oidcc-unsigned-request-object-*`, `oidcc-request-uri-unsigned`,
  `oidcc-ensure-request-object-with-redirect-uri`, `oidcc-idtoken-unsigned`.

## SCIM — SCIM Verify

`e2e/scim-verify-run.mjs` runs the pinned SCIM Verify image against the e2e
lab and gates CI on it. `e2e/scim-verify-expected.txt` lists the leaf tests
knowingly failed:

- *"Returns errors when creating an invalid group"* — the checker asserts the
  error `status` as a JSON number; FlareID emits it as a JSON string, which is
  what RFC 7643 §3.12 specifies. Upstream expectation bug; our representation
  is spec-correct.

Any other failure, or a declaration that stops failing, fails the run.

## SAML — SAMLscope (Kantara IIP profile)

SAMLscope derives case-level verdicts from recorded protocol evidence
(transcripts), plus operator answers where the suite cannot drive a feature.
Artifacts are kept per run in `conformance/samlscope/`:

- `result-run_B8QNVCPW62VSE2Q4WWPZ0AAK22.json` / `.html` — **current run**
  (against v4.5.x: per-SP `encryption_policy`, IdP-initiated SSO, RSA-OAEP
  interoperability fixes, corrected `isDefault` ACS selection)
- `result-run_JW6632Y4EXK9G882ZXHCT7SHX4.json` / `.html` — earlier run
  (against v4.4.x); its findings drove the v4.5 feature work

### Current run: run_B8QNVCPW62VSE2Q4WWPZ0AAK22

Case-level totals: **54 PASS / 33 WARNING / 4 FAIL / 70 NOT_VERIFIED**.
Aggregate: `NON_CONFORMANT` / `INCOMPLETE` (a MUST-level capability gap plus
unverifiable cases both count against the aggregate).

Verified on this run:

- Full SSO happy path incl. bearer SubjectConfirmation Recipient/NotOnOrAfter
  across two ACS destinations (`SSO01-k`), POST + Redirect request bindings
  (`SSO02-a`), and assertion protection (`SSO01-es`).
- **IdP-initiated SSO** (`SSO01-g` PASS; `SSO01-z` WARNING noting unsolicited
  SSO was observed — informational, expected with the feature on).
- **Encryption coverage**: `ALG04-a/b`, `ALG06-a/b/c/d` all PASS — every
  `{rsa-oaep-mgf1p, xmlenc11#rsa-oaep} × {sha1, sha256}` combination, including
  the `mgf1p + sha256` pair WebCrypto cannot express (emitted via a manual
  RSAES-OAEP wrap with MGF1-SHA1 per spec).
- **ECDSA request-signature verification** (`ALG03-a`): RSA control, EC
  success, and corrupted-EC-signature rejection via a SAML error Response.
- **Default-ACS selection** (`IDP12-c`): all six isDefault fixtures accepted —
  explicit-first, explicit-second, implicit, skip-explicit-false, all-false
  fallback, and multiple-true. The `first-omitted` edge failed on the earlier
  run and is fixed.
- **Persistent and transient NameID properties** (`SSO05-a2`, `SSO05-b1`,
  `SSO05-b2`): length limits, XML-Name lexical form, distinct per-session
  transient values.

Remaining FAILs — genuine capability gaps, not evidence problems:

| Case | Obligation | Gap |
| --- | --- | --- |
| `IIP-ALG08-a/b` | MUST | No configurable prevented-algorithms mechanism; FlareID supports a fixed algorithm set only. |
| `IIP-IDP01-a` | MUST | Attribute names are configurable, but `NameFormat` is fixed — cannot emit arbitrary NameFormat values. |
| `IIP-IDP11-a` | MUST | No option to omit `NameID` from assertions; FlareID always emits one. |

NOT_VERIFIED (70) breaks down as:

- Cases requiring a **native adapter** (SimpleSAMLphp/Keycloak/Shibboleth) to
  bind "verified preparation" — none exists for FlareID, so e.g. `IDP02-a`,
  `IDP03-a`, `IDP04-a/b` cannot be concluded either way.
- Cases needing **request shapes the suite never issues** on this run's
  immutable metadata snapshot (`SSO01-x`, `SSO03-b`, `SSO05-a/b`): POST-bound
  error responses and `NameIDPolicy`-carrying requests. These close as
  NOT_VERIFIED at the wait timeout by design — an honest "not tested", not a
  pass.
- Product limitations recorded as undetermined: RequestedAuthnContext
  comparisons (`SSO01-ga/b/c/gj` — FlareID does not process
  `RequestedAuthnContext`), attesting-entity configuration (`SSO01-fr`,
  `SSO01-gd`), non-interactive auth precondition (`SSO01-ae`).

Notable WARNING (worth a fix): `IIP-SSO01-dq` — the `EncryptedKey` `Recipient`
attribute does not match the delivered ACS on some responses (SHOULD-level).
The other warnings are informational "no relevant fields" observations and
the expected unsolicited-SSO note.

### Earlier run: run_JW6632Y4EXK9G882ZXHCT7SHX4

71 PASS / 30 WARNING / **16 FAIL** / 44 NOT_VERIFIED. Its findings drove the
v4.5 releases:

- Fixed and re-verified PASS on the current run: `SSO01-k`, `IDP12-a/c`
  (default-ACS edge), `ALG06` family (OAEP digest URIs + MGF handling),
  `SSO05-a2`, `IDP09-a`.
- Open protocol findings recorded in the backlog (not yet re-verified on the
  current run, still counted in the deferred list): error responses carrying
  an assertion (`SSO01-d`, `SSO07-b`), missing error responses for unknown
  `NameIDPolicy` formats / unsatisfiable authn context (`IDP05-a`),
  RequestedAuthnContext `exact` comparison (`IDP08-a`), `NameIDPolicy`
  handling (`IDP10-b/d`). `SSO05-a` failed there on a stale configuration;
  the capability exists now (`SSO05-a2` passes) but the policy-driven variant
  could not be re-verified.

### Methodology notes

- The suite ran self-hosted at `localhost:8080`; the target was the deployed
  IdP on its public custom domain — no tunnels were created.
- Responses were delivered to the suite's ACS endpoints using HTTP
  absolute-form request-targets so the recorded URLs match the plan's
  registered `https` endpoints.
- Transcript-driven cases cannot be concluded by an operator in SAMLscope;
  pending cases close at their wait timeout, which is why the run ends
  `INCOMPLETE` rather than being forced to a verdict.
