# Conformance testing

FlareID is continuously verified by three independent conformance harnesses:

- **OpenID Foundation conformance suite** — nine OP certification plans
  (basic, config, form_post, dynamic registration, 3rd-party-initiated login,
  RP-initiated logout front/back-channel, session management) run in CI
  against the deployed IdP. Expected warnings and skips are declared in
  `conformance/expected-failures.json` and `expected-skips.json`; each entry
  documents why, and the run fails if a declaration stops applying.
- **SCIM Verify** — the pinned SCIM 2.0 checker gates CI on the provisioning
  API, with one declared upstream-expectation mismatch (FlareID emits the
  error `status` as a JSON string, per RFC 7643).
- **SAMLscope** — Kantara IIP-profile SAML IdP conformance. The current run
  reports 54 PASS / 33 WARNING / 4 FAIL / 70 NOT_VERIFIED; the four failures
  are genuine capability gaps (no configurable prevented-algorithm set, fixed
  attribute `NameFormat`, no `NameID` omission option). Run artifacts are kept
  in `conformance/samlscope/`.

For the full results, per-case verdicts, and methodology notes, see
`docs/conformance.md` in the repository.
