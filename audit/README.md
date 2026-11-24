# Security audits

External-style security audit reports for this codebase, one directory per
run. Each run captures the code as it was at the audited git ref; remediation
lands in later commits - the report itself is a point-in-time record.

- `run-4/` - whole-codebase deep audit at ref `f98ce6d` (v4.13.x, fourth run).
  18 records: 1 high (SAML `require_mfa` not enforced on fresh password
  login), 5 medium, 12 low. All remediated in the same tree; 9 regression
  tests in `test/audit-run5.test.ts`. One run-3 `needs_validation` carryover
  (declared `Content-Length` cap bypass) was confirmed and fixed.

  Files: `REPORT.md` (summary), `findings.json` (machine-readable),
  `coverage-ledger.json` (what was reviewed), `run-metadata.json`.

- `run-3/` - whole-codebase deep audit at ref `0972885` (v4.x, third run).
  57 records: 4 high, 21 medium, 22 low, 1 informational, 8 needs-validation,
  1 rejected. All 97 prior-run findings were revalidated. Remediation:
  `8dada11` (highs + RFC 9207 `iss`), `3808c5f` (mediums/lows),
  `b5c2e62`+`a64c34e` (needs-validation items). The only finding left by
  design is audit-chain tail truncation, which needs an external trust
  anchor.

  Files: `REPORT.md` (summary), `FINDINGS-DETAIL.md` (per-record evidence
  and traces), `NEEDS-VALIDATION.md`, `findings.json` (machine-readable),
  `coverage-ledger.json` (what was reviewed), `architecture.md` (the
  boundary/principal map the auditors worked from), `prior-index.json` and
  `prior-triage.json` (revalidation bookkeeping), `run-metadata.json`.
