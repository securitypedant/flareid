# FlareID run-3 — needs validation

Records whose decisive fact is outside source (deployment/platform behavior). None carry severity until validated.

## 1. Sealed login-flow HMAC key still derives from the first non-empty of three secrets; a >=32-char placeholder or weak value is accepted (prior record: changed, not fully fixed)

- **Fingerprint:** `authorize-state:flowSealKey-placeholder-secret-shadowing`
- **Claimed root cause:** flowSealKey trusts whichever of three optional secrets is non-empty first and applies only a length>=32 check; it does not apply isPlaceholderSecret (the codebase's documented placeholder convention) and the setup gate placeholder-checks only KEY_ENCRYPTION_KEY, leaving a weak-but-long SIGNING_KEY_PKCS8 or COOKIE_ENCRYPTION_KEY usable as the sealed-flow HMAC key.
- **Blockers:**
  - The decisive fact is a deployment's actual secret values: whether SIGNING_KEY_PKCS8 or COOKIE_ENCRYPTION_KEY (or a post-setup-rotated KEY_ENCRYPTION_KEY) is set to a placeholder or otherwise low-entropy string of length >= 32. The source shows the check that would miss it, not that any real deployment has such a value.
- **Local plan:** Set SIGNING_KEY_PKCS8='replace-me-0000000000000000000000000000' (>=32 chars) in .dev.vars, confirm /setup completes (the gate only checks KEY_ENCRYPTION_KEY), then POST /authorize for a registered client and verify flowSealKey derives a key from the placeholder: forge a sealed flow by recomputing HMAC-SHA256 over 'flareid login-flow seal v1\n<placeholder>' and confirm getLoginFlow accepts it (openSealedFlow returns the forged flow).
- **Deployment plan:** Operator check: `npx wrangler secret list` and inspect whether SIGNING_KEY_PKCS8/COOKIE_ENCRYPTION_KEY/KEY_ENCRYPTION_KEY hold shipped or otherwise weak values of length >= 32; also confirm whether COOKIE_ENCRYPTION_KEY is set at all, since it shadows KEY_ENCRYPTION_KEY silently.

## 2. redact-exports.mjs only replaces literal secret strings; secrets appearing in encoded form in suite exports would survive the scrub

- **Fingerprint:** `conformance/redact-exports.mjs-encoded-secret-forms`
- **Claimed root cause:** redact-exports.mjs:66 performs `next.split(s).join("<redacted>")` - exact-substring replacement with no handling of base64/hex/URL-encoded or JSON-escaped representations of the collected secrets, so any non-literal rendering of a secret survives the scrub.
- **Blockers:**
  - Whether the pinned OIDF suite's --export-dir output actually embeds HTTP Authorization headers (or other encoded renderings of client secrets) is behaviour of the external conformance-suite tree at commit 23353b36957d6466010de767c812d2c91ed37638, not of this repository; no exported sample is in-repo.
  - An offline check needs the suite's export format; the decisive in-repo question is only whether the literal replacement is sufficient, which it is not in the general case.
- **Local plan:** Run run-test-plan.py from the pinned suite commit against a dummy FlareID (e2e container) with marker secrets like 'ZZZ-marker-secret'; inspect the produced export dir for the literal marker, its base64 forms (Basic <b64(client_id:marker)>), and percent-encodings. Any encoded occurrence surviving redact-exports.mjs confirms the gap.
- **Deployment plan:** Alternatively the owner can grep a real downloaded conformance-results artifact for base64(<client_id>:) and for the client secret in urlencoded/base64 form - a single run answers it.

## 3. Federation discovery and token-exchange fetches have no timeout; anonymously triggerable and failures are never cached, so every attempt re-issues the fetch

- **Fingerprint:** `flareid:federation.ts:oidc-outbound-fetches-no-timeout`
- **Claimed root cause:** lib/federation.ts:197 and :243 call raw fetch() without an AbortSignal and parse the response with unbounded res.json(); success-only KV caching (line 207) means a failing upstream re-arms the fetch on every anonymous initiation instead of dampening it.
- **Blockers:**
  - Whether concurrent hanging fetches from repeated anonymous requests exhaust a platform-enforced resource (request slots, outgoing connections, wall-clock budget) is a Workers runtime fact outside the repository.
  - The issuer is admin-configured, so whether a realistic deployment exposes a stalling upstream is environmental; an IdP that becomes slow (not attacker-registered) still makes the anonymous trigger repeatable.
- **Local plan:** Point a test upstream IdP at a stub that accepts TCP/HTTP and never responds; repeatedly GET /login/federated/:id with a fresh login flow and observe each request hang with no timeout and each attempt re-issuing the fetch (no negative-cache).
- **Deployment plan:** Confirm Workers subrequest/wall-clock limits applicable to the account and whether hung fetches are bounded by the platform; if a hung request can outlive the request deadline or hold shared slots, the missing timeout is a confirmed defect.

## 4. 4 MiB body cap checks only declared Content-Length - chunked bodies bypass it and are buffered in full (twice on /token, /introspect, /revoke); revalidation of run-1 unbounded-anonymous-request-body-buffering

- **Fingerprint:** `flareid:index.ts:body-cap-declared-length-only-chunked-gap`
- **Claimed root cause:** index.ts:51-53 enforces MAX_BODY_BYTES only via Number(c.req.header('content-length')); no streaming cap, per-route cap, or total-time bound exists for bodies without a declared length, and the claim in the adjacent comment that per-route caps cover the gap is false for most routes. Double buffering on token-family endpoints (edge-limit.ts:58 + token.ts:33) doubles the in-isolate footprint of any accepted body.
- **Blockers:**
  - The Cloudflare platform's own maximum request-body size (and whether it is enforced before the isolate buffers) is not declared in the repository; exploitability of the gap to isolate-memory exhaustion vs. mere larger-than-intended buffering depends on that external limit.
  - Whether a Workers isolate's 128 MB memory ceiling is reachable per-request under concurrent unbounded bodies depends on platform scheduling, also outside the repo.
- **Local plan:** In `wrangler dev`/miniflare, send POST /token and POST /ssf/receive with Transfer-Encoding: chunked and a ~10-50 MB body (no Content-Length); observe that the 413 middleware does not fire and the body is fully buffered/parseable (e.g. token endpoint attempts parseBody, edge-limit clone().text() also completes).
- **Deployment plan:** Confirm with the account's Cloudflare plan docs/dashboard what upstream request-size cap applies to the zone and whether the Workers runtime enforces a request body limit below isolate memory; if the platform cap exceeds isolate memory, treat as a confirmed availability defect.

## 5. Managed domains accept arbitrary strings; a suffix domain such as "com" captures brand resolution for unrelated hostnames (brandDomainForHost suffix match), and wildcard domains break deleteDomain's in-use LIKE

- **Fingerprint:** `lib-domains-addDomain-unvalidated-domain-format`
- **Claimed root cause:** addDomain (src/lib/domains.ts) and all five callers trim+lowercase the domain but never check it against a DNS-name grammar, while consumers (brandDomainForHost suffix matching, deleteDomain LIKE patterns, UPN construction, domainFromHint charset) all assume the invariant that a domains row is a well-formed DNS name.
- **Blockers:**
  - The brand-capture effect only matters when the Worker serves sign-in pages on hostnames other than the issuer (per-brand custom domains / Cloudflare for SaaS custom hostnames). Under a single-hostname deployment the residual is self-inflicted config breakage (wildcard LIKE refusals, unusable default/UPNs), which is below finding threshold on its own.
  - No local environment configured to confirm which hostname classes route to this Worker.
- **Local plan:** Seed the local D1 (wrangler d1 execute --local) with a domains row ('com', brand_id set to a custom brand) and request /login against `wrangler dev` with Host: unrelated.com; observe the custom brand rendered. The SQL semantics are already source-evident.
- **Deployment plan:** Check wrangler.jsonc routes/custom-domain configuration (and any Cloudflare for SaaS custom hostnames) to determine whether non-issuer hostnames reach the Worker; if they do, the brand-capture half is confirmed.

## 6. Cloudflare Analytics Engine fetches in metrics.ts have no timeout - a hung upstream API call leaves admin performance/reporting requests waiting indefinitely

- **Fingerprint:** `metrics:analytics-engine-sql-fetches-no-timeout`
- **Claimed root cause:** src/lib/metrics.ts:71,97,172,215 call fetch() without AbortSignal.timeout or a raced deadline.
- **Blockers:**
  - Deployment-dependent: only fires when Analytics Engine is configured (CF_ACCOUNT_ID etc.), and the practical hang duration depends on platform subrequest behaviour, which cannot be established from source alone.
  - Real-world severity (whether a stalled fetch pins the isolate long enough to matter vs being cut by an outer timeout) needs a live or simulated-slow-upstream test.
- **Local plan:** Confirm no AbortSignal/timeout wrapper exists anywhere in metrics.ts and that monitoring.ts performance paths invoke it without a raced deadline (done - verified by read).
- **Deployment plan:** On a deployment with AE configured, make api.cloudflare.com unreachable (or inject a stalled response) and issue GET /api/v1/performance with a performance:read key; measure request lifetime and concurrent-hang behaviour.

## 7. Legacy non-https SAML ACS/SLO endpoints are never re-validated: write-time https enforcement leaves pre-existing rows deliverable to cleartext or non-URL schemes

- **Fingerprint:** `saml-sp.endpoints.legacy-non-https-no-use-time-check`
- **Claimed root cause:** Scheme validation was added only at write boundaries; resolveAcsUrl and samlPostForm do not re-check scheme at use time, and no migration scrubs pre-existing rows.
- **Blockers:**
  - Whether the deployed D1 actually contains a saml_service_providers row with a non-https acs_urls entry, default_acs_url, or slo_url predating the validation is deployment state not visible in source.
  - Whether any such legacy value is also a non-URL scheme (e.g. javascript:) determines whether impact is cleartext delivery only or additionally auto-executing form-action script in browsers that still honor javascript: form actions.
- **Local plan:** Insert a saml_service_providers row directly into a dev D1 with acs_urls ["http://sp.example/acs"] and slo_url "http://sp.example/slo"; drive /saml/sso and observe the auto-POST form action and the SLO redirect target are emitted verbatim.
- **Deployment plan:** Run `SELECT id, acs_urls, default_acs_url, slo_url FROM saml_service_providers` on the deployed D1 (or `wrangler d1 execute`) and check for any entry not matching ^https://.

## 8. client_credentials grant mints service JWTs with caller-chosen aud and scope, and a client's declared grant_types are not persisted/enforced at the token endpoint

- **Fingerprint:** `token.ts:client_credentials-arbitrary-aud-scope-no-grant-type-binding`
- **Claimed root cause:** client_credentials branch at src/routes/token.ts:164-166 mints service JWTs with caller-chosen aud/scope; grant_types from registration metadata is validated at write time but never persisted or enforced at grant time.
- **Blockers:**
  - Severity/reachability depends on external resource servers that would consume these JWTs - not present in repo.
- **Local plan:** Deploy with a resource server (or inspect Access/service-token consumers) to confirm the aud claim is honored; check whether any caller relies on grant_types being enforced.
