# Securing the IdP edge — WAF, API Shield, and platform hardening

FlareID is a Worker. Application-level defenses (signature verification, session
binding, RBAC, audit chain, rate-limited edge routes) are only half the story —
the other half is the zone. This guide deploys the Cloudflare security stack in
front of the IdP with the Terraform module in `terraform/`.

## Architecture

```
SP / browser / API client
        │
        ▼
Cloudflare zone (proxied hostname, e.g. idp.example.com)
  ├─ Zone settings: TLS ≥1.2, always-HTTPS, TLS 1.3
  ├─ Custom WAF rules: admin ACL, cleartext deny, method allow-list, 4 MiB body cap
  ├─ Rate limiting: per-IP limits on login / token / SSO / SCIM
  ├─ Managed rulesets (opt-in): Cloudflare Managed + OWASP
  ├─ API Shield (opt-in): OpenAPI schema validation + discovery on /api, /scim
        │
        ▼
flareid-idp Worker  ── D1 / KV / Secrets
```

`workers.dev` stays fronted by Cloudflare Access as the ops backdoor — the public
hostname is the only shielded path in.

## Prerequisites

- The IdP's hostname delegated to (or inside) a Cloudflare zone
- `CLOUDFLARE_API_TOKEN` with: Zone WAF edit, API Shield edit, Workers Routes
  edit, DNS edit, Zone Settings edit
- Terraform ≥ 1.5
- API Shield requires the corresponding entitlement on the account
  (`enable_api_shield` stays `false` otherwise)

## Deploy

```sh
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in zone + hostname
terraform init && terraform plan
terraform apply
```

The module pins `cloudflare/cloudflare ~> 4.52`. On provider v5 the resource
names change (`cloudflare_record` → `cloudflare_dns_record`,
`cloudflare_worker_domain` → `cloudflare_workers_custom_domain`) — the rule
logic carries over.

## What each layer enforces

| Layer | Resource | Effect |
|---|---|---|
| Worker custom domain | `cloudflare_worker_domain` | All IdP traffic transits the zone |
| Zone settings | `cloudflare_zone_settings_override` | TLS ≥1.2, always-HTTPS, TLS 1.3 |
| Custom WAF | `cloudflare_ruleset.idp_custom` | `/admin`,`/api/admin` source-IP ACL; cleartext deny; method allow-list; 4 MiB body cap at the edge |
| Rate limiting | `cloudflare_ruleset.idp_ratelimit` | `var.rate_limit_threshold` req/10 s per source IP on `/oidc/token`, `/oauth/token`, `/login`, `/saml/sso`, `/scim/v2` |
| Managed rules | `cloudflare_ruleset.idp_managed` | Cloudflare Managed Ruleset (opt-in) |
| API Shield | `cloudflare_api_shield` + `cloudflare_api_schema` + `…_schema_validation_settings` | OpenAPI schema enforcement + discovery on `/api`, `/scim` |

The schema comes from the repo itself — `npm run docs:api` regenerates
`docs/openapi.json` every release, so API Shield validates the same surface the
/docs reference documents.

## Rollout order

1. `terraform apply` with `enable_managed_rules=false`, `enable_api_shield=false`,
   `waf_mitigation="log"` — everything observes first.
2. Verify: run `npx vitest run` locally, then the e2e lab and the
   integration-verification workflow **against the shielded hostname** — the
   conformance suites are the regression harness.
3. `waf_mitigation="block"` for custom rules + rate limits.
4. `enable_api_shield=true` with `api_shield_mitigation="log"`; check discovery
   findings, then `"block"`.
5. `enable_managed_rules=true` last — see tuning below.

## Tuning notes

- **OWASP false-positives on SAML/OIDC**: assertion posts are base64 XML, token
  grants carry JWTs — the OWASP ruleset can flag them. Tune per-rule overrides
  inside `idp_managed` (add `overrides` blocks to `action_parameters`) before
  enforcing; verify with a live SAML POST and an OIDC token exchange.
- **Admin ACL**: prefer `admin_allowed_ips`; for stronger isolation put the
  admin plane behind mTLS client certs or an Access service-token policy and
  leave `admin_allowed_ips` empty.
- **Machine clients**: SCIM sync, token grants, IdP-initiated SSO are
  server-to-server — keep Bot Management off those paths (scope by URI).
- **Every release**: re-run `npm run docs:api` and `terraform apply` so API
  Shield's schema tracks new endpoints.

## Beyond this module

- **Access** on `workers.dev` (already the deployment pattern) — the bypass-proof
  ops path.
- **mTLS on the admin plane** — API Shield client-certificate validation or an
  Access policy; strongest when admin traffic is few, known machines.
- **Logpush + alert policies** — zone-level security events alongside the app's
  own audit chain (`docs/observability.md`).
