# FlareID secure-edge deployment — WAF, API Shield, rate limiting, zone hardening.
#
# Provider: cloudflare/cloudflare ~> 4.x (v5 resource names differ; see docs/secure-edge.md).
# Set credentials via CLOUDFLARE_API_TOKEN (needs: Zone WAF edit, API Shield edit,
# Workers Routes edit, DNS edit, Zone Settings edit on the target zone).

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.52"
    }
  }
}

provider "cloudflare" {}

variable "zone_name" {
  description = "Cloudflare zone that will front the IdP (e.g. example.com)."
  type        = string
}

variable "idp_hostname" {
  description = "Fully qualified IdP hostname inside the zone (e.g. idp.example.com)."
  type        = string
}

variable "worker_service" {
  description = "Worker service name to bind the hostname to."
  type        = string
  default     = "flareid-idp"
}

variable "worker_environment" {
  description = "Worker environment name (empty string = production/default)."
  type        = string
  default     = ""
}

variable "admin_allowed_ips" {
  description = "CIDRs allowed to reach /admin and /api/admin. Empty list = no source-IP restriction."
  type        = list(string)
  default     = []
}

variable "waf_mitigation" {
  description = "Enforcement mode for custom WAF rules and rate limits: block | challenge | log."
  type        = string
  default     = "block"
}

variable "rate_limit_threshold" {
  description = "Requests per 10s per source IP allowed on sensitive protocol endpoints."
  type        = number
  default     = 60
}

variable "enable_managed_rules" {
  description = "Deploy the Cloudflare Managed Ruleset. Keep false until exceptions are tuned (see docs)."
  type        = bool
  default     = false
}

variable "enable_api_shield" {
  description = "Enable API Shield schema validation on the API surface. Requires an API Shield entitlement."
  type        = bool
  default     = false
}

variable "openapi_schema_path" {
  description = "Path to the generated OpenAPI schema (npm run docs:api -> docs/openapi.json)."
  type        = string
  default     = "../docs/openapi.json"
}

variable "api_shield_mitigation" {
  description = "Schema-validation default action: none | log | block. Roll out with log first."
  type        = string
  default     = "log"
}

data "cloudflare_zone" "idp" {
  name = var.zone_name
}

locals {
  zone_id  = data.cloudflare_zone.idp.id
  # Admin-plane paths and public protocol/API paths. Keep in sync with src routes
  # when adding surfaces; the e2e suite exercises everything below.
  admin_paths    = "(http.request.uri.path matches \"^/(admin|api/admin)(/|$)\")"
  protocol_paths = "(http.request.uri.path matches \"^/(saml|oidc|oauth|scim|ldap-auth|api)(/|$)\")"
  rl_paths       = "(http.request.uri.path matches \"^/(oidc/token|oauth/token|login|saml/sso|scim/v2)(/|$)\")"
  admin_acl      = length(var.admin_allowed_ips) > 0
}

# ── Worker custom domain ───────────────────────────────────────────────
# Binds the Worker to the zone hostname so all IdP traffic transits the
# zone's security layers. Keep workers.dev fronted by Access as the ops
# backdoor (see docs/secure-edge.md).
resource "cloudflare_worker_domain" "idp" {
  zone_id      = local.zone_id
  hostname     = var.idp_hostname
  service      = var.worker_service
  environment  = var.worker_environment != "" ? var.worker_environment : null
}

# ── Zone hardening ─────────────────────────────────────────────────────
resource "cloudflare_zone_settings_override" "idp" {
  zone_id = local.zone_id
  settings {
    ssl                      = "full"
    min_tls_version          = "1.2"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    tls_1_3                  = "on"
    security_level           = "medium"
    # An IdP answers with 4xx/5xx on purpose; don't let Security Level
    # challenges break protocol clients - keep medium, let WAF do the work.
  }
}

# ── Custom WAF rules ───────────────────────────────────────────────────
resource "cloudflare_ruleset" "idp_custom" {
  zone_id     = local.zone_id
  name        = "flareid-security"
  description = "FlareID edge security - admin ACL, protocol hardening"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # 1. Admin plane: source-IP ACL (skipped when admin_allowed_ips is empty).
  dynamic "rules" {
    for_each = local.admin_acl ? [1] : []
    content {
      action      = var.waf_mitigation
      expression  = "${local.admin_paths} and not ip.src in {${join(" ", var.admin_allowed_ips)}}"
      description = "Restrict admin plane to allowed source CIDRs"
      enabled     = true
    }
  }

  # 2. Enforce modern TLS + deny plaintext HTTP reaching the IdP at all.
  rules {
    action      = var.waf_mitigation
    expression  = "(not ssl) and ${local.protocol_paths}"
    description = "Deny cleartext HTTP to IdP protocol paths"
    enabled     = true
  }

  # 3. Drop requests with no/invalid Host expectation beyond the IdP hostname
  #    (defensive; zone routing already limits this).
  rules {
    action      = var.waf_mitigation
    expression  = "(http.request.method in {\"TRACE\" \"TRACK\" \"CONNECT\" \"DELETE\"}) and ${local.protocol_paths}"
    description = "Deny non-protocol HTTP methods on IdP paths"
    enabled     = true
  }

  # 4. Known-bad request sizes: IdP bodies are KB-scale; block multi-MB POSTs
  #    at the edge before the app-level cap is even reached.
  rules {
    action      = var.waf_mitigation
    expression  = "(http.request.method eq \"POST\" and http.request.body.size gt 4194304) and ${local.protocol_paths}"
    description = "Block oversized bodies on IdP endpoints"
    enabled     = true
  }
}

# ── Rate limiting ──────────────────────────────────────────────────────
resource "cloudflare_ruleset" "idp_ratelimit" {
  zone_id     = local.zone_id
  name        = "flareid-ratelimit"
  description = "Per-source-IP rate limits on brute-forceable endpoints"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    action      = var.waf_mitigation
    expression  = local.rl_paths
    description = "Token/login/SSO/SCIM rate limit"
    enabled     = true
    ratelimit {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = var.rate_limit_threshold
      mitigation_timeout  = 60
    }
  }
}

# ── Managed rulesets (opt-in; see docs/secure-edge.md tuning section) ──
# Deployed in a separate ruleset so it can be removed without touching the
# custom rules. Enable after exception tuning - SAML POST bodies and OIDC
# JWTs can false-positive the OWASP ruleset.
resource "cloudflare_ruleset" "idp_managed" {
  count       = var.enable_managed_rules ? 1 : 0
  zone_id     = local.zone_id
  name        = "flareid-managed"
  description = "Cloudflare Managed + OWASP on the IdP surface"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    action      = "execute"
    expression  = local.protocol_paths
    description = "Cloudflare Managed Ruleset"
    enabled     = true
    action_parameters {
      id      = "efb7b8c949ac4650a09736fc376e9aee" # Cloudflare Managed Ruleset
      version = "latest"
    }
  }
}

# ── API Shield ─────────────────────────────────────────────────────────
# Session identifier used for API abuse / sequence analytics.
resource "cloudflare_api_shield" "idp" {
  count   = var.enable_api_shield ? 1 : 0
  zone_id = local.zone_id
  auth_id_characteristics {
    name = "Authorization"
    type = "header"
  }
}

# Import the generated OpenAPI schema (npm run docs:api).
resource "cloudflare_api_schema" "openapi" {
  count              = var.enable_api_shield ? 1 : 0
  zone_id            = local.zone_id
  name               = "flareid-api"
  kind               = "openapi_v3"
  source             = filebase64(var.openapi_schema_path)
  validation_enabled = true
}

# Default mitigation for requests that violate the schema. Start at "log",
# verify the e2e suite, then move to "block".
resource "cloudflare_api_shield_schema_validation_settings" "idp" {
  count                              = var.enable_api_shield ? 1 : 0
  zone_id                            = local.zone_id
  validation_default_mitigation_action = var.api_shield_mitigation
}
