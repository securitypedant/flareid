# Wires FlareID into Cloudflare Access end to end in one apply:
#
#   1. Generates the OIDC client_id / client_secret here, so the same values
#      can be handed to both sides (nothing has to flow back).
#   2. Registers that client in FlareID via its API (POST /api/v1/clients is
#      idempotent on a supplied client_id, so re-applies converge).
#   3. Creates the Generic OIDC identity provider in Zero Trust with SCIM
#      enabled, which yields a scim_base_url and a generated secret.
#   4. Points FlareID's outbound SCIM at that endpoint, so users and groups
#      flow into Access and group names appear in the policy builder.
#   5. Optionally creates an Access application gated by the IdP.
#
# FlareID has no Terraform provider, so the FlareID side uses the generic
# Mastercard/restapi provider against its REST API.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 5.0"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = ">= 1.18"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

# Authenticate with CLOUDFLARE_API_TOKEN (needs Zero Trust write).
provider "cloudflare" {}

provider "restapi" {
  uri                   = var.flareid_base_url
  write_returns_object  = true
  create_returns_object = true
  headers = {
    Authorization = "Bearer ${var.flareid_api_key}"
    Content-Type  = "application/json"
  }
}

# Terraform generates the credential and supplies it to both sides.
resource "random_id" "access_client" {
  byte_length = 16
}
resource "random_password" "access_secret" {
  length  = 48
  special = false
}

locals {
  access_callback = "https://${var.cloudflare_team_name}.cloudflareaccess.com/cdn-cgi/access/callback"
}

# --- FlareID side: register Access as a trusted OIDC client ----------------
# GET/PATCH/DELETE /api/v1/clients/{client_id} give the object real CRUD;
# re-registering the same client_id updates rather than colliding.
resource "restapi_object" "flareid_access_client" {
  path          = "/api/v1/clients"
  id_attribute  = "client_id"
  create_path   = "/api/v1/clients"
  read_path     = "/api/v1/clients/{id}"
  update_method = "PATCH"
  update_path   = "/api/v1/clients/{id}"
  destroy_path  = "/api/v1/clients/{id}"

  data = jsonencode({
    name           = "Cloudflare Access"
    client_id      = random_id.access_client.hex
    client_secret  = random_password.access_secret.result
    redirect_uris  = [local.access_callback]
    client_type    = "confidential"
    trusted        = true
    allowed_claims = ["profile", "email", "groups"]
  })
}

# --- Cloudflare side: Generic OIDC identity provider -----------------------
resource "cloudflare_zero_trust_access_identity_provider" "flareid" {
  account_id = var.cloudflare_account_id
  name       = var.idp_name
  type       = "oidc"
  config = {
    client_id     = random_id.access_client.hex
    client_secret = random_password.access_secret.result
    auth_url      = "${var.flareid_base_url}/authorize"
    token_url     = "${var.flareid_base_url}/token"
    certs_url     = "${var.flareid_base_url}/jwks.json"
    scopes        = ["openid", "email", "profile", "groups"]
    claims        = ["groups", "email"]
  }
  # Enabling SCIM makes Access compute scim_base_url and a one-time secret.
  scim_config = {
    enabled                  = true
    user_deprovision         = true
    group_deprovision        = true
    seat_deprovision         = false
    identity_update_behavior = "automatic"
  }
}

# --- FlareID side: push users and groups to Access's SCIM endpoint ----------
# The config is a singleton (no per-object id), so the resource id is fixed
# and every lifecycle step targets the same URL; destroy clears it, which is
# also how FlareID forgets the credential.
resource "restapi_object" "flareid_scim" {
  path          = "/api/v1/scim/config"
  object_id     = "scim"
  create_path   = "/api/v1/scim/config"
  read_path     = "/api/v1/scim/config"
  update_method = "POST"
  update_path   = "/api/v1/scim/config"
  destroy_method = "POST"
  destroy_path   = "/api/v1/scim/config"
  destroy_data   = jsonencode({ endpoint = "", secret = "" })

  data = jsonencode({
    endpoint = cloudflare_zero_trust_access_identity_provider.flareid.scim_config.scim_base_url
    secret   = cloudflare_zero_trust_access_identity_provider.flareid.scim_config.secret
    scope    = { mode = "all" }
  })
}

# --- Optional: an example Access application behind the new IdP -------------
resource "cloudflare_zero_trust_access_application" "example" {
  count                     = var.example_app_domain == "" ? 0 : 1
  account_id                = var.cloudflare_account_id
  name                      = var.example_app_name
  type                      = "self_hosted"
  domain                    = var.example_app_domain
  session_duration          = "24h"
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.flareid.id]
  auto_redirect_to_identity = true
  policies = [{
    name       = "Allow ${var.example_email_domain}"
    decision   = "allow"
    precedence = 1
    include    = [{ email_domain = { domain = var.example_email_domain } }]
  }]
}
