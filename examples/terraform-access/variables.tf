variable "flareid_base_url" {
  type        = string
  description = "Public origin of the FlareID worker, no trailing slash (e.g. https://idp.example.com)."
}

variable "flareid_api_key" {
  type        = string
  sensitive   = true
  description = "A FlareID API key minted in Admin → Integrations, with oidc:read, oidc:write, scim:read and scim:write."
}

variable "cloudflare_account_id" {
  type        = string
  description = "The Cloudflare account that owns the Zero Trust organisation."
}

variable "cloudflare_team_name" {
  type        = string
  description = "The Zero Trust team name - the <team> in <team>.cloudflareaccess.com."
}

variable "idp_name" {
  type        = string
  default     = "FlareID"
  description = "Display name of the identity provider in Zero Trust."
}

variable "example_app_domain" {
  type        = string
  default     = ""
  description = "If set (e.g. app.example.com), creates an example Access application gated by the FlareID IdP."
}

variable "example_app_name" {
  type        = string
  default     = "FlareID demo app"
}

variable "example_email_domain" {
  type        = string
  default     = "example.com"
  description = "Email domain the example Access policy allows. Adjust to your directory."
}
