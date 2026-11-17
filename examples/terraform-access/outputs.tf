output "identity_provider_id" {
  value       = cloudflare_zero_trust_access_identity_provider.flareid.id
  description = "Zero Trust identity provider id - attach it to other applications' allowed_idps."
}

output "scim_base_url" {
  value       = cloudflare_zero_trust_access_identity_provider.flareid.scim_config.scim_base_url
  description = "The Access SCIM endpoint FlareID is now pushing to."
}

output "flareid_client_id" {
  value = random_id.access_client.hex
}
