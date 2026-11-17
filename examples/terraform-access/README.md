# Terraform: wire FlareID into Cloudflare Access

Automates the manual steps in the README's
[Wiring into Cloudflare Access](../../README.md#wiring-into-cloudflare-access-generic-oidc)
section: registers Access as an OIDC client in FlareID, creates the Generic
OIDC identity provider in Zero Trust, enables SCIM on it, and points FlareID's
outbound provisioning at the generated endpoint — one `terraform apply`.

## Prerequisites

- A FlareID API key (Admin → Integrations → New key) with `oidc:read`,
  `oidc:write`, `scim:read` and `scim:write`.
- A Cloudflare API token with Zero Trust write, exported as
  `CLOUDFLARE_API_TOKEN`.
- `cp terraform.tfvars.example terraform.tfvars` and fill it in.

## Run

```bash
terraform init
terraform apply
```

## How it works

- Terraform generates the `client_id`/`client_secret` and supplies them to
  both sides. `POST /api/v1/clients` accepts a caller-supplied credential
  specifically so nothing has to flow back out of a not-yet-created
  resource — see docs/api.md.
- Registering an existing `client_id` updates rather than colliding, so
  re-runs converge.
- FlareID's REST calls go through the generic `Mastercard/restapi` provider;
  there is no FlareID provider.
- The SCIM config is a singleton: the resource's lifecycle POSTs to
  `/api/v1/scim/config`, and destroy POSTs a blank endpoint, which is how
  FlareID forgets the credential.

## Notes

- The client secret and SCIM secret land in Terraform state (sensitive).
- Group pushes begin on save and reconcile hourly; to kick the full sync
  now, `POST /api/v1/scim/sync` with the same API key.
- On the v4 provider the resource is `cloudflare_access_identity_provider`
  and `scim_config` moves inside `config`; the rest is the same.
- The SCIM secret is generated once when SCIM is first enabled. If state is
  lost, rotate it in the Zero Trust dashboard (the IdP's SCIM section) and
  put the new secret back through `/api/v1/scim/config`.
