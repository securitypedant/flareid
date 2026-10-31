export interface UserRow {
  id: number;
  upn: string;
  /** Just the local part of upn (before @) - unique across every domain, so it can be used alone to log in. */
  username: string;
  display_name: string;
  given_name: string;
  family_name: string;
  password_hash: string;
  password_salt: string;
  password_iterations: number;
  totp_secret: string | null;
  mfa_enabled: number;
  /** Legacy attribute - no longer used for authorization. Membership in the "Super Admins" group is authoritative. */
  is_admin: number;
  status: "active" | "disabled";
  created_at: string;
  updated_at: string;
  /** Remote SCIM resource id (e.g. in Cloudflare Access), once pushed there. */
  scim_id: string | null;
  /** Stable UUID, used as the OIDC "id" claim / SCIM externalId, and as the manager reference (instead of email). */
  external_id: string;
  job_title: string;
  department: string;
  /** The manager's external_id (not email) - stable even if the manager's email changes. */
  manager_external_id: string | null;
  employee_number: string;
  hire_date: string;
  employment_status: string;
  employment_type: string;
  location: string;
}

export interface AuditLogRow {
  id: number;
  at: string;
  actor_user_id: number | null;
  actor_upn: string | null;
  action: string;
  target: string | null;
  details: string | null;
  ip: string | null;
  user_agent: string | null;
}

export interface GroupRow {
  id: number;
  name: string;
  description: string | null;
  scim_id: string | null;
}

export interface OAuthClientRow {
  id: number;
  client_id: string;
  client_secret_hash: string;
  name: string;
  redirect_uris: string; // JSON-encoded string[]
  created_at: string;
}

export interface SamlServiceProviderRow {
  id: number;
  entity_id: string;
  name: string;
  acs_urls: string; // JSON array of absolute URLs - the exact-match allowlist
  default_acs_url: string | null;
  nameid_format: string;
  attribute_map: string; // JSON object: SAML attribute name -> user field
  sign_response: number;
  sign_assertion: number;
  want_authn_requests_signed: number;
  signing_certs: string; // JSON array of PEM strings
  encrypt_assertions: number;
  encryption_cert: string | null;
  metadata_url: string | null;
  metadata_last_refreshed_at: string | null;
  metadata_valid_until: string | null;
  created_at: string;
  updated_at: string;
}
