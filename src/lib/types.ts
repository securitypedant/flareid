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
  /** Where this account's email goes, when not its UPN. NULL = the UPN. */
  email: string | null;
  /** The last TOTP time-step counter accepted - a code at or below it is a replay. */
  totp_last_counter: number | null;
  mfa_enabled: number;
  /** 1 when the user enrolled email one-time codes as a second factor (email-otp.ts). */
  email_otp_enabled: number;
  /** 1 when the user set security questions as a second factor (security-questions.ts). */
  security_questions_enabled: number;
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
  /** The directory schema this user conforms to - controls which attributes are shown/edited. */
  schema_id: number | null;
  /** JSON object of values for attributes defined by schema_id beyond the fixed columns. */
  custom_attributes: string;
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
  /** JSON dynamic-membership rule (see src/lib/groups.ts) - empty for explicit-only groups. */
  rule: string;
  schema_id: number | null;
  custom_attributes: string; // JSON object of schema attribute values
}

export interface OAuthClientRow {
  id: number;
  client_id: string;
  client_secret_hash: string;
  name: string;
  redirect_uris: string; // JSON-encoded string[]
  created_at: string;
  /** "public" clients (SPAs, native apps) have no secret and must use PKCE. */
  client_type: "confidential" | "public";
  /** 1 = first-party, no consent screen. */
  trusted: number;
  /** JSON array of ClaimGroup; NULL = every group (the pre-v3 behaviour). */
  allowed_claims: string | null;
  post_logout_redirect_uris: string; // JSON-encoded string[]
  /** id_token signing algorithm: RS256 (default) or ES256. */
  id_token_signed_response_alg: string;
  /** OIDC Front-Channel Logout 1.0 target ('' = none). */
  frontchannel_logout_uri: string;
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
  /** Where LogoutResponses go (HTTP-Redirect); NULL = no Single Logout. */
  slo_url: string | null;
  encrypt_assertions: number;
  encryption_cert: string | null;
  metadata_url: string | null;
  metadata_last_refreshed_at: string | null;
  metadata_valid_until: string | null;
  /** '' | 'subject-id' | 'pairwise-id' (SAML Subject Identifier Attributes Profile). */
  subject_id: string;
  created_at: string;
  updated_at: string;
}
