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
  /** Legacy single-target remote SCIM resource id - writes moved to scim_user_links; kept for migration history. */
  scim_id: string | null;
  /** The provisioner's own stable id (SCIM externalId) - correlation and manager refs resolve through it. */
  source_id: string | null;
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
  chain_hash: string | null;
}

export interface GroupRow {
  id: number;
  name: string;
  description: string | null;
  /** Legacy single-target remote SCIM resource id - writes moved to scim_group_links; kept for migration history. */
  scim_id: string | null;
  /** JSON dynamic-membership rule (see src/lib/groups.ts) - empty for explicit-only groups. */
  rule: string;
  schema_id: number | null;
  custom_attributes: string; // JSON object of schema attribute values
  /** Whether people may ask for membership on My account (static groups only). */
  requestable: number;
  /** '' for ordinary groups; 'watchlist' for the risk watchlist - membership maintained by code. */
  system: string;
  /** Whether member emails sync to a Cloudflare One gateway list (cf_lists 'group:{id}'). */
  cf_list_sync: number;
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
  /** OIDC Back-Channel Logout 1.0 target ('' = none). */
  backchannel_logout_uri: string;
  /** Third-party-initiated login: the OP endpoint third parties call for this client ('' = not offered). */
  initiate_login_uri: string;
  /** SHA-256 of the RFC 7591 registration access token (NULL = statically provisioned). */
  registration_token_hash: string | null;
  /** RFC 7591 jwks: an embedded JWKS JSON document for private_key_jwt. */
  jwks: string | null;
  /** RFC 7591 jwks_uri: a remote JWKS document for private_key_jwt. */
  jwks_uri: string | null;
  /** RFC 7591 grant_types the client registered; NULL = every supported grant on admin-created rows, the RFC 7591 default on dynamically registered ones. */
  grant_types: string | null;
  /** RFC 7591 `scope` metadata - bounds a client_credentials request's scope when set (unset bounds a dynamically registered client to none). */
  registered_scope: string | null;
  /** RFC 7591 display metadata: rendered on the sign-in page so people can see which app they are authenticating to. */
  logo_uri: string | null;
  policy_uri: string | null;
  tos_uri: string | null;
  client_uri: string | null;
  /** OIDC Registration 3.2: "public" (default = raw user id) or "pairwise" (sector-scoped sub). */
  subject_type: string | null;
  /** OIDC Registration 2: a JSON document listing this client's redirect_uris; its host is the pairwise sector. */
  sector_identifier_uri: string | null;
  /** OIDC Registration 2: JSON array of https URIs the client may pass as request_uri at authorize. */
  request_uris: string | null;
  /** OIDC Registration 2: alg the client wants /userinfo signed with; NULL = plain JSON. */
  userinfo_signed_response_alg: string | null;
  /** JSON array of group ids allowed to see and SSO into this app (restricted mode). */
  assigned_groups: string | null;
  /** 'everyone' | 'restricted': in restricted mode only assigned_users/groups reach the app. */
  access_mode: string;
  /** JSON array of user ids allowed when access_mode = 'restricted'. */
  assigned_users: string | null;
  /** 1 = the session must carry a second factor ('mfa'/'hwk'/'ext' in amr) to SSO. */
  require_mfa: number;
  /** 1 = users without access may ask for it from My account -> Access. */
  requestable: number;
  /** Authentication policy required of sign-ins into this app; NULL = the person's own policy. */
  policy_id: number | null;
}

export interface SamlServiceProviderRow {
  id: number;
  entity_id: string;
  name: string;
  acs_urls: string; // JSON array of absolute URLs - the exact-match allowlist
  default_acs_url: string | null;
  /** 'transient' | 'emailAddress' | 'persistent', or 'none' (omit <saml:NameID> from the Subject - IIP-IDP11). */
  nameid_format: string;
  attribute_map: string; // JSON object: SAML attribute name -> user field
  /** JSON array of {name, field, nameFormat?}: arbitrary Name + NameFormat per released attribute (IIP-IDP01). NULL/[] = use attribute_map. */
  attribute_definitions: string | null;
  sign_response: number;
  sign_assertion: number;
  want_authn_requests_signed: number;
  signing_certs: string; // JSON array of PEM strings
  /** Where LogoutResponses go (HTTP-Redirect); NULL = no Single Logout. */
  slo_url: string | null;
  encrypt_assertions: number;
  encryption_cert: string | null;
  /** JSON {content, transport, digest, mgf, advertised[]} - see spEncryptionPolicy. NULL = default. */
  encryption_policy: string | null;
  metadata_url: string | null;
  metadata_last_refreshed_at: string | null;
  metadata_valid_until: string | null;
  /** '' | 'subject-id' | 'pairwise-id' (SAML Subject Identifier Attributes Profile). */
  subject_id: string;
  /** App icon shown on the user launchpad; absolute https URL, NULL = letter tile. */
  logo_uri: string | null;
  /** JSON array of group ids allowed to see and SSO into this app (restricted mode). */
  assigned_groups: string | null;
  /** 'everyone' | 'restricted': in restricted mode only assigned_users/groups reach the app. */
  access_mode: string;
  /** JSON array of user ids allowed when access_mode = 'restricted'. */
  assigned_users: string | null;
  /** 1 = the session must carry a second factor ('mfa'/'hwk'/'ext' in amr) to SSO. */
  require_mfa: number;
  /** 1 = users without access may ask for it from My account -> Access. */
  requestable: number;
  /** Authentication policy required of sign-ins into this app; NULL = the person's own policy. */
  policy_id: number | null;
  created_at: string;
  updated_at: string;
}

/** A registered LDAP application: a service account plus its visibility policy (migrations/0030_ldap.sql, LDAP.md section 7). */
export interface LdapAppRow {
  id: number;
  slug: string;
  name: string;
  secret_hash: string;
  secret_prefix: string;
  /** AES-256-GCM sealed secret for console reveal; NULL for apps created before reveal existed. */
  secret_enc: string | null;
  /** JSON array of group ids whose members may bind and are visible; '[]' = every active user. */
  user_group_ids: string;
  /** JSON array of group ids visible as group entries; '[]' = all groups. */
  exposed_group_ids: string;
  /** 'password' | 'otp_if_enrolled' | 'otp_required' (LDAP.md section 13). */
  mfa_mode: string;
  include_disabled: number;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}
