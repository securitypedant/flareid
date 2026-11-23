import { z } from "@hono/zod-openapi";

/**
 * Request and response schemas shared by several API routes. Response
 * schemas document what callers can rely on; they are not enforced at run
 * time, and objects may carry more fields than listed (passthrough).
 */

export const IdParam = z.object({ id: z.string().openapi({ description: "Numeric id.", example: "12" }) });

export const Paging = {
  limit: z.string().optional().openapi({ description: "Page size (default 100, at most 500).", example: "100" }),
  offset: z.string().optional().openapi({ description: "Rows to skip.", example: "0" }),
};

export const StringMap = z.record(z.string(), z.string());

export const RuleSchema = z
  .object({
    all: z
      .array(
        z.object({
          field: z.string().openapi({ example: "department" }),
          op: z.enum(["eq", "ne"]),
          value: z.string().openapi({ example: "Sales" }),
          schema: z.string().optional().openapi({ description: "The schema the attribute was picked from; display only." }),
        })
      )
      .min(1),
  })
  .openapi("GroupRule", { description: "A dynamic group's membership rule: every condition must hold." });

export const UserSchema = z
  .object({
    upn: z.string(),
    username: z.string(),
    email: z.string().nullable(),
    emails: z.array(z.object({ value: z.string(), type: z.string(), primary: z.boolean() })).openapi({ description: "Every contact address on the account; the primary is what `email` and mail deliveries use." }),
    display_name: z.string(),
    given_name: z.string(),
    family_name: z.string(),
    external_id: z.string(),
    status: z.enum(["active", "disabled"]),
    mfa_enabled: z.boolean().openapi({ description: "An authenticator app (TOTP) is enrolled. Only that factor: see second_factors for all of them." }),
    email_otp_enabled: z.boolean().openapi({ description: "Email one-time codes are enrolled as a second factor." }),
    security_questions_enabled: z.boolean().openapi({ description: "Security questions are set as a second factor." }),
    second_factors: z
      .array(z.enum(["totp", "passkey", "email_otp", "security_questions"]))
      .openapi({ description: "Every second factor enrolled: an authenticator app, at least one passkey, email codes, security questions (which do not count for administrators). Empty when there is none." }),
    job_title: z.string(),
    department: z.string(),
    employee_number: z.string(),
    hire_date: z.string(),
    employment_status: z.string(),
    employment_type: z.string(),
    location: z.string(),
    manager_external_id: z.string().nullable(),
    manager_upn: z.string().nullable(),
    schema_id: z.number().nullable(),
    schema_name: z.string().nullable(),
    attributes: StringMap,
    groups: z.array(z.string()),
    created_at: z.string(),
    updated_at: z.string(),
  })
  .passthrough()
  .openapi("User");

export const GroupSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    description: z.string().nullable(),
    rule: z.string().openapi({ description: "Rule JSON (see GroupRule), or empty for a static group." }),
    schema_id: z.number().nullable(),
    schema_name: z.string().nullable(),
    attributes: StringMap,
    member_count: z.number(),
    explicit_member_count: z.number(),
    requestable: z.boolean().openapi({ description: "Whether people may ask for membership on My account (static groups only)." }),
    cf_list_sync: z.boolean().openapi({ description: "Member emails are kept in a Cloudflare One gateway list." }),
  })
  .passthrough()
  .openapi("Group");

export const MemberSchema = z
  .object({ upn: z.string(), username: z.string(), display_name: z.string(), status: z.enum(["active", "disabled"]) })
  .openapi("GroupMember");

export const ClientSchema = z
  .object({
    id: z.number(),
    client_id: z.string(),
    name: z.string(),
    client_type: z.enum(["confidential", "public"]),
    redirect_uris: z.array(z.string()),
    post_logout_redirect_uris: z.array(z.string()),
    frontchannel_logout_uri: z.string().nullable(),
    trusted: z.boolean(),
    allowed_claims: z.array(z.string()).nullable().openapi({ description: "Claim groups released to this client; null = every group." }),
    access_mode: z.enum(["everyone", "restricted"]).openapi({ description: "restricted = only assigned_users/groups may see and sign in to this app." }),
    assigned_groups: z.array(z.number()).openapi({ description: "Group ids (static or dynamic) assigned to this app." }),
    assigned_users: z.array(z.number()).openapi({ description: "User ids assigned to this app." }),
    require_mfa: z.boolean().openapi({ description: "The session must carry a second factor to SSO into this app." }),
    requestable: z.boolean().openapi({ description: "People without access may request it under My account -> Access." }),
    id_token_signed_response_alg: z.enum(["RS256", "ES256"]).openapi({ description: "How this client's id_tokens are signed." }),
    created_at: z.string(),
  })
  .passthrough()
  .openapi("OidcClient");

const AttributeDefinitionSchema = z
  .object({
    name: z.string().openapi({ description: "The saml:Attribute Name - an arbitrary string." }),
    field: z.string().openapi({ description: "The user field feeding it (same vocabulary as attribute_map values)." }),
    name_format: z.string().nullable().openapi({ description: "The saml:Attribute NameFormat - an arbitrary URI; null = the IdP default (attrname-format:uri)." }),
  })
  .openapi("SamlAttributeDefinition");

export const ServiceProviderSchema = z
  .object({
    id: z.number(),
    entity_id: z.string(),
    name: z.string(),
    acs_urls: z.array(z.string()),
    default_acs_url: z.string().nullable(),
    nameid_format: z.string().openapi({ description: 'transient, emailAddress, persistent - or "none": the Subject carries no <saml:NameID>.' }),
    attribute_map: StringMap,
    attribute_definitions: z.array(AttributeDefinitionSchema).openapi({ description: "Released attributes with arbitrary Name/NameFormat; overrides attribute_map when non-empty." }),
    sign_response: z.boolean(),
    sign_assertion: z.boolean(),
    want_authn_requests_signed: z.boolean(),
    signing_certs: z.array(z.string()),
    slo_url: z.string().nullable(),
    encryption_cert: z.string().nullable(),
    encrypt_assertions: z.boolean(),
    access_mode: z.enum(["everyone", "restricted"]).openapi({ description: "restricted = only assigned_users/groups may see and SSO into this app." }),
    assigned_groups: z.array(z.number()).openapi({ description: "Group ids (static or dynamic) assigned to this app." }),
    assigned_users: z.array(z.number()).openapi({ description: "User ids assigned to this app." }),
    require_mfa: z.boolean().openapi({ description: "The session must carry a second factor to SSO into this app." }),
    requestable: z.boolean().openapi({ description: "People without access may request it under My account -> Access." }),
    created_at: z.string(),
    updated_at: z.string(),
  })
  .passthrough()
  .openapi("SamlServiceProvider");

export const PasswordPolicySchema = z
  .object({
    minLength: z.number().int().optional(),
    requireUppercase: z.boolean().optional(),
    requireLowercase: z.boolean().optional(),
    requireNumber: z.boolean().optional(),
    requireSymbol: z.boolean().optional(),
  })
  .openapi("PasswordPolicy");

export const SchemaAttributeInput = z.object({
  name: z.string(),
  label: z.string().optional(),
  type: z.string().optional().openapi({ description: "string, number, date, boolean or reference." }),
  required: z.boolean().optional(),
  ref_object: z.string().optional(),
  user_editable: z.boolean().optional(),
});

export const AuditEntrySchema = z
  .object({
    id: z.number(),
    at: z.string(),
    actor_upn: z.string().nullable(),
    action: z.string(),
    target: z.string().nullable(),
    details: z.unknown().nullable(),
    ip: z.string().nullable(),
    user_agent: z.string().nullable(),
  })
  .openapi("AuditEntry");
