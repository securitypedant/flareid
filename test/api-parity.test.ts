// The dashboard uses the API, and the API must be complete as console
// features are built: every action the admin console can take has an API
// operation, every API route is in the OpenAPI document, and the committed
// docs/openapi.json is the document the code generates.
import { describe, expect, it } from "vitest";
import { admin } from "../src/routes/admin.js";
import { account } from "../src/routes/account.js";
import { api } from "../src/routes/api.js";
import { isApiScope } from "../src/lib/api-keys.js";
import committed from "../docs/openapi.json";
import { apiCall, bootstrapInstance } from "./helpers.js";

/**
 * Each mutating console route and the API operation that does the same thing.
 * A new console POST route fails this test until it is mapped here, to an
 * operation that exists in the spec - or, if it genuinely has no meaning for
 * a token, listed in CONSOLE_ONLY with the reason.
 */
const CONSOLE_TO_API: Record<string, string | string[]> = {
  "POST /admin/setup": "POST /api/v1/setup",
  "POST /admin/users/import": "POST /api/v1/directory/import",
  "POST /admin/users": "POST /api/v1/users",
  "POST /admin/users/:id/status": "PATCH /api/v1/users/{username}",
  "POST /admin/users/:id": "PATCH /api/v1/users/{username}",
  "POST /admin/users/:id/invite": "POST /api/v1/users/{username}/invite",
  "POST /admin/users/:id/send-reset": "POST /api/v1/users/{username}/invite",
  "POST /admin/users/:id/reset-mfa": "POST /api/v1/users/{username}/reset-mfa",
  "POST /admin/users/:id/reset-password": "POST /api/v1/users/{username}/reset-password",
  "POST /admin/users/:id/sessions/revoke-all": "DELETE /api/v1/users/{username}/sessions",
  "POST /admin/users/:id/watch": "PUT /api/v1/users/{username}/watch",
  "POST /admin/users/:id/unwatch": "DELETE /api/v1/users/{username}/watch",
  "POST /admin/users/:id/apps/:clientDbId/revoke": "DELETE /api/v1/users/{username}/apps/{client_id}",
  "POST /admin/users/:id/delete": "DELETE /api/v1/users/{username}",
  "POST /admin/groups": "POST /api/v1/groups",
  "POST /admin/groups/:id/members/:uid/remove": "DELETE /api/v1/groups/{id}/members/{username}",
  "POST /admin/groups/:id/managers": "POST /api/v1/groups/{id}/managers",
  "POST /admin/groups/:id/managers/:uid/remove": "DELETE /api/v1/groups/{id}/managers/{username}",
  "POST /admin/groups/:id/freeze": "POST /api/v1/groups/{id}/freeze",
  "POST /admin/groups/:id": "PATCH /api/v1/groups/{id}",
  "POST /admin/groups/:id/delete": "DELETE /api/v1/groups/{id}",
  "POST /admin/groups/bulk": "POST /api/v1/groups/bulk",
  "POST /admin/access/requests/:id": "POST /api/v1/access/requests/{id}",
  "POST /admin/access/reviews": "POST /api/v1/access/campaigns",
  "POST /admin/access/reviews/:id/close": "POST /api/v1/access/campaigns/{id}/close",
  "POST /admin/access/reviews/:id/items/:itemId": "POST /api/v1/access/campaigns/{id}/items/{item_id}",
  "POST /admin/email/enabled": "POST /api/v1/email/enabled",
  "POST /admin/email": "PUT /api/v1/email",
  "POST /admin/email/test": "POST /api/v1/email/test",
  "POST /admin/sms": "PUT /api/v1/sms",
  "POST /admin/users/:id/reports/:rid/resolve": "POST /api/v1/account-reports/{id}/resolve",
  "POST /admin/integrations/cf-one": "PUT /api/v1/integrations/cloudflare-one",
  "POST /admin/integrations/cf-one/sync": "POST /api/v1/integrations/cloudflare-one/sync",
  "POST /admin/integrations/cf-one/watch": "PUT /api/v1/users/{username}/watch",
  "POST /admin/integrations/cf-one/watch/:uid/remove": "DELETE /api/v1/users/{username}/watch",
  "POST /admin/integrations/cf-one/apps/sync": "POST /api/v1/integrations/cloudflare-one/access-apps/sync",
  "POST /admin/integrations/cf-one/apps/schedule": "PUT /api/v1/integrations/cloudflare-one",
  "POST /admin/integrations/cf-one/apps/:id": "PATCH /api/v1/integrations/cloudflare-one/access-apps/{id}",
  "POST /admin/integrations/signals/streams": "POST /api/v1/ssf/streams",
  "POST /admin/integrations/signals/streams/:id/toggle": "PATCH /api/v1/ssf/streams/{id}",
  "POST /admin/integrations/signals/streams/:id/delete": "DELETE /api/v1/ssf/streams/{id}",
  "POST /admin/integrations/signals/drain": "POST /api/v1/ssf/outbox/drain",
  "POST /admin/integrations/signals/transmitters": "POST /api/v1/ssf/transmitters",
  "POST /admin/integrations/signals/transmitters/:id/delete": "DELETE /api/v1/ssf/transmitters/{id}",
  "POST /admin/api-keys": "POST /api/v1/api-keys",
  "POST /admin/api-keys/:id/edit": "PATCH /api/v1/api-keys/{id}",
  "POST /admin/api-keys/:id/revoke": "DELETE /api/v1/api-keys/{id}",
  "POST /admin/clients": "POST /api/v1/clients",
  "POST /admin/clients/:id": "PATCH /api/v1/clients/{client_id}",
  "POST /admin/clients/:id/access": "PATCH /api/v1/clients/{client_id}",
  "POST /admin/clients/:id/policies": "PATCH /api/v1/clients/{client_id}",
  "POST /admin/clients/:id/rotate-secret": "POST /api/v1/clients/{client_id}/rotate-secret",
  "POST /admin/clients/:id/delete": "DELETE /api/v1/clients/{client_id}",
  "POST /admin/saml/import-metadata": "POST /api/v1/saml/service-providers/import-metadata",
  "POST /admin/saml/settings": "PUT /api/v1/saml/settings",
  "POST /admin/saml": "POST /api/v1/saml/service-providers",
  // The API's register call is an upsert keyed on entity_id.
  "POST /admin/saml/:id": "POST /api/v1/saml/service-providers",
  "POST /admin/saml/:id/access": "POST /api/v1/saml/service-providers",
  "POST /admin/saml/:id/policies": "POST /api/v1/saml/service-providers",
  "POST /admin/saml/:id/delete": "DELETE /api/v1/saml/service-providers/{id}",
  "POST /admin/apps/catalog/:slug/apply": "POST /api/v1/app-catalog/{slug}/apply",
  "POST /admin/schemas": "POST /api/v1/schemas",
  "POST /admin/schemas/:id": "PATCH /api/v1/schemas/{id}",
  "POST /admin/schemas/:id/apply": "POST /api/v1/schemas/{id}/apply",
  "POST /admin/schemas/:id/delete": "DELETE /api/v1/schemas/{id}",
  "POST /admin/domains": "POST /api/v1/domains",
  "POST /admin/domains/:id/set-default": "POST /api/v1/domains/{domain}/default",
  "POST /admin/domains/:id/delete": "DELETE /api/v1/domains/{domain}",
  "POST /admin/domains/:id/apply-to-all": "POST /api/v1/domains/{domain}/apply-to-all",
  "POST /admin/domains/:id/brand": "PUT /api/v1/domains/{domain}/brand",
  "POST /admin/security/default-password": "PUT /api/v1/security/new-user-password",
  "POST /admin/security/new-user-password-mode": "PUT /api/v1/security/new-user-password",
  "POST /admin/security/apply-default-password": "POST /api/v1/security/new-user-password/apply-to-all",
  "POST /admin/security/password-policy": "PUT /api/v1/security/password-policy",
  "POST /admin/security/breached-passwords": "PUT /api/v1/security/breached-passwords",
  "POST /admin/security/alias-signin": "PUT /api/v1/security/alias-signin",
  "POST /admin/security/turnstile": "PUT /api/v1/security/turnstile",
  "POST /admin/security/require-mfa": "PUT /api/v1/security/require-mfa",
  "POST /admin/security/rate-limit": "PUT /api/v1/security/rate-limit",
  "POST /admin/security/session-limits": "PUT /api/v1/security/session-limits",
  "POST /admin/security/audit-retention": "PUT /api/v1/security/audit-retention",
  "POST /admin/security/policies": "POST /api/v1/security/policies",
  "POST /admin/security/policies/:id": "PATCH /api/v1/security/policies/{id}",
  "POST /admin/security/policies/:id/delete": "DELETE /api/v1/security/policies/{id}",
  "POST /admin/security/roles": "POST /api/v1/security/roles",
  "POST /admin/security/roles/:id": "PATCH /api/v1/security/roles/{id}",
  "POST /admin/security/roles/:id/delete": "DELETE /api/v1/security/roles/{id}",
  "POST /admin/security/factors/:key": "PUT /api/v1/security/factors/{key}",
  "POST /admin/security/factors/security-questions/settings": "PUT /api/v1/security/security-questions",
  "POST /admin/security/factors/security-questions/questions": "POST /api/v1/security/security-questions/questions",
  "POST /admin/security/factors/security-questions/questions/:id": "PATCH /api/v1/security/security-questions/questions/{id}",
  "POST /admin/security/factors/security-questions/questions/:id/delete": "DELETE /api/v1/security/security-questions/questions/{id}",
  "POST /admin/security/signing-keys/:alg/rotate": "POST /api/v1/security/signing-keys/{alg}/rotate",
  "POST /admin/branding/app-name": "PATCH /api/v1/branding",
  "POST /admin/branding/login-gradient": "PATCH /api/v1/branding",
  "POST /admin/branding/cursor-trail": "PATCH /api/v1/branding",
  "POST /admin/branding/language": "PATCH /api/v1/branding",
  "POST /admin/branding/timezone": "PATCH /api/v1/branding",
  "POST /admin/branding/email-templates/:key": "PUT /api/v1/branding/email-templates/{key}",
  "POST /admin/branding/email-templates/:key/reset": "DELETE /api/v1/branding/email-templates/{key}",
  "POST /admin/branding/email-accent": "PATCH /api/v1/branding",
  "POST /admin/branding/custom-css": "PATCH /api/v1/branding",
  "POST /admin/branding/logo": "PUT /api/v1/branding/logo",
  "POST /admin/branding/logo/delete": "DELETE /api/v1/branding/logo",
  "POST /admin/branding/brands": "POST /api/v1/branding/brands",
  "POST /admin/branding/brands/:id": "PATCH /api/v1/branding/brands/{id}",
  "POST /admin/branding/brands/:id/delete": "DELETE /api/v1/branding/brands/{id}",
  "POST /admin/branding/brands/:id/logo": "PUT /api/v1/branding/brands/{id}/logo",
  "POST /admin/branding/brands/:id/logo/delete": "DELETE /api/v1/branding/brands/{id}/logo",
  "POST /admin/scim/targets": "POST /api/v1/scim/targets",
  "POST /admin/scim/targets/:id": "PATCH /api/v1/scim/targets/{id}",
  "POST /admin/scim/targets/:id/scope": "PATCH /api/v1/scim/targets/{id}",
  "POST /admin/scim/targets/:id/tuning": "PATCH /api/v1/scim/targets/{id}",
  "POST /admin/scim/targets/:id/delete": "DELETE /api/v1/scim/targets/{id}",
  "POST /admin/scim/mappings": "PUT /api/v1/scim/mappings",
  "POST /admin/flows/mappings": "PUT /api/v1/mappings",
  "POST /admin/flows/collision": "PUT /api/v1/mappings/collisions",
  "POST /admin/scim/correlation": "PUT /api/v1/scim/correlation",
  "POST /admin/scim/mastering": "PUT /api/v1/scim/mastering",
  "POST /admin/scim/test": "POST /api/v1/scim/test",
  "POST /admin/scim/sync": "POST /api/v1/scim/sync",
  "POST /admin/federation/idps": "POST /api/v1/federation/idps",
  "POST /admin/federation/idps/:id": "PATCH /api/v1/federation/idps/{id}",
  "POST /admin/federation/idps/:id/delete": "DELETE /api/v1/federation/idps/{id}",
  "POST /admin/social/:key": ["POST /api/v1/federation/idps", "PATCH /api/v1/federation/idps/{id}"],
  "POST /admin/social/:key/delete": "DELETE /api/v1/federation/idps/{id}",
  "POST /admin/integrations/ldap/settings": "POST /api/v1/ldap/settings",
  "POST /admin/ldap": "POST /api/v1/ldap/apps",
  "POST /admin/ldap/:slug": "POST /api/v1/ldap/apps",
  "POST /admin/ldap/:slug/rotate": "POST /api/v1/ldap/apps/{slug}/rotate",
  "POST /admin/ldap/:slug/reveal": "POST /api/v1/ldap/apps/{slug}/reveal",
  "POST /admin/ldap/:slug/revoke": "DELETE /api/v1/ldap/apps/{slug}",
};

/** Console actions with no API meaning, each with why. Keep this list short. */
const CONSOLE_ONLY: Record<string, string> = {
  // Step-up re-authentication proves a person is at the browser; a bearer
  // token is not a person and has nothing to re-enter.
  "POST /admin/reauth": "step-up re-authentication (password or code)",
  "POST /admin/reauth/passkey": "step-up re-authentication (passkey)",
  "POST /admin/reauth/email/send": "step-up re-authentication (emailed code)",
};

/**
 * The self-service console's mutating routes and their API operations. The
 * operation acts on the named user: what "me" can do to their own account,
 * a token can do to any account it has permission for.
 */
const ACCOUNT_TO_API: Record<string, string> = {
  "POST /account/groups/:id/members": "POST /api/v1/groups/{id}/members",
  "POST /account/groups/:id/members/:uid/remove": "DELETE /api/v1/groups/{id}/members/{username}",
  "POST /account/groups/:id/requests/:rid": "POST /api/v1/access/requests/{id}",
  "POST /account/profile": "PATCH /api/v1/users/{username}",
  "POST /account/photo": "PUT /api/v1/users/{username}/photo",
  "POST /account/photo/remove": "DELETE /api/v1/users/{username}/photo",
  "POST /account/access/request": "POST /api/v1/access/requests",
  "POST /account/access/requests/:id/cancel": "POST /api/v1/access/requests/{id}/cancel",
  "POST /account/apps/:clientDbId/revoke": "DELETE /api/v1/users/{username}/apps/{client_id}",
  "POST /account/passkeys/:id/remove": "DELETE /api/v1/users/{username}/passkeys/{credential_id}",
  "POST /account/mfa/disable": "POST /api/v1/users/{username}/reset-mfa",
  "POST /account/devices/:id/revoke": "DELETE /api/v1/users/{username}/devices/{id}",
};

/** Self-service actions with no API meaning. */
const ACCOUNT_CONSOLE_ONLY: Record<string, string> = {
  // These name a secret the browser holds, which the API deliberately never
  // exposes - or prove a person is at the keyboard, which a bearer token is
  // not. Bulk equivalents exist (reset-mfa, sign-out-everywhere).
  "POST /account/sessions/:id/revoke": "a session id is the cookie's secret - the API never exposes it",
  "POST /account/sessions/revoke-others": '"others" is relative to the session cookie itself; a token has no current session',
  "POST /account/password": "requires the current password as proof",
  "POST /account/passkeys": "WebAuthn attestation ceremony",
  "POST /account/mfa/passkey-enrolled": "WebAuthn enrolment ceremony",
  "POST /account/mfa/setup": "TOTP enrolment ceremony (secret display + code proof)",
  "POST /account/mfa/email/send": "emailed one-time code",
  "POST /account/mfa/email/enable": "email-factor enrolment ceremony",
  "POST /account/mfa/email/disable": "partial factor self-management; admin reset-mfa covers recovery",
  "POST /account/mfa/sms/send": "texted one-time code",
  "POST /account/mfa/sms/enable": "SMS-factor enrolment ceremony",
  "POST /account/mfa/sms/disable": "partial factor self-management; admin reset-mfa covers recovery",
  "POST /account/mfa/questions": "security-question enrolment",
  "POST /account/mfa/questions/remove": "partial factor self-management; admin reset-mfa covers recovery",
  "POST /account/mfa/backup-codes/regenerate": "credential self-management; admin reset-mfa covers recovery",
  "POST /account/mfa/backup-codes/generate": "codes are shown to their owner once; admin reset-mfa covers recovery",
  "POST /account/backup-codes/remove": "partial factor self-management; admin reset-mfa covers recovery",
  "POST /account/aliases": "adds an unverified alias and sends a proof-of-ownership code to it",
  "POST /account/aliases/verify": "code-entry ceremony proving ownership of the new alias",
  "POST /account/aliases/delete": "self-service alias removal; admins use PATCH /api/v1/users/{username}",
  "POST /account/sessions/:id/report": "a session id is the cookie's secret - the API never exposes it",
  "POST /account/devices/:id/report": "names a remembered device the person sees on their own Security page",
};

/**
 * Console pages and the API reads that carry their data. A page may draw on
 * several operations; every one listed must exist in the spec. Rendered
 * forms, wizards, redirects and browser ceremonies are CONSOLE_GET_ONLY.
 */
const CONSOLE_GET_TO_API: Record<string, string[]> = {
  "GET /admin": ["GET /api/v1/stats"],
  "GET /admin/access": ["GET /api/v1/access/requests"],
  "GET /admin/access/reviews/:id": ["GET /api/v1/access/campaigns/{id}"],
  "GET /admin/api-keys/:id/edit": ["GET /api/v1/api-keys"],
  "GET /admin/apps": ["GET /api/v1/clients", "GET /api/v1/saml/service-providers"],
  "GET /admin/apps/catalog": ["GET /api/v1/app-catalog"],
  "GET /admin/apps/catalog/:slug": ["GET /api/v1/app-catalog/{slug}"],
  "GET /admin/audit": ["GET /api/v1/audit"],
  "GET /admin/audit/export": ["GET /api/v1/audit/export"],
  "GET /admin/branding": ["GET /api/v1/branding"],
  "GET /admin/branding/brands": ["GET /api/v1/branding/brands"],
  "GET /admin/branding/brands/:id": ["GET /api/v1/branding/brands/{id}"],
  "GET /admin/branding/email-templates": ["GET /api/v1/branding/email-templates"],
  "GET /admin/clients/:id": ["GET /api/v1/clients/{client_id}"],
  "GET /admin/domains": ["GET /api/v1/domains"],
  "GET /admin/flows": ["GET /api/v1/mappings", "GET /api/v1/mappings/collisions"],
  "GET /admin/flows/edit": ["GET /api/v1/mappings"],
  "GET /admin/groups": ["GET /api/v1/groups"],
  "GET /admin/groups/:id": ["GET /api/v1/groups/{id}"],
  "GET /admin/groups/lookup": ["GET /api/v1/groups"],
  "GET /admin/integrations": ["GET /api/v1/status"],
  "GET /admin/integrations/api-keys": ["GET /api/v1/api-keys"],
  "GET /admin/integrations/cf-one": ["GET /api/v1/integrations/cloudflare-one"],
  "GET /admin/integrations/signals": ["GET /api/v1/ssf/streams", "GET /api/v1/ssf/transmitters"],
  "GET /admin/integrations/email": ["GET /api/v1/email"],
  "GET /admin/integrations/sms": ["GET /api/v1/sms"],
  "GET /admin/integrations/federation": ["GET /api/v1/federation/idps"],
  "GET /admin/integrations/federation/:id": ["GET /api/v1/federation/idps/{id}"],
  "GET /admin/integrations/social": ["GET /api/v1/social/providers", "GET /api/v1/federation/idps"],
  "GET /admin/integrations/social/:key": ["GET /api/v1/social/providers", "GET /api/v1/federation/idps/{id}"],
  "GET /admin/integrations/ldap": ["GET /api/v1/ldap/settings", "GET /api/v1/ldap/apps"],
  "GET /admin/integrations/saml": ["GET /api/v1/saml/settings"],
  "GET /admin/integrations/scim": ["GET /api/v1/scim/config", "GET /api/v1/scim/targets"],
  "GET /admin/integrations/scim/:id": ["GET /api/v1/scim/targets/{id}"],
  "GET /admin/ldap/:slug": ["GET /api/v1/ldap/apps/{slug}"],
  "GET /admin/performance": ["GET /api/v1/performance"],
  "GET /admin/performance/live": ["GET /api/v1/performance"],
  "GET /admin/saml/:id": ["GET /api/v1/saml/service-providers/{id}"],
  "GET /admin/schemas": ["GET /api/v1/schemas"],
  "GET /admin/schemas/:id": ["GET /api/v1/schemas"],
  "GET /admin/security": ["GET /api/v1/security"],
  "GET /admin/security/factors": ["GET /api/v1/security/factors"],
  "GET /admin/security/factors/security-questions": ["GET /api/v1/security/security-questions"],
  "GET /admin/security/policies": ["GET /api/v1/security/policies"],
  "GET /admin/security/policies/:id": ["GET /api/v1/security/policies/{id}"],
  "GET /admin/security/roles": ["GET /api/v1/security/roles"],
  "GET /admin/security/roles/:id": ["GET /api/v1/security/roles"],
  "GET /admin/security/signing-keys": ["GET /api/v1/security/signing-keys"],
  "GET /admin/users": ["GET /api/v1/users"],
  "GET /admin/users/:id": ["GET /api/v1/users/{username}"],
  "GET /admin/users/lookup": ["GET /api/v1/users"],
};

/** Pages a token has no use for: rendered forms, wizards, redirects and step-up ceremonies. */
const CONSOLE_GET_ONLY: Record<string, string> = {
  "GET /admin/access/reviews/new": "rendered form",
  "GET /admin/api-keys/new": "rendered form",
  "GET /admin/branding/email-templates/preview": "UI render preview",
  "GET /admin/clients": "redirect to /admin/apps",
  "GET /admin/clients/new": "rendered form",
  "GET /admin/groups/import": "rendered form",
  "GET /admin/groups/new": "rendered form",
  "GET /admin/integrations/federation/new": "rendered form",
  "GET /admin/integrations/oidc": "redirect to /admin/apps",
  "GET /admin/integrations/scim/new": "rendered form",
  "GET /admin/ldap/new": "rendered form",
  "GET /admin/log": "redirect to /admin/audit",
  "GET /admin/reauth": "step-up re-authentication",
  "GET /admin/reauth/passkey/options": "step-up re-authentication ceremony",
  "GET /admin/reauth/resume": "step-up re-authentication",
  "GET /admin/saml/new": "rendered form",
  "GET /admin/security/roles/new": "rendered form",
  "GET /admin/scim": "redirect to /admin/integrations/scim",
  "GET /admin/setup": "first-run setup form",
  "GET /admin/users/import": "rendered form",
  "GET /admin/users/new": "rendered form",
};

/** Self-service pages and the API reads carrying their data. */
const ACCOUNT_GET_TO_API: Record<string, string[]> = {
  "GET /account": ["GET /api/v1/users/{username}", "GET /api/v1/users/{username}/apps"],
  "GET /account/access": ["GET /api/v1/access/requests", "GET /api/v1/groups", "GET /api/v1/clients", "GET /api/v1/saml/service-providers"],
  "GET /account/access/targets": ["GET /api/v1/access/requests", "GET /api/v1/groups", "GET /api/v1/clients", "GET /api/v1/saml/service-providers"],
  "GET /account/applications": ["GET /api/v1/users/{username}/apps"],
  "GET /account/groups": ["GET /api/v1/groups"],
  "GET /account/groups/:id": ["GET /api/v1/groups/{id}"],
  "GET /account/groups/:id/people": ["GET /api/v1/groups/{id}"],
  "GET /account/photo/:uid": ["GET /api/v1/users/{username}/photo"],
  "GET /account/security": ["GET /api/v1/users/{username}/sessions", "GET /api/v1/users/{username}/passkeys", "GET /api/v1/users/{username}/devices"],
};

const ACCOUNT_GET_ONLY: Record<string, string> = {
  "GET /account/mfa/setup": "TOTP enrolment ceremony",
  "GET /account/passkeys/:id/remove": "rendered confirmation",
  "GET /account/passkeys/options": "WebAuthn ceremony",
};

/** Routes on the API app that are not operations in the document. */
const NOT_OPERATIONS: Record<string, string> = {
  // The document itself.
  "GET /api/v1/openapi.json": "serves the OpenAPI document",
};

type Spec = { openapi: string; paths: Record<string, Record<string, { tags?: string[]; "x-permission"?: string; responses: Record<string, unknown> }>>; components: { schemas: Record<string, unknown> } };

const specOps = (spec: Spec) => new Set(Object.entries(spec.paths).flatMap(([path, item]) => Object.keys(item).map((m) => `${m.toUpperCase()} ${path}`)));
const routeKey = (method: string, path: string) => `${method} ${path.replace(/:([^/]+)/g, "{$1}")}`;

async function liveSpec(): Promise<Spec> {
  const res = await apiCall("/api/v1/openapi.json");
  expect(res.status).toBe(200);
  return res.body as Spec;
}

describe("API parity with the admin console", () => {
  it("serves the OpenAPI document without a token", async () => {
    const spec = await liveSpec();
    expect(spec.openapi).toBe("3.1.0");
    expect(Object.keys(spec.paths).length).toBeGreaterThan(40);
  });

  it("maps every mutating console route to an operation in the spec", async () => {
    const ops = specOps(await liveSpec());
    const consoleRoutes = [...new Set(admin.routes.filter((r) => r.method === "POST" && r.path.startsWith("/admin")).map((r) => `${r.method} ${r.path}`))];
    const unmapped = consoleRoutes.filter((r) => !(r in CONSOLE_TO_API) && !(r in CONSOLE_ONLY));
    expect(unmapped, "console actions with no API operation: add the operation, then map it here").toEqual([]);
    const missing = consoleRoutes.flatMap((r) => [CONSOLE_TO_API[r] ?? []].flat().filter((o) => !ops.has(o)).map((o) => `${r} -> ${o}`));
    expect(missing, "mapped to operations the spec does not have").toEqual([]);
    // A stale entry (the console route was removed or renamed) is a mistake too.
    expect(Object.keys(CONSOLE_TO_API).filter((k) => !consoleRoutes.includes(k))).toEqual([]);
    expect(Object.keys(CONSOLE_ONLY).filter((k) => !consoleRoutes.includes(k))).toEqual([]);
  });

  it("maps every mutating self-service route to an operation in the spec", async () => {
    const ops = specOps(await liveSpec());
    const accountRoutes = [...new Set(account.routes.filter((r) => r.method === "POST" && r.path.startsWith("/account")).map((r) => `${r.method} ${r.path}`))];
    const unmapped = accountRoutes.filter((r) => !(r in ACCOUNT_TO_API) && !(r in ACCOUNT_CONSOLE_ONLY));
    expect(unmapped, "self-service actions with no API operation: add the operation, then map it here").toEqual([]);
    const missing = accountRoutes.filter((r) => r in ACCOUNT_TO_API && !ops.has(ACCOUNT_TO_API[r]!)).map((r) => `${r} -> ${ACCOUNT_TO_API[r]}`);
    expect(missing, "mapped to operations the spec does not have").toEqual([]);
    expect(Object.keys(ACCOUNT_TO_API).filter((k) => !accountRoutes.includes(k))).toEqual([]);
    expect(Object.keys(ACCOUNT_CONSOLE_ONLY).filter((k) => !accountRoutes.includes(k))).toEqual([]);
  });

  it("maps every console GET to a readable operation or marks it console-only", async () => {
    const ops = specOps(await liveSpec());
    const consoleGets = [...new Set(admin.routes.filter((r) => r.method === "GET" && r.path.startsWith("/admin")).map((r) => `${r.method} ${r.path}`))];
    const unmapped = consoleGets.filter((r) => !(r in CONSOLE_GET_TO_API) && !(r in CONSOLE_GET_ONLY));
    expect(unmapped, "console pages whose data no API operation returns: add the read, map it here, or mark it console-only").toEqual([]);
    const missing = consoleGets.flatMap((r) => (CONSOLE_GET_TO_API[r] ?? []).filter((o) => !ops.has(o)).map((o) => `${r} -> ${o}`));
    expect(missing, "mapped to operations the spec does not have").toEqual([]);
    expect(Object.keys(CONSOLE_GET_TO_API).filter((k) => !consoleGets.includes(k))).toEqual([]);
    expect(Object.keys(CONSOLE_GET_ONLY).filter((k) => !consoleGets.includes(k))).toEqual([]);
  });

  it("maps every self-service GET to a readable operation or marks it console-only", async () => {
    const ops = specOps(await liveSpec());
    const accountGets = [...new Set(account.routes.filter((r) => r.method === "GET" && r.path.startsWith("/account")).map((r) => `${r.method} ${r.path}`))];
    const unmapped = accountGets.filter((r) => !(r in ACCOUNT_GET_TO_API) && !(r in ACCOUNT_GET_ONLY));
    expect(unmapped, "self-service pages whose data no API operation returns: add the read, map it here, or mark it console-only").toEqual([]);
    const missing = accountGets.flatMap((r) => (ACCOUNT_GET_TO_API[r] ?? []).filter((o) => !ops.has(o)).map((o) => `${r} -> ${o}`));
    expect(missing, "mapped to operations the spec does not have").toEqual([]);
    expect(Object.keys(ACCOUNT_GET_TO_API).filter((k) => !accountGets.includes(k))).toEqual([]);
    expect(Object.keys(ACCOUNT_GET_ONLY).filter((k) => !accountGets.includes(k))).toEqual([]);
  });

  it("documents every API route, and nothing that is not a route", async () => {
    const ops = specOps(await liveSpec());
    const routes = new Set(api.routes.filter((r) => r.method !== "ALL" && r.path.startsWith("/api/v1/")).map((r) => routeKey(r.method, r.path)));
    expect([...routes].filter((r) => !ops.has(r) && !(r in NOT_OPERATIONS))).toEqual([]);
    expect([...ops].filter((o) => !routes.has(o))).toEqual([]);
  });

  it("names a permission and a tag on every operation, and every reference resolves", async () => {
    const spec = await liveSpec();
    for (const [path, item] of Object.entries(spec.paths)) {
      for (const [method, op] of Object.entries(item)) {
        const where = `${method.toUpperCase()} ${path}`;
        expect(op.tags?.length, where).toBe(1);
        const perm = op["x-permission"];
        // "a or b" marks a route either of two permissions satisfies (permissionAnyOf).
        expect(perm === "bootstrap-token" || (typeof perm === "string" && perm.split(" or ").every((p) => isApiScope(p.trim()))), `${where}: ${perm}`).toBe(true);
        expect(Object.keys(op.responses).some((c) => c.startsWith("2")), where).toBe(true);
      }
    }
    const refs = [...JSON.stringify(spec).matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)].map((m) => m[1]!);
    expect(refs.filter((r) => !(r in spec.components.schemas))).toEqual([]);
  });

  it("matches the committed docs/openapi.json (run npm run docs:api)", async () => {
    expect(await liveSpec()).toEqual(committed);
  });

  // Beyond "the operation exists": every GET responds (no 5xx), and every
  // write at least reaches its validation (no 5xx on an empty body). A new
  // operation fails this test until its handler actually works.
  it("exercises every operation: GETs respond, writes reach validation", async () => {
    const { apiKey } = await bootstrapInstance();
    const spec = await liveSpec();
    const PARAMS: Record<string, string> = { username: "admin", id: "1", item_id: "1", slug: "x", client_id: "x", domain: "example.com", alg: "RS256", key: "x", credential_id: "x" };
    const fill = (p: string) => p.replace(/\{([^}]+)\}/g, (_, n: string) => PARAMS[n] ?? "1");
    // An empty body would act, not just validate: these stay covered by
    // api-endpoints.test.ts instead of being poked here.
    const SKIP_WRITE = new Set([
      "POST /api/v1/directory/reset",
      "POST /api/v1/backup/restore",
      "POST /api/v1/scim/sync",
      "POST /api/v1/scim/test",
      "POST /api/v1/email/test",
      "POST /api/v1/integrations/cloudflare-one/sync",
      "POST /api/v1/ssf/outbox/drain",
      "POST /api/v1/security/signing-keys/{alg}/rotate",
      "POST /api/v1/security/new-user-password/apply-to-all",
      "POST /api/v1/domains/{domain}/apply-to-all",
      "POST /api/v1/recovery/admin-reset",
      "POST /api/v1/setup",
    ]);
    const failures: string[] = [];
    for (const [path, item] of Object.entries(spec.paths)) {
      for (const method of Object.keys(item)) {
        const op = `${method.toUpperCase()} ${path}`;
        if (method === "get") {
          const res = await apiCall(fill(path), { token: apiKey });
          if (res.status >= 500) failures.push(`${op}: ${res.status}`);
        } else if (!SKIP_WRITE.has(op)) {
          const res = await apiCall(fill(path), { token: apiKey, method: method.toUpperCase(), body: {} });
          if (res.status >= 500) failures.push(`${op}: ${res.status}`);
        }
      }
    }
    expect(failures).toEqual([]);
  });
});
