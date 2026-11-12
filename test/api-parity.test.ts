// The dashboard uses the API, and the API must be complete as console
// features are built: every action the admin console can take has an API
// operation, every API route is in the OpenAPI document, and the committed
// docs/openapi.json is the document the code generates.
import { describe, expect, it } from "vitest";
import { admin } from "../src/routes/admin.js";
import { api } from "../src/routes/api.js";
import { isApiScope } from "../src/lib/api-keys.js";
import committed from "../docs/openapi.json";
import { apiCall } from "./helpers.js";

/**
 * Each mutating console route and the API operation that does the same thing.
 * A new console POST route fails this test until it is mapped here, to an
 * operation that exists in the spec - or, if it genuinely has no meaning for
 * a token, listed in CONSOLE_ONLY with the reason.
 */
const CONSOLE_TO_API: Record<string, string> = {
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
  "POST /admin/users/:id/apps/:clientDbId/revoke": "DELETE /api/v1/users/{username}/apps/{client_id}",
  "POST /admin/users/:id/delete": "DELETE /api/v1/users/{username}",
  "POST /admin/groups": "POST /api/v1/groups",
  "POST /admin/groups/:id/members/:uid/remove": "DELETE /api/v1/groups/{id}/members/{username}",
  "POST /admin/groups/:id/freeze": "POST /api/v1/groups/{id}/freeze",
  "POST /admin/groups/:id": "PATCH /api/v1/groups/{id}",
  "POST /admin/groups/:id/delete": "DELETE /api/v1/groups/{id}",
  "POST /admin/email/enabled": "POST /api/v1/email/enabled",
  "POST /admin/email": "PUT /api/v1/email",
  "POST /admin/email/test": "POST /api/v1/email/test",
  "POST /admin/api-keys": "POST /api/v1/api-keys",
  "POST /admin/api-keys/:id/revoke": "DELETE /api/v1/api-keys/{id}",
  "POST /admin/clients": "POST /api/v1/clients",
  "POST /admin/clients/:id": "PATCH /api/v1/clients/{client_id}",
  "POST /admin/clients/:id/rotate-secret": "POST /api/v1/clients/{client_id}/rotate-secret",
  "POST /admin/clients/:id/delete": "DELETE /api/v1/clients/{client_id}",
  "POST /admin/saml/import-metadata": "POST /api/v1/saml/service-providers/import-metadata",
  "POST /admin/saml": "POST /api/v1/saml/service-providers",
  // The API's register call is an upsert keyed on entity_id.
  "POST /admin/saml/:id": "POST /api/v1/saml/service-providers",
  "POST /admin/saml/:id/delete": "DELETE /api/v1/saml/service-providers/{id}",
  "POST /admin/schemas": "POST /api/v1/schemas",
  "POST /admin/schemas/:id": "PATCH /api/v1/schemas/{id}",
  "POST /admin/schemas/:id/apply": "POST /api/v1/schemas/{id}/apply",
  "POST /admin/schemas/:id/delete": "DELETE /api/v1/schemas/{id}",
  "POST /admin/domains": "POST /api/v1/domains",
  "POST /admin/domains/:id/set-default": "POST /api/v1/domains/{domain}/default",
  "POST /admin/domains/:id/delete": "DELETE /api/v1/domains/{domain}",
  "POST /admin/domains/:id/apply-to-all": "POST /api/v1/domains/{domain}/apply-to-all",
  "POST /admin/security/default-password": "PUT /api/v1/security/new-user-password",
  "POST /admin/security/new-user-password-mode": "PUT /api/v1/security/new-user-password",
  "POST /admin/security/apply-default-password": "POST /api/v1/security/new-user-password/apply-to-all",
  "POST /admin/security/password-policy": "PUT /api/v1/security/password-policy",
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
  "POST /admin/security/signing-keys/:alg/rotate": "POST /api/v1/security/signing-keys/{alg}/rotate",
  "POST /admin/branding/app-name": "PATCH /api/v1/branding",
  "POST /admin/branding/login-gradient": "PATCH /api/v1/branding",
  "POST /admin/branding/cursor-trail": "PATCH /api/v1/branding",
  "POST /admin/branding/email-templates/:key": "PUT /api/v1/branding/email-templates/{key}",
  "POST /admin/branding/email-templates/:key/reset": "DELETE /api/v1/branding/email-templates/{key}",
  "POST /admin/branding/email-accent": "PATCH /api/v1/branding",
  "POST /admin/scim": "POST /api/v1/scim/config",
  "POST /admin/scim/scope": "POST /api/v1/scim/config",
  "POST /admin/scim/test": "POST /api/v1/scim/test",
  "POST /admin/scim/sync": "POST /api/v1/scim/sync",
};

/** Console actions with no API meaning, each with why. Keep this list short. */
const CONSOLE_ONLY: Record<string, string> = {
  // Step-up re-authentication proves a person is at the browser; a bearer
  // token is not a person and has nothing to re-enter.
  "POST /admin/reauth": "step-up re-authentication (password or code)",
  "POST /admin/reauth/passkey": "step-up re-authentication (passkey)",
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
    const missing = consoleRoutes.filter((r) => r in CONSOLE_TO_API && !ops.has(CONSOLE_TO_API[r]!)).map((r) => `${r} -> ${CONSOLE_TO_API[r]}`);
    expect(missing, "mapped to operations the spec does not have").toEqual([]);
    // A stale entry (the console route was removed or renamed) is a mistake too.
    expect(Object.keys(CONSOLE_TO_API).filter((k) => !consoleRoutes.includes(k))).toEqual([]);
    expect(Object.keys(CONSOLE_ONLY).filter((k) => !consoleRoutes.includes(k))).toEqual([]);
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
        expect(perm === "bootstrap-token" || (typeof perm === "string" && isApiScope(perm)), `${where}: ${perm}`).toBe(true);
        expect(Object.keys(op.responses).some((c) => c.startsWith("2")), where).toBe(true);
      }
    }
    const refs = [...JSON.stringify(spec).matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)].map((m) => m[1]!);
    expect(refs.filter((r) => !(r in spec.components.schemas))).toEqual([]);
  });

  it("matches the committed docs/openapi.json (run npm run docs:api)", async () => {
    expect(await liveSpec()).toEqual(committed);
  });
});
