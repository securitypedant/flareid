import { OpenAPIHono, createRoute, z, type RouteConfig } from "@hono/zod-openapi";
import type { Context, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import type { Env } from "../env.js";
import { requireApiAuth, requireScope } from "../lib/api-auth.js";
import { hasScope, type ApiScope } from "../lib/api-keys.js";
import { ImportValidationError } from "../lib/directory-import.js";
import { ServiceError } from "../services/context.js";
import { VERSION } from "../version.js";

/**
 * The /api/v1 application and the one way routes are added to it.
 *
 * Every route goes through defineRoute(), which registers the Hono handler and
 * the OpenAPI operation from the same definition: the path, the permission
 * the route checks, and the schemas its request is validated against. The
 * spec at GET /api/v1/openapi.json is generated from that registry, so it
 * cannot describe a route that does not exist or miss one that does
 * (test/api-parity.test.ts holds both directions).
 *
 * Request schemas are deliberately permissive about extra fields: they gate
 * types, and the handlers keep their own, more specific validation and
 * messages, which existing callers depend on.
 */

export type ApiEnv = { Bindings: Env };
export type ApiContext = Context<ApiEnv>;

export function badRequest(message: string) {
  return { error: "invalid_request", message };
}

function zodMessage(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "Invalid request.";
  const where = issue.path.length ? `${issue.path.join(".")}: ` : "";
  return `${where}${issue.message}`;
}

export const api = new OpenAPIHono<ApiEnv>({
  // Same error shape as every hand-written refusal in the API.
  defaultHook: (result, c) => {
    if (!result.success) return c.json(badRequest(zodMessage(result.error)), 400);
  },
});

api.openAPIRegistry.registerComponent("securitySchemes", "bearer", {
  type: "http",
  scheme: "bearer",
  description: "An API key (flareid_sk_...) minted in Admin -> Integrations -> API keys or by POST /api/v1/api-keys; before setup completes, the BOOTSTRAP_TOKEN secret.",
});

/** The generated document. Built on request: it only describes routes, never data. */
export function openApiDocument() {
  return api.getOpenAPI31Document({
    openapi: "3.1.0",
    info: {
      title: "FlareID provisioning API",
      version: VERSION,
      description:
        "Everything the admin console does, without a browser. JSON in, JSON out; every mutation is audited against the token that made it. Each operation's `x-permission` names the permission it needs (see Permissions in docs/api.md): `<area>:read` or `<area>:write`, where write implies read, and `*` (an `admin` key) grants everything. The original scopes (`directory:read`, `directory:write`, `clients:write`, `settings:write`, `admin`) are shorthand for sets of permissions and keep working.",
      license: { name: "Apache-2.0", url: "https://www.apache.org/licenses/LICENSE-2.0" },
    },
    servers: [{ url: "/", description: "This FlareID deployment" }],
    tags: TAGS.map((t) => ({ name: t.name, description: t.description })),
  });
}

// Registered before the authentication middleware so it answers without a
// token: the document lists routes and schemas, never data or secrets.
api.get("/api/v1/openapi.json", (c) => c.json(openApiDocument()));

api.use("/api/v1/*", requireApiAuth);

export const TAGS = [
  { name: "Status", description: "Instance status and first-run setup." },
  { name: "Users", description: "People in the directory." },
  { name: "Groups", description: "Static and dynamic (rule-based) groups." },
  { name: "Directory", description: "Bulk import and reset." },
  { name: "Domains", description: "UPN domains." },
  { name: "Schemas", description: "User and group attribute schemas." },
  { name: "OIDC clients", description: "OpenID Connect relying parties." },
  { name: "SAML", description: "SAML service providers." },
  { name: "SCIM", description: "Outbound SCIM provisioning (FlareID as a SCIM client)." },
  { name: "Email", description: "Outbound email settings and templates." },
  { name: "API keys", description: "Bearer tokens for this API." },
  { name: "Branding", description: "App name and sign-in page appearance." },
  { name: "Security", description: "Password, session, rate-limit and audit settings; authentication policies and factors." },
  { name: "Roles", description: "Admin roles: permission sets granted to groups." },
  { name: "Signing keys", description: "Token signing keys (public parts only)." },
  { name: "Monitoring", description: "Overview statistics, performance and the audit log." },
  { name: "Recovery", description: "Break-glass administrator reset (bootstrap token only)." },
] as const;
export type Tag = (typeof TAGS)[number]["name"];

// ---------------------------------------------------------------------------
// Shared schemas
// ---------------------------------------------------------------------------

export const ErrorSchema = z
  .object({
    error: z.string().openapi({ example: "invalid_request" }),
    message: z.string().optional(),
  })
  .passthrough()
  .openapi("Error");

export const OkSchema = z.object({ ok: z.literal(true) }).passthrough().openapi("Ok");

/** Anything JSON: for documented-but-open shapes (import bundles, summaries). */
export const AnyObject = z.record(z.string(), z.unknown());

const ERROR_DESCRIPTIONS: Record<number, string> = {
  400: "Invalid request (`invalid_request`).",
  401: "Missing, unknown, revoked or expired token.",
  403: "The token lacks the permission, or the action needs `*` (admin) because it touches an administrator.",
  404: "No such object.",
  409: "Conflicts with existing state.",
  502: "A downstream service (email, SCIM) failed.",
};

type Method = "get" | "post" | "put" | "patch" | "delete";

export interface RouteSpec {
  method: Method;
  /** OpenAPI-style path: /api/v1/users/{username}. */
  path: string;
  tag: Tag;
  summary: string;
  description?: string;
  /**
   * What the route requires, checked before anything else. null means the
   * route authenticates for itself (the break-glass reset).
   */
  permission: ApiScope | null;
  params?: z.ZodObject;
  query?: z.ZodObject;
  body?: z.ZodType;
  /** Success response body; defaults to { ok: true }. */
  response?: z.ZodType;
  status?: 200 | 201;
  /** Error statuses beyond 400/401/403, which every route can answer. */
  errors?: number[];
}

const PARAM_DOCS: Record<string, string> = {
  username: "The username (the UPN's local part, unique across every domain).",
  id: "Numeric id.",
  client_id: "The OIDC client_id.",
  domain: "The domain name.",
  credential_id: "The passkey's credential id, as listed.",
};

export type ApiHandler = (c: ApiContext) => Response | Promise<Response>;

/**
 * Before the validators: a JSON body sent without a Content-Type (curl -d)
 * has always been accepted, because handlers parsed the body regardless.
 * Labelling it here keeps that working instead of becoming a 415.
 */
const assumeJson: MiddlewareHandler<ApiEnv> = async (c, next) => {
  const type = c.req.header("content-type") ?? "";
  if (!/json/i.test(type) && c.req.raw.body) {
    const headers = new Headers(c.req.raw.headers);
    headers.set("content-type", "application/json");
    c.req.raw = new Request(c.req.raw, { headers });
  }
  await next();
};

/** Registered operations, for the parity test: "METHOD /openapi/path" -> permission. */
export const registeredOperations = new Map<string, ApiScope | null>();

export function defineRoute(spec: RouteSpec, handler: ApiHandler): void {
  const names = [...spec.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
  const params = spec.params ?? (names.length ? z.object(Object.fromEntries(names.map((n) => [n, z.string().openapi({ description: PARAM_DOCS[n] ?? n })]))) : undefined);
  const errorCodes = [...new Set([400, ...(spec.permission === null ? [] : [401]), 403, ...(spec.errors ?? [])])].sort();
  const responses: RouteConfig["responses"] = {
    [spec.status ?? 200]: { description: "Success.", content: { "application/json": { schema: spec.response ?? OkSchema } } },
  };
  for (const code of errorCodes) responses[code] = { description: ERROR_DESCRIPTIONS[code] ?? "Error.", content: { "application/json": { schema: ErrorSchema } } };

  const middleware: MiddlewareHandler<ApiEnv>[] = [];
  if (spec.permission) middleware.push(requireScope(spec.permission) as MiddlewareHandler<ApiEnv>);
  if (spec.body) middleware.push(assumeJson);

  const route = createRoute({
    method: spec.method,
    path: spec.path,
    tags: [spec.tag],
    summary: spec.summary,
    ...(spec.description ? { description: spec.description } : {}),
    security: [{ bearer: [] }],
    "x-permission": spec.permission ?? "bootstrap-token",
    middleware,
    request: {
      ...(params ? { params } : {}),
      ...(spec.query ? { query: spec.query } : {}),
      ...(spec.body ? { body: { required: true, content: { "application/json": { schema: spec.body } } } } : {}),
    },
    responses,
  });
  registeredOperations.set(`${spec.method.toUpperCase()} ${spec.path}`, spec.permission);
  // The handlers are plain Hono handlers reading the raw body, so the typed
  // response machinery of openapi() is bypassed rather than satisfied.
  (api.openapi as unknown as (r: RouteConfig, h: ApiHandler) => void)(route, handler);
}

// ---------------------------------------------------------------------------
// Handler helpers
// ---------------------------------------------------------------------------

export async function readJson<T>(c: { req: { json: () => Promise<unknown> } }): Promise<T> {
  try {
    return (await c.req.json()) as T;
  } catch {
    throw new ImportValidationError("Request body must be valid JSON.");
  }
}

/** For bodies whose fields are all optional: no body at all means {}. */
export async function readOptionalJson<T>(c: { req: { json: () => Promise<unknown>; text: () => Promise<string> } }): Promise<T> {
  try {
    return (await c.req.json()) as T;
  } catch {
    if ((await c.req.text().catch(() => "")).trim() === "") return {} as T;
    throw new ImportValidationError("Request body must be valid JSON.");
  }
}

/** A path parameter, decoded by Hono; never undefined for a declared {name}. */
export function param(c: ApiContext, name: string): string {
  return c.req.param(name) ?? "";
}

export function notFound(c: ApiContext, message: string) {
  return c.json({ error: "not_found", message }, 404);
}

export function forbidden(c: ApiContext, message: string) {
  return c.json({ error: "forbidden", message }, 403);
}

/** Whether the calling token holds everything ("*", an admin key). */
export function isAdminActor(c: ApiContext): boolean {
  return hasScope(c.get("apiActor").scopes, "admin");
}

/** Shared error handling for the API: validation refusals are 400s, never 500s. */
export function apiErrorHandler(err: Error, c: ApiContext) {
  if (err instanceof ServiceError) return c.json({ error: err.code, message: err.message }, err.status);
  if (err instanceof ImportValidationError) return c.json(badRequest(err.message), 400);
  // Validation refusals from the settings/schema layer (e.g. a user-editable
  // attribute that a dynamic group's rule depends on).
  if (err instanceof RangeError) return c.json(badRequest(err.message), 400);
  if (err instanceof HTTPException) {
    // The JSON validator's parse failure: same message as before validation existed.
    if (err.status === 400) return c.json(badRequest("Request body must be valid JSON."), 400);
    return c.json({ error: err.status === 415 ? "unsupported_media_type" : "invalid_request", message: err.message }, err.status);
  }
  console.error(err);
  return c.json({ error: "server_error", message: "Unexpected error." }, 500);
}
