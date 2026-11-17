import type { Context } from "hono";
import type { Env } from "../env.js";
import { auditActor } from "../lib/api-auth.js";
import { hasScope } from "../lib/api-keys.js";
import { logAudit } from "../lib/audit.js";
import type { UserRow } from "../lib/types.js";

/**
 * Services hold the logic behind both the admin console and the provisioning
 * API, so the two cannot drift: each console handler and its API twin parse
 * their own input (a form, a JSON body) and render their own output (a page,
 * JSON), and call the same function in between.
 *
 * A ServiceCtx is who is acting, as far as a service needs to know: the actor
 * the audit log records, whether they hold everything (Super Admin or an
 * admin key - the authority needed to touch administrators), and their own
 * user id, for the "not your own account" rules (an API key has none).
 */
export interface ServiceCtx {
  env: Env;
  actor: UserRow | { id: number | null; upn: string };
  privileged: boolean;
  selfId: number | null;
  req?: Request;
  /** Post-response scheduling (executionCtx.waitUntil). Absent, work runs inline. */
  waitUntil?: (promise: Promise<unknown>) => void;
}

/**
 * Runs `work` after the response when the caller's execution context allows
 * it, else inline. For "best effort" outbound work - SCIM pushes and queue
 * drains - that must never hold a write open against a slow or overloaded
 * remote: the write is recorded, then the push happens. `later` drops `req`
 * like applyScimScope's post-response context.
 */
export function afterResponse(ctx: ServiceCtx, work: (later: ServiceCtx) => Promise<void>): void | Promise<void> {
  const later: ServiceCtx = { ...ctx, req: undefined };
  if (ctx.waitUntil) {
    ctx.waitUntil(work(later).catch((err) => console.error(JSON.stringify({ msg: "post_response_work_failed", error: String(err) }))));
    return;
  }
  return work(later);
}

/** A refusal with an HTTP status: the console renders the message as text, the API as JSON. */
export class ServiceError extends Error {
  constructor(
    public status: 400 | 403 | 404 | 409 | 502,
    message: string
  ) {
    super(message);
  }

  get code(): string {
    return { 400: "invalid_request", 403: "forbidden", 404: "not_found", 409: "conflict", 502: "upstream_failed" }[this.status];
  }
}

export function consoleCtx(c: Context<{ Bindings: Env }>): ServiceCtx {
  const user = c.get("user");
  return { env: c.env, actor: user, privileged: Boolean(c.get("isSuperAdmin")), selfId: user.id, req: c.req.raw, waitUntil: (p) => c.executionCtx.waitUntil(p) };
}

export function apiCtx(c: Context<{ Bindings: Env }>): ServiceCtx {
  const actor = c.get("apiActor");
  return { env: c.env, actor: auditActor(actor), privileged: hasScope(actor.scopes, "admin"), selfId: null, req: c.req.raw, waitUntil: (p) => c.executionCtx.waitUntil(p) };
}

export function audit(ctx: ServiceCtx, action: string, target?: string, details?: Record<string, unknown>): Promise<void> {
  return logAudit(ctx.env, ctx.actor, action, target, details, ctx.req);
}
