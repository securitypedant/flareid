import type { Env } from "../env.js";
import { deactivateUserScim, pushGroupCurrent, pushUser, pushUserToTarget, syncGroups } from "../lib/scim-client.js";
import { getScimTarget, isScimConfigured, updateScimTarget, type ScimScope } from "../lib/scim-targets.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { audit, type ServiceCtx } from "./context.js";

export async function scimConfigured(env: Env): Promise<boolean> {
  return isScimConfigured(env);
}

/** Best-effort push - never blocks the admin action if SCIM isn't configured or a remote call fails. */
export async function syncUserBestEffort(ctx: ServiceCtx, userId: number, action: "push" | "deactivate" | "delete"): Promise<void> {
  if (!(await scimConfigured(ctx.env))) return;
  const user = await ctx.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first<UserRow>();
  if (!user && action !== "delete") return;

  const result =
    action === "push" && user
      ? await pushUser(ctx.env, user)
      : action === "deactivate" && user
        ? await deactivateUserScim(ctx.env, user)
        : { ok: true };

  if (!result.ok) await audit(ctx, "scim.user_sync_failed", user?.upn, { action, error: (result as { error?: string }).error });
}

export async function syncGroupBestEffort(ctx: ServiceCtx, groupId: number): Promise<void> {
  if (!(await scimConfigured(ctx.env))) return;
  const group = await ctx.env.DB.prepare("SELECT * FROM groups WHERE id = ?").bind(groupId).first<GroupRow>();
  if (!group) return;

  const result = await pushGroupCurrent(ctx.env, group);
  if (!result.ok) await audit(ctx, "scim.group_sync_failed", group.name, { error: result.error });
}

/**
 * Saves a target's provisioning scope, then re-evaluates everything already
 * pushed to it against the new scope: users out of scope are deactivated,
 * groups out of scope removed. That runs after the response, via `waitUntil`;
 * failures are audited, as for every other SCIM writer.
 */
export async function applyScimScope(ctx: ServiceCtx, targetId: number, scope: ScimScope, waitUntil: (p: Promise<unknown>) => void): Promise<void> {
  await updateScimTarget(ctx.env, targetId, { scope });
  const target = await getScimTarget(ctx.env, targetId);
  if (!target) return;
  await audit(ctx, "settings.scim_scope_changed", target.name, { mode: scope.mode, groupIds: scope.groupIds });
  if (!target.enabled || !target.endpoint || !target.secret) return;
  const { results } = await ctx.env.DB.prepare("SELECT user_id AS id FROM scim_user_links WHERE target_id = ?").bind(target.id).all<{ id: number }>();
  // Without the request: the work outlives it.
  const later: ServiceCtx = { ...ctx, req: undefined };
  waitUntil(
    (async () => {
      const errors: string[] = [];
      for (const { id } of results) {
        const user = await ctx.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();
        if (!user) continue;
        const r = await pushUserToTarget(ctx.env, target, user);
        if (!r.ok) errors.push(`${user.upn}: ${r.error ?? r.status}`);
      }
      const groups = await syncGroups(ctx.env, target);
      if (errors.length || groups.groupErrors) {
        await audit(later, "scim.user_sync_failed", target.name, { action: "scope_changed", error: errors.join("; ").slice(0, 500), group_errors: groups.groupErrors });
      }
    })().catch((err) => console.error(JSON.stringify({ event: "scim_scope_sync_failed", error: String(err) })))
  );
}
