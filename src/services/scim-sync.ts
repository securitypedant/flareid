import type { Env } from "../env.js";
import { deactivateUserScim, pushGroupCurrent, pushUser, pushUsersById, syncGroups } from "../lib/scim-client.js";
import { getScimConfig, setScimScope, type ScimScope } from "../lib/settings.js";
import type { GroupRow, UserRow } from "../lib/types.js";
import { audit, type ServiceCtx } from "./context.js";

export async function scimConfigured(env: Env): Promise<boolean> {
  const { endpoint, secret } = await getScimConfig(env);
  return !!endpoint && !!secret;
}

/** Best-effort push - never blocks the admin action if SCIM isn't configured or the remote call fails. */
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
 * Saves which users and groups are provisioned, then re-evaluates everything
 * already pushed against the new scope: users out of scope are deactivated,
 * groups out of scope removed (pushGroup). That runs after the response, via
 * `waitUntil`; failures are audited, as for every other SCIM writer.
 */
export async function applyScimScope(ctx: ServiceCtx, scope: ScimScope, waitUntil: (p: Promise<unknown>) => void): Promise<void> {
  await setScimScope(ctx.env, scope);
  await audit(ctx, "settings.scim_scope_changed", undefined, { mode: scope.mode, groupIds: scope.groupIds });
  if (!(await scimConfigured(ctx.env))) return;
  const { results } = await ctx.env.DB.prepare("SELECT id FROM users WHERE scim_id IS NOT NULL").all<{ id: number }>();
  // Without the request: the work outlives it.
  const later: ServiceCtx = { ...ctx, req: undefined };
  waitUntil(
    (async () => {
      const users = await pushUsersById(ctx.env, results.map((r) => r.id));
      const groups = await syncGroups(ctx.env);
      if (!users.ok || groups.groupErrors) {
        await audit(later, "scim.user_sync_failed", undefined, { action: "scope_changed", error: users.error, group_errors: groups.groupErrors });
      }
    })()
  );
}
