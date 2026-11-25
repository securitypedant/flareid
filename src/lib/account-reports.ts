import type { Env } from "../env.js";
import { describeUserAgent } from "./signin-history.js";
import { listActiveSessionsForUser, revokeSession } from "./sessions.js";
import { listTrustedDevices, revokeTrustedDevice } from "./trusted-devices.js";

/**
 * "This wasn't me": a person reports a session or remembered device from
 * their Security page. The item is signed out / forgotten straight away -
 * whatever it is, it shouldn't keep working while someone looks - and an
 * open report reaches administrators' notifications (notifications.ts)
 * until one marks it reviewed on the user's page.
 */

export type ReportKind = "session" | "device";

export interface AccountReportRow {
  id: number;
  user_id: number;
  kind: ReportKind;
  ip: string | null;
  user_agent: string | null;
  item_created_at: string | null;
  status: "open" | "resolved";
  created_at: string;
  resolved_at: string | null;
  resolved_by: number | null;
}

/** Revokes the reported item and files the report. False when the item isn't this person's (or is already gone). */
export async function reportItem(env: Env, userId: number, kind: ReportKind, itemId: string): Promise<boolean> {
  const item =
    kind === "session"
      ? (await listActiveSessionsForUser(env, userId)).find((s) => s.id === itemId)
      : (await listTrustedDevices(env, userId)).find((d) => d.id === itemId);
  if (!item) return false;
  if (kind === "session") await revokeSession(env, itemId);
  else await revokeTrustedDevice(env, userId, itemId);
  await env.DB.prepare("INSERT INTO account_reports (user_id, kind, ip, user_agent, item_created_at, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(userId, kind, item.ip ?? null, item.user_agent ?? null, item.created_at ?? null, new Date().toISOString())
    .run();
  return true;
}

export async function openReportsFor(env: Env, userId: number): Promise<AccountReportRow[]> {
  return (await env.DB.prepare("SELECT * FROM account_reports WHERE user_id = ? AND status = 'open' ORDER BY created_at DESC").bind(userId).all<AccountReportRow>()).results;
}

export type OpenReportView = AccountReportRow & { upn: string; display_name: string };

export async function listOpenReports(env: Env, limit = 100): Promise<OpenReportView[]> {
  return (
    await env.DB.prepare(
      "SELECT r.*, u.upn, u.display_name FROM account_reports r JOIN users u ON u.id = r.user_id WHERE r.status = 'open' ORDER BY r.created_at DESC LIMIT ?"
    )
      .bind(limit)
      .all<OpenReportView>()
  ).results;
}

export async function countOpenReports(env: Env): Promise<number> {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM account_reports WHERE status = 'open'").first<{ n: number }>())?.n ?? 0;
}

export async function getReport(env: Env, id: number): Promise<AccountReportRow | null> {
  return env.DB.prepare("SELECT * FROM account_reports WHERE id = ?").bind(id).first<AccountReportRow>();
}

export async function resolveReport(env: Env, id: number, byUserId: number | null): Promise<boolean> {
  const r = await env.DB.prepare("UPDATE account_reports SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'open'")
    .bind(new Date().toISOString(), byUserId, id)
    .run();
  return Number(r.meta.changes ?? 0) > 0;
}

/** "a session from 203.0.113.9 (Chrome on macOS)" */
export function describeReport(r: Pick<AccountReportRow, "kind" | "ip" | "user_agent">): string {
  const device = describeUserAgent(r.user_agent);
  return `a ${r.kind === "session" ? "session" : "remembered device"}${r.ip ? ` from ${r.ip}` : ""}${device ? ` (${device})` : ""}`;
}
