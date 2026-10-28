import type { Env } from "../env.js";
import { sha256Hex } from "./tokens.js";

const CODE_COUNT = 10;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no ambiguous chars (0/O, 1/I/L)

function generateCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const chars = [...bytes].map((b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}`;
}

function normalizeCode(code: string): string {
  return code.trim().toUpperCase().replace(/\s+/g, "");
}

/** Generates a fresh set of backup codes, discarding any previous ones. Returns the plaintext codes (shown once). */
export async function generateBackupCodes(env: Env, userId: number): Promise<string[]> {
  await env.DB.prepare("DELETE FROM mfa_backup_codes WHERE user_id = ?").bind(userId).run();

  const codes = Array.from({ length: CODE_COUNT }, generateCode);
  const now = new Date().toISOString();

  await env.DB.batch(
    await Promise.all(
      codes.map(async (code) =>
        env.DB.prepare("INSERT INTO mfa_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)").bind(
          userId,
          await sha256Hex(normalizeCode(code)),
          now
        )
      )
    )
  );

  return codes;
}

/** Verifies and, if valid, consumes (marks used) a backup code. Returns whether it was valid. */
export async function verifyAndConsumeBackupCode(env: Env, userId: number, code: string): Promise<boolean> {
  const hash = await sha256Hex(normalizeCode(code));
  const row = await env.DB.prepare(
    "SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"
  )
    .bind(userId, hash)
    .first<{ id: number }>();

  if (!row) return false;

  await env.DB.prepare("UPDATE mfa_backup_codes SET used_at = ? WHERE id = ?").bind(new Date().toISOString(), row.id).run();
  return true;
}

export async function countRemainingBackupCodes(env: Env, userId: number): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) as n FROM mfa_backup_codes WHERE user_id = ? AND used_at IS NULL")
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export async function deleteBackupCodes(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("DELETE FROM mfa_backup_codes WHERE user_id = ?").bind(userId).run();
}
