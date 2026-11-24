/**
 * Sign-in identifiers: users.upn is the single unique canonical name, but its
 * grammar has three shapes (docs/identifiers.md):
 *
 *   UPN    local@domain          simon@d1.com      (native: managed domain;
 *                                                  federated/SCIM: verbatim)
 *   handle ^[a-z0-9][a-z0-9._-]{1,63}$, >=1 non-digit
 *                                  simon, simon-github
 *   phone  ^\+[1-9]\d{6,14}$     +15551234567      (E.164, '+' required)
 *
 * All-digit bare names are reserved so a handle can never shadow a phone.
 * users.username holds the local part / the handle itself / the E.164 digits;
 * it is no longer unique, so it is only a resolution candidate, never a key.
 */

import type { Env } from "../env.js";
import type { UserRow } from "./types.js";
import { getUserByAnyEmail } from "./user-emails.js";
import { getUserByAnyPhone } from "./user-phones.js";

export type IdentifierKind = "upn" | "handle" | "phone";

export interface ParsedIdentifier {
  kind: IdentifierKind;
  /** The canonical string stored in users.upn. */
  normalized: string;
  /** What users.username holds: UPN local part, or the handle/phone itself. */
  username: string;
}

/** The UPN local part (and the pre-existing username grammar). */
export const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;
/** A bare-name identifier: username-shaped, length-bounded, at least one non-digit. */
export const HANDLE_PATTERN = /^[a-z0-9][a-z0-9._-]{1,63}$/;
/** E.164, '+' required - no national-format guessing. */
export const PHONE_PATTERN = /^\+[1-9]\d{6,14}$/;

/** Looks like a phone number someone forgot the '+' on - reserved, never a handle. */
const DIGITS_ONLY = /^\d+$/;

/**
 * Classifies and normalizes a sign-in name or a creation identifier.
 * Shape detection by first character class: '+'/digits-with-punctuation ->
 * phone, contains '@' -> UPN, else handle. Returns null on anything that
 * parses to no valid form.
 */
export function parseIdentifier(raw: string): ParsedIdentifier | null {
  const s = raw.trim();
  if (!s || s.length > 254) return null;

  // Phone: '+' present it is one; phone punctuation without '+' is refused
  // (national formats are not guessed).
  const phoneish = s.startsWith("+") || /^[\d\s().-]+$/.test(s);
  if (phoneish) {
    const normalized = s.replace(/[^\d+]/g, "");
    if (PHONE_PATTERN.test(normalized)) return { kind: "phone", normalized, username: normalized };
    return null;
  }

  if (s.includes("@")) {
    const parts = s.toLowerCase().split("@");
    if (parts.length !== 2) return null;
    const [local, domain] = parts as [string, string];
    if (!USERNAME_PATTERN.test(local) || !/^[a-z0-9][a-z0-9.-]*$/.test(domain) || domain.includes("..")) return null;
    return { kind: "upn", normalized: `${local}@${domain}`, username: local };
  }

  const handle = s.toLowerCase();
  if (!HANDLE_PATTERN.test(handle) || DIGITS_ONLY.test(handle)) return null;
  return { kind: "handle", normalized: handle, username: handle };
}

export interface IdentifierResolution {
  user: UserRow | null;
  /** Bare local part matched more than one account: resolves as "no user",
   * indistinguishable from an unknown name (the audit trail may say why). */
  ambiguous?: boolean;
}

/**
 * Login/recovery/LDAP resolution. '@' -> upn then any contact address;
 * '+' -> upn then any listed phone; bare -> exact upn (a handle owns its own
 * name) then the local-part candidates - exactly one, else no user.
 */
export async function resolveLoginIdentifier(env: Env, identifier: string): Promise<IdentifierResolution> {
  const parsed = parseIdentifier(identifier);
  if (!parsed) return { user: null };

  const byUpn = await env.DB.prepare("SELECT * FROM users WHERE upn = ?").bind(parsed.normalized).first<UserRow>();

  if (parsed.kind === "upn") return { user: byUpn ?? (await getUserByAnyEmail(env, parsed.normalized)) };
  if (parsed.kind === "phone") return { user: byUpn ?? (await getUserByAnyPhone(env, parsed.normalized)) };

  if (byUpn) return { user: byUpn };
  const { results } = await env.DB.prepare("SELECT * FROM users WHERE username = ? LIMIT 2").bind(parsed.username).all<UserRow>();
  if (results.length === 1) return { user: results[0]! };
  return { user: null, ambiguous: results.length > 1 };
}
