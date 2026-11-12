import type { Env } from "../env.js";
import { getPasswordPolicy, isBreachedPasswordCheckEnabled, validatePassword, type PasswordPolicy } from "./settings.js";

/**
 * Breached-password check against Have I Been Pwned's Pwned Passwords range
 * API, using k-anonymity: the password is SHA-1 hashed here, only the first 5
 * hex characters of the hash leave the Worker, and the ~800 suffixes that come
 * back for that prefix are compared locally. Neither the password nor its full
 * hash is ever sent or logged.
 *
 * `Add-Padding: true` makes the service pad every answer with zero-count
 * entries, so the response size does not hint at which prefix was asked for.
 *
 * The check fails open: if the service is slow (over 3 s) or unreachable the
 * password is allowed, and a warning goes to the Worker log. A third-party
 * outage must not stop people from setting a password - the policy check and
 * the hashing still apply.
 */

export const PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const TIMEOUT_MS = 3000;

async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/**
 * How many times the password appears in known breaches: 0 when it does not,
 * null when the service could not be asked (the caller then allows it).
 */
export async function breachCount(password: string): Promise<number | null> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    const res = await fetch(`${PWNED_RANGE_URL}${prefix}`, {
      headers: { "Add-Padding": "true", "User-Agent": "FlareID" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    for (const line of (await res.text()).split("\n")) {
      const [s, n] = line.trim().split(":");
      if (s?.toUpperCase() === suffix) return Number(n) || 0;
    }
    return 0;
  } catch (err) {
    // The error only: never the password, the hash or the prefix.
    console.warn(JSON.stringify({ event: "breached_password_check_unavailable", error: err instanceof Error ? err.name : "error" }));
    return null;
  }
}

export function breachMessage(count: number): string {
  return `This password has appeared in a data breach ${count.toLocaleString("en-US")} ${count === 1 ? "time" : "times"}; choose another.`;
}

/** The breach check alone: a message when the check is on and the password is known breached, otherwise null. */
export async function breachedPasswordError(env: Env, password: string): Promise<string | null> {
  if (!password || !(await isBreachedPasswordCheckEnabled(env))) return null;
  const count = await breachCount(password);
  return count ? breachMessage(count) : null;
}

/**
 * Everything a password a person chose must pass: the complexity policy, then
 * (when switched on) the breach check. The cheap policy check runs first, so a
 * too-short password never costs a request. Generated passwords skip this.
 */
export async function newPasswordError(env: Env, password: string, policy?: PasswordPolicy): Promise<string | null> {
  return validatePassword(password, policy ?? (await getPasswordPolicy(env))) ?? (await breachedPasswordError(env, password));
}
