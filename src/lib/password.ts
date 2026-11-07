import { scrypt, timingSafeEqual } from "node:crypto";
import type { Env } from "../env.js";

// Password hashing.
//
// New hashes are scrypt, written as a self-describing PHC string in
// password_hash - "$scrypt$ln=13,r=8,p=10$<salt>$<hash>" - with password_salt
// and password_iterations left empty. Because every writer stores the
// {hash, salt, iterations} triple from one hashPassword() call, a hash can
// never end up paired with the wrong algorithm or parameters.
//
// Why scrypt: PBKDF2 on Workers is capped at 100,000 iterations (a platform
// limit that wrangler dev and miniflare do NOT enforce, so it only fails once
// deployed), which is a sixth of OWASP's 600,000 for PBKDF2-SHA256. Argon2 is
// not available in node:crypto on Workers; scrypt is. The parameters are
// OWASP's N=2^13, r=8, p=10 - equivalent in strength to their N=2^17
// recommendation but using 8 MiB per hash instead of 128 MiB, which matters in
// a 128 MB isolate serving concurrent sign-ins. About 100 ms of CPU per hash.
//
// Legacy PBKDF2 hashes (hex hash + hex salt + iteration count) still verify,
// and are upgraded to scrypt the next time the user signs in.
//
// PASSWORD_HASHER=pbkdf2 keeps writing PBKDF2 at the platform ceiling, for the
// Workers Free plan, whose 10 ms CPU limit cannot fit a scrypt hash.

const PBKDF2_ITERATIONS = 100_000;
const HASH_BITS = 256;
const SCRYPT = { ln: 13, r: 8, p: 10 } as const;
const SCRYPT_KEY_BYTES = 32;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

function toHex(bytes: ArrayBuffer | Uint8Array): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function deriveBits(password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    HASH_BITS
  );
}

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
const unb64 = (s: string) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));

function scryptBytes(password: string, salt: Uint8Array, params: { ln: number; r: number; p: number }): Promise<Uint8Array> {
  return new Promise((resolve, reject) =>
    scrypt(password.normalize("NFKC"), salt, SCRYPT_KEY_BYTES, { N: 2 ** params.ln, r: params.r, p: params.p, maxmem: SCRYPT_MAXMEM }, (err, key) =>
      err ? reject(err) : resolve(new Uint8Array(key))
    )
  );
}

function parseScrypt(phc: string): { ln: number; r: number; p: number; salt: Uint8Array; hash: Uint8Array } | null {
  const m = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(phc);
  if (!m) return null;
  return { ln: Number(m[1]), r: Number(m[2]), p: Number(m[3]), salt: unb64(m[4]!), hash: unb64(m[5]!) };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface PasswordHash {
  hash: string;
  salt: string;
  iterations: number;
}

type Hasher = "scrypt" | "pbkdf2";
const hasherFor = (env?: Pick<Env, "PASSWORD_HASHER">): Hasher => (env?.PASSWORD_HASHER === "pbkdf2" ? "pbkdf2" : "scrypt");

export async function hashPassword(password: string, env?: Pick<Env, "PASSWORD_HASHER">): Promise<PasswordHash> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  if (hasherFor(env) === "pbkdf2") {
    return { hash: toHex(await deriveBits(password, salt, PBKDF2_ITERATIONS)), salt: toHex(salt), iterations: PBKDF2_ITERATIONS };
  }
  const key = await scryptBytes(password, salt, SCRYPT);
  return { hash: `$scrypt$ln=${SCRYPT.ln},r=${SCRYPT.r},p=${SCRYPT.p}$${b64(salt)}$${b64(key)}`, salt: "", iterations: 0 };
}

export type StoredPassword = { password_hash: string; password_salt: string; password_iterations: number };

export async function verifyPassword(password: string, stored: StoredPassword): Promise<boolean> {
  const phc = parseScrypt(stored.password_hash);
  if (phc) return equalBytes(await scryptBytes(password, phc.salt, phc), phc.hash);
  if (stored.password_hash.startsWith("$")) return false; // a format this build doesn't know - fail closed

  const derived = new Uint8Array(await deriveBits(password, fromHex(stored.password_salt), stored.password_iterations));
  return equalBytes(derived, fromHex(stored.password_hash));
}

/**
 * Whether a stored hash is weaker than what this deployment writes today.
 * Only ever upgrades: a scrypt hash on a PASSWORD_HASHER=pbkdf2 deployment is
 * left alone (it still verifies).
 */
export function needsRehash(stored: StoredPassword, env?: Pick<Env, "PASSWORD_HASHER">): boolean {
  const phc = parseScrypt(stored.password_hash);
  if (phc) return hasherFor(env) === "scrypt" && (phc.ln < SCRYPT.ln || phc.r < SCRYPT.r || phc.p < SCRYPT.p);
  return hasherFor(env) === "scrypt" || stored.password_iterations < PBKDF2_ITERATIONS;
}

/** After a successful sign-in, re-hashes the password if the stored hash is legacy - the only moment the plaintext is available. */
export async function upgradePasswordHashIfNeeded(env: Env, user: StoredPassword & { id: number }, password: string): Promise<boolean> {
  if (!needsRehash(user, env)) return false;
  const { hash, salt, iterations } = await hashPassword(password, env);
  await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ? WHERE id = ?")
    .bind(hash, salt, iterations, user.id)
    .run();
  return true;
}

interface PasswordComplexity {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
}

const LOWER = "abcdefghijkmnpqrstuvwxyz"; // no ambiguous l/o
const UPPER = "ABCDEFGHJKMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%^&*-_=+";

function randomChar(alphabet: string): string {
  const byte = crypto.getRandomValues(new Uint8Array(1))[0]!;
  return alphabet[byte % alphabet.length]!;
}

/** Generates a random password that's guaranteed to satisfy the given complexity policy (or a strong default if none is given). */
export function generateTempPassword(policy?: PasswordComplexity): string {
  const minLength = Math.max(policy?.minLength ?? 12, 12);
  const required: string[] = [];

  // Guarantee every explicitly required class is present...
  if (policy?.requireUppercase) required.push(randomChar(UPPER));
  if (policy?.requireLowercase) required.push(randomChar(LOWER));
  if (policy?.requireNumber) required.push(randomChar(DIGITS));
  if (policy?.requireSymbol) required.push(randomChar(SYMBOLS));

  // ...and otherwise still aim for a good mix by default.
  if (!policy?.requireUppercase) required.push(randomChar(UPPER));
  if (!policy?.requireLowercase) required.push(randomChar(LOWER));
  if (!policy?.requireNumber) required.push(randomChar(DIGITS));

  const fullAlphabet = LOWER + UPPER + DIGITS + (policy?.requireSymbol ? SYMBOLS : "");
  while (required.length < minLength) required.push(randomChar(fullAlphabet));

  // Fisher-Yates shuffle so the guaranteed characters aren't predictably at the front.
  for (let i = required.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1);
    const temp = required[i]!;
    required[i] = required[j]!;
    required[j] = temp;
  }

  return required.join("");
}
