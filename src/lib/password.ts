// Password hashing via PBKDF2 (Web Crypto) - no external dependency needed and
// well-suited to the Workers runtime. Iteration count is stored per-row so it can
// be raised in the future without invalidating existing hashes.

const DEFAULT_ITERATIONS = 100_000;
const HASH_BITS = 256;

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

export interface PasswordHash {
  hash: string;
  salt: string;
  iterations: number;
}

export async function hashPassword(password: string, iterations = DEFAULT_ITERATIONS): Promise<PasswordHash> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await deriveBits(password, salt, iterations);
  return { hash: toHex(derived), salt: toHex(salt), iterations };
}

export async function verifyPassword(
  password: string,
  stored: { password_hash: string; password_salt: string; password_iterations: number }
): Promise<boolean> {
  const derived = await deriveBits(password, fromHex(stored.password_salt), stored.password_iterations);
  const candidate = toHex(derived);
  // Constant-time-ish comparison.
  if (candidate.length !== stored.password_hash.length) return false;
  let mismatch = 0;
  for (let i = 0; i < candidate.length; i++) {
    mismatch |= candidate.charCodeAt(i) ^ stored.password_hash.charCodeAt(i);
  }
  return mismatch === 0;
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
