import { exportJWK, generateKeyPair, importJWK, importPKCS8, type JWK } from "jose";
import type { Env } from "../env.js";

/**
 * Token signing keys, kept in D1 (migration 0021) so they can be rotated from
 * the console. One active key per algorithm (RS256 and ES256); a rotated-out
 * key stays published as "retired" for RETIRED_PUBLISH_HOURS so tokens it
 * signed remain verifiable, then is deleted by the hourly cleanup.
 *
 * Private keys are encrypted with AES-256-GCM under KEY_ENCRYPTION_KEY (a
 * Worker secret). Without it the key is derived from SIGNING_KEY_PKCS8, which
 * is already a secret - set KEY_ENCRYPTION_KEY before relying on rotation, and
 * never change it afterwards (stored keys could no longer be decrypted).
 */

export type SigningAlg = "RS256" | "ES256";
export const SIGNING_ALGS: SigningAlg[] = ["RS256", "ES256"];
export const RETIRED_PUBLISH_HOURS = 24;

export interface SigningKeyRow {
  kid: string;
  alg: SigningAlg;
  public_jwk: string;
  private_jwk_enc: string;
  status: "active" | "retired";
  created_at: string;
  retired_at: string | null;
}

const b64 = {
  enc: (b: Uint8Array) => btoa(String.fromCharCode(...b)),
  dec: (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function kek(env: Env): Promise<CryptoKey> {
  const material = env.KEY_ENCRYPTION_KEY || `flareid kek v1\n${env.SIGNING_KEY_PKCS8 ?? ""}`;
  if (!env.KEY_ENCRYPTION_KEY && !env.SIGNING_KEY_PKCS8) throw new Error("KEY_ENCRYPTION_KEY (or SIGNING_KEY_PKCS8) must be set to store signing keys");
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(env: Env, jwk: JWK): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(env), new TextEncoder().encode(JSON.stringify(jwk))));
  return `v1.${b64.enc(iv)}.${b64.enc(ct)}`;
}

async function unseal(env: Env, sealed: string): Promise<JWK> {
  const [, iv, ct] = sealed.split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(iv!) }, await kek(env), b64.dec(ct!));
  return JSON.parse(new TextDecoder().decode(pt)) as JWK;
}

const newKid = (alg: SigningAlg) => `flareid-${alg.toLowerCase()}-${new Date().toISOString().slice(0, 10)}-${crypto.getRandomValues(new Uint32Array(1))[0]!.toString(36)}`;

async function insertKey(env: Env, alg: SigningAlg, kid: string, privateJwk: JWK, publicJwk: JWK): Promise<void> {
  await env.DB.prepare("INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk_enc, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)")
    .bind(kid, alg, JSON.stringify({ ...publicJwk, kid, alg, use: "sig" }), await seal(env, privateJwk), new Date().toISOString())
    .run();
}

async function generate(env: Env, alg: SigningAlg): Promise<void> {
  const { privateKey, publicKey } = await generateKeyPair(alg, alg === "RS256" ? { modulusLength: 2048, extractable: true } : { extractable: true });
  await insertKey(env, alg, newKid(alg), await exportJWK(privateKey), await exportJWK(publicKey));
}

/** First use: the RS256 key from the environment (same kid), and a fresh ES256 key. */
async function ensureKeys(env: Env): Promise<void> {
  const { results } = await env.DB.prepare("SELECT alg FROM signing_keys WHERE status = 'active'").all<{ alg: SigningAlg }>();
  const have = new Set(results.map((r) => r.alg));
  if (!have.has("RS256")) {
    if (env.SIGNING_KEY_PKCS8 && env.SIGNING_PUBLIC_JWK) {
      const priv = await exportJWK(await importPKCS8(env.SIGNING_KEY_PKCS8, "RS256", { extractable: true }));
      await insertKey(env, "RS256", env.SIGNING_KEY_ID || "flareid-key-1", priv, JSON.parse(env.SIGNING_PUBLIC_JWK) as JWK).catch(() => undefined);
    } else {
      await generate(env, "RS256");
    }
  }
  if (!have.has("ES256")) await generate(env, "ES256").catch(() => undefined);
}

const importCache = new Map<string, CryptoKey | Uint8Array>();

/** The active key for an algorithm, imported for signing. */
export async function activeSigningKey(env: Env, alg: SigningAlg): Promise<{ kid: string; key: CryptoKey | Uint8Array }> {
  let row = await env.DB.prepare("SELECT * FROM signing_keys WHERE alg = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1").bind(alg).first<SigningKeyRow>();
  if (!row) {
    await ensureKeys(env);
    row = await env.DB.prepare("SELECT * FROM signing_keys WHERE alg = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1").bind(alg).first<SigningKeyRow>();
    if (!row) throw new Error(`No ${alg} signing key`);
  }
  let key = importCache.get(row.kid);
  if (!key) {
    key = await importJWK(await unseal(env, row.private_jwk_enc), alg);
    importCache.set(row.kid, key);
  }
  return { kid: row.kid, key };
}

/** Every public key a relying party may need: active ones, and retired ones still inside their window. */
export async function publishedKeys(env: Env): Promise<Record<string, unknown>[]> {
  await ensureKeys(env);
  const cutoff = new Date(Date.now() - RETIRED_PUBLISH_HOURS * 3600 * 1000).toISOString();
  const { results } = await env.DB.prepare("SELECT public_jwk FROM signing_keys WHERE status = 'active' OR retired_at > ? ORDER BY alg, created_at DESC").bind(cutoff).all<{ public_jwk: string }>();
  const keys = results.map((r) => JSON.parse(r.public_jwk) as Record<string, unknown>);
  // The pre-0021 previous key from the environment, while it is still configured.
  if (env.SIGNING_PUBLIC_JWK_PREVIOUS && env.SIGNING_KEY_ID_PREVIOUS && !keys.some((k) => k.kid === env.SIGNING_KEY_ID_PREVIOUS)) {
    keys.push({ ...(JSON.parse(env.SIGNING_PUBLIC_JWK_PREVIOUS) as Record<string, unknown>), kid: env.SIGNING_KEY_ID_PREVIOUS, use: "sig", alg: "RS256" });
  }
  return keys;
}

export async function listSigningKeys(env: Env): Promise<SigningKeyRow[]> {
  await ensureKeys(env);
  return (await env.DB.prepare("SELECT * FROM signing_keys ORDER BY alg, created_at DESC").all<SigningKeyRow>()).results;
}

/** A new active key for `alg`; the old one is retired but stays published for RETIRED_PUBLISH_HOURS. */
export async function rotateSigningKey(env: Env, alg: SigningAlg): Promise<string> {
  await ensureKeys(env);
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE signing_keys SET status = 'retired', retired_at = ? WHERE alg = ? AND status = 'active'").bind(now, alg).run();
  await generate(env, alg);
  return (await env.DB.prepare("SELECT kid FROM signing_keys WHERE alg = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1").bind(alg).first<{ kid: string }>())!.kid;
}

/** Hourly cleanup: drop retired keys that can no longer have signed a live token. */
export async function purgeRetiredKeys(env: Env, now = Date.now()): Promise<number> {
  const cutoff = new Date(now - RETIRED_PUBLISH_HOURS * 3600 * 1000).toISOString();
  const r = await env.DB.prepare("DELETE FROM signing_keys WHERE status = 'retired' AND retired_at < ?").bind(cutoff).run();
  return Number(r.meta.changes ?? 0);
}
