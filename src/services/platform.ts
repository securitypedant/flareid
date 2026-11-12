import { revokeApiKey } from "../lib/api-keys.js";
import { deleteDomain } from "../lib/domains.js";
import { rotateSigningKey, SIGNING_ALGS, type SigningAlg } from "../lib/signing-keys.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/** Removes a domain; refused (and the attempt audited) while it is the last one or still in use. */
export async function removeDomain(ctx: ServiceCtx, id: number): Promise<void> {
  const { error } = await deleteDomain(ctx.env, id);
  await audit(ctx, "domain.delete_attempted", String(id), error ? { error } : undefined);
  if (error) throw new ServiceError(error === "Unknown domain" ? 404 : 409, error);
}

/** Revokes an API key; anything using it stops working on its next request. */
export async function revokeKey(ctx: ServiceCtx, id: number): Promise<void> {
  const key = await ctx.env.DB.prepare("SELECT name FROM api_keys WHERE id = ?").bind(id).first<{ name: string }>();
  if (!key) throw new ServiceError(404, "Not found");
  await revokeApiKey(ctx.env, id);
  await audit(ctx, "api_key.revoked", key.name);
}

/** A new active signing key for `alg`; the old one stays published for RETIRED_PUBLISH_HOURS. */
export async function rotateKey(ctx: ServiceCtx, alg: string): Promise<string> {
  if (!(SIGNING_ALGS as string[]).includes(alg)) throw new ServiceError(400, `Unknown algorithm "${alg}". Valid: ${SIGNING_ALGS.join(", ")}.`);
  const kid = await rotateSigningKey(ctx.env, alg as SigningAlg);
  await audit(ctx, "signing_key.rotated", kid, { alg });
  return kid;
}
