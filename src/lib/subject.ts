import { sha256Hex } from "./tokens.js";
import type { Env } from "../env.js";
import type { OAuthClientRow } from "./types.js";

/**
 * OIDC Core §8.1 pairwise subject identifiers. A "public" client gets the raw
 * user id as sub (the pre-existing behaviour); a "pairwise" client gets a
 * sector-scoped pseudonym so different sectors cannot correlate the user.
 *
 * The sector is the host of the client's sector_identifier_uri when one is
 * registered, else the host its redirect_uris share (OIDC Registration §2).
 * The derivation is keyed with an instance secret: a plain hash of
 * sector + user.id would let a relying party recover numeric user ids by
 * brute force, and correlation keys that rotate with deployments defeat the
 * point of a stable sub.
 */
export function clientSector(client: Pick<OAuthClientRow, "subject_type" | "sector_identifier_uri" | "redirect_uris">): string | null {
  if (client.sector_identifier_uri) {
    try {
      return new URL(client.sector_identifier_uri).host;
    } catch {
      return null;
    }
  }
  const uris = JSON.parse(client.redirect_uris) as string[];
  const hosts = new Set(uris.map((u) => new URL(u).host));
  return hosts.size === 1 ? [...hosts][0]! : null;
}

/** The `sub` claim an OIDC response asserts for this user to this client. */
export async function subjectFor(env: Env, client: Pick<OAuthClientRow, "subject_type" | "sector_identifier_uri" | "redirect_uris">, userId: number): Promise<string> {
  if (client.subject_type !== "pairwise") return String(userId);
  const sector = clientSector(client);
  if (!sector) return String(userId);
  const material = env.KEY_ENCRYPTION_KEY || env.SIGNING_KEY_PKCS8 || "";
  return `_${await sha256Hex(`flareid pairwise sub v1\n${material}\n${sector}\n${userId}`)}`;
}
