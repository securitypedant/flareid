export interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  APP_NAME: string;
  ISSUER_URL: string;
  /** Public half of the *current* signing key as a JSON JWK string - safe to be non-secret. Published at /jwks.json. */
  SIGNING_PUBLIC_JWK: string;
  /** Key id for the current signing key. Bump this whenever you rotate SIGNING_KEY_PKCS8. */
  SIGNING_KEY_ID?: string;
  /** PKCS8 PEM of the RS256 private key used to sign id_tokens. Set via `wrangler secret put SIGNING_KEY_PKCS8`. */
  SIGNING_KEY_PKCS8?: string;
  /**
   * Public half of the *previous* signing key + its kid, kept published at
   * /jwks.json for a transition window after rotating so tokens issued just
   * before the rotation (up to their ~10m expiry) can still be verified.
   * Remove both once you're sure nothing is still relying on the old key.
   */
  SIGNING_PUBLIC_JWK_PREVIOUS?: string;
  SIGNING_KEY_ID_PREVIOUS?: string;
  /** Any random string, signs the IdP session cookie. Set via `wrangler secret put COOKIE_ENCRYPTION_KEY`. */
  COOKIE_ENCRYPTION_KEY?: string;

  /**
   * One-shot provisioning secret for the /api/v1 API, set at deploy time via
   * `wrangler secret put BOOTSTRAP_TOKEN`.
   *
   * A fresh deployment has no users - the migrations do not ship an
   * administrator - so this is the only way to configure one. It is accepted
   * for every API call until initial setup completes, and after that only by
   * POST /api/v1/recovery/admin-reset. Unset it to close even that door.
   */
  BOOTSTRAP_TOKEN?: string;

}
