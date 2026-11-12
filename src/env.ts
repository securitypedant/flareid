export interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  APP_NAME: string;
  /**
   * The issuer. Empty in wrangler.jsonc by default: src/index.ts resolves it
   * before the app runs (the issuer stored at setup, else the request's https
   * origin - lib/issuer.ts), so inside the app it is never empty. Set the var
   * to pin it.
   */
  ISSUER_URL: string;
  /**
   * Optional: an RS256 keypair to import as the first signing key (with
   * SIGNING_KEY_ID as its kid) instead of generating one. Signing keys live
   * in D1 (lib/signing-keys.ts); these are read only while D1 has no RS256 key.
   */
  SIGNING_PUBLIC_JWK?: string;
  SIGNING_KEY_ID?: string;
  /** PKCS8 PEM of that RS256 private key, as a secret. Optional - see SIGNING_PUBLIC_JWK. */
  SIGNING_KEY_PKCS8?: string;
  /**
   * Public half of the *previous* signing key + its kid, kept published at
   * /jwks.json for a transition window after rotating so tokens issued just
   * before the rotation (up to their ~10m expiry) can still be verified.
   * Remove both once you're sure nothing is still relying on the old key.
   */
  SIGNING_PUBLIC_JWK_PREVIOUS?: string;
  SIGNING_KEY_ID_PREVIOUS?: string;
  /** Optional random string; keys the MAC on sealed login flows (lib/authorize-state.ts) when SIGNING_KEY_PKCS8 is not set. */
  COOKIE_ENCRYPTION_KEY?: string;

  /**
   * PEM X.509 certificate presented in SAML signatures' KeyInfo and published
   * in /saml/metadata. Not confidential - it is handed to every service
   * provider - but set as a secret beside SAML_SIGNING_KEY_PKCS8, so the
   * committed wrangler.jsonc stays deployable by anyone. Generate the pair with
   * `npm run saml:keygen`. Without both, SAML answers 503.
   */
  SAML_SIGNING_CERT?: string;
  /** PKCS8 PEM of the RSA private key that signs SAML Responses and Assertions. */
  SAML_SIGNING_KEY_PKCS8?: string;

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

  /**
   * "scrypt" (default) or "pbkdf2". Set "pbkdf2" only on the Workers Free plan:
   * a scrypt hash takes ~100 ms of CPU, beyond its 10 ms limit. Existing hashes
   * of either kind keep verifying whichever is set. See src/lib/password.ts.
   */
  PASSWORD_HASHER?: string;

  /**
   * Cloudflare Email Sending (`send_email` binding). Optional: without it, or
   * without a From address in Admin -> Integrations -> Email, recovery and
   * invitations are switched off and admins hand out passwords as before.
   */
  EMAIL?: SendEmail;

  /** Edge flood control for the browser sign-in routes (see edge-limit.ts). Optional. */
  AUTH_LIMITER?: RateLimit;
  /** Edge flood control for the API, token, introspection, userinfo and SCIM endpoints. Optional. */
  API_LIMITER?: RateLimit;
  /** Optional Analytics Engine dataset for per-request performance metrics (lib/metrics.ts). */
  METRICS?: AnalyticsEngineDataset;
  /** Account id and Account Analytics:Read token for reading those metrics back on the overview. */
  CF_ACCOUNT_ID?: string;
  CF_ANALYTICS_TOKEN?: string;
  /** Encrypts the signing keys stored in D1 (signing-keys.ts). Set once; never change. */
  KEY_ENCRYPTION_KEY?: string;
  /**
   * Optional Cloudflare Turnstile secret key. When set it is used instead of
   * the one saved under Security > Settings > Bot protection (turnstile.ts),
   * so the secret can live only in Worker secrets. The site key and the on/off
   * switch are still set in the console.
   */
  TURNSTILE_SECRET_KEY?: string;
}
