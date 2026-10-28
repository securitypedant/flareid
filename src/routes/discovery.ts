import { Hono } from "hono";
import type { Env } from "../env.js";
import { getPublicJwks } from "../lib/jwt.js";

export const discovery = new Hono<{ Bindings: Env }>();

discovery.get("/.well-known/openid-configuration", (c) => {
  const issuer = c.env.ISSUER_URL;
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks.json`,
    introspection_endpoint: `${issuer}/introspect`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "email", "profile", "groups"],
    claims_supported: ["sub", "email", "name", "groups"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256", "plain"],
  });
});

discovery.get("/jwks.json", (c) => {
  return c.json({ keys: getPublicJwks(c.env) });
});
