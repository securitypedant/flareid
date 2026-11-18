import { Hono } from "hono";
import type { Env } from "../env.js";
import { getPublicJwks } from "../lib/jwt.js";
import { ACR_VALUES, SUPPORTED_SCOPES } from "../lib/oidc.js";
import { SSF_EVENTS } from "../lib/ssf.js";

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
    end_session_endpoint: `${issuer}/oidc/logout`,
    frontchannel_logout_supported: true,
    frontchannel_logout_session_supported: true,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    device_authorization_endpoint: `${issuer}/device_authorization`,
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256", "ES256"],
    scopes_supported: SUPPORTED_SCOPES,
    claims_supported: [
      "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid", "at_hash",
      "id", "name", "given_name", "family_name", "preferred_username", "email", "email_verified",
      "groups", "job_title", "department", "manager", "custom",
    ],
    acr_values_supported: ACR_VALUES,
    prompt_values_supported: ["none", "login", "consent"],
    claims_parameter_supported: true,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
  });
});

discovery.get("/jwks.json", async (c) => {
  return c.json({ keys: await getPublicJwks(c.env) });
});

// Shared Signals Framework transmitter metadata (OpenID SSF): receivers read
// this to learn our issuer, signing keys and the events we push.
discovery.get("/.well-known/ssf-configuration", (c) => {
  const issuer = c.env.ISSUER_URL;
  return c.json({
    issuer,
    jwks_uri: `${issuer}/jwks.json`,
    delivery_methods_supported: ["https://schemas.openid.net/secevent/risc/delivery-method/push"],
    events_supported: Object.values(SSF_EVENTS),
    // Stream registration is by API/console, not the spec's stream-management
    // endpoint - the receiver just needs the events it wants named there.
    configuration_endpoint: `${issuer}/api/v1/ssf/streams`,
  });
});
