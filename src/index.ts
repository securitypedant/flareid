import { errorResponse } from "./lib/html.js";
import { refreshSpMetadata } from "./lib/saml/sp-metadata.js";
import { continueScimSync, drainScimDeprovisionQueue } from "./lib/scim-client.js";
import { Hono } from "hono";
import type { Env } from "./env.js";
import { discovery } from "./routes/discovery.js";
import { authorize } from "./routes/authorize.js";
import { saml } from "./routes/saml.js";
import { login } from "./routes/login.js";
import { recovery } from "./routes/recovery.js";
import { oidcSession } from "./routes/oidc-session.js";
import { samlSlo } from "./routes/saml-slo.js";
import { token } from "./routes/token.js";
import { introspect } from "./routes/introspect.js";
import { userinfo } from "./routes/userinfo.js";
import { account } from "./routes/account.js";
import { admin } from "./routes/admin.js";
import { api } from "./routes/api.js";
import { scimServer } from "./routes/scim-server.js";
import { getAppName } from "./lib/settings.js";
import { purgeExpiredState } from "./lib/cleanup.js";
import { purgeRetiredKeys } from "./lib/signing-keys.js";
import { csrfProtection, securityHeaders } from "./lib/security-headers.js";
import { edgeRateLimit } from "./lib/edge-limit.js";
import { recordRequestMetrics } from "./lib/metrics.js";
import { scheduledEnv, withResolvedIssuer } from "./lib/issuer.js";
import { isSetupCompleted } from "./lib/settings.js";
import { setup } from "./routes/setup.js";

const app = new Hono<{ Bindings: Env }>();

// Every response, the API included.
app.use("*", securityHeaders);
// Flood control for anonymous routes, before any handler can write anything.
app.use("*", edgeRateLimit);
// Per-request performance data point (Analytics Engine; no-op without the binding).
app.use("*", recordRequestMetrics);

app.get("/health", (c) => c.json({ status: "ok", service: "flareid-idp" }));

// Mounted before the appName middleware: these are machine callers that never
// render a page, and they include the only routes that work on an instance with
// no users in it at all.
app.route("/", api);
// Inbound SCIM 2.0 (machine callers, bearer API keys), mounted with the API.
app.route("/", scimServer);

// Resolves the admin-configurable display name once per request so every
// downstream handler/view can read it synchronously via c.get("appName").
app.use("*", async (c, next) => {
  c.set("appName", await getAppName(c.env));
  await next();
});

// Browser routes only - the API above authenticates with bearer tokens.
app.use("*", csrfProtection);

// A fresh deployment has nobody to sign in as: send the visitor to first-run setup.
app.get("/", async (c) => c.redirect((await isSetupCompleted(c.env)) ? "/account" : "/setup", 302));

app.route("/", setup);
app.route("/", discovery);
app.route("/", authorize);
app.route("/", saml);
app.route("/", login);
app.route("/", recovery);
app.route("/", oidcSession);
app.route("/", samlSlo);
app.route("/", token);
app.route("/", introspect);
app.route("/", userinfo);
app.route("/", account);
app.route("/", admin);

app.onError((err, c) => {
  console.error(err);
  return errorResponse(c.req.raw, c.get("appName") ?? "FlareID", 500, "Something went wrong on our side. Please try again in a moment.");
});

app.notFound((c) => errorResponse(c.req.raw, c.get("appName") ?? "FlareID", 404, "There's no page at this address. Check the link, or go back."));

export default {
  // ISSUER_URL is resolved here, once, before anything reads it: the pinned
  // var, else the issuer stored at setup, else (before setup) the request's
  // own https origin - see lib/issuer.ts. Everything downstream sees a
  // non-empty c.env.ISSUER_URL.
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const resolved = await withResolvedIssuer(env, request);
    if (resolved instanceof Response) return resolved;
    return app.fetch(request, resolved, ctx);
  },
  // Hourly Cron Trigger (wrangler.jsonc): garbage-collect expired codes, tokens,
  // sessions, devices and old audit entries. Logged so a run is visible in
  // Workers logs; failures surface there too rather than failing silently.
  //
  // There is no request to take an issuer from, so ISSUER_URL is the pinned or
  // stored one, or "" before setup. None of the jobs below depends on it (none
  // mints a token or builds a link); a future one that does must skip when it
  // is empty.
  async scheduled(_controller: ScheduledController, rawEnv: Env, ctx: ExecutionContext) {
    const env = await scheduledEnv(rawEnv);
    ctx.waitUntil(
      purgeExpiredState(env).then(
        (removed) => console.log(JSON.stringify({ event: "cleanup", removed })),
        (err) => console.error(JSON.stringify({ event: "cleanup_failed", error: String(err) }))
      )
    );
    // Retired signing keys past their RETIRED_PUBLISH_HOURS window. Separate from
    // purgeExpiredState, whose report reads its batch results by position.
    ctx.waitUntil(
      purgeRetiredKeys(env).then(
        (removed) => removed > 0 && console.log(JSON.stringify({ event: "signing_keys_purged", removed })),
        (err) => console.error(JSON.stringify({ event: "signing_key_purge_failed", error: String(err) }))
      )
    );
    // Re-read SP metadata registered from a URL (daily per SP).
    ctx.waitUntil(refreshSpMetadata(env).catch((err) => console.error(JSON.stringify({ event: "saml_metadata_refresh_error", error: String(err) }))));
    // Carry on a full SCIM sync that did not fit in one invocation.
    ctx.waitUntil(continueScimSync(env).catch((err) => console.error(JSON.stringify({ event: "scim_sync_continue_failed", error: String(err) }))));
    // Retry queued downstream SCIM deletions (replace-mode import, reset).
    ctx.waitUntil(
      drainScimDeprovisionQueue(env).then(
        (r) => r.removed + r.failed > 0 && console.log(JSON.stringify({ event: "scim_deprovision", ...r })),
        (err) => console.error(JSON.stringify({ event: "scim_deprovision_failed", error: String(err) }))
      )
    );
  },
} satisfies ExportedHandler<Env>;
