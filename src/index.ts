import { drainScimDeprovisionQueue } from "./lib/scim-client.js";
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
import { csrfProtection, securityHeaders } from "./lib/security-headers.js";
import { edgeRateLimit } from "./lib/edge-limit.js";
import { recordRequestMetrics } from "./lib/metrics.js";

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

app.get("/", (c) => c.redirect("/account", 302));

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
  return c.text("Internal server error", 500);
});

app.notFound((c) => c.text("Not found", 404));

export default {
  fetch: app.fetch,
  // Hourly Cron Trigger (wrangler.jsonc): garbage-collect expired codes, tokens,
  // sessions, devices and old audit entries. Logged so a run is visible in
  // Workers logs; failures surface there too rather than failing silently.
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      purgeExpiredState(env).then(
        (removed) => console.log(JSON.stringify({ event: "cleanup", removed })),
        (err) => console.error(JSON.stringify({ event: "cleanup_failed", error: String(err) }))
      )
    );
    // Retry queued downstream SCIM deletions (replace-mode import, reset).
    ctx.waitUntil(
      drainScimDeprovisionQueue(env).then(
        (r) => r.removed + r.failed > 0 && console.log(JSON.stringify({ event: "scim_deprovision", ...r })),
        (err) => console.error(JSON.stringify({ event: "scim_deprovision_failed", error: String(err) }))
      )
    );
  },
} satisfies ExportedHandler<Env>;
