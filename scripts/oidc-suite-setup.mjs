// Seeds a FlareID instance for the OpenID Foundation conformance suite and
// writes the suite's plan config (conformance/suite-config.json, git-ignored).
//
// Idempotent: the two clients and the "conformance" user are upserted, and the
// user gets a fresh random password every run (which also ends its old sessions).
//
//   FLAREID_ISSUER        e.g. https://idp.tmesandbox.com
//   FLAREID_API_KEY       key with clients:write and directory:write
//   CONFORMANCE_SERVER    default https://www.certification.openid.net/
//   CONFORMANCE_ALIAS     default flareid-ci (the suite's callback path uses it)
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const issuer = (process.env.FLAREID_ISSUER ?? "").replace(/\/$/, "");
const key = process.env.FLAREID_API_KEY ?? "";
if (!issuer || !key) {
  console.error("FLAREID_ISSUER and FLAREID_API_KEY are required");
  process.exit(2);
}
const suite = (process.env.CONFORMANCE_SERVER ?? "https://www.certification.openid.net/").replace(/\/?$/, "/");
const alias = process.env.CONFORMANCE_ALIAS ?? "flareid-ci";
const base = `${suite}test/a/${alias}/`;

async function api(path, body, method = "POST") {
  const r = await fetch(`${issuer}/api/v1${path}`, { method, headers: { Authorization: `Bearer ${key}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}

const secret = () => randomBytes(24).toString("base64url");
const clients = [];
for (const n of [1, 2]) {
  const c = { client_id: `conformance-${alias}-${n}`, client_secret: secret() };
  await api("/clients", {
    name: `OIDF conformance (${alias}) ${n}`,
    ...c,
    trusted: true,
    redirect_uris: [`${base}callback`],
    post_logout_redirect_uris: [`${base}post_logout_redirect`],
    frontchannel_logout_uri: `${base}frontchannel_logout`,
    backchannel_logout_uri: `${base}backchannel_logout`,
    initiate_login_uri: `${base}initiate_login`,
  });
  clients.push(c);
}

// `groups` is left out, so the user's memberships stay as they are. With
// SCIM configured the import still re-pushes every group the user is in -
// including dynamic ones its empty attributes match ("location != London" in
// the sample directory: thousands of members). Those pushes are deltas
// against the last push (nothing is sent when membership did not change);
// they used to be full member-list PUTs, which made this step take minutes.
// The scope-* test modules ask for address and phone claims: give the test
// user a schema that holds them and values to release.
const SCHEMA = "OIDF Conformance";
const ATTRS = ["street_address", "locality", "region", "postal_code", "country", "phone_number", "phone_number_verified"].map((name) => ({ name, label: name }));
try {
  await api("/schemas", { object_type: "user", name: SCHEMA, attributes: ATTRS });
} catch (e) {
  if (!String(e).includes("409")) throw e;
  const { schemas } = await api("/schemas", undefined, "GET");
  const existing = (schemas ?? []).find((s) => s.object_type === "user" && s.name === SCHEMA);
  if (existing) await api(`/schemas/${existing.id}`, { attributes: ATTRS }, "PATCH");
}

const password = `Cf-${secret()}`;
const domain = new URL(issuer).hostname;
const imported = await api("/directory/import", {
  version: 1,
  users: [
    {
      username: "conformance",
      given_name: "Conformance",
      family_name: "Suite",
      email: `conformance@${domain}`,
      status: "active",
      password,
      schema: SCHEMA,
      attributes: {
        street_address: "12 Normandy Avenue",
        locality: "Cambridge",
        region: "Cambridgeshire",
        postal_code: "CB3 0DU",
        country: "GB",
        phone_number: "+44 1223 000000",
        phone_number_verified: "true",
      },
    },
  ],
});
if (imported.errors?.length) throw new Error(`user import: ${JSON.stringify(imported.errors)}`);
const upn = `conformance@${imported.domain ?? domain}`;

const login = {
  match: `${issuer}/authorize*`,
  tasks: [
    {
      task: "Sign in",
      match: `${issuer}/authorize*`,
      optional: true,
      commands: [
        ["text", "name", "upn", upn],
        ["text", "name", "password", password],
        ["click", "css", "button[type=submit].primary"],
      ],
    },
    // prompt=consent shows the consent screen even for a trusted client.
    { task: "Consent", match: `${issuer}/consent/*`, optional: true, commands: [["click", "css", "button[name=decision][value=allow]"]] },
    { task: "Verify complete", match: `${base}callback*`, commands: [["wait", "id", "submission_complete", 10]] },
  ],
};

// RP-initiated logout sends the browser to end_session, not /authorize. The
// suite only navigates a URL when a browser entry matches it; without this
// entry the end_session URL is queued for manual interaction and every
// oidcc-rp-initiated-logout* module times out in WAITING. The navigation
// alone is the test for the redirect modules; the error/confirm modules
// additionally ask for a screenshot of whatever the OP renders, so the
// capture runs on any page the logout URL answers with (optional variant -
// the base module requests no placeholder).
const capture = (text, optional = false) => ["wait", "xpath", "//*", 10, text, optional ? "update-image-placeholder-optional" : "update-image-placeholder"];
const logout = {
  match: `${issuer}/oidc/logout*`,
  tasks: [{ task: "Capture the logout outcome", match: `${issuer}/oidc/logout*`, optional: true, commands: [capture(".+", true)] }],
};

// Modules that want a screenshot get one from the scripted browser: a "wait"
// for text on the page with update-image-placeholder records it, the way the
// suite's own CI configuration does. Each override replaces the browser
// script for that module only.
const secondLogin = {
  ...login,
  tasks: login.tasks.map((t) => (t.task === "Sign in" ? { ...t, commands: [capture("Sign in", true), ...t.commands] } : t)),
};
const errorPage = { match: `${issuer}/authorize*`, tasks: [{ task: "Expect an error page", match: `${issuer}/authorize*`, commands: [capture("This app can.t sign you in")] }] };
// The registration display tests end at the sign-in page: they want a
// screenshot of it showing the metadata the client registered
// (login_page_placeholder), not a completed sign-in.
const snapshotLogin = (text) => ({
  match: `${issuer}/authorize*`,
  tasks: [{ task: "Snapshot the sign-in page", match: `${issuer}/authorize*`, commands: [capture(text)] }],
});
const override = {
  // prompt=login / max_age=1: the second authorization must show the sign-in page again.
  "oidcc-prompt-login": { browser: [secondLogin] },
  "oidcc-max-age-1": { browser: [secondLogin] },
  // An unregistered redirect_uri, or one only inside a request object, must end on an error page, not a redirect.
  "oidcc-ensure-registered-redirect-uri": { browser: [errorPage] },
  "oidcc-ensure-request-object-with-redirect-uri": { browser: [errorPage] },
  // RFC 7591 display metadata: the sign-in page shows the registered logo
  // ("Continue to <name>" sits under it) and links to the policy/TOS documents.
  "oidcc-registration-logo-uri": { browser: [snapshotLogin("Continue to")] },
  "oidcc-registration-policy-uri": { browser: [snapshotLogin("Privacy policy")] },
  "oidcc-registration-tos-uri": { browser: [snapshotLogin("Terms of service")] },
};

const config = {
  alias,
  description: `FlareID ${issuer}`,
  server: { discoveryUrl: `${issuer}/.well-known/openid-configuration` },
  client: { ...clients[0], scope: "openid email profile address phone" },
  client2: { ...clients[1], scope: "openid email profile address phone" },
  client_secret_post: { ...clients[0] },
  browser: [login, logout],
  override,
};
// The config carries live client secrets and the test user's password.
writeFileSync(new URL("../conformance/suite-config.json", import.meta.url), JSON.stringify(config, null, 2), { mode: 0o600 });
console.log(`seeded ${clients.length} clients and ${upn}; wrote conformance/suite-config.json (alias ${alias})`);
