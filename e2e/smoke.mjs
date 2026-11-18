// Drives a local FlareID (e2e/Dockerfile, or `npm run dev`) end-to-end through
// its real HTTP surface: bootstrap -> setup -> API key -> browser-style login
// -> a full OIDC authorization_code flow -> admin console -> audit chain ->
// backup -> SSF. Zero dependencies; plain fetch.
//
//   node e2e/smoke.mjs                 # http://localhost:8787
//   BASE=http://localhost:9999 node e2e/smoke.mjs
//   BOOTSTRAP_TOKEN=... node e2e/smoke.mjs
//
// Exit code is the number of failed checks (0 = clean).

const BASE = (process.env.BASE ?? "http://localhost:8787").replace(/\/$/, "");
const BOOTSTRAP = process.env.BOOTSTRAP_TOKEN ?? "e2e-bootstrap-token";
const ADMIN_PW = "Adm1n-Gr0up-Of-Tw0!";
const USER_PW = "Ada-Test-Pw-4";

let passed = 0, failed = 0;
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log(`  ok   ${name}`); }
  else { failed++; console.log(`  FAIL ${name}${detail ? `  -- ${detail}` : ""}`); }
}

async function api(path, key, { method = "GET", body } = {}) {
  const r = await fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, json: await r.json().catch(() => ({})), headers: r.headers };
}

async function waitReady(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* still starting */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`No /health from ${BASE} within ${timeoutMs / 1000}s`);
}

// A minimal cookie jar keyed per user: Set-Cookie in, Cookie header out.
function jar() {
  const cookies = new Map();
  return {
    absorb(res) {
      for (const line of res.headers.getSetCookie?.() ?? []) {
        const [pair] = line.split(";");
        const i = pair.indexOf("=");
        if (i > 0) cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
      }
    },
    header() { return [...cookies].map(([k, v]) => `${k}=${v}`).join("; "); },
  };
}

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function uxLogin(upn, password) {
  const j = jar();
  const page = await fetch(`${BASE}/login`);
  const html = await page.text();
  const flowId = html.match(/name="flow_id"[^>]*value="([^"]+)"/)?.[1] ?? html.match(/value="([^"]+)"[^>]*name="flow_id"/)?.[1];
  if (!flowId) return { jar: j, res: null, err: "no flow_id on /login" };
  const res = await fetch(`${BASE}/login`, {
    method: "POST",
    headers: { ...FORM, Cookie: j.header() },
    body: new URLSearchParams({ flow_id: flowId, upn, password }).toString(),
    redirect: "manual",
  });
  j.absorb(res);
  return { jar: j, res };
}

async function getPage(j, path) {
  const r = await fetch(`${BASE}${path}`, { headers: { Cookie: j.header() }, redirect: "manual" });
  return { status: r.status, text: await r.text() };
}

console.log(`\nFlareID e2e smoke  ${BASE}\n`);

await waitReady();
check("GET /health", true);

// -- Bootstrap + setup --------------------------------------------------------
const mint = await api("/api-keys", BOOTSTRAP, { method: "POST", body: { name: "e2e-smoke", scopes: ["*"] } });
check("mint admin API key (bootstrap token)", mint.status === 200 && !!mint.json.token, JSON.stringify(mint.json));
const KEY = mint.json.token;

const setup = await api("/setup", KEY, {
  method: "POST",
  body: {
    domain: "example.com",
    admin: { username: "admin", password: ADMIN_PW, display_name: "E2E Admin" },
    require_mfa: false,
    admin_mfa: false,
    complete: true,
  },
});
check("POST /setup completes", setup.status === 200 && setup.json.setup_completed === true, JSON.stringify(setup.json));

const user = await api("/users", KEY, {
  method: "POST",
  body: { username: "ada", given_name: "Ada", family_name: "Chen", email: "ada@example.com", password: USER_PW, status: "active" },
});
check("POST /users creates ada", user.status === 201 && user.json.upn === "ada@example.com", JSON.stringify(user.json));

const grp = await api("/groups", KEY, { method: "POST", body: { name: "Engineering", description: "e2e" } });
check("POST /groups", grp.status === 201 || grp.status === 200, JSON.stringify(grp.json));
const grpId = grp.json.id ?? grp.json.group?.id;
if (grpId) {
  const members = await api(`/groups/${grpId}/members`, KEY, { method: "POST", body: { usernames: ["ada"] } });
  check("add ada to group", members.status === 200 || members.status === 204, JSON.stringify(members.json));
}

// -- Browser UX ---------------------------------------------------------------
const ada = await uxLogin("ada@example.com", USER_PW);
check("UX login (user)", ada.res && (ada.res.status === 302 || ada.res.status === 303), ada.err ?? `status ${ada.res?.status}`);
const acct = await getPage(ada.jar, "/account");
check("GET /account renders", acct.status === 200 && acct.text.includes("Ada"), `status ${acct.status}`);

const admin = await uxLogin("admin@example.com", ADMIN_PW);
check("UX login (admin)", admin.res && (admin.res.status === 302 || admin.res.status === 303), admin.err ?? `status ${admin.res?.status}`);
for (const p of ["/admin", "/admin/audit", "/admin/integrations/cf-one", "/admin/integrations/signals"]) {
  const pg = await getPage(admin.jar, p);
  check(`GET ${p} renders`, pg.status === 200, `status ${pg.status}`);
}

// -- OIDC authorization_code --------------------------------------------------
const disco = await fetch(`${BASE}/.well-known/openid-configuration`).then((r) => r.json());
check("OIDC discovery doc", disco.issuer && disco.authorization_endpoint, JSON.stringify(disco).slice(0, 120));
const jwks = await fetch(`${BASE}/jwks.json`).then((r) => r.json());
check("JWKS has an RSA signing key", Array.isArray(jwks.keys) && jwks.keys.some((k) => k.kty === "RSA"));

const REDIRECT = `${BASE}/e2e-callback`;
const client = await api("/clients", KEY, { method: "POST", body: { name: "e2e-app", redirect_uris: [REDIRECT], trusted: true } });
check("POST /clients", client.status === 200 && !!client.json.client_id, JSON.stringify(client.json));

const authz = await fetch(
  `${BASE}/authorize?response_type=code&client_id=${encodeURIComponent(client.json.client_id)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=openid+profile+email+groups&state=e2e123`,
  { headers: { Cookie: ada.jar.header() }, redirect: "manual" }
);
const loc = authz.headers.get("location") ?? "";
const code = new URL(loc, BASE).searchParams.get("code");
check("GET /authorize issues a code", authz.status === 302 && !!code, `status ${authz.status} loc ${loc.slice(0, 80)}`);

const token = await fetch(`${BASE}/token`, {
  method: "POST",
  headers: FORM,
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: code ?? "",
    redirect_uri: REDIRECT,
    client_id: client.json.client_id,
    client_secret: client.json.client_secret ?? "",
  }).toString(),
}).then((r) => r.json());
check("POST /token returns id+access token", !!token.id_token && !!token.access_token, JSON.stringify(token).slice(0, 160));
const idPayload = token.id_token ? JSON.parse(Buffer.from(token.id_token.split(".")[1], "base64url").toString()) : {};
check("id_token claims", idPayload.aud === client.json.client_id && idPayload.sub, JSON.stringify({ iss: idPayload.iss, aud: idPayload.aud }));

const ui = await fetch(`${BASE}/userinfo`, { headers: { Authorization: `Bearer ${token.access_token}` } });
const uiJson = await ui.json();
check("GET /userinfo", ui.status === 200 && uiJson.sub === idPayload.sub, JSON.stringify(uiJson).slice(0, 120));

const intro = await fetch(`${BASE}/introspect`, {
  method: "POST",
  headers: { ...FORM, Authorization: `Basic ${Buffer.from(`${client.json.client_id}:${client.json.client_secret}`).toString("base64")}` },
  body: new URLSearchParams({ token: token.access_token }).toString(),
}).then((r) => r.json());
check("POST /introspect active", intro.active === true, JSON.stringify(intro).slice(0, 120));

// -- Hardening endpoints from the release -------------------------------------
const chain = await api("/audit/verify", KEY);
check("audit chain verifies", chain.status === 200 && chain.json.status === "ok", JSON.stringify(chain.json).slice(0, 160));
const exp = await fetch(`${BASE}/api/v1/audit/export`, { headers: { Authorization: `Bearer ${KEY}` } });
const ndjson = await exp.text();
check("audit export carries chain_hash", exp.status === 200 && ndjson.includes("chain_hash"));

const backup = await api("/backup", KEY);
check("GET /backup returns tables", backup.status === 200 && (backup.json.tables?.users?.length ?? 0) >= 2, JSON.stringify(backup.json).slice(0, 160));

const ssfDoc = await fetch(`${BASE}/.well-known/ssf-configuration`).then((r) => r.json());
check("SSF discovery doc", !!ssfDoc.events_supported?.length, JSON.stringify(ssfDoc).slice(0, 120));
const stream = await api("/ssf/streams", KEY, {
  method: "POST",
  body: { name: "e2e-stream", endpoint_url: "https://receiver.invalid/events", events: [ssfDoc.events_supported[0]] },
});
check("POST /ssf/streams", stream.status === 201 || stream.status === 200, JSON.stringify(stream.json).slice(0, 160));

// -- Report -------------------------------------------------------------------
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
