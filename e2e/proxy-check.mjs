// Drives the compose lab's oauth2-proxy leg end to end with plain fetch: hit
// the protected upstream, get bounced through FlareID's password login, land
// back on the upstream and check the identity headers it received. Exercises a
// real third-party OIDC RP (discovery, auth code + PKCE, id_token validation,
// claim pass-through) that vitest cannot see.
//
//   docker compose -f e2e/compose.yml up -d flareid oauth2-proxy whoami
//   node e2e/real-apps.mjs            # seeds users/groups/clients + state/*.env
//   node e2e/proxy-check.mjs
//
// The IdP issuer is http://host.docker.internal:8787; on Linux the name needs a
// hosts entry (`127.0.0.1 host.docker.internal`) - CI sets it, Docker Desktop
// resolves it natively.
//
// PROXY defaults to http://localhost:4180. Exit code is the number of failed
// checks (0 = clean).

const PROXY = (process.env.PROXY ?? "http://localhost:4180").replace(/\/$/, "");
const UPN = process.env.LAB_UPN ?? "ada@example.com";
const PASSWORD = process.env.LAB_PASSWORD ?? "Ada-Test-Pw-4";

let passed = 0, failed = 0;
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log(`  ok   ${name}`); }
  else { failed++; console.log(`  FAIL ${name}${detail ? `  -- ${detail}` : ""}`); }
}

// Cookies scoped by hostname, like a browser: the proxy's CSRF/session cookies
// live on localhost:4180, the IdP session on the issuer host.
const jars = new Map();
const jarFor = (url) => {
  const host = new URL(url).hostname;
  if (!jars.has(host)) jars.set(host, new Map());
  return jars.get(host);
};
function absorb(url, res) {
  const jar = jarFor(url);
  for (const line of res.headers.getSetCookie?.() ?? []) {
    const [pair] = line.split(";");
    const i = pair.indexOf("=");
    if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}
const cookieHeader = (url) => [...jarFor(url)].map(([k, v]) => `${k}=${v}`).join("; ");

async function get(url) {
  const res = await fetch(url, { headers: { Cookie: cookieHeader(url) }, redirect: "manual" });
  absorb(url, res);
  return res;
}

async function waitReady(timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if ((await fetch(`${PROXY}/ping`)).ok) return; } catch { /* starting */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`oauth2-proxy not ready at ${PROXY} within ${timeoutMs / 1000}s`);
}

console.log(`\nFlareID oauth2-proxy e2e  ${PROXY}\n`);
await waitReady();

// Follows redirects, and clicks through oauth2-proxy's interstitial sign-in
// page (a 403 carrying a form that starts the OIDC flow).
async function follow(startUrl) {
  let url = startUrl;
  for (let i = 0; i < 14; i++) {
    const res = await get(url);
    const loc = res.headers.get("location");
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      url = new URL(loc, url).href;
      continue;
    }
    const text = await res.text();
    const start = url.startsWith(PROXY) ? text.match(/action="(\/oauth2\/start[^"]*)"/)?.[1] : null;
    if (!start) return { res, url, text };
    url = new URL(start, url).href;
  }
  throw new Error("redirect chain did not settle");
}

// -- Bounce from the protected upstream to the IdP sign-in page ----------------
let body;
let { res, url, text: loginHtml } = await follow(`${PROXY}/`);
check("unauthenticated request lands on the FlareID sign-in page", res.status === 200 && /name="upn"/.test(loginHtml), `ended at ${url} status ${res.status}`);

const flowId = loginHtml.match(/name="flow_id"[^>]*value="([^"]+)"/)?.[1] ?? loginHtml.match(/value="([^"]+)"[^>]*name="flow_id"/)?.[1];
check("sign-in page carries a flow_id", !!flowId);

// -- Password login ------------------------------------------------------------
const origin = new URL(url).origin;
res = await fetch(`${origin}/login`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin, Cookie: cookieHeader(url) },
  body: new URLSearchParams({ flow_id: flowId ?? "", upn: UPN, password: PASSWORD }).toString(),
  redirect: "manual",
});
absorb(url, res);
check("login POST redirects onward", [301, 302, 303].includes(res.status), `status ${res.status}`);

// -- Back through /authorize and the proxy callback to the upstream ------------
({ res, url, text: body } = await follow(new URL(res.headers.get("location") ?? "/", url).href));
check("back on the protected upstream", url.startsWith(PROXY) && res.status === 200, `ended at ${url} status ${res.status}`);
check("upstream received X-Forwarded-Email", body.includes(`X-Forwarded-Email: ${UPN}`), body.slice(0, 300));
check("upstream received X-Forwarded-Groups", /X-Forwarded-Groups: [^\n]*Engineering/.test(body));

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
