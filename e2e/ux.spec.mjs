// Real-browser checks against the local e2e instance. Needs Playwright:
//
//   npm i -D playwright && npx playwright install chromium
//   node e2e/ux.spec.mjs
//
// BASE defaults to http://localhost:8787 (the e2e container or `npm run dev`).
// Run e2e/smoke.mjs first so the instance is set up (admin@example.com and
// ada@example.com exist with the passwords below).

import { chromium } from "playwright";

const BASE = (process.env.BASE ?? "http://localhost:8787").replace(/\/$/, "");
const USERS = [
  { upn: "ada@example.com", password: "Ada-Test-Pw-4", admin: false },
  { upn: "admin@example.com", password: "Adm1n-Gr0up-Of-Tw0!", admin: true },
];

let passed = 0, failed = 0;
const check = (n, ok) => { ok ? passed++ : failed++; console.log(` ${ok ? "ok  " : "FAIL"} ${n}`); };

const browser = await chromium.launch();
try {
  const probe = await browser.newPage();
  await probe.goto(`${BASE}/login`);
  check("/login renders the sign-in card", await probe.locator("input[name=upn]").isVisible());
  await probe.close();

  for (const u of USERS) {
    // A fresh context per user: /login redirects away when a session cookie is
    // present, so reusing one page hides the form after the first sign-in.
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${BASE}/login`);
    await page.fill("input[name=upn]", u.upn);
    await page.fill("input[name=password]", u.password);
    await page.click("button[type=submit].primary");
    await page.waitForURL(`${BASE}/account`);
    check(`${u.upn} lands on /account`, page.url() === `${BASE}/account`);
    if (u.admin) {
      await page.goto(`${BASE}/admin`);
      check("admin console renders", await page.locator("text=Dashboard").first().isVisible());
    }
    await ctx.close();
  }

  // Localized login: ?lang=es should switch the form strings.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${BASE}/login?lang=es`);
  check("Spanish locale loads", (await page.locator("button[type=submit].primary").innerText()).trim() === "Iniciar sesión");
  await ctx.close();
} finally {
  await browser.close();
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
