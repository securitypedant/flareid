// Translations and accessibility of the pages people sign in through: the
// locale files are complete and consistent, the language is negotiated the
// documented way and carried through a sign-in, and the rendered pages have
// the attributes assistive technology relies on.
import { beforeEach, describe, expect, it } from "vitest";
import { env, SELF } from "cloudflare:test";
import { LOCALES } from "../locales/index.js";
import en from "../locales/en.json";
import { formatList, matchLocale, parseAcceptLanguage, pickLocale, t, tHtml, html, tPlural, uiLocalesPreference } from "../src/lib/i18n.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { totp } from "./helpers-totp.js";
import { createSession } from "../src/lib/sessions.js";

const placeholders = (s: string) => [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]!).sort();
const SOURCE = en.messages as Record<string, string>;

describe("locale files", () => {
  const codes = Object.keys(LOCALES);

  it("ships English and at least one translation", () => {
    expect(codes[0]).toBe("en");
    expect(codes.length).toBeGreaterThanOrEqual(2);
  });

  for (const code of codes) {
    describe(code, () => {
      const file = LOCALES[code]!;
      const messages = file.messages;

      it("has exactly en.json's keys", () => {
        const missing = Object.keys(SOURCE).filter((k) => !(k in messages));
        const extra = Object.keys(messages).filter((k) => !(k in SOURCE));
        expect(missing, `${code}.json is missing keys`).toEqual([]);
        expect(extra, `${code}.json has keys en.json does not`).toEqual([]);
      });

      it("keeps every placeholder, and adds none", () => {
        const wrong = Object.keys(SOURCE)
          .filter((k) => k in messages && placeholders(messages[k]!).join() !== placeholders(SOURCE[k]!).join())
          .map((k) => `${k}: expected {${placeholders(SOURCE[k]!).join("}, {")}}, got "${messages[k]}"`);
        expect(wrong).toEqual([]);
      });

      it("has no empty or non-string messages", () => {
        expect(Object.entries(messages).filter(([, v]) => typeof v !== "string" || v.trim() === "").map(([k]) => k)).toEqual([]);
      });

      it("describes itself: code, names, direction, review status", () => {
        expect(file._meta.code).toBe(code);
        expect(file._meta.name).toBeTruthy();
        expect(file._meta.nativeName).toBeTruthy();
        expect(["ltr", "rtl"]).toContain(file._meta.dir);
        if (code !== "en") expect(typeof file._meta.machineAssisted).toBe("boolean");
      });
    });
  }

  it("has both plural forms of every plural message", () => {
    const keys = Object.keys(SOURCE);
    const one = keys.filter((k) => k.endsWith(".one")).map((k) => k.slice(0, -4));
    const other = keys.filter((k) => k.endsWith(".other")).map((k) => k.slice(0, -6));
    expect(one.sort()).toEqual(other.sort());
  });
});

describe("i18n helpers", () => {
  it("parses Accept-Language by q-value, dropping q=0 and *", () => {
    expect(parseAcceptLanguage("de;q=0.5, fr-CA, fr;q=0.9, en;q=0, *;q=0.1")).toEqual(["fr-CA", "fr", "de"]);
    expect(parseAcceptLanguage("")).toEqual([]);
    expect(parseAcceptLanguage(null)).toEqual([]);
  });

  it("matches a region to its language, case-insensitively, and refuses junk", () => {
    expect(matchLocale("FR-ca")).toBe("fr");
    expect(matchLocale("de_DE")).toBe("de");
    expect(matchLocale("ja")).toBeNull();
    expect(matchLocale('fr"><script>')).toBeNull();
    expect(pickLocale(["ja", "es", "de-AT"], "en")).toBe("de");
    expect(pickLocale(["ja"], "fr")).toBe("fr");
    expect(uiLocalesPreference("ja de-CH fr")).toBe("de");
  });

  it("fills placeholders, formats numbers and lists, and falls back to English", () => {
    expect(t("fr", "mfa.rememberDevice", { days: 30 })).toBe("Mémoriser cet appareil pendant 30 jours");
    expect(t("xx", "login.title")).toBe("Sign in");
    expect(formatList("en", ["a", "b", "c"])).toBe("a, b and c");
    expect(formatList("de", ["a", "b"])).toBe("a und b");
    expect(tPlural("en", "password.error.breached", 1234)).toBe("This password has appeared in a data breach 1,234 times; choose another.");
    expect(tPlural("en", "password.error.breached", 1)).toBe("This password has appeared in a data breach 1 time; choose another.");
  });

  it("escapes values in tHtml unless they are trusted markup", () => {
    expect(tHtml("en", "recovery.reset.for", { upn: "<b>x</b>" })).toBe("For &lt;b&gt;x&lt;/b&gt;.");
    expect(tHtml("en", "recovery.reset.for", { upn: html("<strong>a@b</strong>") })).toBe("For <strong>a@b</strong>.");
  });
});

// ---------------------------------------------------------------------------
// Rendered pages
// ---------------------------------------------------------------------------

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function get(path: string, headers: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}${path}`, { headers, redirect: "manual" });
  return { res, html: await res.text() };
}
async function post(path: string, fields: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, ...headers }, body: new URLSearchParams(fields).toString(), redirect: "manual" });
  return { res, html: await res.text() };
}
const flowIdOf = (html: string) => /name="flow_id" value="([^"]*)"/.exec(html)?.[1] ?? "";
const mfaIdOf = (html: string) => /name="mfa_id" value="([^"]*)"/.exec(html)?.[1] ?? "";
const attr = (tag: string, name: string) => new RegExp(`\\s${name}="([^"]*)"`).exec(tag)?.[1];
const tags = (html: string, name: string) => [...html.matchAll(new RegExp(`<${name}\\b[^>]*>`, "g"))].map((m) => m[0]);
const inputTag = (html: string, id: string) => tags(html, "input").find((i) => attr(i, "id") === id) ?? "";
const scripts = (html: string) => [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]!).sort();

/** The structure every auth-flow page must have: language, one h1, a main landmark, a title, labelled inputs. */
function expectAccessiblePage(html: string, lang: string) {
  expect(html).toMatch(new RegExp(`<html lang="${lang}" dir="(ltr|rtl)"`));
  expect(html.match(/<h1\b/g)?.length, "one <h1>").toBe(1);
  expect(html).toContain('<main class="center-wrap">');
  expect(/<title>[^<]+ - [^<]+<\/title>/.test(html)).toBe(true);
  for (const input of tags(html, "input").filter((i) => !/type="hidden"/.test(i))) {
    const id = attr(input, "id");
    expect(id, `an id on ${input}`).toBeTruthy();
    expect(html, `a <label for="${id}">`).toContain(`<label for="${id}"`);
  }
  // A link is never wrapped around a button (nested interactive content).
  expect(html).not.toMatch(/<a\b[^>]*>\s*<button/);
}

describe("sign-in pages", () => {
  let apiKey = "";
  beforeEach(async () => {
    await resetDatabase();
    ({ apiKey } = await bootstrapInstance());
  });

  it("render in English by default, with lang, labels, autocomplete and a language picker", async () => {
    const { html } = await get("/login");
    expectAccessiblePage(html, "en");
    expect(html).toContain("<title>Sign in - ");
    expect(html).toContain('<h1 class="visually-hidden">Sign in to ');
    expect(inputTag(html, "upn")).toContain('autocomplete="username"');
    expect(inputTag(html, "password")).toContain('autocomplete="current-password"');
    expect(html).toContain('<nav class="auth-lang" aria-label="Language">');
    expect(html).toMatch(/<a href="\/login\/language\?lang=fr&amp;flow_id=[^"]+" lang="fr" hreflang="fr">Français<\/a>/);
    expect(html).toContain('lang="en" hreflang="en" aria-current="true">English</a>');
    // The passkey control is a real, labelled button; its failure message is announced.
    expect(html).toMatch(/<button class="secondary" type="button" data-passkey-login[^>]*data-failed="Passkey sign-in was cancelled or failed\."/);
    expect(html).toContain('id="passkey-login-status" role="status" aria-live="polite"');
    // The decorative trail is hidden from assistive technology and off for reduced motion.
    expect(html).toContain('<canvas id="cursor-fx" aria-hidden="true"');
    expect(html).toContain("prefers-reduced-motion: reduce");
  });

  it("follows Accept-Language, then ?lang= (remembered in a cookie), then the cookie", async () => {
    const fr = await get("/login", { "Accept-Language": "ja, fr-CA;q=0.8, de;q=0.5" });
    expect(fr.html).toContain('<html lang="fr" dir="ltr"');
    expect(fr.html).toContain("Nom d&#039;utilisateur");
    expect(fr.res.headers.get("Set-Cookie") ?? "").not.toContain("flareid_lang");

    const de = await get("/login?lang=de", { "Accept-Language": "fr" });
    expect(de.html).toContain('<html lang="de" dir="ltr"');
    expect(de.html).toContain(">Anmelden</button>");
    const cookie = de.res.headers.get("Set-Cookie") ?? "";
    expect(cookie).toMatch(/flareid_lang=de; Path=\/; Max-Age=\d+; Secure; HttpOnly; SameSite=Lax/);

    const remembered = await get("/login", { "Accept-Language": "fr", Cookie: "flareid_lang=de" });
    expect(remembered.html).toContain('<html lang="de"');

    // An unknown ?lang= is ignored, and sets nothing.
    const unknown = await get("/login?lang=xx-evil", { "Accept-Language": "fr" });
    expect(unknown.html).toContain('<html lang="fr"');
    expect(unknown.res.headers.get("Set-Cookie") ?? "").not.toContain("flareid_lang");
  });

  it("falls back to the instance's default language, set under Branding or over the API", async () => {
    const bad = await apiCall("/api/v1/branding", { token: apiKey, method: "PATCH", body: { default_language: "xx" } });
    expect(bad.status).toBe(400);
    const ok = await apiCall("/api/v1/branding", { token: apiKey, method: "PATCH", body: { default_language: "de" } });
    expect(ok.status).toBe(200);
    expect(ok.body.default_language).toBe("de");
    expect(ok.body.available_languages.map((l: { code: string }) => l.code)).toEqual(Object.keys(LOCALES));

    expect((await get("/login", { "Accept-Language": "ja" })).html).toContain('<html lang="de"');
    expect((await get("/login")).html).toContain('<html lang="de"');
    // A language the browser asks for still wins over the default.
    expect((await get("/login", { "Accept-Language": "en-GB" })).html).toContain('<html lang="en"');
  });

  it("carries the language through the sealed flow, and ties a credential error to the fields", async () => {
    const { html } = await get("/login?lang=fr");
    // No cookie and no Accept-Language on the post: the flow alone says French.
    const failed = await post("/login", { flow_id: flowIdOf(html), upn: "admin", password: "wrong" });
    expect(failed.html).toContain('<html lang="fr"');
    expect(failed.html).toContain('<p class="error" id="form-error-0" role="alert">Nom d&#039;utilisateur/UPN ou mot de passe incorrect.</p>');
    for (const id of ["upn", "password"]) {
      expect(inputTag(failed.html, id)).toContain('aria-invalid="true"');
      expect(inputTag(failed.html, id)).toContain('aria-describedby="form-error-0"');
    }
    expectAccessiblePage(failed.html, "fr");
  });

  it("keeps English error output as it was, with the error announced", async () => {
    const { html } = await get("/login");
    const failed = await post("/login", { flow_id: flowIdOf(html), upn: "admin", password: "wrong" });
    expect(failed.html).toContain("Incorrect username/UPN or password.");
    expect(failed.html).toContain('role="alert"');
    expect(inputTag(failed.html, "upn")).toContain('aria-invalid="true"');
  });

  it("switches the language of a flow in progress from the picker", async () => {
    const { html } = await get("/login");
    const flowId = flowIdOf(html);
    const switched = await get(`/login/language?lang=de&flow_id=${encodeURIComponent(flowId)}`);
    expect(switched.res.status).toBe(200);
    expect(switched.html).toContain('<html lang="de"');
    expect(switched.res.headers.get("Set-Cookie") ?? "").toContain("flareid_lang=de");
    // Resealed in German: a post without the cookie still answers in German.
    const failed = await post("/login", { flow_id: flowIdOf(switched.html), upn: "admin", password: "wrong" });
    expect(failed.html).toContain("Benutzername/UPN oder Passwort ist falsch.");

    const stale = await get("/login/language?lang=de&flow_id=s.bogus.mac");
    expect(stale.res.status).toBe(302);
    expect(stale.res.headers.get("Location")).toBe("/login?lang=de");
  });

  it("renders the second step in the flow's language, with the code field labelled and tied to its error", async () => {
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE username = 'admin'").run();
    const { html } = await get("/login?lang=fr");
    const step = await post("/login", { flow_id: flowIdOf(html), upn: "admin", password: "test-admin-password-1" });
    expect(step.html).toContain('<html lang="fr"');
    expect(step.html).toContain("<title>Authentification à deux facteurs - ");
    expectAccessiblePage(step.html, "fr");
    expect(inputTag(step.html, "code")).toContain('autocomplete="one-time-code"');
    expect(step.html).toContain('<label for="remember_device"');

    const wrong = await post("/login/mfa", { mfa_id: mfaIdOf(step.html), code: "000000" });
    expect(wrong.html).toContain('<html lang="fr"');
    expect(wrong.html).toContain("Code incorrect, veuillez réessayer.");
    expect(inputTag(wrong.html, "code")).toContain('aria-invalid="true" aria-describedby="form-error-0"');

    const right = await post("/login/mfa", { mfa_id: mfaIdOf(step.html), code: await totp("JBSWY3DPEHPK3PXP") });
    expect(right.res.status).toBe(302);
  });

  it("translates the auth error pages, with a link (not a button inside a link) to sign in again", async () => {
    const expired = await post("/login", { flow_id: "s.bogus.mac", upn: "a", password: "b" }, { "Accept-Language": "de" });
    expect(expired.res.status).toBe(400);
    expect(expired.html).toContain("<h1>Diese Anmeldung ist abgelaufen</h1>");
    expect(expired.html).toContain('<a class="button primary" href="/login">Erneut anmelden</a>');
    expectAccessiblePage(expired.html, "de");

    const english = await post("/login", { flow_id: "s.bogus.mac", upn: "a", password: "b" });
    expect(english.html).toContain("<h1>This sign-in has expired</h1>");
  });

  it("uses an app's OIDC ui_locales for the sign-in page", async () => {
    const client = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "RP", redirect_uris: ["https://rp.test/cb"] } });
    expect(client.status).toBeLessThan(300);
    const q = new URLSearchParams({ client_id: client.body.client_id, redirect_uri: "https://rp.test/cb", response_type: "code", scope: "openid", ui_locales: "ja de" });
    const { html } = await get(`/authorize?${q}`, { "Accept-Language": "fr" });
    expect(html).toContain('<html lang="de"');
    // The explicit choice (the cookie) still wins over the app's.
    expect((await get(`/authorize?${q}`, { Cookie: "flareid_lang=fr" })).html).toContain('<html lang="fr"');
  });

  it("renders the inline scripts identically in every language, so their CSP hashes hold", async () => {
    const en = scripts((await get("/login")).html);
    const fr = scripts((await get("/login?lang=fr")).html);
    const de = scripts((await get("/login?lang=de")).html);
    expect(fr).toEqual(en);
    expect(de).toEqual(en);
  });

  it("labels the Turnstile widget and asks it for the page's language", async () => {
    expect((await apiCall("/api/v1/security/turnstile", { token: apiKey, method: "PUT", body: { mode: "on", site_key: "1x00000000000000000000AA", secret: "1x0000000000000000000000000000000AA" } })).status).toBe(200);
    const { html } = await get("/login?lang=fr");
    expect(html).toMatch(/<div id="turnstile-widget" class="turnstile-widget" role="group" aria-label="Vérification de sécurité"[^>]*data-language="fr"/);
  });

  it("translates the sign-out confirmation and the recovery pages", async () => {
    const userId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, userId, ["pwd"], new Request(BASE))).setCookie.split(";")[0]!;
    const out = await get("/oidc/logout", { Cookie: `${cookie}; flareid_lang=de` });
    expect(out.html).toContain("<h1>Abmelden?</h1>");
    expectAccessiblePage(out.html, "de");

    // Recovery needs email; without it, the message page says so - translated.
    const off = await get("/forgot-password", { "Accept-Language": "fr" });
    expect(off.html).toContain("La récupération du mot de passe n&#039;est pas disponible");
  });
});

describe("the setup page", () => {
  beforeEach(resetDatabase);

  it("is translated, labelled, and ties each error to its field", async () => {
    const page = await get("/setup", { "Accept-Language": "de" });
    expect(page.res.status).toBe(200);
    expectAccessiblePage(page.html, "de");
    expect(page.html).toContain("Ersteinrichtung");
    expect(inputTag(page.html, "password")).toContain('aria-describedby="password-policy"');

    const res = await post("/setup", { bootstrap_token: "test-bootstrap-token", domain: "", username: "admin", password: "a-long-password-1", confirm: "different-1" }, { "Accept-Language": "de" });
    expect(res.res.status).toBe(400);
    expect(res.html).toContain('<div class="form-errors" role="alert">');
    expect(res.html).toContain("Geben Sie die primäre Domain für Benutzerkonten ein.");
    expect(inputTag(res.html, "domain")).toContain('aria-invalid="true" aria-describedby="form-error-0"');
    expect(inputTag(res.html, "confirm")).toContain('aria-invalid="true" aria-describedby="form-error-1"');
    expect(inputTag(res.html, "username")).not.toContain("aria-invalid");
  });
});

