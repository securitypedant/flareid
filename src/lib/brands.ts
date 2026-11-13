import type { Env } from "../env.js";
import { DEFAULT_ACCENT } from "./email-templates.js";
import { DEFAULT_LOGIN_GRADIENT, DEFAULT_LOGIN_SUBTITLE, isHexColor, type LoginGradient } from "./settings.js";

/**
 * Brands (migration 0027): the look of the pages people sign in through and
 * of the email they get, per UPN domain.
 *
 * The default brand is the instance's own Branding settings (idp_settings).
 * Any number of further brands can be attached to domains (domains.brand_id);
 * a field a brand leaves empty falls back to the default brand's value. App-wide
 * names - the issuer, OIDC/SAML metadata, the admin console - always use the
 * default brand.
 *
 * Which brand a page uses (brandFor and requestBrandDomain):
 *   - once the person is known (the second step, consent, My account, a reset
 *     or invitation link, any email to them): the brand of their UPN's domain;
 *   - before that, on the sign-in and recovery pages: a hint - the OIDC
 *     `login_hint` (its part after the last "@") or `?domain=` / `?login_hint=`
 *     on /login, carried in the sealed sign-in flow - else the hostname the
 *     page was reached on when it is a branded domain or a subdomain of one
 *     (never the issuer's own hostname), else the default brand;
 *   - `/login?brand_preview=<id|default>` for an administrator with
 *     branding:read (see login.ts).
 */

export interface Brand {
  /** brands.id, or null for the default brand. */
  id: number | null;
  name: string;
  appName: string;
  /** The line under the name on the sign-in page; empty shows none. */
  subtitle: string;
  gradient: LoginGradient;
  /** Email accent colour. */
  accent: string;
  /** Path of the uploaded logo (/brand/logo/...), or null for FlareID's own mark. */
  logoUrl: string | null;
  /** Path of the custom stylesheet (/brand/css/...), or null when there is none. */
  cssUrl: string | null;
}

export const DEFAULT_BRAND_NAME = "Default";
export const LOGO_MAX_BYTES = 256 * 1024;
export const CUSTOM_CSS_MAX_BYTES = 20 * 1024;
export const BRAND_NAME_MAX = 60;
export const APP_NAME_MAX = 60;
export const SUBTITLE_MAX = 140;

export type LogoType = "image/png" | "image/jpeg";

const LOGO_EXT: Record<LogoType, string> = { "image/png": "png", "image/jpeg": "jpg" };

export function logoPath(id: number, sha256: string, type: string): string {
  return `/brand/logo/${id}-${sha256.slice(0, 16)}.${LOGO_EXT[type as LogoType] ?? "png"}`;
}

export function cssPath(key: number | "default", hash: string): string {
  return `/brand/css/${key}-${hash}.css`;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

const DEFAULT_KEYS = ["app_name", "login_subtitle", "login_gradient_from", "login_gradient_to", "email_accent", "brand_logo_asset_id", "custom_css_hash"];

/** The default brand, in one query (the logo's hash joined in). */
export async function defaultBrand(env: Env): Promise<Brand> {
  const { results } = await env.DB.prepare(
    `SELECT s.key, s.value, a.id AS logo_id, a.sha256 AS logo_sha, a.content_type AS logo_type
       FROM idp_settings s
       LEFT JOIN brand_assets a ON s.key = 'brand_logo_asset_id' AND a.id = CAST(s.value AS INTEGER)
      WHERE s.key IN (SELECT value FROM json_each(?))`
  )
    .bind(JSON.stringify(DEFAULT_KEYS))
    .all<{ key: string; value: string; logo_id: number | null; logo_sha: string | null; logo_type: string | null }>();
  const get = (k: string) => results.find((r) => r.key === k)?.value ?? null;
  const logo = results.find((r) => r.key === "brand_logo_asset_id" && r.logo_id !== null);
  const from = get("login_gradient_from");
  const to = get("login_gradient_to");
  const accent = get("email_accent");
  const cssHash = get("custom_css_hash");
  return {
    id: null,
    name: DEFAULT_BRAND_NAME,
    appName: get("app_name") || env.APP_NAME,
    subtitle: get("login_subtitle") ?? DEFAULT_LOGIN_SUBTITLE,
    gradient: isHexColor(from) && isHexColor(to) ? { from, to } : DEFAULT_LOGIN_GRADIENT,
    accent: accent && isHexColor(accent) ? accent.toLowerCase() : DEFAULT_ACCENT,
    logoUrl: logo ? logoPath(logo.logo_id!, logo.logo_sha!, logo.logo_type!) : null,
    cssUrl: cssHash ? cssPath("default", cssHash) : null,
  };
}

export interface BrandRow {
  id: number;
  name: string;
  app_name: string;
  login_subtitle: string | null;
  gradient_from: string | null;
  gradient_to: string | null;
  email_accent: string | null;
  logo_asset_id: number | null;
  css_hash: string;
  created_at: string;
  updated_at: string;
  logo_sha: string | null;
  logo_type: string | null;
}

const BRAND_COLUMNS = `b.id, b.name, b.app_name, b.login_subtitle, b.gradient_from, b.gradient_to, b.email_accent, b.logo_asset_id, b.css_hash, b.created_at, b.updated_at,
  a.sha256 AS logo_sha, a.content_type AS logo_type`;

/** A brand row over the default brand: what it leaves empty, the default supplies. */
export function mergeBrand(def: Brand, row: BrandRow): Brand {
  return {
    id: row.id,
    name: row.name,
    appName: row.app_name.trim() || def.appName,
    subtitle: row.login_subtitle ?? def.subtitle,
    gradient: isHexColor(row.gradient_from) && isHexColor(row.gradient_to) ? { from: row.gradient_from, to: row.gradient_to } : def.gradient,
    accent: isHexColor(row.email_accent) ? row.email_accent.toLowerCase() : def.accent,
    logoUrl: row.logo_asset_id !== null && row.logo_sha && row.logo_type ? logoPath(row.logo_asset_id, row.logo_sha, row.logo_type) : def.logoUrl,
    cssUrl: row.css_hash ? cssPath(row.id, row.css_hash) : def.cssUrl,
  };
}

export async function getBrandRow(env: Env, id: number): Promise<BrandRow | null> {
  if (!Number.isInteger(id)) return null;
  return env.DB.prepare(`SELECT ${BRAND_COLUMNS} FROM brands b LEFT JOIN brand_assets a ON a.id = b.logo_asset_id WHERE b.id = ?`).bind(id).first<BrandRow>();
}

export async function listBrandRows(env: Env): Promise<(BrandRow & { domains: string[] })[]> {
  const [{ results }, { results: links }] = await Promise.all([
    env.DB.prepare(`SELECT ${BRAND_COLUMNS} FROM brands b LEFT JOIN brand_assets a ON a.id = b.logo_asset_id ORDER BY b.name`).all<BrandRow>(),
    env.DB.prepare("SELECT domain, brand_id FROM domains WHERE brand_id IS NOT NULL ORDER BY domain").all<{ domain: string; brand_id: number }>(),
  ]);
  return results.map((r) => ({ ...r, domains: links.filter((l) => l.brand_id === r.id).map((l) => l.domain) }));
}

/** A domain as typed, a UPN or a login_hint, as the domain it names; null when it names none. */
export function domainFromHint(value: string | null | undefined): string | null {
  if (!value) return null;
  const v = value.trim().toLowerCase();
  const d = v.includes("@") ? v.slice(v.lastIndexOf("@") + 1) : v;
  return d && d.length <= 253 && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(d) ? d : null;
}

export interface BrandHint {
  /** An explicit brand (the preview): a brands.id or "default". */
  brandId?: number | "default" | null;
  /** The person, once known: their UPN's domain decides. */
  userId?: number | null;
  upn?: string | null;
  /** A domain (or anything domainFromHint reads) from a hint or the hostname. */
  domain?: string | null;
}

/**
 * The brand for a page or an email. An explicit brand wins, then the person
 * (their UPN's domain), then the domain hint; a domain with no brand, or no
 * hint at all, gets the default brand.
 */
export async function brandFor(env: Env, hint: BrandHint = {}): Promise<Brand> {
  const def = await defaultBrand(env);
  if (hint.brandId === "default") return def;
  if (typeof hint.brandId === "number") {
    const row = await getBrandRow(env, hint.brandId);
    return row ? mergeBrand(def, row) : def;
  }
  let upn = hint.upn ?? null;
  if (!upn && hint.userId) upn = (await env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(hint.userId).first<{ upn: string }>())?.upn ?? null;
  const domain = upn ? domainFromHint(upn) : domainFromHint(hint.domain);
  if (!domain) return def;
  const row = await env.DB.prepare(`SELECT ${BRAND_COLUMNS} FROM domains d JOIN brands b ON b.id = d.brand_id LEFT JOIN brand_assets a ON a.id = b.logo_asset_id WHERE d.domain = ?`)
    .bind(domain)
    .first<BrandRow>();
  return row ? mergeBrand(def, row) : def;
}

/**
 * The branded domain a hostname belongs to: the domain itself or a subdomain
 * of it (login.acme.com -> acme.com), most specific first. The issuer's own
 * hostname never counts: it serves every domain, so a brand attached to the
 * domain it happens to sit under must not become everyone's sign-in page.
 */
export async function brandDomainForHost(env: Env, host: string): Promise<string | null> {
  const h = host.toLowerCase();
  try {
    if (env.ISSUER_URL && new URL(env.ISSUER_URL).hostname.toLowerCase() === h) return null;
  } catch {
    // An unparseable issuer is not ours to judge here.
  }
  const row = await env.DB.prepare(
    "SELECT domain FROM domains WHERE brand_id IS NOT NULL AND (domain = ?1 OR substr(?1, -(length(domain) + 1)) = '.' || domain) ORDER BY length(domain) DESC LIMIT 1"
  )
    .bind(h)
    .first<{ domain: string }>();
  return row?.domain ?? null;
}

// ---------------------------------------------------------------------------
// Logos
// ---------------------------------------------------------------------------

/**
 * The image type from its first bytes - never from a declared Content-Type or
 * file name. "svg" is recognised only to refuse it with a clear message:
 * SVG is a document that can carry script, and most email clients (Gmail,
 * Outlook) do not display it anyway.
 */
export function sniffLogo(bytes: Uint8Array): LogoType | "svg" | null {
  const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length >= 24 && png.every((b, i) => bytes[i] === b) && String.fromCharCode(...bytes.slice(12, 16)) === "IHDR") return "image/png";
  if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  const head = new TextDecoder().decode(bytes.slice(0, 512)).replace(/^\uFEFF/, "").trimStart().toLowerCase();
  if (head.startsWith("<svg") || (head.startsWith("<?xml") && head.includes("<svg")) || (head.startsWith("<!doctype svg"))) return "svg";
  return null;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256HexBytes(bytes: Uint8Array | string): Promise<string> {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Stores a validated logo; returns its id and path. */
export async function insertLogoAsset(env: Env, bytes: Uint8Array, type: LogoType): Promise<{ id: number; url: string }> {
  const sha = await sha256HexBytes(bytes);
  const row = await env.DB.prepare("INSERT INTO brand_assets (content_type, data, sha256, bytes, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id")
    .bind(type, bytesToBase64(bytes), sha, bytes.length, new Date().toISOString())
    .first<{ id: number }>();
  return { id: row!.id, url: logoPath(row!.id, sha, type) };
}

/** Deletes an asset nothing refers to any more (a replaced or removed logo). */
export async function deleteAssetIfUnused(env: Env, id: number | null | undefined): Promise<void> {
  if (!id) return;
  await env.DB.prepare(
    `DELETE FROM brand_assets WHERE id = ?1
       AND NOT EXISTS (SELECT 1 FROM brands WHERE logo_asset_id = ?1)
       AND NOT EXISTS (SELECT 1 FROM idp_settings WHERE key = 'brand_logo_asset_id' AND value = CAST(?1 AS TEXT))`
  )
    .bind(id)
    .run();
}

/** A logo for GET /brand/logo/:file, when the name (id, hash and extension) is exactly the asset's. */
export async function logoForFile(env: Env, file: string): Promise<{ type: LogoType; bytes: Uint8Array } | null> {
  const m = /^(\d{1,12})-([0-9a-f]{16})\.(png|jpg)$/.exec(file);
  if (!m) return null;
  const row = await env.DB.prepare("SELECT content_type, data, sha256 FROM brand_assets WHERE id = ?").bind(Number(m[1])).first<{ content_type: LogoType; data: string; sha256: string }>();
  if (!row || row.sha256.slice(0, 16) !== m[2] || LOGO_EXT[row.content_type] !== m[3]) return null;
  return { type: row.content_type, bytes: base64ToBytes(row.data) };
}

// ---------------------------------------------------------------------------
// Custom CSS
// ---------------------------------------------------------------------------

/** First 16 hex digits of the CSS's SHA-256: its URL, so an edit is never served stale. */
export async function cssHash(css: string): Promise<string> {
  return css ? (await sha256HexBytes(css)).slice(0, 16) : "";
}

/** CSS with comments removed and escapes decoded, lowercased: what a check must look at, since `\\75 rl(` is `url(`. */
function normaliseCss(css: string): string {
  return css
    .replace(/\/\*[\s\S]*?(\*\/|$)/g, " ")
    .replace(/\\([0-9a-fA-F]{1,6})[ \t\r\n\f]?/g, (_, hex: string) => {
      const cp = parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
    })
    .replace(/\\([\s\S])/g, "$1")
    .toLowerCase();
}

/** Whether a url() target is allowed: a same-origin path ("/..." but not "//...") or a data: URL. */
function allowedUrl(target: string): boolean {
  const t = target.trim().replace(/^['"]|['"]$/g, "").trim();
  if (t.startsWith("data:")) return true;
  if (t.startsWith("#")) return true;
  return t.startsWith("/") && !t.startsWith("//") && !t.startsWith("/\\");
}

/**
 * Why a custom stylesheet is refused, or null when it is acceptable. The CSS
 * is served as its own text/css file (never inlined), and the page's CSP
 * already blocks anything remote; these checks refuse what has no business in
 * it, so a mistake is reported when it is saved rather than silently ignored
 * by the browser.
 */
export function customCssProblem(css: string): string | null {
  if (new TextEncoder().encode(css).length > CUSTOM_CSS_MAX_BYTES) return `Custom CSS can be at most ${CUSTOM_CSS_MAX_BYTES / 1024} KB.`;
  if (css.includes("\u0000")) return "Custom CSS cannot contain NUL characters.";
  const plain = normaliseCss(css);
  for (const text of [css.toLowerCase(), plain]) {
    if (/<\s*\/?\s*(style|script)/.test(text)) return "Custom CSS cannot contain <style> or <script> tags: enter the rules only.";
  }
  if (/@import/.test(plain)) return "@import isn't allowed: put the rules in this stylesheet. Remote stylesheets and fonts are blocked by the Content-Security-Policy anyway.";
  if (/expression\s*\(/.test(plain)) return "CSS expression() isn't allowed.";
  if (/(java|vb)script\s*:/.test(plain)) return "javascript: URLs aren't allowed in custom CSS.";
  if (/-moz-binding|behavior\s*:/.test(plain)) return "-moz-binding and behavior aren't allowed in custom CSS.";
  for (const m of plain.matchAll(/url\s*\(\s*([^)]*)\)?/g)) {
    if (!allowedUrl(m[1] ?? "")) return "url() can only point at this site (a path starting with /) or be a data: URL. Images and fonts from other sites are blocked by the Content-Security-Policy.";
  }
  // Bare strings are URLs inside image-set() and @font-face src.
  if (/(['"])\s*(https?:|\/\/|ftp:)/.test(plain)) return "Remote URLs aren't allowed in custom CSS: images and fonts from other sites are blocked by the Content-Security-Policy.";
  return null;
}

/** The stylesheet for GET /brand/css/:file, when the name's brand and hash are current. */
export async function cssForFile(env: Env, file: string): Promise<string | null> {
  const m = /^(default|\d{1,12})-([0-9a-f]{16})\.css$/.exec(file);
  if (!m) return null;
  let css: string | null;
  let hash: string | null;
  if (m[1] === "default") {
    const { results } = await env.DB.prepare("SELECT key, value FROM idp_settings WHERE key IN ('custom_css', 'custom_css_hash')").all<{ key: string; value: string }>();
    css = results.find((r) => r.key === "custom_css")?.value ?? null;
    hash = results.find((r) => r.key === "custom_css_hash")?.value ?? null;
  } else {
    const row = await env.DB.prepare("SELECT custom_css, css_hash FROM brands WHERE id = ?").bind(Number(m[1])).first<{ custom_css: string; css_hash: string }>();
    css = row?.custom_css ?? null;
    hash = row?.css_hash ?? null;
  }
  return css && hash === m[2] ? css : null;
}

/** The default brand's custom CSS, for the editor. */
export async function defaultCustomCss(env: Env): Promise<string> {
  return (await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'custom_css'").first<{ value: string }>())?.value ?? "";
}
