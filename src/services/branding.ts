import {
  APP_NAME_MAX,
  BRAND_NAME_MAX,
  CUSTOM_CSS_MAX_BYTES,
  DEFAULT_BRAND_NAME,
  LOGO_MAX_BYTES,
  SUBTITLE_MAX,
  cssHash,
  customCssProblem,
  deleteAssetIfUnused,
  getBrandRow,
  insertLogoAsset,
  sniffLogo,
  type BrandRow,
} from "../lib/brands.js";
import { getSetting, isHexColor, setSetting } from "../lib/settings.js";
import { audit, ServiceError, type ServiceCtx } from "./context.js";

/**
 * Brands, logos and custom CSS (brands.ts) for the console's Branding and
 * Domains pages and their API twins. Inputs are `unknown` because a form and
 * a JSON body arrive differently; both end up validated here, before anything
 * is written.
 */

/** A brand's fields as given; a field left out keeps its value. null (or "") means "use the default brand's". */
export interface BrandInput {
  name?: unknown;
  app_name?: unknown;
  login_subtitle?: unknown;
  login_gradient?: { from?: unknown; to?: unknown } | null;
  email_accent?: unknown;
  custom_css?: unknown;
  /** Replaces the set of domains using this brand. */
  domains?: unknown;
}

interface CleanBrand {
  name?: string;
  app_name?: string;
  login_subtitle?: string | null;
  gradient?: { from: string; to: string } | null;
  email_accent?: string | null;
  custom_css?: string;
  domains?: string[];
}

function cleanName(v: unknown): string {
  const name = String(v ?? "").trim().replace(/\s+/g, " ");
  if (!name) throw new ServiceError(400, "A brand needs a name.");
  if (name.length > BRAND_NAME_MAX) throw new ServiceError(400, `A brand name can be at most ${BRAND_NAME_MAX} characters.`);
  if (name.toLowerCase() === DEFAULT_BRAND_NAME.toLowerCase()) throw new ServiceError(400, `"${DEFAULT_BRAND_NAME}" is the name of the default brand.`);
  return name;
}

/** CSS checked against the sanitiser; a refusal says why. */
export function cleanCustomCss(v: unknown): string {
  if (typeof v !== "string") throw new ServiceError(400, "custom_css must be a string.");
  const css = v.replace(/\r\n?/g, "\n").trim();
  const problem = customCssProblem(css);
  if (problem) throw new ServiceError(400, problem);
  return css;
}

async function validate(ctx: ServiceCtx, input: BrandInput, creating: boolean): Promise<CleanBrand> {
  const out: CleanBrand = {};
  if (creating || input.name !== undefined) out.name = cleanName(input.name);
  if (input.app_name !== undefined) {
    const v = input.app_name === null ? "" : String(input.app_name).trim();
    if (v.length > APP_NAME_MAX) throw new ServiceError(400, `The app name can be at most ${APP_NAME_MAX} characters.`);
    out.app_name = v;
  }
  if (input.login_subtitle !== undefined) {
    const v = input.login_subtitle === null ? null : String(input.login_subtitle).trim();
    if (v !== null && v.length > SUBTITLE_MAX) throw new ServiceError(400, `The sign-in message can be at most ${SUBTITLE_MAX} characters.`);
    out.login_subtitle = v;
  }
  if (input.login_gradient !== undefined) {
    const g = input.login_gradient;
    if (g === null) out.gradient = null;
    else if (!isHexColor(g.from) || !isHexColor(g.to)) throw new ServiceError(400, "The gradient colours must both be #rrggbb hex values.");
    else out.gradient = { from: g.from.toLowerCase(), to: g.to.toLowerCase() };
  }
  if (input.email_accent !== undefined) {
    const v = input.email_accent === null || input.email_accent === "" ? null : input.email_accent;
    if (v !== null && !isHexColor(v)) throw new ServiceError(400, "The email accent must be a #rrggbb hex colour.");
    out.email_accent = v === null ? null : v.toLowerCase();
  }
  if (input.custom_css !== undefined) out.custom_css = input.custom_css === null ? "" : cleanCustomCss(input.custom_css);
  if (input.domains !== undefined) {
    if (!Array.isArray(input.domains)) throw new ServiceError(400, "domains must be a list of domain names.");
    const wanted = [...new Set(input.domains.map((d) => String(d).trim().toLowerCase()).filter(Boolean))];
    const { results } = await ctx.env.DB.prepare("SELECT domain FROM domains WHERE domain IN (SELECT value FROM json_each(?))").bind(JSON.stringify(wanted)).all<{ domain: string }>();
    const unknown = wanted.filter((d) => !results.some((r) => r.domain === d));
    if (unknown.length) throw new ServiceError(400, `No such domain(s): ${unknown.join(", ")}.`);
    out.domains = wanted;
  }
  return out;
}

/** Brand names are unique, ignoring case. */
async function assertNameFree(ctx: ServiceCtx, name: string | undefined, exceptId?: number): Promise<void> {
  if (!name) return;
  const clash = await ctx.env.DB.prepare("SELECT id FROM brands WHERE name = ? COLLATE NOCASE").bind(name).first<{ id: number }>();
  if (clash && clash.id !== exceptId) throw new ServiceError(409, "A brand with that name already exists.");
}

async function writeDomains(ctx: ServiceCtx, brandId: number, domains: string[]): Promise<void> {
  await ctx.env.DB.batch([
    ctx.env.DB.prepare("UPDATE domains SET brand_id = NULL WHERE brand_id = ? AND domain NOT IN (SELECT value FROM json_each(?))").bind(brandId, JSON.stringify(domains)),
    ctx.env.DB.prepare("UPDATE domains SET brand_id = ? WHERE domain IN (SELECT value FROM json_each(?))").bind(brandId, JSON.stringify(domains)),
  ]);
}

async function requireBrand(ctx: ServiceCtx, id: number): Promise<BrandRow> {
  const row = await getBrandRow(ctx.env, id);
  if (!row) throw new ServiceError(404, "No such brand.");
  return row;
}

export async function createBrand(ctx: ServiceCtx, input: BrandInput): Promise<BrandRow> {
  const clean = await validate(ctx, input, true);
  await assertNameFree(ctx, clean.name);
  const now = new Date().toISOString();
  const css = clean.custom_css ?? "";
  const row = await ctx.env.DB.prepare(
    `INSERT INTO brands (name, app_name, login_subtitle, gradient_from, gradient_to, email_accent, custom_css, css_hash, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
  )
    .bind(clean.name!, clean.app_name ?? "", clean.login_subtitle ?? null, clean.gradient?.from ?? null, clean.gradient?.to ?? null, clean.email_accent ?? null, css, await cssHash(css), now, now)
    .first<{ id: number }>();
  if (clean.domains) await writeDomains(ctx, row!.id, clean.domains);
  await audit(ctx, "brand.created", clean.name, { id: row!.id, ...(clean.domains ? { domains: clean.domains } : {}) });
  return (await getBrandRow(ctx.env, row!.id))!;
}

export async function updateBrand(ctx: ServiceCtx, id: number, input: BrandInput): Promise<BrandRow> {
  const current = await requireBrand(ctx, id);
  const clean = await validate(ctx, input, false);
  await assertNameFree(ctx, clean.name, id);
  const sets: string[] = [];
  const binds: unknown[] = [];
  const set = (col: string, v: unknown) => {
    sets.push(`${col} = ?`);
    binds.push(v);
  };
  if (clean.name !== undefined) set("name", clean.name);
  if (clean.app_name !== undefined) set("app_name", clean.app_name);
  if (clean.login_subtitle !== undefined) set("login_subtitle", clean.login_subtitle);
  if (clean.gradient !== undefined) {
    set("gradient_from", clean.gradient?.from ?? null);
    set("gradient_to", clean.gradient?.to ?? null);
  }
  if (clean.email_accent !== undefined) set("email_accent", clean.email_accent);
  if (clean.custom_css !== undefined) {
    set("custom_css", clean.custom_css);
    set("css_hash", await cssHash(clean.custom_css));
  }
  set("updated_at", new Date().toISOString());
  await ctx.env.DB.prepare(`UPDATE brands SET ${sets.join(", ")} WHERE id = ?`).bind(...binds, id).run();
  if (clean.domains) await writeDomains(ctx, id, clean.domains);
  const changed = Object.keys(clean);
  await audit(ctx, "brand.updated", clean.name ?? current.name, { id, changed, ...(clean.domains ? { domains: clean.domains } : {}) });
  return (await getBrandRow(ctx.env, id))!;
}

/** Deletes a brand: its domains go back to the default brand, and its logo is deleted. */
export async function deleteBrand(ctx: ServiceCtx, id: number): Promise<void> {
  const row = await requireBrand(ctx, id);
  await ctx.env.DB.batch([ctx.env.DB.prepare("UPDATE domains SET brand_id = NULL WHERE brand_id = ?").bind(id), ctx.env.DB.prepare("DELETE FROM brands WHERE id = ?").bind(id)]);
  await deleteAssetIfUnused(ctx.env, row.logo_asset_id);
  await audit(ctx, "brand.deleted", row.name, { id });
}

/** Sets which brand a domain's people see; null is the default brand. */
export async function assignDomainBrand(ctx: ServiceCtx, domain: string, brandId: number | null): Promise<void> {
  const d = await ctx.env.DB.prepare("SELECT id, domain FROM domains WHERE domain = ?").bind(domain.trim().toLowerCase()).first<{ id: number; domain: string }>();
  if (!d) throw new ServiceError(404, `No such domain "${domain}".`);
  const brand = brandId === null ? null : await requireBrand(ctx, brandId);
  await ctx.env.DB.prepare("UPDATE domains SET brand_id = ? WHERE id = ?").bind(brand?.id ?? null, d.id).run();
  await audit(ctx, "domain.brand_changed", d.domain, { brand: brand?.name ?? DEFAULT_BRAND_NAME, brand_id: brand?.id ?? null });
}

/** The default brand's custom CSS (Branding > Settings). Empty removes it. */
export async function saveDefaultCustomCss(ctx: ServiceCtx, css: unknown): Promise<void> {
  const clean = css === null ? "" : cleanCustomCss(css);
  await setSetting(ctx.env, "custom_css", clean);
  await setSetting(ctx.env, "custom_css_hash", await cssHash(clean));
  await audit(ctx, "branding.custom_css_changed", DEFAULT_BRAND_NAME, { bytes: new TextEncoder().encode(clean).length });
}

/**
 * Validates an uploaded logo by its bytes: PNG or JPEG, at most 256 KB. SVG is
 * refused - it is a document that can run script, and most email clients
 * would not show it anyway.
 */
export function validateLogo(bytes: Uint8Array): "image/png" | "image/jpeg" {
  if (bytes.length === 0) throw new ServiceError(400, "Choose an image file to upload.");
  if (bytes.length > LOGO_MAX_BYTES) throw new ServiceError(400, `That image is ${Math.ceil(bytes.length / 1024)} KB: a logo can be at most ${LOGO_MAX_BYTES / 1024} KB.`);
  const type = sniffLogo(bytes);
  if (type === "svg") throw new ServiceError(400, "SVG logos aren't accepted: an SVG can carry script, and most email clients don't display SVG. Upload a PNG or JPEG.");
  if (!type) throw new ServiceError(400, "That file isn't a PNG or JPEG image.");
  return type;
}

/** Uploads a logo for a brand (null: the default brand), replacing - and deleting - the previous one. Returns its path. */
export async function uploadLogo(ctx: ServiceCtx, brandId: number | null, bytes: Uint8Array): Promise<string> {
  const type = validateLogo(bytes);
  const brand = brandId === null ? null : await requireBrand(ctx, brandId);
  const previous = brand ? brand.logo_asset_id : Number(await getSetting(ctx.env, "brand_logo_asset_id")) || null;
  const asset = await insertLogoAsset(ctx.env, bytes, type);
  if (brand) await ctx.env.DB.prepare("UPDATE brands SET logo_asset_id = ?, updated_at = ? WHERE id = ?").bind(asset.id, new Date().toISOString(), brand.id).run();
  else await setSetting(ctx.env, "brand_logo_asset_id", String(asset.id));
  await deleteAssetIfUnused(ctx.env, previous);
  await audit(ctx, "branding.logo_changed", brand?.name ?? DEFAULT_BRAND_NAME, { type, bytes: bytes.length });
  return asset.url;
}

/** Removes a brand's logo: the default brand goes back to FlareID's mark, another brand to the default brand's logo. */
export async function removeLogo(ctx: ServiceCtx, brandId: number | null): Promise<void> {
  const brand = brandId === null ? null : await requireBrand(ctx, brandId);
  const previous = brand ? brand.logo_asset_id : Number(await getSetting(ctx.env, "brand_logo_asset_id")) || null;
  if (brand) await ctx.env.DB.prepare("UPDATE brands SET logo_asset_id = NULL, updated_at = ? WHERE id = ?").bind(new Date().toISOString(), brand.id).run();
  else await setSetting(ctx.env, "brand_logo_asset_id", "");
  await deleteAssetIfUnused(ctx.env, previous);
  await audit(ctx, "branding.logo_removed", brand?.name ?? DEFAULT_BRAND_NAME);
}

export { CUSTOM_CSS_MAX_BYTES, LOGO_MAX_BYTES };
