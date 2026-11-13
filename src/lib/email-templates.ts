import type { Env } from "../env.js";
import type { Brand } from "./brands.js";
import { getSetting, setSetting } from "./settings.js";

/**
 * Editable email templates (Admin -> Branding -> Email templates). Each
 * template is a few plain-text fields with {{placeholders}}; the layout is
 * FlareID's own, so an edit can change the words and the accent colour but
 * never produce broken or unescaped HTML.
 */

export type TemplateKey = "invitation" | "password_reset" | "email_otp";

export interface EmailTemplate {
  subject: string;
  heading: string;
  body: string;
  /** Button label, for templates with a link. */
  action: string;
  footer: string;
}

export const TEMPLATE_INFO: Record<TemplateKey, { label: string; placeholders: string[]; hasLink: boolean }> = {
  invitation: { label: "Invitation", placeholders: ["app_name", "name"], hasLink: true },
  password_reset: { label: "Password reset", placeholders: ["app_name", "name"], hasLink: true },
  email_otp: { label: "Sign-in code", placeholders: ["app_name", "name", "code", "minutes"], hasLink: false },
};

export const DEFAULT_TEMPLATES: Record<TemplateKey, EmailTemplate> = {
  invitation: {
    subject: "You've been invited to {{app_name}}",
    heading: "Welcome, {{name}}",
    body: "An administrator has set up a {{app_name}} account for you. Choose a password to activate it. The link works once, for the next 7 days.",
    action: "Activate your account",
    footer: "If you weren't expecting this, you can ignore this email.",
  },
  password_reset: {
    subject: "Reset your {{app_name}} password",
    heading: "Reset your password",
    body: "Someone - hopefully you - asked to reset the password for your {{app_name}} account. The link works once, for the next hour.",
    action: "Choose a new password",
    footer: "If you didn't ask for this, ignore this email: your password stays the same.",
  },
  email_otp: {
    subject: "Your {{app_name}} sign-in code: {{code}}",
    heading: "Your sign-in code",
    body: "Enter this code to finish signing in to {{app_name}}. It works once, for the next {{minutes}} minutes.",
    action: "",
    footer: "If you didn't try to sign in, change your password: someone else knows it.",
  },
};

export const DEFAULT_ACCENT = "#f6821f";
const LIMITS: Record<keyof EmailTemplate, number> = { subject: 150, heading: 150, body: 1500, action: 60, footer: 500 };

export async function getTemplate(env: Env, key: TemplateKey): Promise<EmailTemplate> {
  const raw = await getSetting(env, `email_template_${key}`);
  if (!raw) return DEFAULT_TEMPLATES[key];
  try {
    return { ...DEFAULT_TEMPLATES[key], ...(JSON.parse(raw) as Partial<EmailTemplate>) };
  } catch {
    return DEFAULT_TEMPLATES[key];
  }
}

export async function setTemplate(env: Env, key: TemplateKey, t: Partial<EmailTemplate> | null): Promise<void> {
  if (t === null) return setSetting(env, `email_template_${key}`, "");
  const clean = Object.fromEntries(
    (Object.keys(LIMITS) as (keyof EmailTemplate)[]).map((f) => [f, String(t[f] ?? DEFAULT_TEMPLATES[key][f]).replace(/\r/g, "").slice(0, LIMITS[f])])
  ) as unknown as EmailTemplate;
  if (!clean.subject.trim() || !clean.heading.trim()) throw new Error("Subject and heading cannot be empty.");
  await setSetting(env, `email_template_${key}`, JSON.stringify(clean));
}

export async function getAccent(env: Env): Promise<string> {
  const v = await getSetting(env, "email_accent");
  return v && /^#[0-9a-f]{6}$/i.test(v) ? v : DEFAULT_ACCENT;
}
export async function setAccent(env: Env, v: string): Promise<void> {
  if (!/^#[0-9a-f]{6}$/i.test(v)) throw new Error("The accent colour must be a hex colour like #f6821f.");
  await setSetting(env, "email_accent", v.toLowerCase());
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const fill = (s: string, vars: Record<string, string>) => s.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (m, k: string) => (k in vars ? vars[k]! : m));

/**
 * Renders a template: placeholders filled, then laid out as text and escaped
 * HTML. `logoUrl` is an absolute https URL of the brand's uploaded logo, shown
 * above the name (email clients need an absolute URL; FlareID's own mark is
 * not sent, so an unbranded email loads no image).
 */
export function renderEmail(t: EmailTemplate, accent: string, vars: Record<string, string>, link?: string, logoUrl?: string | null): { subject: string; text: string; html: string } {
  const f = Object.fromEntries(Object.entries(t).map(([k, v]) => [k, fill(v, vars)])) as unknown as EmailTemplate;
  const code = vars.code;
  const paragraphs = f.body.split(/\n{2,}/).map((p) => `<p style="margin:0 0 16px;line-height:1.5;color:#334155;">${esc(p).replace(/\n/g, "<br />")}</p>`).join("");
  const text = [f.heading, "", f.body, "", ...(code ? [code, ""] : []), ...(link ? [`${f.action}: ${link}`, ""] : []), f.footer, ""].join("\n");
  const html = `<!doctype html><html><body style="margin:0;padding:24px;background:#f6f7f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:28px;border-top:4px solid ${accent};">
    ${logoUrl ? `<img src="${esc(logoUrl)}" alt="" height="40" style="display:block;height:40px;width:auto;max-width:200px;margin:0 0 12px;border:0;" />` : ""}
    <p style="margin:0 0 16px;font-weight:700;font-size:18px;color:#0f172a;">${esc(vars.app_name ?? "")}</p>
    <h1 style="margin:0 0 12px;font-size:22px;line-height:1.3;font-weight:700;color:#0f172a;">${esc(f.heading)}</h1>
    ${paragraphs}
    ${code ? `<p style="margin:0 0 20px;font-size:30px;letter-spacing:6px;font-weight:700;font-family:ui-monospace,Menlo,monospace;color:#0f172a;">${esc(code)}</p>` : ""}
    ${
      link
        ? `<p style="margin:0 0 20px;"><a href="${esc(link)}" style="display:inline-block;background:${accent};color:#fff;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:8px;">${esc(f.action)}</a></p>
    <p style="margin:0 0 6px;font-size:13px;color:#64748b;">Or paste this link into your browser:</p>
    <p style="margin:0 0 20px;font-size:13px;word-break:break-all;"><a href="${esc(link)}" style="color:${accent};">${esc(link)}</a></p>`
        : ""
    }
    <p style="margin:0;font-size:13px;color:#64748b;">${esc(f.footer)}</p>
  </div></body></html>`;
  return { subject: f.subject.replace(/\n/g, " "), text, html };
}

/** The email for a person, in their brand (brandFor in brands.ts): its name as {{app_name}}, its accent and logo. */
export async function buildEmail(env: Env, key: TemplateKey, brand: Brand, vars: Record<string, string>, link?: string) {
  return renderEmail(await getTemplate(env, key), brand.accent, { ...vars, app_name: brand.appName }, link, emailLogoUrl(env, brand));
}

/** The absolute logo URL email needs: the brand's upload under an https issuer, else none. */
export function emailLogoUrl(env: Env, brand: Pick<Brand, "logoUrl">): string | null {
  return brand.logoUrl && env.ISSUER_URL.startsWith("https://") ? `${env.ISSUER_URL.replace(/\/$/, "")}${brand.logoUrl}` : null;
}
