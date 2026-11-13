import { LOCALES, SOURCE_LOCALE } from "../../locales/index.js";
import { escapeHtml } from "./html.js";

/**
 * Translations for the pages people sign in through (sign-in, second step,
 * consent, sign-out, recovery, setup and their error pages).
 *
 * The strings live in locales/<code>.json - en.json is the source, every other
 * file has exactly its keys (test/i18n.test.ts) - and are bundled into the
 * Worker. Messages are plain text with {name} placeholders; keys ending in
 * ".one" / ".other" are the two plural forms tPlural() picks between.
 *
 * t() returns plain text: callers escape it like any other text. tHtml()
 * returns markup - the message escaped, with placeholders filled by escaped
 * values or by trusted markup wrapped in html() - for the few messages that
 * carry emphasis around a value.
 */

export type MessageKey = keyof typeof SOURCE_LOCALE.messages;
export type Locale = string;
export type Vars = Record<string, string | number>;

/** Keys that have a ".one" and ".other" form, without the suffix. */
export type PluralKey = { [K in MessageKey]: K extends `${infer B}.one` ? B : never }[MessageKey];

export const DEFAULT_LOCALE: Locale = "en";
export const SUPPORTED_LOCALES: readonly Locale[] = Object.keys(LOCALES);

const SOURCE: Record<string, string> = SOURCE_LOCALE.messages;

export function isSupportedLocale(code: unknown): boolean {
  return typeof code === "string" && Object.prototype.hasOwnProperty.call(LOCALES, code);
}

export interface LocaleInfo {
  code: Locale;
  name: string;
  nativeName: string;
  dir: "ltr" | "rtl";
  machineAssisted: boolean;
}

export function localeInfo(code: Locale): LocaleInfo {
  const meta = (LOCALES[code] ?? SOURCE_LOCALE)._meta;
  return { code: isSupportedLocale(code) ? code : DEFAULT_LOCALE, name: meta.name, nativeName: meta.nativeName, dir: meta.dir === "rtl" ? "rtl" : "ltr", machineAssisted: Boolean(meta.machineAssisted) };
}

export function allLocales(): LocaleInfo[] {
  return SUPPORTED_LOCALES.map(localeInfo);
}

function lookup(locale: Locale, key: string): string {
  const own = LOCALES[locale]?.messages[key];
  if (typeof own === "string" && own !== "") return own;
  return SOURCE[key] ?? key;
}

function fill(template: string, vars: Record<string, string>): string {
  return template.replace(/\{([A-Za-z0-9_]+)\}/g, (whole, name: string) => (Object.prototype.hasOwnProperty.call(vars, name) ? vars[name]! : whole));
}

/** The message in this locale (English when the locale lacks it), placeholders filled. Plain text: escape it. */
export function t(locale: Locale, key: MessageKey, vars: Vars = {}): string {
  const values: Record<string, string> = {};
  for (const [k, v] of Object.entries(vars)) values[k] = typeof v === "number" ? formatNumber(locale, v) : v;
  return fill(lookup(locale, key), values);
}

/** Trusted markup for a tHtml() placeholder - only ever markup built in this codebase. */
export class Html {
  constructor(readonly html: string) {}
}
export function html(markup: string): Html {
  return new Html(markup);
}

/** The message as HTML: its text escaped, placeholders filled with escaped values or html() markup. */
export function tHtml(locale: Locale, key: MessageKey, vars: Record<string, string | number | Html> = {}): string {
  const values: Record<string, string> = {};
  for (const [k, v] of Object.entries(vars)) values[k] = v instanceof Html ? v.html : escapeHtml(typeof v === "number" ? formatNumber(locale, v) : v);
  return fill(escapeHtml(lookup(locale, key)), values);
}

function pluralForm(locale: Locale, count: number): "one" | "other" {
  try {
    return new Intl.PluralRules(locale).select(count) === "one" ? "one" : "other";
  } catch {
    return count === 1 ? "one" : "other";
  }
}

/** The ".one" or ".other" form for this count, with {count} filled in. */
export function tPlural(locale: Locale, key: PluralKey, count: number, vars: Vars = {}): string {
  return t(locale, `${key}.${pluralForm(locale, count)}` as MessageKey, { count, ...vars });
}

export function formatNumber(locale: Locale, n: number): string {
  try {
    return n.toLocaleString(locale === "en" ? "en-US" : locale);
  } catch {
    return String(n);
  }
}

/** "a, b and c" with the locale's separators. */
export function formatList(locale: Locale, items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(t(locale, "common.listSeparator"))}${t(locale, "common.listFinalSeparator")}${items[items.length - 1]}`;
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

/**
 * The supported locale a language tag asks for: the exact tag, else its
 * primary subtag ("fr-CA" -> "fr"), case-insensitively. Null when none.
 */
export function matchLocale(tag: string | null | undefined): Locale | null {
  if (!tag) return null;
  const clean = tag.trim().toLowerCase().replace(/_/g, "-");
  if (!/^[a-z]{2,8}(-[a-z0-9]{1,8})*$/.test(clean)) return null;
  if (isSupportedLocale(clean)) return clean;
  const primary = clean.split("-")[0]!;
  return isSupportedLocale(primary) ? primary : null;
}

/**
 * The language ranges of an Accept-Language header, most preferred first
 * (q-values, then order); q=0 and "*" are dropped. Bounded: a header is the
 * caller's to make as long as it likes.
 */
export function parseAcceptLanguage(header: string | null | undefined): string[] {
  if (!header) return [];
  const ranges: { tag: string; q: number; i: number }[] = [];
  header
    .slice(0, 1024)
    .split(",")
    .slice(0, 32)
    .forEach((part, i) => {
      const [tag, ...params] = part.trim().split(";");
      if (!tag || tag === "*") return;
      let q = 1;
      for (const p of params) {
        const m = /^\s*q\s*=\s*([0-9.]+)\s*$/i.exec(p);
        if (m) q = Number(m[1]);
      }
      if (!Number.isFinite(q) || q <= 0) return;
      ranges.push({ tag: tag.trim(), q: Math.min(q, 1), i });
    });
  return ranges.sort((a, b) => b.q - a.q || a.i - b.i).map((r) => r.tag);
}

/** The first candidate that names a supported locale, else the fallback. */
export function pickLocale(candidates: (string | null | undefined)[], fallback: Locale = DEFAULT_LOCALE): Locale {
  for (const c of candidates) {
    const m = matchLocale(c);
    if (m) return m;
  }
  return isSupportedLocale(fallback) ? fallback : DEFAULT_LOCALE;
}

/** The first supported locale in an OIDC ui_locales value (space-separated BCP 47 tags, preferred first). */
export function uiLocalesPreference(uiLocales: string | null | undefined): Locale | null {
  if (!uiLocales) return null;
  for (const tag of uiLocales.slice(0, 256).split(/\s+/).slice(0, 16)) {
    const m = matchLocale(tag);
    if (m) return m;
  }
  return null;
}
