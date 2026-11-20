import { DOCS_PAGES } from "./content.generated.js";

/**
 * Which documentation page each admin console page links to from the (?) next
 * to its title. Keyed by the console's section and sub-page, as layout() in
 * routes/admin.ts works them out from the breadcrumbs; a section key alone is
 * the fallback for any of its pages. Values are /docs paths, optionally with a
 * heading anchor - test/docs.test.ts checks every one exists.
 */
export const ADMIN_HELP: Record<string, string> = {
  overview: "/docs/monitoring",
  "overview/performance": "/docs/monitoring#performance",
  users: "/docs/users",
  groups: "/docs/groups",
  "groups/access": "/docs/groups#access-requests-and-reviews",
  applications: "/docs/applications",
  "applications/catalog": "/docs/applications#app-catalog",
  integrations: "/docs",
  "integrations/oidc": "/docs/oidc",
  "integrations/saml": "/docs/saml",
  "integrations/api-keys": "/docs/api#api-keys",
  "integrations/scim": "/docs/scim",
  "integrations/ldap": "/docs/ldap",
  "integrations/federation": "/docs/federation",
  "integrations/email": "/docs/email",
  "integrations/cf-one": "/docs/cloudflare-one",
  "integrations/signals": "/docs/shared-signals",
  domains: "/docs/domains",
  schemas: "/docs/schemas",
  branding: "/docs/branding",
  "branding/brands": "/docs/branding#brands",
  "branding/email-templates": "/docs/email#templates",
  security: "/docs/security",
  "security/policies": "/docs/policies",
  "security/factors": "/docs/policies#second-factors",
  "security/roles": "/docs/roles",
  "security/signing-keys": "/docs/signing-keys",
  audit: "/docs/monitoring#audit-log",
};

/** The guide for a console page - its URL and title - or null when there is none. CSV import pages share one guide. */
export function adminHelp(section: string, sub: string, pageLabel?: string): { href: string; title: string } | null {
  const href = pageLabel === "Import CSV" && (section === "users" || section === "groups") ? "/docs/importing" : (ADMIN_HELP[`${section}/${sub}`] ?? ADMIN_HELP[section]);
  if (!href) return null;
  const slug = href.replace(/^\/docs\/?/, "").split("#")[0] || "index";
  return { href, title: DOCS_PAGES[slug]?.title ?? "Documentation" };
}
