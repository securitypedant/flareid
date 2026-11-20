// The app catalog (catalog/*.json): every entry validates against
// catalog/schema.json, carries the fields its protocol needs, and the
// placeholder machinery in src/lib/catalog.ts resolves deployment facts while
// leaving app-side values visibly marked.
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import schemaJson from "../catalog/schema.json";
import templateJson from "../catalog/_template.json";
import {
  getCatalogEntry,
  idpPlaceholders,
  listCatalog,
  placeholdersIn,
  renderInstructions,
  substitutePlaceholders,
  templateToClientInput,
  templateToSpInput,
} from "../src/lib/catalog.js";
import { CLAIM_GROUPS } from "../src/lib/oidc.js";
import { USER_ATTRIBUTE_FIELDS } from "../src/lib/saml/attributes.js";

beforeEach(resetDatabase);

// ---------------------------------------------------------------------------
// A JSON Schema subset validator: the keywords catalog/schema.json uses
// (type, enum, const, required, properties, additionalProperties, items,
// minItems, minLength, minProperties, pattern, allOf, if/then/else). There is
// no ajv in the dependency tree, and adding one to check ten small files is
// not worth it.
// ---------------------------------------------------------------------------

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function validate(node: unknown, schema: unknown, path: string, errors: string[]): void {
  if (typeof schema !== "object" || schema === null) return;
  const s = schema as Record<string, unknown>;

  if (Array.isArray(s.enum) && !(s.enum as unknown[]).includes(node)) {
    errors.push(`${path}: ${JSON.stringify(node)} not in enum ${JSON.stringify(s.enum)}`);
  }
  if ("const" in s && node !== s.const) errors.push(`${path}: !== const ${JSON.stringify(s.const)}`);
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? (s.type as string[]) : [s.type as string];
    if (!types.includes(typeOf(node))) {
      errors.push(`${path}: type ${typeOf(node)}, want ${types.join(" | ")}`);
      return;
    }
  }

  if (typeof node === "string") {
    if (typeof s.minLength === "number" && node.length < s.minLength) errors.push(`${path}: shorter than minLength ${s.minLength}`);
    if (typeof s.pattern === "string" && !new RegExp(s.pattern).test(node)) errors.push(`${path}: ${JSON.stringify(node)} fails pattern ${s.pattern}`);
  }

  if (Array.isArray(node)) {
    if (typeof s.minItems === "number" && node.length < s.minItems) errors.push(`${path}: fewer than minItems ${s.minItems}`);
    if (s.items && typeof s.items === "object") node.forEach((item, i) => validate(item, s.items, `${path}[${i}]`, errors));
  }

  if (node !== null && typeof node === "object" && !Array.isArray(node)) {
    const obj = node as Record<string, unknown>;
    if (Array.isArray(s.required)) {
      for (const k of s.required as string[]) if (!(k in obj)) errors.push(`${path}: missing required "${k}"`);
    }
    if (typeof s.minProperties === "number" && Object.keys(obj).length < s.minProperties) {
      errors.push(`${path}: fewer than minProperties ${s.minProperties}`);
    }
    const props = (s.properties ?? {}) as Record<string, unknown>;
    for (const [k, sub] of Object.entries(props)) {
      if (k in obj) validate(obj[k], sub, `${path}.${k}`, errors);
    }
    if (s.additionalProperties === false) {
      for (const k of Object.keys(obj)) if (!(k in props)) errors.push(`${path}: unexpected key "${k}"`);
    } else if (s.additionalProperties && typeof s.additionalProperties === "object") {
      for (const [k, v] of Object.entries(obj)) if (!(k in props)) validate(v, s.additionalProperties, `${path}.${k}`, errors);
    }
  }

  if (Array.isArray(s.allOf)) for (const sub of s.allOf) validate(node, sub, path, errors);

  if (s.if && typeof s.if === "object") {
    const probe: string[] = [];
    validate(node, s.if, path, probe);
    const branch = probe.length === 0 ? s.then : s.else;
    if (branch && typeof branch === "object") validate(node, branch, path, errors);
  }
}

const EXPECTED_SLUGS = [
  "atlassian-cloud",
  "aws-sso",
  "cloudflare-access",
  "github-enterprise",
  "gitlab",
  "google-workspace",
  "grafana",
  "salesforce",
  "slack",
  "zoom",
];

const entries = listCatalog();
const KNOWN_IDP_PLACEHOLDERS = new Set(Object.keys(idpPlaceholders("https://idp.example")));

describe("app catalog", () => {
  it("ships the ten expected apps, on unique slugs", () => {
    const slugs = entries.map((e) => e.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
    expect([...slugs].sort()).toEqual([...EXPECTED_SLUGS].sort());
  });

  it("is listed by display name", () => {
    const names = entries.map((e) => e.name);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
  });

  const cases: [string, unknown][] = [...entries.map((e): [string, unknown] => [`${e.slug}.json`, e]), ["_template.json", templateJson]];
  for (const [label, entry] of cases) {
    it(`validates ${label} against catalog/schema.json`, () => {
      const errors: string[] = [];
      validate(entry, schemaJson, label, errors);
      expect(errors).toEqual([]);
    });
  }

  for (const entry of entries) {
    describe(entry.slug, () => {
      if (entry.protocol === "saml") {
        it("has the SAML fields the SP form needs", () => {
          expect(entry.saml).toBeTruthy();
          const s = entry.saml!;
          expect(s.entity_id.length).toBeGreaterThan(0);
          expect(s.acs_urls.length).toBeGreaterThanOrEqual(1);
          expect(["transient", "emailAddress", "persistent", "none"]).toContain(s.nameid_format);
          // The console rejects attribute fields outside this vocabulary, so
          // a template must stay inside it (or the applied value would fail
          // validation on save).
          for (const def of s.attribute_definitions) {
            expect(USER_ATTRIBUTE_FIELDS, `attribute "${def.name}" uses unknown field "${def.field}"`).toContain(def.field);
          }
        });
      } else {
        it("has the OIDC fields the client form needs", () => {
          expect(entry.oidc).toBeTruthy();
          const o = entry.oidc!;
          expect(o.redirect_uris.length).toBeGreaterThanOrEqual(1);
          expect(o.redirect_uris.every((u) => u.startsWith("https://"))).toBe(true);
          expect(o.grant_types).toContain("authorization_code");
          for (const claim of o.claims) {
            expect(CLAIM_GROUPS as readonly string[], `unknown claim group "${claim}"`).toContain(claim);
          }
        });
      }

      it("only uses {idp_*} placeholders the renderer knows", () => {
        const steps = [...entry.instructions.app, ...entry.instructions.flareid];
        for (const step of steps) {
          for (const name of placeholdersIn(step)) {
            if (name.startsWith("idp_")) expect(KNOWN_IDP_PLACEHOLDERS, `${entry.slug}: unknown {${name}}`).toContain(name);
          }
        }
      });
    });
  }
});

describe("renderInstructions", () => {
  const slack = getCatalogEntry("slack")!;
  const grafana = getCatalogEntry("grafana")!;

  it("resolves {idp_*} placeholders from the issuer", () => {
    const r = renderInstructions(slack, { issuer: "https://idp.example" });
    const app = r.app.join("\n");
    expect(app).toContain("https://idp.example/saml/sso");
    expect(app).toContain("https://idp.example/saml/cert.pem");
    expect(app).not.toContain("{idp_");
  });

  it("leaves app-side placeholders visibly marked and reports them", () => {
    const r = renderInstructions(slack, { issuer: "https://idp.example" });
    expect(r.app.join("\n")).toContain("{team}");
    expect(r.placeholders).toContain("team");
    expect(r.placeholders.some((p) => p.startsWith("idp_"))).toBe(false);
  });

  it("keeps {client_id}/{client_secret} marked for OIDC apps", () => {
    const r = renderInstructions(grafana, { issuer: "https://idp.example" });
    expect(r.placeholders).toEqual(expect.arrayContaining(["client_id", "client_secret", "host"]));
  });

  it("fills app-side values given in the context", () => {
    const r = renderInstructions(slack, { issuer: "https://idp.example", values: { team: "acme" } });
    expect(r.app.join("\n")).toContain("https://acme.slack.com/admin");
    expect(r.placeholders).not.toContain("team");
  });

  it("leaves {idp_*} marked when no issuer is known", () => {
    const r = renderInstructions(slack, {});
    expect(r.app.join("\n")).toContain("{idp_sso_url}");
    expect(r.placeholders).toContain("idp_sso_url");
  });

  it("substitutes only what it knows in a bare string", () => {
    const r = substitutePlaceholders("a {one} b {two}", { one: "1" });
    expect(r.text).toBe("a 1 b {two}");
    expect(r.missing).toEqual(["two"]);
  });
});

describe("templateToSpInput", () => {
  it("produces the SP form's field values", () => {
    const sp = templateToSpInput(getCatalogEntry("slack")!)!;
    expect(sp.name).toBe("Slack");
    expect(sp.entity_id).toBe("https://slack.com");
    expect(sp.acs_urls).toBe("https://{team}.slack.com/sso/saml");
    expect(sp.nameid_format).toBe("emailAddress");
    expect(sp.sign_response).toBe(true);
    expect(sp.sign_assertion).toBe(true);
    expect(sp.want_authn_requests_signed).toBe(false);
    expect(sp.encrypt_assertions).toBe(false);
    const defs = JSON.parse(sp.attribute_definitions) as { name: string; field: string }[];
    expect(defs.map((d) => d.name)).toEqual(["email", "first_name", "last_name"]);
    // Empty attribute_map stays an empty textarea, not "null" or "{}".
    expect(sp.attribute_map).toBe("");
  });

  it("substitutes supplied app-side values", () => {
    const sp = templateToSpInput(getCatalogEntry("slack")!, { team: "acme" })!;
    expect(sp.acs_urls).toBe("https://acme.slack.com/sso/saml");
  });

  it("returns null for OIDC entries", () => {
    expect(templateToSpInput(getCatalogEntry("grafana")!)).toBeNull();
  });
});

describe("templateToClientInput", () => {
  it("produces the client form's field values", () => {
    const cl = templateToClientInput(getCatalogEntry("grafana")!)!;
    expect(cl.name).toBe("Grafana");
    expect(cl.redirect_uris).toBe("https://{host}/login/generic_oauth");
    expect(cl.client_type).toBe("confidential");
    expect(cl.trusted).toBe(false);
    expect(cl.allowed_claims).toEqual(["email", "profile", "groups"]);
    expect(cl.grant_types).toContain("authorization_code");
  });

  it("substitutes supplied app-side values", () => {
    const cl = templateToClientInput(getCatalogEntry("cloudflare-access")!, { team: "acme" })!;
    expect(cl.redirect_uris).toBe("https://acme.cloudflareaccess.com/cdn-cgi/access/callback");
  });

  it("returns null for SAML entries", () => {
    expect(templateToClientInput(getCatalogEntry("slack")!)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The catalog API: browse + apply through the same service path as the
// console's apply wizard (services/apps.ts applyCatalogEntry).
// ---------------------------------------------------------------------------

describe("catalog API", () => {
  it("lists and describes entries for a read-scoped token", async () => {
    const { apiKey } = await bootstrapInstance();
    const list = await apiCall("/api/v1/app-catalog", { token: apiKey });
    expect(list.status).toBe(200);
    expect((list.body.entries as unknown[]).length).toBeGreaterThanOrEqual(10);
    const slack = (list.body.entries as { slug: string; placeholders: string[] }[]).find((e) => e.slug === "slack")!;
    expect(slack.placeholders).toContain("team");

    const detail = await apiCall("/api/v1/app-catalog/slack", { token: apiKey });
    expect(detail.status).toBe(200);
    // IdP-side facts are rendered in; app-side placeholders stay braced.
    expect(detail.body.instructions.flareid.join("\n")).toContain("http");
    expect(detail.body.saml.entity_id).toBeDefined();
    expect(await apiCall("/api/v1/app-catalog/nope", { token: apiKey })).toMatchObject({ status: 404 });
  });

  it("applies a SAML entry into a service provider", async () => {
    const { apiKey } = await bootstrapInstance();
    const res = await apiCall("/api/v1/app-catalog/slack/apply", { token: apiKey, body: { values: { team: "acme" } } });
    expect(res.status).toBe(201);
    expect(res.body.protocol).toBe("saml");
    const sp = await env.DB.prepare("SELECT * FROM saml_service_providers WHERE id = ?").bind(res.body.id).first<{ entity_id: string; acs_urls: string; logo_uri: string }>();
    expect(sp!.entity_id).toBe("https://slack.com");
    expect(JSON.parse(sp!.acs_urls)).toEqual(["https://acme.slack.com/sso/saml"]);
    expect(sp!.logo_uri).toContain("/catalog-icons/slack.svg");
  });

  it("applies an OIDC entry and returns the once-only secret", async () => {
    const { apiKey } = await bootstrapInstance();
    const res = await apiCall("/api/v1/app-catalog/cloudflare-access/apply", { token: apiKey, body: { values: { team: "acme" } } });
    expect(res.status).toBe(201);
    expect(res.body.protocol).toBe("oidc");
    expect(res.body.client_id).toMatch(/^flareid_/);
    expect(res.body.client_secret.length).toBeGreaterThanOrEqual(24);
    // And once only: the client read never carries it.
    const cl = await apiCall(`/api/v1/clients/${res.body.client_id}`, { token: apiKey });
    expect(cl.body.client_secret).toBeUndefined();
  });

  it("requires values for every placeholder", async () => {
    const { apiKey } = await bootstrapInstance();
    const res = await apiCall("/api/v1/app-catalog/slack/apply", { token: apiKey, body: { values: {} } });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain("team");
  });

  it("gates reads and writes on the protocol's scope", async () => {
    const { apiKey } = await bootstrapInstance();
    // A users-only key can neither browse nor apply.
    const usersKey = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "users", scopes: ["users:read"] } });
    expect((await apiCall("/api/v1/app-catalog", { token: usersKey.body.token })).status).toBe(403);
    expect((await apiCall("/api/v1/app-catalog/slack/apply", { token: usersKey.body.token, body: { values: { team: "x" } } })).status).toBe(403);
    // An oidc:write key passes the gate but cannot apply a SAML entry.
    const oidcKey = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "oidc", scopes: ["oidc:write"] } });
    expect((await apiCall("/api/v1/app-catalog", { token: oidcKey.body.token })).status).toBe(200);
    expect((await apiCall("/api/v1/app-catalog/slack/apply", { token: oidcKey.body.token, body: { values: { team: "x" } } })).status).toBe(403);
  });
});
