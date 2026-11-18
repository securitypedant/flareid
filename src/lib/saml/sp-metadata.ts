import { DOMParser, type Element as XmlElement } from "@xmldom/xmldom";
import { normalizeCertPem } from "./x509.js";
import { logAudit } from "../audit.js";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const MAX_METADATA_BYTES = 256 * 1024;

export class SpMetadataError extends Error {}

export interface ParsedSpMetadata {
  entityId: string;
  acsUrls: string[];
  defaultAcsUrl: string | null;
  signingCerts: string[];
  encryptionCert: string | null;
  sloUrl: string | null;
  nameIdFormat: "transient" | "persistent" | "emailAddress" | null;
  wantAuthnRequestsSigned: boolean;
  /** From the subject-id:req entity attribute: which subject identifier the SP wants. */
  subjectId: "subject-id" | "pairwise-id" | null;
  /** The metadata's own validUntil, if any (ISO). */
  validUntil: string | null;
}

const NS_MDATTR = "urn:oasis:names:tc:SAML:metadata:attribute";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUBJECT_ID_REQ = "urn:oasis:names:tc:SAML:profiles:subject-id:req";

/**
 * Reads an SP's <md:EntityDescriptor> into the fields FlareID's SP registry
 * stores. Metadata is configuration an administrator pasted in, not a signed
 * message, so it is parsed but not signature-checked - the administrator is
 * the trust decision. DOCTYPE/entities are refused, and the size is capped.
 */
export function parseSpMetadata(xml: string): ParsedSpMetadata {
  if (xml.length > MAX_METADATA_BYTES) throw new SpMetadataError("Metadata is larger than 256 KB.");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new SpMetadataError("Metadata must not contain a DOCTYPE or entity declarations.");
  let doc: ReturnType<DOMParser["parseFromString"]>;
  try {
    doc = new DOMParser().parseFromString(xml, "text/xml");
  } catch {
    throw new SpMetadataError("Metadata is not well-formed XML.");
  }
  const root = doc.documentElement;
  const entity =
    root?.localName === "EntityDescriptor" && root.namespaceURI === NS_MD ? root : (root?.getElementsByTagNameNS(NS_MD, "EntityDescriptor")[0] ?? null);
  if (!entity) throw new SpMetadataError("No md:EntityDescriptor found.");
  const entityId = entity.getAttribute("entityID")?.trim() ?? "";
  if (!entityId) throw new SpMetadataError("The EntityDescriptor has no entityID.");
  const sp = entity.getElementsByTagNameNS(NS_MD, "SPSSODescriptor")[0];
  if (!sp) throw new SpMetadataError("No md:SPSSODescriptor: this is not service provider metadata.");

  const acs = Array.from(sp.getElementsByTagNameNS(NS_MD, "AssertionConsumerService"))
    .filter((e) => e.getAttribute("Binding") === BINDING_POST)
    .sort((a, b) => Number(a.getAttribute("index") ?? 0) - Number(b.getAttribute("index") ?? 0));
  // Assertions are bearer credentials: only https endpoints are registrable,
  // whatever the publisher advertised.
  const acsUrls = acs.map((e) => e.getAttribute("Location")?.trim() ?? "").filter((u) => /^https:\/\//.test(u));
  if (acsUrls.length === 0) throw new SpMetadataError("No https AssertionConsumerService with the HTTP-POST binding.");
  const defaultAcsRaw = acs.find((e) => e.getAttribute("isDefault") === "true")?.getAttribute("Location")?.trim() ?? null;
  const defaultAcs = defaultAcsRaw && acsUrls.includes(defaultAcsRaw) ? defaultAcsRaw : null;

  const certs = (use: string) =>
    Array.from(sp.getElementsByTagNameNS(NS_MD, "KeyDescriptor"))
      .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === use)
      .flatMap((k) => Array.from(k.getElementsByTagNameNS(NS_DS, "X509Certificate")))
      .map((c) => normalizeCertPem(c.textContent ?? ""))
      .filter((p): p is string => p !== null);

  const slo = Array.from(sp.getElementsByTagNameNS(NS_MD, "SingleLogoutService")).find((e) => e.getAttribute("Binding") === BINDING_REDIRECT);
  const formats = Array.from(sp.getElementsByTagNameNS(NS_MD, "NameIDFormat")).map((e) => e.textContent?.trim() ?? "");
  const nameIdFormat = formats.some((f) => f.endsWith(":emailAddress"))
    ? "emailAddress"
    : formats.some((f) => f.endsWith(":persistent"))
      ? "persistent"
      : formats.some((f) => f.endsWith(":transient"))
        ? "transient"
        : null;

  return {
    entityId,
    acsUrls,
    defaultAcsUrl: defaultAcs,
    signingCerts: [...new Set(certs("signing"))],
    encryptionCert: certs("encryption")[0] ?? null,
    sloUrl: (() => {
      const u = slo?.getAttribute("Location")?.trim() ?? "";
      return /^https:\/\//.test(u) ? u : null;
    })(),
    nameIdFormat,
    wantAuthnRequestsSigned: sp.getAttribute("AuthnRequestsSigned") === "true",
    subjectId: subjectIdRequest(entity),
    validUntil: (() => {
      const v = entity.getAttribute("validUntil") ?? root?.getAttribute("validUntil");
      return v && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : null;
    })(),
  };
}

/** "pairwise-id" or "subject-id" (or "any", which gets the privacy-preserving pairwise-id); "none"/absent -> null. */
function subjectIdRequest(entity: XmlElement): "subject-id" | "pairwise-id" | null {
  for (const ea of Array.from(entity.getElementsByTagNameNS(NS_MDATTR, "EntityAttributes"))) {
    for (const a of Array.from(ea.getElementsByTagNameNS(NS_SAML, "Attribute"))) {
      if (a.getAttribute("Name") !== SUBJECT_ID_REQ) continue;
      const v = a.getElementsByTagNameNS(NS_SAML, "AttributeValue")[0]?.textContent?.trim();
      if (v === "subject-id") return "subject-id";
      if (v === "pairwise-id" || v === "any") return "pairwise-id";
    }
  }
  return null;
}

/**
 * Fetches SP metadata from its published URL: https only, 10 s, 256 KB.
 * Not signature-checked (same trust decision as pasting it): the admin chose
 * the URL, and HTTPS authenticates the publisher.
 */
export async function fetchSpMetadata(url: string): Promise<ParsedSpMetadata> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new SpMetadataError("The metadata URL is not a valid URL.");
  }
  if (u.protocol !== "https:") throw new SpMetadataError("The metadata URL must use https.");
  let res: Response;
  try {
    // No redirects: https on the registered URL is what authenticates the
    // publisher, and a redirect would silently move that trust to a host
    // (or scheme) the administrator never chose.
    res = await fetch(u.toString(), { headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" }, signal: AbortSignal.timeout(10_000), redirect: "error" });
  } catch (e) {
    throw new SpMetadataError(`Could not fetch the metadata: ${String((e as Error).message ?? e).slice(0, 120)}`);
  }
  if (!res.ok) throw new SpMetadataError(`The metadata URL answered ${res.status}.`);
  if (!res.body) throw new SpMetadataError("The metadata response had no body.");
  // Bound the read itself: checking the string after res.text() would already
  // have buffered the whole body.
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_METADATA_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new SpMetadataError("Metadata is larger than 256 KB.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return parseSpMetadata(new TextDecoder().decode(bytes));
}

/** Creates or updates (by entityID) an SP registry row from parsed metadata. Returns its id. */
export async function upsertSpFromMetadata(env: import("../../env.js").Env, meta: ParsedSpMetadata, name?: string, metadataUrl?: string): Promise<number> {
  const now = new Date().toISOString();
  const existing = await env.DB.prepare("SELECT id FROM saml_service_providers WHERE entity_id = ?").bind(meta.entityId).first<{ id: number }>();
  const fields = [
    JSON.stringify(meta.acsUrls),
    meta.defaultAcsUrl,
    meta.nameIdFormat ?? "transient",
    meta.wantAuthnRequestsSigned && meta.signingCerts.length > 0 ? 1 : 0,
    JSON.stringify(meta.signingCerts),
    meta.sloUrl,
    meta.encryptionCert,
    meta.encryptionCert ? 1 : 0,
  ];
  if (existing) {
    await env.DB.prepare(
      `UPDATE saml_service_providers SET acs_urls = ?, default_acs_url = ?, nameid_format = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, updated_at = ?${name ? ", name = ?" : ""} WHERE id = ?`
    )
      .bind(...fields, now, ...(name ? [name] : []), existing.id)
      .run();
    await afterUpsert(env, existing.id, meta, metadataUrl);
    return existing.id;
  }
  const row = await env.DB.prepare(
    `INSERT INTO saml_service_providers (entity_id, name, acs_urls, default_acs_url, nameid_format, want_authn_requests_signed, signing_certs, slo_url, encryption_cert, encrypt_assertions, attribute_map, sign_response, sign_assertion, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 1, 1, ?, ?) RETURNING id`
  )
    .bind(meta.entityId, name || meta.entityId, ...fields, now, now)
    .first<{ id: number }>();
  await afterUpsert(env, row!.id, meta, metadataUrl);
  return row!.id;
}

/** Metadata-derived fields kept apart from the main upsert: subject identifier, URL and refresh bookkeeping. */
async function afterUpsert(env: import("../../env.js").Env, id: number, meta: ParsedSpMetadata, metadataUrl?: string): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE saml_service_providers SET metadata_valid_until = ?${meta.subjectId ? ", subject_id = ?" : ""}${metadataUrl !== undefined ? ", metadata_url = ?, metadata_last_refreshed_at = ?" : ""} WHERE id = ?`
  )
    .bind(meta.validUntil, ...(meta.subjectId ? [meta.subjectId] : []), ...(metadataUrl !== undefined ? [metadataUrl, now] : []), id)
    .run();
}

/**
 * Cron: re-reads metadata for SPs registered from a URL, at most daily and a
 * few per run. The remote document is unsigned, so a refresh may only
 * strengthen the stored trust configuration - never weaken or re-point it:
 * registered ACS endpoints are never removed and new ones are never added
 * (that is the administrator's decision, by re-importing or editing the SP),
 * signing certificates accumulate (old + new stay valid through rollover),
 * signed-request and encryption requirements, once on, stay on, and any new
 * endpoint must be https. Non-security fields (NameID format, subject-id
 * preference, validity bookkeeping) still track the document.
 */
/** A publisher could otherwise grow signing_certs one entry per refresh, unbounded. */
const MAX_SIGNING_CERTS = 16;

export async function refreshSpMetadata(env: import("../../env.js").Env): Promise<{ refreshed: number; failed: number }> {
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { results } = await env.DB.prepare(
    "SELECT * FROM saml_service_providers WHERE metadata_url IS NOT NULL AND metadata_url != '' AND (metadata_last_refreshed_at IS NULL OR metadata_last_refreshed_at < ?) LIMIT 5"
  )
    .bind(dayAgo)
    .all<{
      id: number;
      entity_id: string;
      metadata_url: string;
      acs_urls: string;
      default_acs_url: string | null;
      want_authn_requests_signed: number;
      signing_certs: string;
      slo_url: string | null;
      encryption_cert: string | null;
      encrypt_assertions: number;
    }>();
  let refreshed = 0;
  let failed = 0;
  for (const sp of results) {
    try {
      const meta = await fetchSpMetadata(sp.metadata_url);
      // The URL must keep describing the same SP; a different entityID is refused, not re-pointed.
      if (meta.entityId !== sp.entity_id) throw new SpMetadataError(`entityID changed to ${meta.entityId}`);

      const storedAcs = JSON.parse(sp.acs_urls) as string[];
      const storedCerts = JSON.parse(sp.signing_certs) as string[];
      const httpsOnly = (u: string | null) => (u && u.startsWith("https://") ? u : null);
      const merged = {
        acsUrls: storedAcs.filter((u) => meta.acsUrls.includes(u)), // an endpoint the publisher withdrew stops being offered; it is never re-pointed
        certs: [...new Set([...storedCerts, ...meta.signingCerts])].slice(-MAX_SIGNING_CERTS),
        wantSigned: sp.want_authn_requests_signed === 1 || (meta.wantAuthnRequestsSigned && meta.signingCerts.length > 0),
        sloUrl: httpsOnly(sp.slo_url) ?? httpsOnly(meta.sloUrl),
        encryptionCert: sp.encryption_cert ?? meta.encryptionCert,
      };
      // A withdrawn ACS that was the only one registered is kept rather than
      // leaving the SP with no legal assertion target.
      if (merged.acsUrls.length === 0) merged.acsUrls = storedAcs;

      const now = new Date().toISOString();
      const drifts: string[] = [];
      if (meta.acsUrls.some((u) => !storedAcs.includes(u))) drifts.push("acs_added");
      if (!sp.want_authn_requests_signed && meta.wantAuthnRequestsSigned && meta.signingCerts.length === 0) drifts.push("signing_downgrade");
      if (sp.encryption_cert && !meta.encryptionCert) drifts.push("encryption_dropped");
      await env.DB.prepare(
        `UPDATE saml_service_providers SET acs_urls = ?, default_acs_url = ?, nameid_format = ?, want_authn_requests_signed = ?, signing_certs = ?, slo_url = ?, encryption_cert = ?, encrypt_assertions = ?, metadata_valid_until = ?, metadata_last_refreshed_at = ?${meta.subjectId ? ", subject_id = ?" : ""} WHERE id = ?`
      )
        .bind(
          JSON.stringify(merged.acsUrls),
          merged.acsUrls.includes(sp.default_acs_url ?? "") ? sp.default_acs_url : merged.acsUrls[0],
          meta.nameIdFormat ?? "transient",
          merged.wantSigned ? 1 : 0,
          JSON.stringify(merged.certs),
          merged.sloUrl,
          merged.encryptionCert,
          merged.encryptionCert ? 1 : 0,
          meta.validUntil,
          now,
          ...(meta.subjectId ? [meta.subjectId] : []),
          sp.id
        )
        .run();
      if (drifts.length) {
        await logAudit(env, { id: null, upn: "cron" }, "saml.metadata_refresh_held", sp.entity_id, { held: drifts });
      }
      refreshed++;
    } catch (e) {
      failed++;
      await env.DB.prepare("UPDATE saml_service_providers SET metadata_last_refreshed_at = ? WHERE id = ?").bind(new Date().toISOString(), sp.id).run();
      console.error(JSON.stringify({ event: "saml_metadata_refresh_failed", entity_id: sp.entity_id, error: String((e as Error).message ?? e) }));
    }
  }
  return { refreshed, failed };
}
