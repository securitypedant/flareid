import { Hono } from "hono";
import type { Env } from "../env.js";
import { cssForFile, logoForFile } from "../lib/brands.js";

/**
 * Uploaded logos and custom stylesheets (brands.ts), public: the sign-in page
 * and email clients load them without a session.
 *
 * Both names carry the content's hash and nothing at a name ever changes - a
 * new logo is a new asset, an edited stylesheet a new hash - so they are
 * cached for a year as immutable, and a name whose hash is not current is a
 * 404 rather than stale content.
 *
 * A logo is only ever PNG or JPEG (validated by magic bytes at upload; SVG is
 * refused), served with the type it was validated as. The stylesheet is
 * text/css and never inlined into a page. Both get X-Content-Type-Options:
 * nosniff and `default-src 'none'` from security-headers.ts like every
 * non-HTML response.
 */
export const brandAssets = new Hono<{ Bindings: Env }>();

const IMMUTABLE = "public, max-age=31536000, immutable";

brandAssets.get("/brand/logo/:file", async (c) => {
  const logo = await logoForFile(c.env, c.req.param("file"));
  if (!logo) return c.text("Not found", 404);
  return new Response(logo.bytes as BodyInit, {
    headers: {
      "Content-Type": logo.type,
      "Content-Length": String(logo.bytes.length),
      "Cache-Control": IMMUTABLE,
      // Email clients and webmail load it from their own origins.
      "Cross-Origin-Resource-Policy": "cross-origin",
    },
  });
});

brandAssets.get("/brand/css/:file", async (c) => {
  const css = await cssForFile(c.env, c.req.param("file"));
  if (css === null) return c.text("Not found", 404);
  return new Response(css, { headers: { "Content-Type": "text/css; charset=utf-8", "Cache-Control": IMMUTABLE } });
});
