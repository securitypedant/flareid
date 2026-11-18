import { Hono } from "hono";
import type { Env } from "../env.js";
import { receiveSet, SsfReceiveError } from "../lib/ssf.js";

/**
 * The Shared Signals receiver: transmitters (registered under Integrations ->
 * Signals or POST /api/v1/ssf/transmitters) push signed Security Event Tokens
 * here. Authentication IS the SET signature - there's no bearer token.
 */
export const ssfReceiver = new Hono<{ Bindings: Env }>();

ssfReceiver.post("/ssf/receive", async (c) => {
  const token = (await c.req.text()).trim();
  if (!token) return c.json({ error: "invalid_set", message: "Body must be a Security Event Token (JWT)." }, 400);
  try {
    const result = await receiveSet(c.env, token);
    return c.json(result, 202);
  } catch (e) {
    if (e instanceof SsfReceiveError) return c.json({ error: "invalid_set", message: e.message }, e.status as 400 | 401);
    throw e;
  }
});
