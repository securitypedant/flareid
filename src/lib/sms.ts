/**
 * Outbound SMS for alias verification codes. The provider is a settings-level
 * choice (Admin -> Integrations -> SMS); absent settings mean "not
 * configured" and every phone-verification attempt reports that plainly.
 *
 * Providers:
 *   twilio  POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json
 *           Basic (sid:auth_token), form To/From/Body. US traffic needs an
 *           A2P-registered sender.
 *   vonage  POST https://rest.nexmo.com/sms/json
 *           JSON api_key/api_secret/to/from/text. `from` may be an
 *           alphanumeric sender id in countries that allow it - no number to
 *           buy for those routes.
 *   telnyx  POST https://api.telnyx.com/v2/messages
 *           Bearer api key, JSON from/to/text. Needs a Telnyx number (or a
 *           messaging profile id as `from`).
 *   plivo   POST https://api.plivo.com/v1/Account/{auth_id}/Message/
 *           Basic (auth_id:auth_token), JSON src/dst/text. Numbers are cheap
 *           and the console is lighter than Twilio's; a Powerpack can stand
 *           in for `src` too.
 *
 * Secrets sit in idp_settings sealed (sealed.ts) like the other recoverable
 * credentials; empty fields on save keep the stored value.
 */

import type { Env } from "../env.js";
import { getSetting, setSetting } from "./settings.js";
import { sealMaybe, unsealMaybe } from "./sealed.js";

export type SmsProvider = "twilio" | "vonage" | "telnyx" | "plivo";
export const SMS_PROVIDERS: { key: SmsProvider; label: string; fields: string }[] = [
  { key: "twilio", label: "Twilio", fields: "Account SID + Auth Token + From number" },
  { key: "vonage", label: "Vonage", fields: "API key + API secret + From (number or sender id)" },
  { key: "telnyx", label: "Telnyx", fields: "API key + From number" },
  { key: "plivo", label: "Plivo", fields: "Auth ID + Auth Token + From number" },
];

export interface SmsConfig {
  provider: SmsProvider | "";
  /** Twilio only. */
  accountSid: string;
  /** Twilio only. */
  authToken: string;
  /** Vonage only. */
  apiKey: string;
  /** Vonage only. */
  apiSecret: string;
  /** Telnyx only. */
  telnyxKey: string;
  /** Plivo only. */
  plivoId: string;
  /** Plivo only. */
  plivoToken: string;
  /** Sender: E.164 number, messaging profile id, or (Vonage) sender id. */
  from: string;
}

export async function getSmsConfig(env: Env): Promise<SmsConfig> {
  const p = (await getSetting(env, "sms_provider")) ?? "";
  return {
    provider: (["twilio", "vonage", "telnyx", "plivo"] as const).find((k) => k === p) ?? "",
    accountSid: (await unsealMaybe(env, await getSetting(env, "sms_twilio_sid"))) ?? "",
    authToken: (await unsealMaybe(env, await getSetting(env, "sms_twilio_token"))) ?? "",
    apiKey: (await unsealMaybe(env, await getSetting(env, "sms_vonage_key"))) ?? "",
    apiSecret: (await unsealMaybe(env, await getSetting(env, "sms_vonage_secret"))) ?? "",
    telnyxKey: (await unsealMaybe(env, await getSetting(env, "sms_telnyx_key"))) ?? "",
    plivoId: (await unsealMaybe(env, await getSetting(env, "sms_plivo_id"))) ?? "",
    plivoToken: (await unsealMaybe(env, await getSetting(env, "sms_plivo_token"))) ?? "",
    from: (await getSetting(env, "sms_from")) ?? "",
  };
}

export interface SmsSettingsInput {
  provider: string;
  accountSid?: string;
  authToken?: string;
  apiKey?: string;
  apiSecret?: string;
  telnyxKey?: string;
  plivoId?: string;
  plivoToken?: string;
  from: string;
}

/** Secret fields left blank keep the stored value (sealed at rest). */
export async function saveSmsConfig(env: Env, input: SmsSettingsInput): Promise<void> {
  const provider = input.provider.trim();
  if (provider && !SMS_PROVIDERS.some((p) => p.key === provider)) throw new Error(`Unknown SMS provider "${provider}".`);
  const keep = async (key: string, value: string | undefined) => {
    if (value !== undefined && value !== "") await setSetting(env, key, await sealMaybe(env, value.trim()));
  };
  await setSetting(env, "sms_provider", provider);
  await keep("sms_twilio_sid", input.accountSid);
  await keep("sms_twilio_token", input.authToken);
  await keep("sms_vonage_key", input.apiKey);
  await keep("sms_vonage_secret", input.apiSecret);
  await keep("sms_telnyx_key", input.telnyxKey);
  await keep("sms_plivo_id", input.plivoId);
  await keep("sms_plivo_token", input.plivoToken);
  await setSetting(env, "sms_from", input.from.trim());
}

/** Whether a provider + its required fields are all present. */
export function smsConfigured(config: SmsConfig): boolean {
  if (!config.from) return false;
  switch (config.provider) {
    case "twilio": return Boolean(config.accountSid && config.authToken);
    case "vonage": return Boolean(config.apiKey && config.apiSecret);
    case "telnyx": return Boolean(config.telnyxKey);
    case "plivo": return Boolean(config.plivoId && config.plivoToken);
    default: return false;
  }
}

export type SmsResult = { ok: true } | { ok: false; error: string };

export async function sendSms(env: Env, to: string, body: string): Promise<SmsResult> {
  const config = await getSmsConfig(env);
  if (!smsConfigured(config)) return { ok: false, error: "SMS is not configured (Admin -> Integrations -> SMS)." };
  try {
    if (config.provider === "twilio") {
      const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.accountSid)}/Messages.json`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${btoa(`${config.accountSid}:${config.authToken}`)}` },
        body: new URLSearchParams({ To: to, From: config.from, Body: body }).toString(),
      });
      if (!res.ok) return { ok: false, error: `Twilio refused the message (HTTP ${res.status}).` };
    } else if (config.provider === "vonage") {
      const res = await fetch("https://rest.nexmo.com/sms/json", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: config.apiKey, api_secret: config.apiSecret, to: to.replace(/^\+/, ""), from: config.from, text: body }),
      });
      const j = (await res.json().catch(() => null)) as { messages?: { status?: string; ["error-text"]?: string }[] } | null;
      const msg = j?.messages?.[0];
      if (!res.ok || (msg && msg.status !== "0")) return { ok: false, error: `Vonage refused the message (${msg?.["error-text"] ?? `HTTP ${res.status}`}).` };
    } else if (config.provider === "telnyx") {
      const res = await fetch("https://api.telnyx.com/v2/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.telnyxKey}` },
        body: JSON.stringify({ from: config.from, to, text: body }),
      });
      if (!res.ok) return { ok: false, error: `Telnyx refused the message (HTTP ${res.status}).` };
    } else {
      // Plivo takes src/dst with no leading '+'.
      const res = await fetch(`https://api.plivo.com/v1/Account/${encodeURIComponent(config.plivoId)}/Message/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Basic ${btoa(`${config.plivoId}:${config.plivoToken}`)}` },
        body: JSON.stringify({ src: config.from.replace(/^\+/, ""), dst: to.replace(/^\+/, ""), text: body }),
      });
      if (!res.ok && res.status !== 202) return { ok: false, error: `Plivo refused the message (HTTP ${res.status}).` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: `The SMS provider could not be reached (${e instanceof Error ? e.message : String(e)}).` };
  }
}
