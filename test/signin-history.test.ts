import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { describeUserAgent, signInHistory } from "../src/lib/signin-history.js";
import { createSession } from "../src/lib/sessions.js";

const PASSWORD = "user-password-123";
beforeEach(() => resetDatabase());

async function attempt(upn: string, password: string) {
  const page = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await page.text())?.[1] ?? "";
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" },
    body: new URLSearchParams({ flow_id: flowId, upn, password }).toString(),
    redirect: "manual",
  });
  await res.text();
}

describe("sign-in history", () => {
  it("lists successes and failures, including attempts typed as a verified alias", async () => {
    const { apiKey } = await bootstrapInstance();
    expect((await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "Ada", username: "ada", domain: "example.com", password: PASSWORD, status: "active" } })).status).toBe(201);
    const user = (await env.DB.prepare("SELECT id, upn, username FROM users WHERE upn = 'ada@example.com'").first<{ id: number; upn: string; username: string }>())!;
    await env.DB.prepare("INSERT INTO user_emails (user_id, email, type, is_primary, verified, created_at) VALUES (?, 'ada@partner.com', 'work', 0, 1, '')").bind(user.id).run();

    await attempt("ada@example.com", "wrong-password-1");
    await attempt("ada@partner.com", "wrong-password-2");
    await attempt("ada@example.com", PASSWORD);

    const events = await signInHistory(env, user);
    expect(events.map((e) => [e.ok, e.reason])).toEqual([
      [true, ""],
      [false, "Wrong password"],
      [false, "Wrong password"],
    ]);
    expect(events[0]!.method).toBe("Password");
    expect(events[0]!.device).toBe("Chrome on macOS");

    const cookie = (await createSession(env, user.id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const html = await (await SELF.fetch(`${BASE}/account/security`, { headers: { Cookie: cookie } })).text();
    expect(html).toContain("Sign-in history");
    expect(html.match(/>Failed</g)).toHaveLength(2);
  });

  it("names browsers and systems", () => {
    expect(describeUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")).toBe("Safari on iOS");
    expect(describeUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0")).toBe("Edge on Windows");
    expect(describeUserAgent(null)).toBe("");
  });
});
