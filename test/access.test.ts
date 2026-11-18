import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function sessionFor(userId: number): Promise<string> {
  const { setCookie } = await createSession(env, userId, ["pwd", "mfa"], new Request(BASE));
  return setCookie.split(";")[0]!;
}

async function adminCookie(): Promise<string> {
  const admin = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>();
  return sessionFor(admin!.id);
}

async function seedUser(apiKey: string, username: string): Promise<number> {
  const res = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: username[0]!.toUpperCase() + username.slice(1), password: "user-password-123", status: "active" } });
  if (res.status !== 201) throw new Error(`user create failed: ${JSON.stringify(res.body)}`);
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

async function makeGroup(apiKey: string, name: string, extra: Record<string, unknown> = {}): Promise<number> {
  const res = await apiCall("/api/v1/groups", { token: apiKey, body: { name, ...extra } });
  if (res.status !== 201) throw new Error(`group create failed: ${JSON.stringify(res.body)}`);
  return res.body.id;
}

const memberOf = async (groupId: number, userId: number) =>
  env.DB.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").bind(groupId, userId).first();

const requestRow = (id: number) => env.DB.prepare("SELECT * FROM access_requests WHERE id = ?").bind(id).first<any>();

describe("access requests", () => {
  it("runs the full ask -> approve -> member cycle through console and API", async () => {
    const { apiKey } = await bootstrapInstance();
    const uid = await seedUser(apiKey, "pat");
    const groupId = await makeGroup(apiKey, "VPN users", { requestable: true, description: "For the field team" });
    const cookie = await sessionFor(uid);

    // The group shows up on My account as something to ask for, searchable by
    // name or description, with both shown.
    const accountPage = await (await SELF.fetch(`${BASE}/account/groups`, { headers: { Cookie: cookie } })).text();
    expect(accountPage).toContain("Request access");
    const found = await (await SELF.fetch(`${BASE}/account/access/groups?q=field`, { headers: { Cookie: cookie } })).json() as { id: number; label: string; desc: string; badges: { label: string }[] }[];
    expect(found).toEqual([{ id: groupId, label: "VPN users", desc: "For the field team", badges: [] }]);
    expect(await (await SELF.fetch(`${BASE}/account/access/groups?q=nomatch`, { headers: { Cookie: cookie } })).json()).toEqual([]);

    const ask = await SELF.fetch(`${BASE}/account/access/request`, {
      method: "POST",
      headers: { ...FORM, Cookie: cookie },
      body: new URLSearchParams({ group_id: String(groupId), reason: "need it for the field team" }).toString(),
      redirect: "manual",
    });
    expect(ask.headers.get("Location")).toContain("saved=access-requested");
    const req = await env.DB.prepare("SELECT id, status FROM access_requests WHERE user_id = ?").bind(uid).first<{ id: number; status: string }>();
    expect(req!.status).toBe("pending");
    // While the ask waits it drops out of the picker - asking twice would only error.
    expect(await (await SELF.fetch(`${BASE}/account/access/groups?q=VPN`, { headers: { Cookie: cookie } })).json()).toEqual([]);

    // The console queue lists it for a groups admin.
    const admin = await adminCookie();
    const list = await (await SELF.fetch(`${BASE}/admin/access`, { headers: { Cookie: admin } })).text();
    expect(list).toContain("pat@");
    expect(list).toContain("VPN users");
    expect(list).toContain("need it for the field team");

    // Approving adds the member exactly like a group edit does.
    const approve = await SELF.fetch(`${BASE}/admin/access/requests/${req!.id}`, {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: new URLSearchParams({ decision: "approved", note: "welcome aboard" }).toString(),
      redirect: "manual",
    });
    expect(approve.headers.get("Location")).toContain("saved=1");
    expect(await memberOf(groupId, uid)).toBeTruthy();
    expect((await requestRow(req!.id))!.status).toBe("approved");

    // The requester sees the outcome on My account.
    const after = await (await SELF.fetch(`${BASE}/account/groups`, { headers: { Cookie: cookie } })).text();
    expect(after).toContain("Approved");
    // And can't ask again - already a member.
    expect(await (await SELF.fetch(`${BASE}/account/access/groups?q=VPN`, { headers: { Cookie: cookie } })).json()).toEqual([]);
  });

  it("refuses requests for anything not open to them, and double-asking", async () => {
    const { apiKey } = await bootstrapInstance();
    const uid = await seedUser(apiKey, "pat");
    const closed = await makeGroup(apiKey, "Closed shop");
    const dynamic = await makeGroup(apiKey, "Dyn", { rule: { all: [{ field: "username", op: "eq", value: "pat" }] }, requestable: true });
    const cookie = await sessionFor(uid);

    for (const gid of [closed, dynamic]) {
      const res = await SELF.fetch(`${BASE}/account/access/request`, {
        method: "POST",
        headers: { ...FORM, Cookie: cookie },
        body: new URLSearchParams({ group_id: String(gid), reason: "x" }).toString(),
      });
      expect(res.status).toBe(200); // the friendly error page
      expect(await env.DB.prepare("SELECT 1 FROM access_requests WHERE group_id = ? AND user_id = ?").bind(gid, uid).first()).toBeNull();
    }
    // A dynamic group can never become requestable even via the API.
    const dyn = await env.DB.prepare("SELECT requestable FROM groups WHERE id = ?").bind(dynamic).first<{ requestable: number }>();
    expect(dyn!.requestable).toBe(0);

    const open = await makeGroup(apiKey, "Open", { requestable: true });
    await SELF.fetch(`${BASE}/account/access/request`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `group_id=${open}&reason=a` });
    const again = await SELF.fetch(`${BASE}/account/access/request`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `group_id=${open}&reason=b` });
    expect(await again.text()).toContain("already waiting");
    expect((await env.DB.prepare("SELECT COUNT(*) n FROM access_requests WHERE group_id = ?").bind(open).first<{ n: number }>())!.n).toBe(1);
  });

  it("denies a request without granting membership, and lets the requester withdraw", async () => {
    const { apiKey } = await bootstrapInstance();
    const uid = await seedUser(apiKey, "pat");
    const uid2 = await seedUser(apiKey, "sam");
    const groupId = await makeGroup(apiKey, "VPN users", { requestable: true });
    const cookie = await sessionFor(uid);
    await SELF.fetch(`${BASE}/account/access/request`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `group_id=${groupId}&reason=` });
    const req = (await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ?").bind(uid).first<{ id: number }>())!;

    // Someone else can't withdraw it.
    const cancel2 = await SELF.fetch(`${BASE}/account/access/requests/${req.id}/cancel`, { method: "POST", headers: { ...FORM, Cookie: await sessionFor(uid2) } });
    expect((await requestRow(req.id))!.status).toBe("pending");
    await cancel2.text();

    // Deny it: no membership, status + note recorded.
    const denied = await apiCall(`/api/v1/access/requests/${req.id}`, { token: apiKey, body: { decision: "denied", note: "not this quarter" } });
    expect(denied.status).toBe(200);
    expect(await memberOf(groupId, uid)).toBeNull();
    const row = await requestRow(req.id);
    expect([row.status, row.note]).toEqual(["denied", "not this quarter"]);
    // A decided request can't be decided again.
    const again = await apiCall(`/api/v1/access/requests/${req.id}`, { token: apiKey, body: { decision: "approved" } });
    expect(again.status).toBe(409);

    // Asking again is allowed after a decision.
    const reAsk = await SELF.fetch(`${BASE}/account/access/request`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `group_id=${groupId}`, redirect: "manual" });
    expect(reAsk.headers.get("Location")).toContain("saved=access-requested");
    const pending = (await env.DB.prepare("SELECT id FROM access_requests WHERE status = 'pending'").first<{ id: number }>())!;
    const withdraw = await SELF.fetch(`${BASE}/account/access/requests/${pending.id}/cancel`, { method: "POST", headers: { ...FORM, Cookie: cookie }, redirect: "manual" });
    expect(withdraw.headers.get("Location")).toContain("saved=access-cancelled");
    expect((await requestRow(pending.id))!.status).toBe("cancelled");
  });

  it("keeps an admin role group un-approvable by anyone who couldn't edit it", async () => {
    const { apiKey } = await bootstrapInstance();
    const uid = await seedUser(apiKey, "pat");
    // Super Admins grants console access; make it requestable as a lure.
    const sup = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>())!;
    await env.DB.prepare("UPDATE groups SET requestable = 1 WHERE id = ?").bind(sup.id).run();
    const cookie = await sessionFor(uid);
    await SELF.fetch(`${BASE}/account/access/request`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `group_id=${sup.id}` });
    const req = (await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ?").bind(uid).first<{ id: number }>())!;

    // A key with groups:write but not admin can decide requests in general -
    // but this group is protected, and the request must stay pending.
    const scoped = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "dir-admin", scopes: ["groups:write"] } });
    const blocked = await apiCall(`/api/v1/access/requests/${req.id}`, { token: scoped.body.token, body: { decision: "approved" } });
    expect(blocked.status).toBe(403);
    expect((await requestRow(req.id))!.status).toBe("pending");
    expect(await memberOf(sup.id, uid)).toBeNull();

    const fine = await apiCall(`/api/v1/access/requests/${req.id}`, { token: apiKey, body: { decision: "approved" } });
    expect(fine.status).toBe(200);
    expect(await memberOf(sup.id, uid)).toBeTruthy();
  });
});

describe("the requests queue", () => {
  it("searches by person, group and reason, and pages", async () => {
    const { apiKey } = await bootstrapInstance();
    const groupId = await makeGroup(apiKey, "VPN users", { requestable: true });
    // Seed 25 requests from different people so pagination has something to do.
    for (let i = 0; i < 25; i++) {
      const uid = await seedUser(apiKey, `seeker${String(i).padStart(2, "0")}`);
      const cookie = await sessionFor(uid);
      await SELF.fetch(`${BASE}/account/access/request`, {
        method: "POST",
        headers: { ...FORM, Cookie: cookie },
        body: new URLSearchParams({ group_id: String(groupId), reason: i === 7 ? "needle project" : "access" }).toString(),
      });
    }

    const all = await apiCall("/api/v1/access/requests?status=all&limit=10", { token: apiKey });
    expect(all.body.total).toBe(25);
    expect(all.body.requests.length).toBe(10);
    const second = await apiCall("/api/v1/access/requests?status=all&limit=10&offset=20", { token: apiKey });
    expect(second.body.requests.length).toBe(5);

    const byReason = await apiCall("/api/v1/access/requests?status=all&search=needle", { token: apiKey });
    expect(byReason.body.total).toBe(1);
    expect(byReason.body.requests[0].reason).toBe("needle project");
    const byPerson = await apiCall("/api/v1/access/requests?status=all&search=seeker07", { token: apiKey });
    expect(byPerson.body.total).toBe(1);
    const byGroup = await apiCall("/api/v1/access/requests?status=all&search=VPN", { token: apiKey });
    expect(byGroup.body.total).toBe(25);
    const none = await apiCall("/api/v1/access/requests?status=all&search=zzz", { token: apiKey });
    expect(none.body.total).toBe(0);

    // The console page pages the same way.
    const admin = await adminCookie();
    const page1 = await (await SELF.fetch(`${BASE}/admin/access?status=all&pageSize=20&page=1`, { headers: { Cookie: admin } })).text();
    expect(page1).toContain("Page 1 of 2");
    const search = await (await SELF.fetch(`${BASE}/admin/access?status=all&search=needle`, { headers: { Cookie: admin } })).text();
    expect(search).toContain("needle project");
    expect(search).not.toContain("Page 1 of");
  });
});

describe("bulk group actions", () => {
  it("toggles requestable across static groups, skipping dynamic and protected ones", async () => {
    const { apiKey } = await bootstrapInstance();
    const a = await makeGroup(apiKey, "Bulk A");
    const b = await makeGroup(apiKey, "Bulk B");
    const dyn = await makeGroup(apiKey, "Dyn", { rule: { all: [{ field: "username", op: "eq", value: "nobody" }] } });
    const sup = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>())!;

    // A groups:write key (not admin) can mass-toggle - but protected groups skip.
    const scoped = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "dir", scopes: ["groups:write"] } });
    const res = await apiCall("/api/v1/groups/bulk", { token: scoped.body.token, body: { group_ids: [a, b, dyn, sup.id], action: "requestable_on" } });
    expect(res.status).toBe(200);
    expect(res.body.applied.sort()).toEqual(["Bulk A", "Bulk B"]);
    expect(res.body.skipped.sort()).toEqual(["Dyn", "Super Admins"]);
    const { results: flags } = await env.DB.prepare("SELECT name, requestable FROM groups").all<{ name: string; requestable: number }>();
    expect(Object.fromEntries(flags.map((f) => [f.name, f.requestable]))).toMatchObject({ "Bulk A": 1, "Bulk B": 1, Dyn: 0, "Super Admins": 0 });

    const off = await apiCall("/api/v1/groups/bulk", { token: scoped.body.token, body: { group_ids: [a, b], action: "requestable_off" } });
    expect(off.status).toBe(200);
    expect((await env.DB.prepare("SELECT COUNT(*) n FROM groups WHERE requestable = 1").first<{ n: number }>())!.n).toBe(0);
  });

  it("adds the same people to every selected static group", async () => {
    const { apiKey } = await bootstrapInstance();
    const pat = await seedUser(apiKey, "pat");
    const sam = await seedUser(apiKey, "sam");
    const a = await makeGroup(apiKey, "Bulk A");
    const b = await makeGroup(apiKey, "Bulk B");
    const dyn = await makeGroup(apiKey, "Dyn", { rule: { all: [{ field: "username", op: "eq", value: "nobody" }] } });

    const res = await apiCall("/api/v1/groups/bulk", { token: apiKey, body: { group_ids: [a, b, dyn], action: "add_members", usernames: ["pat", "sam"] } });
    expect(res.status).toBe(200);
    expect(res.body.added).toBe(4);
    expect(res.body.skipped).toEqual(["Dyn"]);
    for (const [g, u] of [[a, pat], [a, sam], [b, pat], [b, sam]] as const) expect(await memberOf(g, u)).toBeTruthy();
    // Adding again is a no-op, not an error.
    const again = await apiCall("/api/v1/groups/bulk", { token: apiKey, body: { group_ids: [a], action: "add_members", usernames: ["pat"] } });
    expect(again.body.added).toBe(0);
  });

  it("goes through the console bulk form too", async () => {
    const { apiKey } = await bootstrapInstance();
    const a = await makeGroup(apiKey, "Bulk A");
    const admin = await adminCookie();
    const res = await SELF.fetch(`${BASE}/admin/groups/bulk`, {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: new URLSearchParams({ action: "requestable", requestable: "1", group_ids: String(a) }).toString(),
      redirect: "manual",
    });
    expect(res.headers.get("Location")).toContain("notice=");
    expect((await env.DB.prepare("SELECT requestable FROM groups WHERE id = ?").bind(a).first<{ requestable: number }>())!.requestable).toBe(1);
  });
});

describe("certification campaigns", () => {
  it("certifies and revokes the memberships it snapshot at creation", async () => {
    const { apiKey } = await bootstrapInstance();
    const pat = await seedUser(apiKey, "pat");
    const sam = await seedUser(apiKey, "sam");
    const groupId = await makeGroup(apiKey, "Contractors", { members: ["pat", "sam"] });
    const late = await makeGroup(apiKey, "Empty later", { requestable: true });

    const created = await apiCall("/api/v1/access/campaigns", { token: apiKey, body: { name: "Q1 review", group_ids: [groupId, late] } });
    expect(created.status).toBe(201);
    const campaign = created.body.campaign;
    expect(campaign.status).toBe("open");

    const detail = await apiCall(`/api/v1/access/campaigns/${campaign.id}`, { token: apiKey });
    expect(detail.body.items.length).toBe(2);
    const [patItem, samItem] = detail.body.items.sort((a: any, b: any) => a.upn.localeCompare(b.upn));

    const keep = await apiCall(`/api/v1/access/campaigns/${campaign.id}/items/${patItem.id}`, { token: apiKey, body: { decision: "certify" } });
    expect(keep.status).toBe(200);
    const revoke = await apiCall(`/api/v1/access/campaigns/${campaign.id}/items/${samItem.id}`, { token: apiKey, body: { decision: "revoke" } });
    expect(revoke.status).toBe(200);
    expect(await memberOf(groupId, pat)).toBeTruthy();
    expect(await memberOf(groupId, sam)).toBeNull();
    // Double-deciding is a conflict.
    expect((await apiCall(`/api/v1/access/campaigns/${campaign.id}/items/${patItem.id}`, { token: apiKey, body: { decision: "revoke" } })).status).toBe(409);

    const closed = await apiCall(`/api/v1/access/campaigns/${campaign.id}/close`, { token: apiKey, method: "POST" });
    expect(closed.status).toBe(200);
    // A closed campaign takes no more decisions; memberships live on outside it.
    const third = await seedUser(apiKey, "kim");
    await apiCall(`/api/v1/groups/${groupId}/members`, { token: apiKey, body: { usernames: ["kim"] } });
    expect(await memberOf(groupId, third)).toBeTruthy();
  });

  it("snapshots creation-time members only, and skips rule-managed groups", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, "pat");
    const staticId = await makeGroup(apiKey, "Static", { members: ["pat"] });
    const dynId = await makeGroup(apiKey, "Dyn", { rule: { all: [{ field: "username", op: "eq", value: "pat" }] } });

    const created = await apiCall("/api/v1/access/campaigns", { token: apiKey, body: { name: "Scope check", group_ids: [staticId, dynId] } });
    const detail = await apiCall(`/api/v1/access/campaigns/${created.body.campaign.id}`, { token: apiKey });
    // Only the explicit membership - the dynamic group's matches aren't reviewable.
    expect(detail.body.items.length).toBe(1);
    expect(detail.body.items[0].group_id).toBe(staticId);

    // A member added after the snapshot isn't under review either.
    await seedUser(apiKey, "late");
    await apiCall(`/api/v1/groups/${staticId}/members`, { token: apiKey, body: { usernames: ["late"] } });
    const again = await apiCall(`/api/v1/access/campaigns/${created.body.campaign.id}`, { token: apiKey });
    expect(again.body.items.length).toBe(1);
  });

  it("runs through the console review page too", async () => {
    const { apiKey } = await bootstrapInstance();
    const pat = await seedUser(apiKey, "pat");
    const groupId = await makeGroup(apiKey, "Static", { members: ["pat"] });
    const admin = await adminCookie();

    const create = await SELF.fetch(`${BASE}/admin/access/reviews`, {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: new URLSearchParams({ name: "Console review", group_ids: String(groupId) }).toString(),
      redirect: "manual",
    });
    expect(create.headers.get("Location")).toMatch(/\/admin\/access\/reviews\/\d+/);
    const campaignId = Number(create.headers.get("Location")!.match(/reviews\/(\d+)/)![1]);

    const page = await (await SELF.fetch(`${BASE}/admin/access/reviews/${campaignId}`, { headers: { Cookie: admin } })).text();
    expect(page).toContain("pat@");
    expect(page).toContain("0 of 1 memberships decided");

    const item = await env.DB.prepare("SELECT id FROM cert_items WHERE campaign_id = ?").bind(campaignId).first<{ id: number }>();
    const revoke = await SELF.fetch(`${BASE}/admin/access/reviews/${campaignId}/items/${item!.id}`, {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: "decision=revoke",
      redirect: "manual",
    });
    expect(revoke.headers.get("Location")).toContain("saved=1");
    expect(await memberOf(groupId, pat)).toBeNull();
  });
});
