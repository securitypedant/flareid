import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { setMasteredFields } from "../src/lib/scim-mapping.js";

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

const get = (path: string, cookie: string) => SELF.fetch(`${BASE}${path}`, { headers: { Cookie: cookie }, redirect: "manual" });
const post = (path: string, body: string | URLSearchParams, cookie: string) => SELF.fetch(`${BASE}${path}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: body.toString(), redirect: "manual" });

describe("group managers", () => {
  it("a named manager runs a group's members and requests from My account", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const manager = await seedUser(apiKey, "rosa");
    const member = await seedUser(apiKey, "lou");
    const asker = await seedUser(apiKey, "ned");
    const groupId = await makeGroup(apiKey, "Facilities", { requestable: true, description: "Site team" });
    const [admin, rosa] = [await adminCookie(), await sessionFor(manager)];

    // Admin names her a manager (console form) - she appears in the card.
    expect((await post(`/admin/groups/${groupId}/managers`, `manager_ids=${manager}`, admin)).headers.get("Location")).toContain("saved=1");
    expect(await (await get(`/admin/groups/${groupId}`, admin)).text()).toContain("rosa@");

    // Her My account groups page lists it under management.
    const mine = await (await get("/account/groups", rosa)).text();
    expect(mine).toContain("Groups you manage");
    expect(mine).toContain("Facilities");

    // The manage page: she adds Lou, finds him by search, removes him.
    const page = await (await get(`/account/groups/${groupId}`, rosa)).text();
    expect(page).toContain("Requests");
    expect(page).toContain("Members");
    expect(await (await get(`/account/groups/${groupId}/people?q=lou`, rosa)).json()).toEqual([{ id: member, label: "Lou", desc: "lou@horizon.test" }]);
    expect((await post(`/account/groups/${groupId}/members`, `user_ids=${member}`, rosa)).headers.get("Location")).toContain("saved=members");
    expect(await memberOf(groupId, member)).toBeTruthy();
    expect((await post(`/account/groups/${groupId}/members/${member}/remove`, "", rosa)).headers.get("Location")).toContain("saved=members");
    expect(await memberOf(groupId, member)).toBeFalsy();

    // Ned asks to join; she answers it from the same page.
    await post("/account/access/request", new URLSearchParams({ group_id: String(groupId), reason: "please" }), await sessionFor(asker));
    const pending = await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ? AND status = 'pending'").bind(asker).first<{ id: number }>();
    const queue = await (await get(`/account/groups/${groupId}`, rosa)).text();
    expect(queue).toContain("ned@");
    expect((await post(`/account/groups/${groupId}/requests/${pending!.id}`, "decision=approved&note=ok", rosa)).headers.get("Location")).toContain("saved=request");
    expect(await memberOf(groupId, asker)).toBeTruthy();
  });

  it("denies management to anyone not named, and refuses managers on role groups", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const rosa = await seedUser(apiKey, "rosa");
    const eve = await seedUser(apiKey, "eve");
    const groupId = await makeGroup(apiKey, "Facilities", {});
    const other = await makeGroup(apiKey, "Other group", {});
    const [admin, rosaCookie, eveCookie] = [await adminCookie(), await sessionFor(rosa), await sessionFor(eve)];
    await post(`/admin/groups/${groupId}/managers`, `manager_ids=${rosa}`, admin);

    // Eve neither sees nor acts on Rosa's group.
    const denied = await get(`/account/groups/${groupId}`, eveCookie);
    expect(denied.status).toBe(404);
    expect(await (await get("/account/groups", eveCookie)).text()).not.toContain("Groups you manage");
    const forged = await post(`/account/groups/${groupId}/members`, `user_ids=${eve}`, eveCookie);
    expect(forged.headers.get("Location")).toContain("error=");
    expect(await memberOf(groupId, eve)).toBeFalsy();
    // Nor her own group's page under Rosa's management - Rosa only manages hers.
    expect((await get(`/account/groups/${other}`, rosaCookie)).status).toBe(404);

    // Dynamic groups take no managers; admin-role groups can't have them either.
    const dyn = await makeGroup(apiKey, "By rule", { rule: { all: [{ field: "status", op: "eq", value: "active" }] } });
    expect((await post(`/admin/groups/${dyn}/managers`, `manager_ids=${rosa}`, admin)).headers.get("Location")).toContain("error=");
    const sup = await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>();
    expect((await post(`/admin/groups/${sup!.id}/managers`, `manager_ids=${rosa}`, admin)).headers.get("Location")).toContain("error=");

    // Removing the manager ends it.
    expect((await post(`/admin/groups/${groupId}/managers/${rosa}/remove`, "", admin)).headers.get("Location")).toContain("saved=1");
    expect((await get(`/account/groups/${groupId}`, rosaCookie)).status).toBe(404);
  });

  it("keeps rights one-way: a manager can't request or decide their own group", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const rosa = await seedUser(apiKey, "rosa");
    const groupId = await makeGroup(apiKey, "Facilities", { requestable: true });
    const admin = await adminCookie();
    const rosaCookie = await sessionFor(rosa);
    await post(`/admin/groups/${groupId}/managers`, `manager_ids=${rosa}`, admin);

    // The picker no longer offers it, and a direct POST refuses.
    expect(await (await get(`/account/access/groups?q=Facil`, rosaCookie)).json()).toEqual([]);
    const ask = await post("/account/access/request", `group_id=${groupId}`, rosaCookie);
    expect(await memberOf(groupId, rosa)).toBeFalsy();
    expect(ask.headers.get("Location")).toBeNull(); // an error page, not a redirect

    // A request filed *before* she became a manager is still not hers to decide.
    await env.DB.prepare("DELETE FROM group_managers WHERE group_id = ?").bind(groupId).run();
    await post("/account/access/request", `group_id=${groupId}`, rosaCookie);
    const req = await env.DB.prepare("SELECT id FROM access_requests WHERE user_id = ? AND status = 'pending'").bind(rosa).first<{ id: number }>();
    await post(`/admin/groups/${groupId}/managers`, `manager_ids=${rosa}`, admin);
    const decide = await post(`/account/groups/${groupId}/requests/${req!.id}`, "decision=approved", rosaCookie);
    expect(decide.headers.get("Location")).toContain("error=");
    expect((await env.DB.prepare("SELECT status FROM access_requests WHERE id = ?").bind(req!.id).first<{ status: string }>())!.status).toBe("pending");
    // And she can still put herself in directly - that is what management means.
    expect((await post(`/account/groups/${groupId}/members`, `user_ids=${rosa}`, rosaCookie)).headers.get("Location")).toContain("saved=members");
    expect(await memberOf(groupId, rosa)).toBeTruthy();
  });

  it("exposes managers on the group API", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const rosa = await seedUser(apiKey, "rosa");
    const groupId = await makeGroup(apiKey, "Facilities", {});
    const add = await apiCall(`/api/v1/groups/${groupId}/managers`, { token: apiKey, body: { usernames: ["rosa"] } });
    expect(add.body).toEqual({ ok: true, added: 1 });
    const detail = await apiCall(`/api/v1/groups/${groupId}`, { token: apiKey });
    expect(detail.body.managers).toEqual([{ upn: "rosa@horizon.test", username: "rosa", display_name: "Rosa", status: "active" }]);
    expect((await apiCall(`/api/v1/groups/${groupId}/managers/rosa`, { token: apiKey, method: "DELETE" })).body).toEqual({ ok: true });
    expect((await apiCall(`/api/v1/groups/${groupId}`, { token: apiKey })).body.managers).toEqual([]);
  });
});

describe("account pages and notifications", () => {
  it("splits My account into profile, groups and security pages", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "pat");
    const cookie = await sessionFor(uid);
    const account = await (await get("/account", cookie)).text();
    expect(account).toContain("Profile");
    expect(account).toContain("pat@horizon.test");
    expect(account).not.toContain("Change password");
    const security = await (await get("/account/security", cookie)).text();
    expect(security).toContain("Change password");
    expect(security).toContain("Authenticator app");
    const groups = await (await get("/account/groups", cookie)).text();
    expect(groups).toContain("Your groups");
  });

  it("badges the admin nav and fills the bell while requests wait", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "ned");
    const groupId = await makeGroup(apiKey, "VPN users", { requestable: true });
    const admin = await adminCookie();
    // Nothing pending: no badge anywhere.
    expect(await (await get("/admin", admin)).text()).not.toContain('class="nav-badge"');
    await post("/account/access/request", `group_id=${groupId}`, await sessionFor(uid));
    const page = await (await get("/admin", admin)).text();
    expect(page).toContain('class="nav-badge"');
    expect(page).toContain("asked to join VPN users");
    // The Access page itself badges the sub-item.
    const access = await (await get("/admin/access", admin)).text();
    expect(access).toContain('class="nav-badge"');
  });

  it("shows a group manager the bell on My account, nobody else", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const rosa = await seedUser(apiKey, "rosa");
    const eve = await seedUser(apiKey, "eve");
    const ned = await seedUser(apiKey, "ned");
    const groupId = await makeGroup(apiKey, "Facilities", { requestable: true });
    const admin = await adminCookie();
    await post(`/admin/groups/${groupId}/managers`, `manager_ids=${rosa}`, admin);
    await post("/account/access/request", `group_id=${groupId}`, await sessionFor(ned));
    const rosaPage = await (await get("/account/groups", await sessionFor(rosa))).text();
    expect(rosaPage).toContain("asked to join Facilities");
    expect(rosaPage).toContain('class="notif-dot"');
    expect(await (await get("/account", await sessionFor(eve))).text()).not.toContain('class="notif-dot"');
  });
});

describe("role visibility on groups", () => {
  it("names a role in the list and filters down to role-bearing groups", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await makeGroup(apiKey, "Plain group", {});
    const admin = await adminCookie();
    const list = await (await get("/admin/groups", admin)).text();
    expect(list).toContain("Super Admins");
    expect(list).toContain(">Role<");
    const filtered = await (await get("/admin/groups?roles=1", admin)).text();
    expect(filtered).toContain("Super Admins");
    expect(filtered).not.toContain("Plain group");
  });
});

describe("profile photos", () => {
  // A 1x1 transparent PNG.
  const PNG = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="), (c) => c.charCodeAt(0));

  it("round-trips an upload through the photo route", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "pat");
    const cookie = await sessionFor(uid);
    const fd = new FormData();
    fd.append("photo", new File([PNG], "me.png", { type: "image/png" }));
    const up = await SELF.fetch(`${BASE}/account/photo`, { method: "POST", headers: { Cookie: cookie, Origin: BASE }, body: fd, redirect: "manual" });
    expect(up.headers.get("Location")).toContain("saved=photo");
    const img = await get(`/account/photo/${uid}`, cookie);
    expect(img.status).toBe(200);
    expect(img.headers.get("content-type")).toBe("image/png");
    expect(img.headers.get("cache-control")).toContain("max-age=300");
    expect(new Uint8Array(await img.arrayBuffer())).toEqual(PNG);
    expect((await get("/account", cookie)).status).toBe(200);
    // A non-image is refused and nothing is stored.
    const bad = new FormData();
    bad.append("photo", new File([new TextEncoder().encode("not an image")], "x.png", { type: "image/png" }));
    expect((await SELF.fetch(`${BASE}/account/photo`, { method: "POST", headers: { Cookie: cookie, Origin: BASE }, body: bad })).status).toBe(200);
    await post("/account/photo/remove", "", cookie);
    // A miss is never cacheable - a cached 404 would hide a just-uploaded photo.
    const miss = await get(`/account/photo/${uid}`, cookie);
    expect(miss.status).toBe(404);
    expect(miss.headers.get("cache-control")).toBe("no-store");
  });

  it("serves photos stored before base64 - raw BLOB or driver-serialized string", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const uid = await seedUser(apiKey, "pat");
    const cookie = await sessionFor(uid);
    // A raw bound ArrayBuffer is whatever the driver returns for a BLOB.
    await env.DB.prepare("INSERT INTO user_photos (user_id, content_type, data, updated_at) VALUES (?, 'image/png', ?, ?)")
      .bind(uid, PNG.buffer, new Date().toISOString()).run();
    const img = await get(`/account/photo/${uid}`, cookie);
    expect(img.status).toBe(200);
    expect(new Uint8Array(await img.arrayBuffer())).toEqual(PNG);
    // Some drivers serialize a BLOB column as "137,80,78,…" decimal text.
    await env.DB.prepare("UPDATE user_photos SET data = ? WHERE user_id = ?").bind([...PNG].join(","), uid).run();
    const img2 = await get(`/account/photo/${uid}`, cookie);
    expect(img2.status).toBe(200);
    expect(new Uint8Array(await img2.arrayBuffer())).toEqual(PNG);
  });

  it("takes a photo from SCIM and marks the field mastered", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dataUri = `data:image/png;base64,${btoa(String.fromCharCode(...PNG))}`;
    const created = await SELF.fetch(`${BASE}/scim/v2/Users`, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/scim+json" },
      body: JSON.stringify({ userName: "ivana@horizon.test", name: { givenName: "Ivana", familyName: "Tree" }, active: true, photos: [{ value: dataUri, primary: true }] }),
    });
    expect(created.status).toBe(201);
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ivana'").first<{ id: number }>())!.id;
    const cookie = await sessionFor(uid);
    const img = await get(`/account/photo/${uid}`, cookie);
    expect(img.status).toBe(200);
    // With photo mastered by provisioning, the upload UI hides and POSTs refuse.
    await setMasteredFields(env, ["photo"]);
    expect(await (await get("/account", cookie)).text()).toContain("managed by your HR system");
    const fd = new FormData();
    fd.append("photo", new File([PNG], "me.png", { type: "image/png" }));
    expect((await SELF.fetch(`${BASE}/account/photo`, { method: "POST", headers: { Cookie: cookie, Origin: BASE }, body: fd })).status).toBe(200);
  });
});
