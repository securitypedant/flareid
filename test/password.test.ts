import { describe, expect, it } from "vitest";
import { generateTempPassword, hashPassword, needsRehash, verifyPassword } from "../src/lib/password.js";
import { validatePassword, type PasswordPolicy } from "../src/lib/settings.js";

const STRICT: PasswordPolicy = {
  minLength: 16,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSymbol: true,
};

describe("password hashing", () => {
  it("verifies a password against its own hash", async () => {
    const stored = await hashPassword("correct horse battery staple");
    expect(
      await verifyPassword("correct horse battery staple", {
        password_hash: stored.hash,
        password_salt: stored.salt,
        password_iterations: stored.iterations,
      })
    ).toBe(true);
  });

  it("rejects the wrong password", async () => {
    const stored = await hashPassword("correct horse battery staple");
    expect(
      await verifyPassword("Correct horse battery staple", {
        password_hash: stored.hash,
        password_salt: stored.salt,
        password_iterations: stored.iterations,
      })
    ).toBe(false);
  });

  it("salts per call, so the same password hashes differently", async () => {
    const a = await hashPassword("same-password");
    const b = await hashPassword("same-password");
    expect(a.hash).not.toBe(b.hash);
  });

  it("writes scrypt as a self-describing PHC string", async () => {
    const stored = await hashPassword("pw");
    expect(stored.hash).toMatch(/^\$scrypt\$ln=13,r=8,p=10\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
    expect(stored.salt).toBe("");
    expect(stored.iterations).toBe(0);
  });

  it("still verifies legacy PBKDF2 hashes, and flags them for an upgrade", async () => {
    // PBKDF2 at 100,000 iterations is what every hash written before scrypt
    // looks like: hex hash, hex salt, iteration count in its own column.
    const legacy = await hashPassword("legacy", { PASSWORD_HASHER: "pbkdf2" });
    const row = { password_hash: legacy.hash, password_salt: legacy.salt, password_iterations: legacy.iterations };
    expect(legacy.iterations).toBe(100_000);
    expect(await verifyPassword("legacy", row)).toBe(true);
    expect(await verifyPassword("Legacy", row)).toBe(false);
    expect(needsRehash(row)).toBe(true);
    // ...unless the deployment deliberately writes PBKDF2 (the Free-plan setting).
    expect(needsRehash(row, { PASSWORD_HASHER: "pbkdf2" })).toBe(false);
  });

  it("does not flag a current scrypt hash, and never downgrades one", async () => {
    const current = await hashPassword("pw");
    const row = { password_hash: current.hash, password_salt: current.salt, password_iterations: current.iterations };
    expect(needsRehash(row)).toBe(false);
    expect(needsRehash(row, { PASSWORD_HASHER: "pbkdf2" })).toBe(false);
  });

  it("fails closed on a hash format it doesn't recognise", async () => {
    expect(await verifyPassword("pw", { password_hash: "$argon2id$v=19$m=65536,t=3,p=4$abc$def", password_salt: "", password_iterations: 0 })).toBe(false);
  });
});

describe("generated passwords", () => {
  it("always satisfies the policy it was generated for", () => {
    // Generated 50 times rather than once: the generator shuffles, and a
    // single sample would not catch a class that only sometimes survives.
    for (let i = 0; i < 50; i++) {
      const password = generateTempPassword(STRICT);
      expect(validatePassword(password, STRICT), `failed for "${password}"`).toBeNull();
    }
  });

  it("never falls below 12 characters even if the policy asks for less", () => {
    const password = generateTempPassword({ ...STRICT, minLength: 4 });
    expect(password.length).toBeGreaterThanOrEqual(12);
  });
});

describe("password policy validation", () => {
  it("reports the first unmet requirement", () => {
    expect(validatePassword("short", STRICT)).toMatch(/at least 16/);
    expect(validatePassword("alllowercase1234!", STRICT)).toMatch(/uppercase/);
    expect(validatePassword("ALLUPPERCASE1234!", STRICT)).toMatch(/lowercase/);
    expect(validatePassword("NoDigitsHereAtAll!", STRICT)).toMatch(/number/);
    expect(validatePassword("NoSymbolsHere12345", STRICT)).toMatch(/symbol/);
  });

  it("accepts a password that meets everything", () => {
    expect(validatePassword("Tr0ubador&3xcellent", STRICT)).toBeNull();
  });
});
