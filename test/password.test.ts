import { describe, expect, it } from "vitest";
import { generateTempPassword, hashPassword, verifyPassword } from "../src/lib/password.js";
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
    expect(a.salt).not.toBe(b.salt);
    expect(a.hash).not.toBe(b.hash);
  });

  it("honours the iteration count stored with the hash", async () => {
    // The point of storing iterations per row is that the cost can be raised
    // later without invalidating what is already there, so an old low-cost hash
    // has to keep verifying.
    const stored = await hashPassword("legacy", 1000);
    expect(stored.iterations).toBe(1000);
    expect(
      await verifyPassword("legacy", {
        password_hash: stored.hash,
        password_salt: stored.salt,
        password_iterations: 1000,
      })
    ).toBe(true);
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
