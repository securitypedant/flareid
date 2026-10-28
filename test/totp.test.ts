import { describe, expect, it } from "vitest";
import { buildOtpAuthUri, generateBase32Secret, verifyTotp } from "../src/lib/totp.js";

// RFC 6238 Appendix B, SHA-1 column. The seed there is the ASCII string
// "12345678901234567890", which is this in base32. The published codes are
// eight digits; FlareID issues six, which is the same truncation with a
// smaller modulus - so the expected values below are the last six digits of
// each published code.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const VECTORS: { seconds: number; code: string }[] = [
  { seconds: 59, code: "287082" },
  { seconds: 1111111109, code: "081804" },
  { seconds: 1111111111, code: "050471" },
  { seconds: 1234567890, code: "005924" },
  { seconds: 2000000000, code: "279037" },
];

describe("TOTP", () => {
  it("matches the RFC 6238 test vectors", async () => {
    for (const { seconds, code } of VECTORS) {
      expect(await verifyTotp(RFC_SECRET, code, seconds * 1000), `vector at T=${seconds}`).toBe(true);
    }
  });

  it("rejects a code from a different time window", async () => {
    expect(await verifyTotp(RFC_SECRET, "287082", 1111111109 * 1000)).toBe(false);
  });

  it("tolerates one step of clock drift in each direction", async () => {
    // The code for T=59 sits in counter 1, so it must also verify 30 seconds
    // either side - an authenticator app and a server rarely agree exactly.
    expect(await verifyTotp(RFC_SECRET, "287082", (59 - 30) * 1000)).toBe(true);
    expect(await verifyTotp(RFC_SECRET, "287082", (59 + 30) * 1000)).toBe(true);
    expect(await verifyTotp(RFC_SECRET, "287082", (59 + 90) * 1000)).toBe(false);
  });

  it("ignores whitespace in the submitted code", async () => {
    expect(await verifyTotp(RFC_SECRET, "287 082", 59 * 1000)).toBe(true);
  });

  it("generates secrets an authenticator app can read", () => {
    const secret = generateBase32Secret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    // 20 bytes is 160 bits, which base32 encodes as 32 characters.
    expect(secret).toHaveLength(32);
  });

  it("builds an otpauth URI carrying the parameters the code actually uses", () => {
    const uri = buildOtpAuthUri({ secret: "ABCDEF", upn: "ada@example.com", issuer: "FlareID" });
    expect(uri).toContain("otpauth://totp/FlareID%3Aada%40example.com");
    expect(uri).toContain("secret=ABCDEF");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });
});
