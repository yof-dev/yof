import { describe, expect, it } from "vitest";
import { isPlaceholder, KEY_RULES, maskAll, maskSecret, scanText } from "../src/secrets";
import { fakeKeys, rand } from "./helpers";

describe("key patterns", () => {
  const cases = fakeKeys();

  it("covers every rule yof knows", () => {
    expect(new Set(cases.map(([id]) => id))).toEqual(new Set(Object.keys(KEY_RULES)));
  });

  for (const [ruleId, text, value] of cases) {
    it(`finds ${ruleId} and never returns it in full (${value.slice(0, 6)}…)`, () => {
      expect(isPlaceholder(value)).toBe(false);
      const hits = scanText(text).filter((m) => m.ruleId === ruleId);
      expect(hits.length, JSON.stringify(scanText(text).map((m) => m.ruleId))).toBe(1);
      const m = hits[0]!;
      expect(m.masked.endsWith("••••••••")).toBe(true);
      expect(m.masked).not.toBe(value);
      if (ruleId !== "secret.private_key") {
        expect(m.masked.length).toBeLessThan(value.length);
        expect(m.snippet.includes(value)).toBe(false);
        expect(JSON.stringify(m).includes(value)).toBe(false);
      }
      expect(m.line).toBeGreaterThanOrEqual(1);
    });
  }

  it("reports the right line and column", () => {
    const value = ["sk", "_live_", rand(28)].join("");
    const [m] = scanText(`one\ntwo\n  key = "${value}"`);
    expect(m).toMatchObject({ ruleId: "secret.stripe_live", line: 3, column: 10 });
  });

  it("keeps the recognisable prefix and four characters", () => {
    const value = ["sk", "_live_", "51Ab", rand(24)].join("");
    expect(maskSecret(value)).toBe("sk_live_51Ab••••••••");
  });

  it("does not judge a JWT that is not a service or anon key", () => {
    const b = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    expect(scanText([b({ alg: "HS256" }), b({ sub: "user", role: "authenticated" }), rand(43)].join("."))).toEqual([]);
  });

  it("an SK hash without Twilio nearby, or an auth token without an Account SID, is not a finding", () => {
    expect(scanText(`const h = "${["S", "K"].join("")}${rand(32, "0123456789abcdef")}";`)).toEqual([]);
    expect(scanText(`authToken = "${rand(32, "0123456789abcdef", 9)}"`)).toEqual([]);
  });

  it("maskAll hides every secret-looking run in a text", () => {
    const value = ["gh", "p_", rand(36)].join("");
    expect(maskAll(`x ${value} y`).includes(value)).toBe(false);
  });
});

describe("placeholders are ignored", () => {
  const placeholders = [
    ["sk", "_live_", "x".repeat(24)],
    ["sk", "_live_", "X".repeat(30)],
    ["sk", "_live_", "your_stripe_key_here_please"].map((s) => s.replace(/_/g, "_")),
    ["sk", "_test_", "0".repeat(24)],
    ["gh", "p_", "a".repeat(36)],
    ["sk-", "proj-", "EXAMPLE", "a".repeat(40)],
    ["AK", "IA", "IOSFODNN7EXAMPLE"],
    ["sk", "_live_", "1234567890", "abcdefghij", "ABCD"],
  ].map((p) => p.join(""));

  for (const value of placeholders) {
    it(`skips ${value.slice(0, 10)}…`, () => {
      expect(isPlaceholder(value)).toBe(true);
      expect(scanText(`key = "${value}"`).filter((m) => !m.ruleId.startsWith("public."))).toEqual([]);
    });
  }

  it("named settings with template values are skipped", () => {
    expect(scanText(`VITE_${"API"}_SECRET="\${process.env.X}"`)).toEqual([]);
    expect(scanText(`NEXT_PUBLIC_${"DB"}_PASSWORD="changeme-later-ok"`)).toEqual([]);
  });

  it("can be turned off", () => {
    const value = ["sk", "_live_", "x".repeat(24)].join("");
    expect(scanText(value, { ignorePlaceholders: false })).toHaveLength(1);
  });
});
