/**
 * Test helpers. Every fake key is ASSEMBLED AT RUN TIME from pieces, so no file in this repository contains a string
 * that looks like a real key (the leak scan in no-secrets.test.ts would fail on it, and so would any secret scanner).
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { GitRunner } from "../src/files";
import type { PackageFetcher, PackageResponse } from "../src/packages";

/** Deterministic pseudo-random characters (a small LCG), so failures are reproducible. */
export function rand(n: number, alphabet = "ABCDEFGHJKLMNPQRSTUVWabcdefghjkmnpqrstuvw23456789", seed = 7): string {
  let s = seed * 2654435761 % 4294967296;
  let out = "";
  for (let i = 0; i < n; i++) { s = (s * 1103515245 + 12345) % 2147483648; out += alphabet[Math.floor(s / 65536) % alphabet.length]; }
  return out;
}
export const hex = (n: number, seed = 3) => rand(n, "0123456789abcdef", seed);
export const digits = (n: number, seed = 5) => rand(n, "0123456789", seed);
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
export const jwt = (payload: Record<string, unknown>) => [b64url({ alg: "HS256", typ: "JWT" }), b64url(payload), rand(43, undefined, 11)].join(".");

const P = (...parts: string[]) => parts.join("");

/** One fake value per rule: [ruleId, text containing the value, the value itself]. */
export function fakeKeys(): [string, string, string][] {
  const awsId = P("AK", "IA", rand(16, "ABCDEFGHJKLMNPQRSTUVWXYZ234567", 13));
  const awsSecret = rand(40, undefined, 17);
  const twilioSid = P("A", "C", hex(32, 19));
  const twilioToken = hex(32, 23);
  const v = {
    service: jwt({ iss: "supabase", ref: rand(20, "abcdefghjkmnpqrstuvw", 29), role: "service_role" }),
    anon: jwt({ iss: "supabase", ref: rand(20, "abcdefghjkmnpqrstuvw", 31), role: "anon" }),
    live: P("sk", "_live_", rand(28, undefined, 37)),
    restricted: P("rk", "_live_", rand(28, undefined, 41)),
    test: P("sk", "_test_", rand(28, undefined, 43)),
    publishable: P("pk", "_live_", rand(28, undefined, 47)),
    webhook: P("wh", "sec_", rand(32, undefined, 53)),
    ghp: P("gh", "p_", rand(36, undefined, 59)),
    ghpat: P("github", "_pat_", rand(22, undefined, 61), "_", rand(59, undefined, 67)),
    slackBot: P("xo", "xb-", digits(11, 71), "-", digits(12, 73), "-", rand(24, undefined, 79)),
    slackApp: P("xa", "pp-", "1-", rand(10, "ABCDEFGHJKLMNPQRSTUVW23456789", 83), "-", digits(12, 89), "-", hex(64, 97)),
    slackHook: P("https://hooks.", "slack.com/services/T", rand(9, "ABCDEFGHJKLMNPQRSTUVW23456789", 101), "/B", rand(9, "ABCDEFGHJKLMNPQRSTUVW23456789", 103), "/", rand(24, undefined, 107)),
    hf: P("h", "f_", rand(34, undefined, 109)),
    groq: P("gs", "k_", rand(52, undefined, 113)),
    replicate: P("r", "8_", rand(37, undefined, 127)),
    mailgun: P("ke", "y-", hex(32, 131)),
    twilioKey: P("S", "K", hex(32, 137)),
    anthropic: P("sk-", "ant-", "api03-", rand(90, undefined, 139)),
    openaiProj: P("sk-", "proj-", rand(56, undefined, 149)),
    openaiLegacy: P("sk-", rand(20, undefined, 151), "T3Blbk", "FJ", rand(20, undefined, 157)),
    openai48: P("sk-", rand(48, undefined, 163)),
    resend: P("r", "e_", rand(10, undefined, 167), "_", rand(20, undefined, 173)),
    sendgrid: P("S", "G.", rand(22, undefined, 179), ".", rand(43, undefined, 181)),
    privateKey: P("-----BEGIN ", "RSA PRIVATE", " KEY-----"),
    firebase: P("AI", "za", rand(35, undefined, 191)),
    namedEnv: rand(32, undefined, 193),
  };
  return [
    ["secret.supabase_service_role", `const k = "${v.service}";`, v.service],
    ["public.supabase_anon", `const k = "${v.anon}";`, v.anon],
    ["secret.stripe_live", `STRIPE_KEY=${v.live}`, v.live],
    ["secret.stripe_restricted", `key: "${v.restricted}"`, v.restricted],
    ["secret.stripe_test", `key: "${v.test}"`, v.test],
    ["public.stripe_publishable", `key: "${v.publishable}"`, v.publishable],
    ["secret.stripe_webhook", `hook = "${v.webhook}"`, v.webhook],
    ["secret.github", `token=${v.ghp}`, v.ghp],
    ["secret.github", `token=${v.ghpat}`, v.ghpat],
    ["secret.slack", `slack=${v.slackBot}`, v.slackBot],
    ["secret.slack", `slack=${v.slackApp}`, v.slackApp],
    ["secret.slack", `url = "${v.slackHook}"`, v.slackHook],
    ["secret.huggingface", `hf = "${v.hf}"`, v.hf],
    ["secret.groq", `groq = "${v.groq}"`, v.groq],
    ["secret.replicate", `rep = "${v.replicate}"`, v.replicate],
    ["secret.mailgun", `mg = "${v.mailgun}"`, v.mailgun],
    ["secret.twilio", `// twilio\nconst apiKey = "${v.twilioKey}";`, v.twilioKey],
    ["secret.anthropic", `a = "${v.anthropic}"`, v.anthropic],
    ["secret.openai", `o = "${v.openaiProj}"`, v.openaiProj],
    ["secret.openai", `o = "${v.openaiLegacy}"`, v.openaiLegacy],
    ["secret.openai", `o = "${v.openai48}"`, v.openai48],
    ["secret.resend", `r = "${v.resend}"`, v.resend],
    ["secret.sendgrid", `s = "${v.sendgrid}"`, v.sendgrid],
    ["secret.private_key", `${v.privateKey}\nMIIE${rand(60, undefined, 197)}`, v.privateKey],
    ["public.firebase_web", `apiKey: "${v.firebase}"`, v.firebase],
    ["secret.twilio", `const sid = "${twilioSid}";\nconst authToken = "${twilioToken}";`, twilioToken],
    ["secret.aws_key_id", `const id = "${awsId}";`, awsId],
    ["secret.aws", `const id = "${awsId}";\nconst secretAccessKey = "${awsSecret}";`, awsId],
    ["secret.named_env", `VITE_${"STRIPE"}_SECRET="${v.namedEnv}"`, v.namedEnv],
  ];
}

/** A fake Stripe live key for the CLI tests. */
export const fakeStripeLive = () => P("sk", "_live_", rand(28, undefined, 211));

export function tempDir(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "yof-test-"));
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), c); }
  return dir;
}

/** git, isolated from the machine's own git config (no global hooksPath, no templates). */
export const testGit: GitRunner = (args, cwd) => execFileSync("git", args, {
  cwd, stdio: ["ignore", "pipe", "pipe"],
  env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_TEMPLATE_DIR: "" },
});

/** A mocked registry: a map from URL (or URL prefix) to a response. Unknown URLs → status 0 (no answer). */
export function mockFetcher(routes: Record<string, PackageResponse>, calls: string[] = []): PackageFetcher {
  return async (url, init) => {
    calls.push(`${init?.method ?? "GET"} ${url}`);
    return routes[url] ?? { status: 0 };
  };
}

export interface Captured { out: string[]; err: string[] }
export function captureIo(cwd: string, extra: Partial<{ fetcher: PackageFetcher; git: GitRunner; now: Date }> = {}) {
  const cap: Captured = { out: [], err: [] };
  return { cap, io: { cwd, out: (s: string) => cap.out.push(s), err: (s: string) => cap.err.push(s), git: testGit, ...extra } };
}
