/**
 * yof attack: is this host proven for YOUR yof account? (security audit 3.2, 11 Nov 2026)
 *
 * Before, a live host counted as yours when your app's proof token was found on it. That token is public by design:
 * it sits in a file, a meta tag or a DNS record for anyone to read, so a person who copied it into their own run
 * passed for a site that is not theirs. Now the CLI asks yof, and yof answers from the account: the host must be one
 * of your own apps, proven in the yof app. A copied token proves nothing, because it is never read here.
 *
 * Who is asking, one of:
 *   YOF_HOOK_URL   the upload address from your app's Attack tests page (the same secret `--upload` sends results to)
 *   YOF_API_KEY    a key from the yof app, Connect your AI builder (the same key `yof mcp` uses)
 *
 * What is sent: the host name, nothing else. What comes back: yes or no, and how the app was proven.
 *
 * Fail closed: no credential, no answer, an answer that is not a clear yes, or yof not reachable all mean the host is
 * NOT tested. Only `yof attack` on a live host needs this; `yof check`, `yof diff`, a run on localhost and a platform
 * preview that GitHub proves keep working without an account and offline as before.
 */
import { USER_AGENT, type FetchFn } from "./http";

export const ACCOUNT_TIMEOUT_MS = 15_000;
export const DEFAULT_ACCOUNT_URL = "https://mcp.yof.io";
const KEY_SHAPE = /^yof_mcp_[A-Za-z0-9_-]{43}$/;
const HOOK_SHAPE = /^https:\/\/[^/\s?#]+\/[^\s?#]+$/;
const LOCAL_TEST = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/;
const METHODS = ["file", "meta", "dns"] as const;
export type AccountMethod = (typeof METHODS)[number];

export type AccountRefusal = "no_account" | "key_refused" | "unreachable" | "not_proven";
export type AccountAnswer = { ok: true; method: AccountMethod } | { ok: false; code: AccountRefusal; message: string };

/** How to prove an app, in one sentence a person can follow. */
export const howToProve = (host: string) =>
  `To prove it: sign in to the yof app at https://yof.io/ and add ${host}, then follow the ownership steps there (a file, a meta tag or a DNS record) and press "Check my proof". Then run this again.`;

/** Where the question goes, and with which credential. The upload address first: it is the one attack runs already hold. */
export function accountEndpoint(env: Record<string, string | undefined>): { url: string; headers: Record<string, string> } | null {
  const hook = (env.YOF_HOOK_URL ?? "").trim().replace(/\/$/, "");
  if (HOOK_SHAPE.test(hook) || LOCAL_TEST.test(hook)) return { url: `${hook}/host-proof`, headers: {} };
  const key = (env.YOF_API_KEY ?? "").trim();
  if (!KEY_SHAPE.test(key)) return null;
  let base = (env.YOF_MCP_URL ?? DEFAULT_ACCOUNT_URL).trim().replace(/\/$/, "").replace(/\/mcp$/, "");
  // Only https (or a local test server), so the key never travels in the clear.
  if (!/^https:\/\//.test(base) && !LOCAL_TEST.test(base)) base = DEFAULT_ACCOUNT_URL;
  return { url: `${base}/host-proof`, headers: { Authorization: `Bearer ${key}` } };
}

/** Ask yof whether `host` is proven for the account behind the credential in `env`. Never throws. */
export async function askYofProven(host: string, env: Record<string, string | undefined>, f: FetchFn = (u, i) => fetch(u, i)): Promise<AccountAnswer> {
  const to = accountEndpoint(env);
  if (!to) {
    return {
      ok: false, code: "no_account",
      message: `yof attack tests ${host} only after yof confirms that it is proven for your account, and this run does not say whose account it is. Set YOF_HOOK_URL (yof app, your app, Attack tests: the upload address) or YOF_API_KEY (yof app, Connect your AI builder) and run this again.`,
    };
  }
  const unreachable = (why: string): AccountAnswer => ({
    ok: false, code: "unreachable",
    message: `${why}, so yof could not confirm that ${host} is proven for your account and nothing was tested. Try again in a minute.`,
  });
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ACCOUNT_TIMEOUT_MS);
  try {
    const r = await f(to.url, {
      method: "POST", redirect: "manual", signal: ctl.signal,
      headers: { ...to.headers, "Content-Type": "application/json", Accept: "application/json", "User-Agent": USER_AGENT },
      body: JSON.stringify({ host }),
    });
    if (r.status === 401 || r.status === 403 || r.status === 404) {
      return { ok: false, code: "key_refused", message: `yof did not accept this run's ${to.headers.Authorization ? "YOF_API_KEY" : "YOF_HOOK_URL"}. It may have been replaced or revoked: copy the current one from the yof app and run this again. Nothing was tested.` };
    }
    if (r.status !== 200) return unreachable(`yof answered ${r.status}`);
    const a = (await r.json().catch(() => null)) as { host?: unknown; proven?: unknown; method?: unknown } | null;
    if (!a || typeof a.proven !== "boolean" || a.host !== host) return unreachable("yof's answer could not be read");
    if (a.proven !== true) return { ok: false, code: "not_proven", message: `${host} is not proven for your yof account. ${howToProve(host)}` };
    const method = METHODS.find((m) => m === a.method);
    if (!method) return unreachable("yof's answer could not be read");
    return { ok: true, method };
  } catch {
    return unreachable(ctl.signal.aborted ? "yof did not answer in time" : "yof could not be reached");
  } finally { clearTimeout(timer); }
}
