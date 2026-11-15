/**
 * yof attack: may this host be attacked at all? Nothing is sent to a target before this says yes.
 *
 *   local       localhost, 127.0.0.1 or ::1 (your own machine). http is allowed only here.
 *   preview     a deployment of THIS repository that GitHub reports as successful for the commit under test (the
 *               GitHub Actions token reads it), at an address that is ALSO one of this repository's own:
 *                 - a preview address on Vercel, Netlify or Cloudflare Pages named after the repository (or, on
 *                   Vercel, after the project the deployment names), when the deployment status was written by that
 *                   platform's own GitHub app (a status anyone with write access wrote proves nothing: security
 *                   audit 3.2), or
 *                 - a host on the same site (registrable domain) as the config's app, once yof confirms the app is
 *                   proven for your account (below). On shared hosting (github.io, vercel.app, ...) two customers
 *                   are never one site: see TENANT_SUFFIXES.
 *               A deployment status alone names any host its repository writes, so it is never proof on its own
 *               (security audit A5, 11 Nov 2026). A deployment GitHub marks as production, an environment whose name
 *               starts with prod, production or live ("Production – shop" is how Vercel names one), and the app's
 *               own host all count as production.
 *   production  any other https host: the config's app, proven for YOUR yof account. The CLI asks yof (account.ts,
 *               with YOF_HOOK_URL or YOF_API_KEY); yof answers from the account. The proof token on the site is
 *               public, so finding it there proves nothing about who is running this (security audit 3.2), and the
 *               CLI no longer reads it. No answer, or yof not reachable, means the host is not tested.
 *
 * Then the production rule: never against production unless the config turns it on for this app
 * ("production": { "enabled": true }). With it on, a light (read-only) run may go any time; a full run only inside the
 * agreed window ("window": "02:00-04:00", UTC).
 */
import { askYofProven } from "./account";
import { inWindow, type AttackConfig } from "./config";
import { USER_AGENT, type FetchFn } from "./http";

export type TargetKind = "local" | "preview" | "production";
export type ProofMethod = "local" | "github-deployment" | "file" | "meta" | "dns";
export type Mode = "full" | "light";

export interface ProofOk { ok: true; kind: TargetKind; method: ProofMethod; origin: string; host: string }
export interface ProofRefused { ok: false; code: "bad_url" | "not_https" | "not_proven" | "not_this_app" | "production_off" | "outside_window"; message: string }
export type ProofResult = ProofOk | ProofRefused;

export interface ProofDeps {
  fetch?: FetchFn;
  env?: Record<string, string | undefined>;
  now?: Date;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const GITHUB_API_DEFAULT = "https://api.github.com";

/**
 * A deployment environment that is production by name, whatever GitHub's production flag says. The name STARTS with
 * prod, production or live as a whole word. Read from real deployments (11 Nov 2026): Vercel's GitHub app writes
 * "Production" for a repository with one project and "Production – <project>" for one with several, and sets
 * production_environment to false on both, so the flag alone and an exact-name match both missed a production build.
 */
export const PRODUCTION_ENV = /^(?:prod|production|live)(?![a-z0-9])/i;

/**
 * The project a platform names in a deployment's environment ("Preview – shop-web", "Production – shop-web": Vercel,
 * for a repository with several projects), spelled as it appears in a host name. Null when the name carries none. Pure.
 */
export function environmentProject(environment: string | null | undefined): string | null {
  const m = /^(?:preview|production)\s+[–—-]\s+(\S.*)$/i.exec((environment ?? "").trim());
  const slug = (m?.[1] ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return slug || null;
}

/** Second-level labels under a two-letter country code that sell names (example.co.uk, example.com.au). */
const PUBLIC_SECOND = new Set(["co", "com", "net", "org", "gov", "ac", "edu", "ltd", "plc", "ne", "or"]);

/**
 * Shared hosting where every customer gets a name under the suffix (security audit 3.2, 11 Nov 2026). Without this,
 * attacker.github.io and victim.github.io read as one site, "github.io". Here the site is ONE label deeper than the
 * suffix: victim.github.io, and <branch>.<project>.pages.dev belongs to <project>.pages.dev. A short explicit list, no
 * download and no dependency; a suffix that is missing falls back to the usual shape, so add it here.
 */
export const TENANT_SUFFIXES: readonly string[] = [
  "github.io", "gitlab.io", "bitbucket.io", "codeberg.page", "vercel.app", "now.sh", "netlify.app", "netlify.com", "pages.dev", "workers.dev",
  "web.app", "firebaseapp.com", "herokuapp.com", "onrender.com", "fly.dev", "cloudfront.net", "amplifyapp.com", "ondigitalocean.app",
  "deno.dev", "surge.sh", "glitch.me", "repl.co", "replit.app", "koyeb.app", "zeabur.app", "kinsta.app", "edgeone.app", "streamlit.app",
  "hf.space", "webflow.io", "framer.app", "framer.website", "lovable.app", "bubbleapps.io", "csb.app", "codesandbox.io", "stackblitz.io",
  "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok-free.dev", "trycloudflare.com", "loca.lt", "supabase.co", "myshopify.com",
  "wordpress.com", "blogspot.com", "wixsite.com", "notion.site", "gitbook.io", "readthedocs.io", "neocities.org", "pythonanywhere.com",
  "cloudfunctions.net", "firebaseio.com", "convex.site", "convex.cloud", "modal.run", "shuttleapp.rs",
];
/**
 * Shared hosting whose names have deeper or mixed shapes (bucket.s3.eu-west-1.amazonaws.com, app.scm.azurewebsites.net,
 * service-hash-uc.a.run.app). No rule of thumb is safe there, so only the exact host is "the same site".
 */
export const EXACT_HOST_SUFFIXES: readonly string[] = [
  "amazonaws.com", "amazonaws.com.cn", "elasticbeanstalk.com", "awsapprunner.com", "azurewebsites.net", "azurestaticapps.net", "azureedge.net",
  "azurefd.net", "windows.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "appspot.com", "run.app", "googleusercontent.com",
  "railway.app", "northflank.app", "replit.dev", "github.dev", "githubpreview.dev", "gitpod.io", "vusercontent.net", "webcontainer.io",
  "digitaloceanspaces.com", "r2.dev", "backblazeb2.com", "fastly.net", "akamaized.net", "edgekey.net", "cdn.cloudflare.net",
];
const underSuffix = (host: string, list: readonly string[]): string | null => {
  let best: string | null = null;
  for (const suffix of list) if ((host === suffix || host.endsWith(`.${suffix}`)) && (!best || suffix.length > best.length)) best = suffix;
  return best;
};

/**
 * The registrable domain ("site") of a host. No public-suffix list is downloaded: the usual shapes, plus the explicit
 * shared-hosting lists above, where two customers never count as one site. Pure.
 */
export function registrableDomain(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, "");
  const labels = h.split(".").filter(Boolean);
  if (underSuffix(h, EXACT_HOST_SUFFIXES)) return labels.join(".");
  const tenant = underSuffix(h, TENANT_SUFFIXES);
  if (tenant) return labels.slice(-Math.min(labels.length, tenant.split(".").length + 1)).join(".");
  if (labels.length <= 2) return labels.join(".");
  const tld = labels[labels.length - 1]!, second = labels[labels.length - 2]!;
  const n = tld.length === 2 && PUBLIC_SECOND.has(second) ? 3 : 2;
  return labels.slice(-n).join(".");
}
/** Are two hosts on the same site? The same host, or the same registrable domain; never through a bare hosting suffix. Pure. */
export const sameSite = (a: string, b: string): boolean => {
  const x = a.toLowerCase().replace(/\.$/, ""), y = b.toLowerCase().replace(/\.$/, "");
  if (x === y) return true;
  // A bare suffix ("github.io" as the app) owns nothing under it.
  if (TENANT_SUFFIXES.includes(x) || TENANT_SUFFIXES.includes(y) || EXACT_HOST_SUFFIXES.includes(x) || EXACT_HOST_SUFFIXES.includes(y)) return false;
  return registrableDomain(x) === registrableDomain(y);
};

/** The repository's name as hosting platforms spell a project ("Acme/My_Shop" -> "my-shop"). Pure. */
export function repoSlug(repo: string): string {
  const name = repo.split("/")[1] ?? "";
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

/**
 * Is `host` a preview address of THIS repository on a hosting platform whose preview names carry the project name?
 *   Vercel   <project>.vercel.app, <project>-<hash>-<team>.vercel.app, <project>-git-<branch>-<team>.vercel.app
 *   Netlify  <site>.netlify.app, deploy-preview-<n>--<site>.netlify.app, <branch>--<site>.netlify.app
 *   Pages    <project>.pages.dev, <hash>.<project>.pages.dev, <branch>.<project>.pages.dev
 * `vercelProject`: the project Vercel's own app named in the deployment's environment (environmentProject). A
 * repository with several Vercel projects has previews named after each project, not after the repository; the caller
 * passes it only when Vercel's app wrote both the deployment and its status.
 * Pure.
 */
export function previewPlatformMatch(host: string, repo: string, vercelProject?: string | null): boolean {
  const slug = repoSlug(repo);
  if (!slug) return false;
  const h = host.toLowerCase();
  const sub = (suffix: string) => (h.endsWith(`.${suffix}`) ? h.slice(0, -(suffix.length + 1)).split(".") : null);
  const v = sub("vercel.app");
  if (v) return v.length === 1 && [slug, ...(vercelProject ? [vercelProject] : [])].some((s) => v[0] === s || v[0]!.startsWith(`${s}-`));
  const n = sub("netlify.app");
  if (n) return n.length === 1 && (n[0] === slug || n[0]!.endsWith(`--${slug}`));
  const p = sub("pages.dev");
  if (p) return p.length <= 2 && p[p.length - 1] === slug;
  return false;
}

/**
 * The GitHub apps of the hosting platforms above. A repository's name is picked by whoever creates it, and anyone with
 * write access can write a deployment status naming any address (security audit 3.2, 11 Nov 2026): a repository called
 * "shop" plus a status naming shop-git-x-victim.vercel.app proved nothing. So a platform preview counts only when the
 * status was written by the platform's own GitHub app, which reports only addresses of projects linked to this
 * repository. GitHub sets the author of a status; an app's login ("name[bot]") cannot be taken by a person.
 *
 * Checked against real deployments on 11 Nov 2026 (public repositories, GitHub's REST API; the shape is kept in
 * test/fixtures/github-vercel-deployments.json): Vercel's deployments and their statuses carry creator.login
 * "vercel[bot]" with creator.type "Bot", and the preview address is in environment_url. The Netlify and Cloudflare
 * names below are from those platforms' documentation and were not seen on a real deployment.
 */
const PLATFORM_APPS: readonly { suffix: string; name: string; logins: readonly string[] }[] = [
  { suffix: "vercel.app", name: "Vercel", logins: ["vercel[bot]"] },
  { suffix: "netlify.app", name: "Netlify", logins: ["netlify[bot]"] },
  { suffix: "pages.dev", name: "Cloudflare Pages", logins: ["cloudflare-workers-and-pages[bot]", "cloudflare-pages[bot]"] },
];
/** The platform a preview host is on, and whether the status author is that platform's own app. Pure. */
export function platformAuthor(host: string, author: { login?: string; type?: string } | null | undefined): { platform: string; own: boolean } | null {
  const h = host.toLowerCase();
  const app = PLATFORM_APPS.find((x) => h.endsWith(`.${x.suffix}`));
  if (!app) return null;
  return { platform: app.name, own: !!author && author.type === "Bot" && app.logins.includes(String(author.login ?? "").toLowerCase()) };
}

export function parseTarget(raw: string): { ok: true; url: URL } | ProofRefused {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return { ok: false, code: "bad_url", message: `Not a web address: ${raw.slice(0, 80)}` }; }
  if (u.username || u.password) return { ok: false, code: "bad_url", message: "The address may not carry a user name or password." };
  if (u.protocol === "http:" && !LOOPBACK.has(u.hostname)) return { ok: false, code: "not_https", message: "yof attack tests https addresses (http only on localhost)." };
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, code: "bad_url", message: "Use an http(s) address." };
  return { ok: true, url: u };
}

type GitHubActor = { login?: string; type?: string } | null;
export interface DeploymentProof {
  kind: "preview" | "production";
  url: string;
  /** Who wrote the successful status (GitHub sets it). */
  author: GitHubActor;
  /** Who created the deployment itself, and the environment name they gave it. */
  deployer: GitHubActor;
  environment: string | null;
}

/**
 * A preview proven by GitHub: a successful deployment status of this repository, for this commit, whose address is
 * the target. Read with the workflow's own GITHUB_TOKEN; nothing is written.
 */
export async function githubDeploymentProof(host: string, env: Record<string, string | undefined>, f: FetchFn): Promise<DeploymentProof | null> {
  const token = env.GITHUB_TOKEN, repo = env.GITHUB_REPOSITORY, sha = env.YOF_HEAD_SHA ?? env.GITHUB_SHA;
  if (!token || !repo || !sha || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !/^[0-9a-f]{7,64}$/.test(sha)) return null;
  const api = (env.GITHUB_API_URL ?? GITHUB_API_DEFAULT).replace(/\/$/, "");
  if (!/^https:\/\//i.test(api)) return null;   // the token never goes to a plain-http "API"
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": USER_AGENT };
  const get = async <T>(p: string): Promise<T | null> => {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 10_000);
    try { const r = await f(`${api}${p}`, { method: "GET", headers, redirect: "manual", signal: ctl.signal }); return r.ok ? ((await r.json()) as T) : null; }
    catch { return null; } finally { clearTimeout(t); }
  };
  const actor = (a: GitHubActor | undefined): GitHubActor => (a ? { login: a.login, type: a.type } : null);
  const deployments = await get<{ id: number; environment?: string; production_environment?: boolean; creator?: GitHubActor }[]>(`/repos/${repo}/deployments?sha=${sha}&per_page=30`);
  for (const d of deployments ?? []) {
    const statuses = await get<{ state?: string; environment_url?: string; target_url?: string; creator?: { login?: string; type?: string } | null }[]>(`/repos/${repo}/deployments/${d.id}/statuses?per_page=10`);
    for (const s of statuses ?? []) {
      if (s.state !== "success") continue;
      // The environment address only (security audit A5): target_url is a log or details page, not the deployment.
      const u = s.environment_url;
      if (!u) continue;
      try {
        if (new URL(u).hostname.toLowerCase() === host) {
          const production = d.production_environment === true || PRODUCTION_ENV.test(d.environment ?? "");
          return { kind: production ? "production" : "preview", url: u, author: actor(s.creator), deployer: actor(d.creator), environment: d.environment ?? null };
        }
      } catch { /* not an address */ }
    }
  }
  return null;
}

/** The preview address GitHub reports for this commit (for a pull-request run that was given no address). */
export async function findPreviewUrl(env: Record<string, string | undefined>, f: FetchFn = (u, i) => fetch(u, i)): Promise<string | null> {
  const token = env.GITHUB_TOKEN, repo = env.GITHUB_REPOSITORY, sha = env.YOF_HEAD_SHA ?? env.GITHUB_SHA;
  if (!token || !repo || !sha) return null;
  const api = (env.GITHUB_API_URL ?? GITHUB_API_DEFAULT).replace(/\/$/, "");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": USER_AGENT };
  try {
    const r = await f(`${api}/repos/${repo}/deployments?sha=${sha}&per_page=30`, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return null;
    for (const d of (await r.json()) as { id: number; environment?: string; production_environment?: boolean }[]) {
      if (d.production_environment || PRODUCTION_ENV.test(d.environment ?? "")) continue;
      const s = await f(`${api}/repos/${repo}/deployments/${d.id}/statuses?per_page=10`, { method: "GET", headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
      if (!s.ok) continue;
      const ok = ((await s.json()) as { state?: string; environment_url?: string }[]).find((x) => x.state === "success" && x.environment_url);
      if (ok?.environment_url) return ok.environment_url;
    }
  } catch { return null; }
  return null;
}

/** May `target` be attacked in this mode? The one gate every run passes first. */
export async function proveTarget(target: string, cfg: AttackConfig, mode: Mode, deps: ProofDeps = {}): Promise<ProofResult> {
  const parsed = parseTarget(target);
  if (!parsed.ok) return parsed;
  const u = parsed.url;
  const host = u.hostname.toLowerCase();
  const origin = u.origin;
  const env = deps.env ?? process.env;
  const f: FetchFn = deps.fetch ?? ((url, init) => fetch(url, init));

  if (LOOPBACK.has(host)) return { ok: true, kind: "local", method: "local", origin, host };

  let kind: TargetKind | null = null;
  let method: ProofMethod | null = null;
  const appHost = cfg.app.replace(/:\d+$/, "").toLowerCase();
  const isAppHost = host === appHost || host === `www.${appHost}` || `www.${host}` === appHost;
  const dep = await githubDeploymentProof(host, env, f);
  if (dep) {
    // A deployment status names whatever host its repository writes (security audit A5, 11 Nov 2026), so the host must
    // also be this repository's own: a platform preview named after it, or the app's own site with the app proven.
    const author = platformAuthor(host, dep.author);
    // The project name in the environment counts only when the platform's own app wrote the deployment AND its status.
    const project = author?.own && platformAuthor(host, dep.deployer)?.own ? environmentProject(dep.environment) : null;
    const named = previewPlatformMatch(host, env.GITHUB_REPOSITORY ?? "", project);
    if (!(named && author?.own)) {
      if (!sameSite(host, appHost)) {
        return {
          ok: false, code: "not_this_app",
          message: named && author
            ? `GitHub reports a deployment at ${host}, but the report was not written by ${author.platform}'s own GitHub app, so it does not show that the address belongs to this repository. Connect the repository to ${author.platform} (its app then reports each preview), or test a host on ${cfg.app}'s own domain.`
            : `GitHub reports a deployment at ${host}, but it is not a preview address of this repository and not on ${cfg.app}'s own domain.`,
        };
      }
      // On the app's own domain: the app must be proven for the account running this (account.ts). Fail closed.
      const mine = await askYofProven(appHost, env, f);
      if (!mine.ok) return { ok: false, code: "not_proven", message: host === appHost ? mine.message : `${host} is on ${cfg.app}'s domain, so ${cfg.app} must be yours first. ${mine.message}` };
    }
    // The production switch and window are never skipped: production by GitHub's flag, by name, or the app itself.
    kind = dep.kind === "production" || isAppHost ? "production" : "preview";
    method = "github-deployment";
  }
  else {
    if (!isAppHost) {
      return { ok: false, code: "not_this_app", message: `${host} is not ${cfg.app}, the app named in the config, and GitHub reports no deployment of this repository there.` };
    }
    // A live host is tested only when yof says it is proven for the account running this (account.ts). A proof token
    // found on the site is public and proves nothing about who is asking, so it is not read. Fail closed.
    const mine = await askYofProven(host, env, f);
    if (!mine.ok) return { ok: false, code: "not_proven", message: mine.message };
    method = mine.method;
    kind = "production";
  }

  if (kind === "production") {
    if (!cfg.production.enabled) return { ok: false, code: "production_off", message: `${host} is production. Turn it on for this app with "production": { "enabled": true } in the config.` };
    if (mode === "full" && !(cfg.production.window && inWindow(cfg.production.window, deps.now ?? new Date()))) {
      return { ok: false, code: "outside_window", message: `A full run on production only goes inside the agreed window${cfg.production.window ? ` (${cfg.production.window} UTC)` : ' ("production.window" is not set)'}. A light, read-only run may go now: --mode light.` };
    }
  }
  return { ok: true, kind, method, origin, host };
}
