/**
 * The hosting platform's own GitHub app, against the shape of REAL deployments (fixtures/github-vercel-deployments.json,
 * read from public repositories on 11 Nov 2026; names made up). Until then the bot login and the environment names in
 * proof.ts had never been compared with a real deployment. What the real shape showed:
 *   - Vercel's app is creator.login "vercel[bot]", creator.type "Bot", on the deployment and on each status: as coded;
 *   - production_environment is false even for production, and the environment is "Production" or, in a repository
 *     with several projects, "Production – <project>": an exact-name match missed the second form, so a production
 *     build on a vercel.app address read as a preview and skipped the production switch;
 *   - with several projects the preview host is named after the project, not the repository.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { parseAttackConfig } from "../src/attack/config";
import { environmentProject, findPreviewUrl, githubDeploymentProof, platformAuthor, previewPlatformMatch, PRODUCTION_ENV, proveTarget } from "../src/attack/proof";
import { fakeConfig } from "./fake-app";

interface Actor { login: string; id?: number; type: string }
interface Fixture {
  sha: string;
  deployments: { id: number; environment: string; production_environment: boolean; creator: Actor }[];
  statuses: Record<string, { state: string; environment_url: string; target_url: string; creator: Actor }[]>;
}
const real = JSON.parse(readFileSync(join(__dirname, "fixtures", "github-vercel-deployments.json"), "utf8")) as Fixture;

/** GitHub's API answering from the fixture; `edit` changes a copy first. */
function github(edit: (fx: Fixture) => void = () => {}) {
  const fx = JSON.parse(JSON.stringify(real)) as Fixture;
  edit(fx);
  return async (u: string) => {
    if (u.includes("/deployments?sha=")) return Response.json(fx.deployments);
    const m = /\/deployments\/(\d+)\/statuses/.exec(u);
    if (m) return Response.json(fx.statuses[m[1]!] ?? []);
    return new Response("", { status: 404 });
  };
}
const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "acme/shop", YOF_HEAD_SHA: real.sha };
const cfg = parseAttackConfig(fakeConfig({ app: "shop.example.com", consent: consentText("shop.example.com") }));
const url = (id: number) => real.statuses[String(id)]![0]!.environment_url;
const host = (id: number) => new URL(url(id)).hostname;

describe("the platform's own GitHub app, as real deployments look", () => {
  it("the fixture is what Vercel's app writes: vercel[bot], type Bot, on deployments and statuses; the flag is false", () => {
    for (const d of real.deployments) {
      expect(d.creator).toMatchObject({ login: "vercel[bot]", type: "Bot" });
      expect(d.production_environment).toBe(false);
      for (const s of real.statuses[String(d.id)]!) {
        expect(s.creator).toMatchObject({ login: "vercel[bot]", type: "Bot" });
        expect(platformAuthor(new URL(s.environment_url).hostname, s.creator)).toEqual({ platform: "Vercel", own: true });
      }
    }
  });

  it("production by name: Vercel's real names count, a preview does not", () => {
    for (const name of ["Production", "production", "Production – shop-web", "Production - shop-web", "prod", "prod-eu", "live", "Live (EU)"]) expect(PRODUCTION_ENV.test(name), name).toBe(true);
    for (const name of ["Preview", "Preview – shop-web", "Preview – production-site", "staging", "liveblog", "productive", "pre-production", ""]) expect(PRODUCTION_ENV.test(name), name).toBe(false);
  });

  it("the project in the environment name", () => {
    expect(environmentProject("Preview – shop-web")).toBe("shop-web");
    expect(environmentProject("Production – Shop_Web")).toBe("shop-web");
    expect(environmentProject("Preview - shop-web")).toBe("shop-web");
    for (const none of ["Preview", "Production", "staging – shop-web", "Preview –", "", null, undefined]) expect(environmentProject(none), String(none)).toBeNull();
  });

  it("a real preview is proven and reads as preview, for one project and for several", async () => {
    for (const id of [7000000001, 7000000004]) {
      const dep = await githubDeploymentProof(host(id), env, github());
      expect(dep, String(id)).toMatchObject({ kind: "preview", url: url(id), author: { login: "vercel[bot]", type: "Bot" }, deployer: { login: "vercel[bot]", type: "Bot" } });
      expect(await proveTarget(url(id), cfg, "full", { fetch: github(), env }), String(id)).toMatchObject({ ok: true, kind: "preview", method: "github-deployment" });
    }
  });

  it("a real production deployment is production, so the production switch applies (it read as a preview before)", async () => {
    for (const id of [7000000002, 7000000003]) {
      expect(await githubDeploymentProof(host(id), env, github()), String(id)).toMatchObject({ kind: "production" });
      expect(await proveTarget(url(id), cfg, "full", { fetch: github(), env }), String(id)).toMatchObject({ ok: false, code: "production_off" });
    }
  });

  it("with no address given, the preview is picked, never a production deployment", async () => {
    expect(await findPreviewUrl(env, github())).toBe(url(7000000001));
    expect(await findPreviewUrl(env, github((fx) => { fx.deployments = fx.deployments.filter((d) => d.environment.startsWith("Production")); }))).toBeNull();
  });

  it("a host named after the project counts only when Vercel's app wrote the deployment AND its status", async () => {
    const h = host(7000000001);   // shop-web-…: named after the project, and (as it happens) after the repository "shop" too
    expect(previewPlatformMatch(h, "acme/shop", "shop-web")).toBe(true);
    // A repository whose name is not in the host at all: only the project name can match.
    const other = { ...env, GITHUB_REPOSITORY: "acme/monorepo" };
    expect(previewPlatformMatch(h, "acme/monorepo")).toBe(false);
    expect(await proveTarget(url(7000000001), cfg, "full", { fetch: github(), env: other })).toMatchObject({ ok: true, kind: "preview" });
    // The environment name is written by whoever creates the deployment: a person's deployment naming a project proves nothing.
    const byPerson = github((fx) => { fx.deployments[0]!.creator = { login: "mallory", type: "User" }; });
    expect(await proveTarget(url(7000000001), cfg, "full", { fetch: byPerson, env: other })).toMatchObject({ ok: false, code: "not_this_app" });
    // And a status written by a person on Vercel's deployment proves nothing either.
    const statusByPerson = github((fx) => { fx.statuses["7000000001"]![0]!.creator = { login: "github-actions[bot]", type: "Bot" }; });
    expect(await proveTarget(url(7000000001), cfg, "full", { fetch: statusByPerson, env: other })).toMatchObject({ ok: false, code: "not_this_app" });
    // The project name never reaches another platform's hosts, or a host that only shares a prefix.
    expect(previewPlatformMatch("deploy-preview-4--shop-web.netlify.app", "acme/monorepo", "shop-web")).toBe(false);
    expect(previewPlatformMatch("shop-webmaster-x.vercel.app", "acme/monorepo", "shop-web")).toBe(false);
  });
});
