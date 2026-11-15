/**
 * yof's public benchmark: the two practice apps it is run against, pinned, and how each item of their OFFICIAL list is
 * scored. Run by .github/workflows/yof-benchmark.yml on GitHub's machines only (owner decision 2026-11-08): nothing
 * deliberately vulnerable is downloaded or started anywhere else. How to run it: docs/YOF_BENCHMARK.md.
 *
 * The official list is read at run time from the SAME commit as the app (Juice Shop: data/static/challenges.yml;
 * NodeGoat: the tutorial menu in app/views/tutorial/layout.html), so a name or a count is never typed in by hand.
 * This file only says, per item key:
 *   tested         yof claims to test this kind of problem. Found when one of the detectors fired, missed otherwise
 *                  (with the reason we expect it to be missed, written BEFORE any run, so a miss is never explained
 *                  away afterwards). relation "same" = the same weakness; "root" = the root cause the item exploits.
 *   not_tested     yof does not test this kind of problem. Listed, never counted as a miss or a find.
 *   not_available  the item cannot happen in this run (turned off by the app in Docker, or it needs a part this run
 *                  does not start). Listed with the reason.
 * Every key not named here is not_tested with the target's default reason. A key named here that is missing from the
 * pinned list fails the scoring (score.ts), so the mapping can never drift silently from the list.
 */

export type Relation = "same" | "root";
export type PackageIssueName = "made_up" | "brand_new" | "lookalike" | "vulnerable";

/** One yof result that counts for an item. Regexes match the file (repository-relative) or the route as configured. */
export type Detector =
  | { source: "key"; rule?: string; file?: RegExp }
  | { source: "package"; issues: PackageIssueName[]; names?: string[]; file?: RegExp }
  | { source: "attack"; rule: string; route?: RegExp };

export type MappingEntry =
  | { key: string; kind: "tested"; relation: Relation; detectors: Detector[]; why: string; ifMissed: string }
  | { key: string; kind: "not_tested" | "not_available"; why: string };

export type ListFormat = "juice-shop-challenges" | "nodegoat-tutorial";

export interface Target {
  id: "juice-shop" | "nodegoat";
  name: string;
  repo: string;
  /** The release tag, when the project tags releases (NodeGoat does not). */
  tag: string | null;
  /** The full commit the source, the list and the running app come from. */
  commit: string;
  /** How the app runs inside the runner. */
  run: string;
  /** Juice Shop: the official image of the same release, pinned by digest. */
  image: { ref: string; digest: string } | null;
  list: { file: string; format: ListFormat; label: string };
  origin: string;
  /** Items the app itself turns off in this environment (Juice Shop's disabledEnv). */
  disabledEnv: string | null;
  defaultNotTested: string;
  mapping: MappingEntry[];
}

const NOT_YOF =
  "Outside what yof checks. yof looks for leaked keys and risky packages in the source, and runs five attack groups against the running app: sign-in bypass, one user reading or changing another user's records, member access to admin routes, assistant probes, and redirects, headers and sign-in limits.";

const NEEDS_MODEL =
  "Needs the shop's AI chatbot, which talks to a local language-model server. The benchmark does not start one, to keep the run short, so yof's assistant probes are not run here.";

/** OWASP Juice Shop v20.3.0 (released 2026-10-11). */
export const JUICE_SHOP: Target = {
  id: "juice-shop",
  name: "OWASP Juice Shop",
  repo: "https://github.com/juice-shop/juice-shop",
  tag: "v20.3.0",
  commit: "f189f521266f42c6bd05884468292000cee852ed",
  run: "The project's official Docker image of the same release, pinned by digest, on 127.0.0.1:3000 inside the runner.",
  image: { ref: "bkimminich/juice-shop:v20.3.0", digest: "sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27" },
  list: { file: "data/static/challenges.yml", format: "juice-shop-challenges", label: "challenges" },
  origin: "http://localhost:3000",
  disabledEnv: "Docker",
  defaultNotTested: NOT_YOF,
  mapping: [
    {
      key: "knownVulnerableComponentChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["express-jwt", "sanitize-html"], file: /^package\.json$/ }],
      why: "The challenge's accepted answers are express-jwt 0.1.3 and sanitize-html 1.4.2, both pinned in package.json. yof's package check looks up exact pinned versions in the OSV advisory database.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "jwtUnsignedChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["jsonwebtoken", "express-jwt"], file: /^package\.json$/ }],
      why: "The shop accepts a token signed with the 'none' algorithm because it pins jsonwebtoken 0.4.0 and express-jwt 0.1.3, which have published advisories for that token check.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "jwtForgedChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["jsonwebtoken", "express-jwt"], file: /^package\.json$/ }],
      why: "The forged token works because the pinned jsonwebtoken 0.4.0 accepts a token signed with the public key as an HMAC secret, the advisory published for versions before 4.2.2.",
      ifMissed: "OSV did not return an advisory for either pinned version, or the registry did not answer during the run.",
    },
    {
      key: "typosquattingNpmChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["lookalike", "made_up"], names: ["epilogue-js"] }],
      why: "A typosquatting package (epilogue-js) the shop once depended on.",
      ifMissed: "The package is named only in ftp/package.json.bak, a backup file. yof reads package.json, requirements files and pyproject.toml, not backups.",
    },
    {
      key: "typosquattingAngularChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["lookalike", "made_up"], names: ["ngy-cookie"] }],
      why: "A typosquatting package (ngy-cookie) in frontend/package.json.",
      ifMissed: "yof flags a lookalike only when the name is one or two letters from a package on its bundled popular list. ngx-cookie, the package it imitates, is not on that list.",
    },
    {
      key: "supplyChainAttackChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], names: ["eslint-scope"] }],
      why: "A compromised eslint-scope release the developers used.",
      ifMissed: "eslint-scope is not pinned in a manifest yof reads; the challenge points at the forgotten backup files under ftp/.",
    },
    {
      key: "basketAccessChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_read", route: /^\/rest\/basket/ }],
      why: "One user reading another user's basket is the cross-user read yof's tenant group tests.",
      ifMissed: "yof's tenant test creates a record holding a marker text and reads it back as account B. A basket holds products, not text yof can mark, so the test cannot be set up for baskets.",
    },
    {
      key: "basketManipulateChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_write", route: /^\/(?:api\/BasketItems|rest\/basket)/ }],
      why: "Changing another user's basket is the cross-user write yof's tenant group tests.",
      ifMissed: "The same limit as View Basket: yof's tenant test needs a record with a text field it can mark, and basket items have none.",
    },
    {
      key: "forgedReviewChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_write", route: /^\/rest\/products\// }],
      why: "Editing another user's review is a cross-user write.",
      ifMissed: "Reviews are changed with the review id in the request body. yof's tenant test needs the id in the address, so it cannot be configured for reviews.",
    },
    {
      key: "adminSectionChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "attack", rule: "attack.rbac_escalation", route: /^\/api\/Users$/ }],
      why: "The administration page is hidden only in the browser. The user list it shows comes from /api/Users, which any signed-in member can read.",
      ifMissed: "yof's member-versus-admin test did not see admin data at /api/Users as a member.",
    },
    {
      key: "redirectChallenge", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.open_redirect", route: /^\/redirect/ }],
      why: "An open redirect through /redirect?to=.",
      ifMissed: "The shop allows a redirect when an allowed address appears anywhere in the link. yof's probe sends a plain outside address, which the shop refuses.",
    },
    {
      key: "weakPasswordChallenge", kind: "tested", relation: "root",
      detectors: [{ source: "attack", rule: "attack.no_rate_limit", route: /^\/rest\/user\/login$/ }],
      why: "Nothing slows down password guessing at sign-in, which is how the admin's weak password can be found by trying.",
      ifMissed: "Twelve wrong passwords in a row were slowed down or refused.",
    },
    { key: "chatbotPromptInjectionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "chatbotGreedyInjectionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "systemPromptExtractionChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "aiDebuggingChallenge", kind: "not_available", why: NEEDS_MODEL },
    { key: "leakedApiKeyChallenge", kind: "not_available", why: "The key is not in the shop's source code: it sits in a separate scheduled job, so no source check of this repository can find it." },
    { key: "exposedCredentialsChallenge", kind: "not_tested", why: "yof finds keys by their exact shape. An email address and a password written in code have no shape it can tell apart from ordinary text." },
    { key: "vulnerableDockerImageChallenge", kind: "not_tested", why: "yof does not read Dockerfiles or container images." },
    { key: "exposedMetricsChallenge", kind: "not_tested", why: "yof attack tests the routes its config lists. It does not search for unlisted pages such as /metrics." },
  ],
};

/** OWASP NodeGoat, master at 2023-06-21 (the project does not tag releases). */
export const NODEGOAT: Target = {
  id: "nodegoat",
  name: "OWASP NodeGoat",
  repo: "https://github.com/OWASP/NodeGoat",
  tag: null,
  commit: "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
  run: "Built from its own Dockerfile at the pinned commit, with MongoDB 4.4.29 (pinned by digest), on 127.0.0.1:4000 inside the runner.",
  image: null,
  list: { file: "app/views/tutorial/layout.html", format: "nodegoat-tutorial", label: "tutorial topics" },
  origin: "http://localhost:4000",
  disabledEnv: null,
  defaultNotTested: NOT_YOF,
  mapping: [
    {
      key: "a2", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.no_rate_limit" }, { source: "attack", rule: "attack.weak_session_cookie" }],
      why: "Unlimited password guessing and weak session cookie flags are the sign-in checks of yof's surface group.",
      ifMissed: "yof's sign-in checks need a sign-in route that answers 2xx with a token or a cookie. NodeGoat answers its sign-in with a redirect, so the benchmark signs in itself and those two checks cannot run.",
    },
    {
      key: "a4", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.tenant_read", route: /^\/allocations/ }],
      why: "Reading another user's allocations by changing the user id in the address.",
      ifMissed: "yof's tenant test creates its own record through a JSON API and reads it back as account B. NodeGoat's pages are server-rendered forms with no such API, so the test cannot be set up.",
    },
    {
      key: "a5", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.missing_headers" }],
      why: "The fix the app documents for this topic (server.js, \"Fix for A5\") adds the security headers that yof's surface group checks for.",
      ifMissed: "yof saw the security headers it checks for.",
    },
    {
      key: "a7", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.rbac_escalation", route: /^\/benefits$/ }],
      why: "A normal member opening the admin-only benefits page.",
      ifMissed: "yof compares JSON answers to decide whether a member got admin data. /benefits answers an HTML page that differs per user, so yof cannot tell the member's page from the admin's.",
    },
    {
      key: "a9", kind: "tested", relation: "same",
      detectors: [{ source: "package", issues: ["vulnerable"], file: /^package\.json$/ }],
      why: "Dependencies with published advisories, which yof's package check looks up for exact pinned versions.",
      ifMissed: "OSV returned no advisory for an exactly pinned version in package.json (yof checks exact pins only), or the registry did not answer.",
    },
    {
      key: "a10", kind: "tested", relation: "same",
      detectors: [{ source: "attack", rule: "attack.open_redirect", route: /^\/learn/ }],
      why: "An open redirect through /learn?url=.",
      ifMissed: "The redirect sits behind sign-in, and yof's redirect probe runs signed out.",
    },
  ],
};

export const TARGETS: readonly Target[] = [JUICE_SHOP, NODEGOAT];
export const targetById = (id: string): Target | undefined => TARGETS.find((t) => t.id === id);

// ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
// Engagement library (Y24 stage 4): the seeded fixture (oss/yof/test/fixtures/vuln-app.ts). It holds one instance of
// each attack class and a safe twin, so every technique has a known true hit and a known true miss. This is NOT one
// of the public TARGETS above (it has no external official list to score against): it is the private seed set the
// design calls for. NOT YET RUN as a scored benchmark here, only as the hit/miss unit test engage-library.test.ts.
// The held-out operators stay for a later private run. Status stays "not_yet_run" until the benchmark run is wired.
// ───────────────────────────────────────────────────────────────────────────────────────────────────────────────

export type FixtureStatus = "not_yet_run";
/** One technique's expected result on the fixture (true hit) and its twin (true miss). */
export interface FixtureExpectation {
  technique: string;
  rule: string;
  /** The expected outcome on the vulnerable app: it must demonstrate or need validation. */
  onVulnerable: "violated" | "needs_validation";
  /** The expected outcome on the safe twin: silence. */
  onTwin: "held" | "not_testable";
  /** A technique whose safety class the default rules forbid (the command marker-echo) is never run; the governor refuses it. */
  governorRefuses?: boolean;
  why: string;
}

export interface FixtureTarget {
  id: "yof-seed-fixture";
  name: string;
  status: FixtureStatus;
  source: string;
  expectations: readonly FixtureExpectation[];
}

export const FIXTURE_BENCH: FixtureTarget = {
  id: "yof-seed-fixture",
  name: "yof seeded fixture (one of each class, plus a safe twin)",
  status: "not_yet_run",
  source: "oss/yof/test/fixtures/vuln-app.ts",
  expectations: [
    { technique: "access.id_swap", rule: "attack.tenant_read", onVulnerable: "violated", onTwin: "held", why: "Another account reads a note by its id on the vulnerable app; the twin answers 404." },
    { technique: "access.anon_read", rule: "attack.auth_bypass", onVulnerable: "violated", onTwin: "held", why: "A note reads with no sign-in on the vulnerable app; the twin answers 401." },
    { technique: "access.role_swap", rule: "attack.rbac_escalation", onVulnerable: "violated", onTwin: "held", why: "A member opens the admin notes route on the vulnerable app; the twin answers 403." },
    { technique: "access.sequential_id", rule: "attack.tenant_read", onVulnerable: "violated", onTwin: "held", why: "Numeric ids follow each other and the next one is readable; the twin uses unguessable ids and refuses." },
    { technique: "access.id_moved", rule: "attack.tenant_read", onVulnerable: "needs_validation", onTwin: "not_testable", why: "The fixture names no query or body alternate for the id, so this is not testable on it (listed for a later fixture)." },
    { technique: "access.method_override", rule: "attack.tenant_write", onVulnerable: "needs_validation", onTwin: "held", why: "The fixture does not honour a method-override header, so the plain refusal control is not set up (listed for a later fixture)." },
    { technique: "access.content_type", rule: "attack.tenant_write", onVulnerable: "needs_validation", onTwin: "held", why: "The fixture accepts only JSON, so the alternate content type control is not set up (listed for a later fixture)." },
    { technique: "access.cross_write", rule: "attack.tenant_write", onVulnerable: "violated", onTwin: "held", why: "Another account changes a note on the vulnerable app and the owner reads the change; the twin answers 404." },
    { technique: "mass_assign.update", rule: "attack.mass_assignment", onVulnerable: "violated", onTwin: "held", why: "An extra role field sticks on update on the vulnerable app; the twin ignores it." },
    { technique: "mass_assign.create", rule: "attack.mass_assignment", onVulnerable: "violated", onTwin: "held", why: "An extra role field sticks on create on the vulnerable app; the twin ignores it." },
    { technique: "injection.sql_boolean", rule: "attack.query_injection", onVulnerable: "needs_validation", onTwin: "held", why: "A boolean condition added to the search decides whether the run's own record is found; the twin matches literally." },
    { technique: "injection.sql_error", rule: "attack.query_injection", onVulnerable: "needs_validation", onTwin: "held", why: "An unbalanced quote brings a database error on the vulnerable app; the twin does not." },
    { technique: "injection.sql_time", rule: "attack.query_injection", onVulnerable: "needs_validation", onTwin: "not_testable", why: "Timing tests are off except where the record allows them; the fixture does not model a timed query." },
    { technique: "injection.template", rule: "attack.template_injection", onVulnerable: "violated", onTwin: "held", why: "A sum in template brackets is evaluated on the vulnerable app; the twin escapes it." },
    { technique: "injection.xss_reflected", rule: "attack.unescaped_markup", onVulnerable: "violated", onTwin: "held", why: "A test element comes back as markup on the vulnerable app; the twin escapes it." },
    { technique: "injection.xss_stored", rule: "attack.unescaped_markup", onVulnerable: "needs_validation", onTwin: "held", why: "The fixture serves the stored note as JSON, so the stored-markup path is not exercised here (listed for a later fixture)." },
    { technique: "injection.command", rule: "attack.command_injection", onVulnerable: "violated", onTwin: "held", governorRefuses: true, why: "An echo of a sum runs on the vulnerable app; the twin does not. Run directly only: the default rules forbid the command class." },
    { technique: "logic.numeric_bound", rule: "attack.number_out_of_bounds", onVulnerable: "violated", onTwin: "held", why: "A negative quantity is stored on the vulnerable app; the twin refuses it." },
    { technique: "logic.state_skip", rule: "attack.step_skipped", onVulnerable: "needs_validation", onTwin: "not_testable", why: "The fixture does not model an ordered flow yet (listed for a later fixture)." },
    { technique: "logic.single_use", rule: "attack.single_use_reuse", onVulnerable: "violated", onTwin: "held", why: "A once-only action counts twice on the vulnerable app; the twin refuses the second." },
    { technique: "race.parallel_use", rule: "attack.race_condition", onVulnerable: "violated", onTwin: "held", why: "Parallel requests all pass the limit on the vulnerable app; the twin refuses all but one." },
    { technique: "files.content_mismatch", rule: "attack.unsafe_upload", onVulnerable: "violated", onTwin: "held", why: "An HTML file named .png is served as a page on the vulnerable app; the twin serves it as a download." },
    { technique: "files.active_type", rule: "attack.unsafe_upload", onVulnerable: "violated", onTwin: "held", why: "An HTML or SVG file is served as a page on the vulnerable app; the twin serves it as a download." },
    { technique: "files.path_name", rule: "attack.unsafe_upload", onVulnerable: "needs_validation", onTwin: "held", why: "The vulnerable app keeps the folder part of the uploaded name; the twin chooses its own name." },
    { technique: "ssrf.canary", rule: "attack.server_fetch", onVulnerable: "violated", onTwin: "held", why: "On a real run the server fetches the public https canary; the unit test asserts the fixture's local http canary is refused as a safety behaviour." },
    { technique: "deserial.object_stream", rule: "attack.unsafe_deserializer", onVulnerable: "needs_validation", onTwin: "held", why: "A typed body brings a deserializer error on the vulnerable app; the twin refuses the media type." },
    { technique: "deserial.type_hint", rule: "attack.unsafe_deserializer", onVulnerable: "needs_validation", onTwin: "held", why: "A type-hint body is answered on the vulnerable app; the twin refuses it." },
    { technique: "crypto.sequential_ids", rule: "attack.predictable_token", onVulnerable: "needs_validation", onTwin: "held", why: "Record ids follow each other on the vulnerable app; the twin uses unguessable ids." },
    { technique: "crypto.short_token", rule: "attack.predictable_token", onVulnerable: "needs_validation", onTwin: "held", why: "Needs a short session value; the fixture's bearer session models this in a later variant." },
    { technique: "crypto.predictable_token", rule: "attack.predictable_token", onVulnerable: "needs_validation", onTwin: "held", why: "Needs two sign-ins that share a prefix; the fixture's bearer session models this in a later variant." },
    { technique: "csrf.state_change", rule: "attack.csrf", onVulnerable: "violated", onTwin: "held", why: "Needs a cookie session; covered in the engage core tests, modelled by a later cookie fixture." },
    { technique: "session.sign_out", rule: "attack.session_not_ended", onVulnerable: "violated", onTwin: "held", why: "Needs a server-side session; modelled by a later session fixture." },
    { technique: "session.reset_reuse", rule: "attack.single_use_reuse", onVulnerable: "violated", onTwin: "held", why: "Needs a reset flow; modelled by a later session fixture." },
    { technique: "session.jwt_none", rule: "attack.token_unverified", onVulnerable: "violated", onTwin: "held", why: "Needs a signed-token session; modelled by a later JWT fixture." },
    { technique: "session.jwt_signature", rule: "attack.token_unverified", onVulnerable: "violated", onTwin: "held", why: "Needs a signed-token session; modelled by a later JWT fixture." },
    { technique: "session.cookie_flags", rule: "attack.weak_session_cookie", onVulnerable: "needs_validation", onTwin: "held", why: "Needs a cookie set at sign-in; modelled by a later cookie fixture." },
    { technique: "session.password_limit", rule: "attack.no_rate_limit", onVulnerable: "needs_validation", onTwin: "held", why: "Needs a sign-in request; modelled by a later session fixture." },
    { technique: "ai.prompt_extraction", rule: "attack.prompt_extraction", onVulnerable: "violated", onTwin: "held", why: "The assistant hands out its instructions on the vulnerable app; the twin does not." },
    { technique: "ai.prompt_injection", rule: "attack.prompt_injection", onVulnerable: "violated", onTwin: "held", why: "The assistant obeys a hidden instruction on the vulnerable app; the twin does not." },
    { technique: "ai.indirect_injection", rule: "attack.indirect_injection", onVulnerable: "violated", onTwin: "held", why: "The assistant obeys a hidden instruction in pasted text on the vulnerable app; the twin does not." },
    { technique: "ai.unsafe_output", rule: "attack.unsafe_output", onVulnerable: "violated", onTwin: "held", why: "The assistant returns live markup on the vulnerable app; the twin does not." },
    { technique: "ai.jailbreak", rule: "attack.jailbreak", onVulnerable: "violated", onTwin: "held", why: "The assistant drops its rules on the vulnerable app; the twin does not." },
    { technique: "ai.data_disclosure", rule: "attack.data_disclosure", onVulnerable: "violated", onTwin: "held", why: "The assistant names internal details on the vulnerable app; the twin does not." },
    { technique: "ai.excessive_agency", rule: "attack.excessive_agency", onVulnerable: "violated", onTwin: "held", why: "The assistant claims an outward action on the vulnerable app; the twin does not." },
  ],
};

// ── rules2 (12 Nov 2026): the code and config patterns, NOT YET RUN ──────────────────────────────────────────────
/**
 * What the second rule set (src/rules2: code and config patterns, read offline by `yof check`) is expected to do on
 * the two pinned sources. WRITTEN BEFORE ANY RUN, from reading the rules and from what the builder knows of the two
 * projects' source at the pinned commits; nothing here has been checked against a run, and the benchmark was not
 * started to write it. Every entry therefore has status "not_yet_run".
 *
 * These are NOT part of the scoring: score.ts reads `mapping` above and nothing else, so the published numbers do not
 * change. When the patterns become a detector source of the benchmark, each entry moves into `mapping` with its item
 * key checked against the pinned official list (a key that is not in the list fails the scoring there), and the
 * reason below stays as the `ifMissed` text, word for word, so a miss is never explained away afterwards.
 *
 *   expect "hit"   the rule should fire on the named file, for the stated reason
 *   expect "miss"  the rule should stay quiet, and the reason says which limit of the rule causes it
 */
export interface Rules2Prediction {
  target: Target["id"];
  /** The official item this is about (Juice Shop: the challenge key; NodeGoat: the tutorial topic). To be checked against the pinned list before it is scored. */
  item: string;
  rule: string;
  expect: "hit" | "miss";
  /** Where in the source (repository-relative), when one place is meant. */
  file?: string;
  /** Written first: why the rule should fire, or which limit of the rule makes it miss. */
  reason: string;
  status: "not_yet_run";
}
const P = (target: Target["id"], item: string, rule: string, expect: "hit" | "miss", file: string | undefined, reason: string): Rules2Prediction =>
  ({ target, item, rule, expect, ...(file ? { file } : {}), reason, status: "not_yet_run" });

export const RULES2_PREDICTIONS: readonly Rules2Prediction[] = [
  // OWASP Juice Shop
  P("juice-shop", "loginAdminChallenge", "inside.code_sql_injection", "hit", "routes/login.ts", "The sign-in query is a template literal with req.body.email inside it, handed to sequelize.query in the same handler."),
  P("juice-shop", "unionSqlInjectionChallenge", "inside.code_sql_injection", "hit", "routes/search.ts", "The search term is read from req.query.q into a local name and placed in a template literal given to sequelize.query in the same handler."),
  P("juice-shop", "noSqlCommandChallenge", "inside.code_nosql_injection", "hit", "routes/showProductReviews.ts", "A $where string is built with + from req.params.id and passed to a find call. Depends on the rule seeing a MongoDB-style library: the shop uses MarsDB, which is on the rule's list only if package.json names it."),
  P("juice-shop", "noSqlReviewsChallenge", "inside.code_nosql_injection", "hit", "routes/updateProductReviews.ts", "The update filter is { _id: req.body.id }: a value from the request body used as it is."),
  P("juice-shop", "ssrfChallenge", "inside.code_ssrf", "hit", "routes/profileImageUrlUpload.ts", "The image address is read from req.body.imageUrl and fetched by the server in the same handler, with no host check the rule recognises."),
  P("juice-shop", "redirectChallenge", "inside.code_open_redirect", "miss", "routes/redirect.ts", "The handler calls an allow-list function before it redirects. The rule treats any allow-list check in the handler as a guard and cannot see that this one matches by substring and can be bypassed."),
  P("juice-shop", "rceChallenge", "inside.code_eval_input", "miss", "routes/b2bOrder.ts", "The order text runs through vm.runInContext, but the code string handed to vm is a fixed literal and the request value arrives through the sandbox object. The rule needs request input as the code itself."),
  P("juice-shop", "sstiChallenge", "inside.code_template_injection", "miss", "routes/userProfile.ts", "The template is built from the user's stored name, read from the database, not from the request in the same function. Values that come back from a database are out of scope."),
  P("juice-shop", "reflectedXssChallenge", "inside.code_xss_sink", "miss", undefined, "The page is an Angular app that trusts the value with bypassSecurityTrustHtml. The rule knows dangerouslySetInnerHTML, innerHTML, insertAdjacentHTML, document.write and HTML answers, not Angular's own bypass call."),
  P("juice-shop", "localXssChallenge", "inside.code_xss_sink", "miss", undefined, "Same as the reflected one: Angular's bypassSecurityTrustHtml is not a sink the rule knows."),
  P("juice-shop", "weirdCryptoChallenge", "inside.crypto_weak_hash", "miss", "lib/insecurity.ts", "Passwords are hashed with MD5 in a helper whose argument is called data, and the callers pass the password in from other files. The rule needs a password or token name at the hash call itself."),
  P("juice-shop", "jwtUnsignedChallenge", "inside.code_jwt_unverified", "miss", "lib/insecurity.ts", "The unsigned token is accepted because of the old library versions pinned in package.json (the package check's finding), not because the code allows the none algorithm in so many words."),
  P("juice-shop", "jwtForgedChallenge", "inside.crypto_hardcoded_key", "hit", "lib/insecurity.ts", "An HMAC helper passes a text literal as the key to crypto.createHmac. This is a neighbour of the challenge (a fixed key in the code), not the forged-token weakness itself, so it would be scored as root at most."),
  P("juice-shop", "fileWriteChallenge", "inside.code_upload_unchecked", "hit", "routes/fileUpload.ts", "The upload handlers build the stored path from the client's file name (file.originalname) with path.join or path.resolve."),
  P("juice-shop", "uploadTypeChallenge", "inside.code_upload_unchecked", "miss", "routes/fileUpload.ts", "The type check exists in the code and is only applied in the browser. The rule sees a type check in the file and stays quiet about the content type; it cannot tell that the server never enforces it."),
  P("juice-shop", "csrfChallenge", "inside.code_csrf_missing", "miss", undefined, "The shop signs people in with a JWT in an Authorization header and a cookie copy, not with express-session or cookie-session. The rule reads only those two session libraries, and any sign of token sign-in silences it."),
  P("juice-shop", "exposedCredentialsChallenge", "inside.cred_password_literal", "miss", undefined, "The test credentials sit in the Angular front end as properties named testingUsername and testingPassword inside a component; the value has no digit or symbol the rule requires of a password literal, so it reads as a label."),
  P("juice-shop", "weakPasswordChallenge", "inside.cred_default_login", "miss", "data/static/users.yml", "The seed users have weak passwords, but next to an email address, not next to a user name such as admin or root. The rule needs a well-known user name within three lines."),
  P("juice-shop", "knownVulnerableComponentChallenge", "inside.docker_base_eol", "miss", "Dockerfile", "The Dockerfile builds on a current Node release line and a distroless image, neither past its end of life in the table dated 2026-11-12."),
  // OWASP NodeGoat
  P("nodegoat", "a1", "inside.code_eval_input", "hit", "app/routes/contributions.js", "The contribution amounts are passed from req.body straight to eval in the handler."),
  P("nodegoat", "a1", "inside.code_nosql_injection", "miss", "app/data/allocations-dao.js", "The $where string is built in a data-access function from an argument. The request is read in the route file and passed in, and a value that crosses a function is out of scope."),
  P("nodegoat", "a2", "inside.crypto_weak_hash", "miss", "app/data/user-dao.js", "Passwords are stored as plain text (the bcrypt lines are commented out). The rule looks for a weak hash and has nothing to match when there is no hash at all."),
  P("nodegoat", "a2", "inside.code_cookie_flags", "miss", "server.js", "The session cookie's httpOnly and secure options are commented out, not set to false. The rule reports a session only when its cookie options turn a protection off in so many words."),
  P("nodegoat", "a6", "inside.crypto_hardcoded_key", "miss", "config/env/all.js", "The crypto key and cookie secret end in _here, which the placeholder guard takes for sample values. They are in fact the values the app runs with."),
  P("nodegoat", "a8", "inside.code_csrf_missing", "miss", "server.js", "The app uses express-session and has state-changing routes, but the CSRF middleware is present as commented-out code. The project-wide guard reads the text of every file, comments included, so the word csrf silences the rule."),
  P("nodegoat", "a10", "inside.code_open_redirect", "hit", "app/routes/index.js", "The /learn route redirects to req.query.url with no check in the handler."),
  P("nodegoat", "ssrf", "inside.code_ssrf", "hit", "app/routes/research.js", "The address is built as req.query.url + req.query.symbol and fetched with needle.get in the same handler, with no host check."),
  P("nodegoat", "a9", "inside.docker_base_eol", "hit", "Dockerfile", "The Dockerfile builds on an old Node release line that is past its end of life in the table dated 2026-11-12. Only if the pinned commit still names such a tag."),
];
