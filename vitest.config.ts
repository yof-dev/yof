import { defineConfig } from "vitest/config";

export default defineConfig({
  // The tests run in CI on pull requests too. yof check reads its settings from the base branch on a pull request
  // (GITHUB_EVENT_NAME, GITHUB_BASE_REF), so those two are cleared here: a test that wants them passes its own env.
  test: { include: ["test/**/*.test.ts", "benchmark/test/**/*.test.ts"], environment: "node", testTimeout: 20_000, env: { GITHUB_EVENT_NAME: "", GITHUB_BASE_REF: "" } },
});
