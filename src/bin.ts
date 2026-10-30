#!/usr/bin/env node
import { main } from "./cli";

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (e: unknown) => { process.stderr.write(`yof: ${e instanceof Error ? e.message : String(e)}\n`); process.exitCode = 2; },
);
