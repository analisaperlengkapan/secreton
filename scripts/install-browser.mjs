#!/usr/bin/env node
// Fetch the Chromium build that the pinned `playwright-core` expects, into the per-version
// cache Playwright resolves at launch.
//
// This is deliberately a separate, explicit step (`npm run browser:install`) rather than a
// `postinstall` hook: `npm install` should not reach the network for a browser from a
// repository where nothing else needs one, and the Rust build must never trigger it.
//
// If a system Chromium is already installed and you would rather not download one, skip
// this and set CHROMIUM_PATH — the screenshot script launches it directly.

import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import path from "node:path";

const require = createRequire(import.meta.url);

let cli;
try {
  const pkg = require.resolve("playwright-core/package.json");
  const manifest = require(pkg);
  cli = path.join(path.dirname(pkg), manifest.bin["playwright-core"]);
} catch {
  console.error("playwright-core is not installed. Run `npm install` first.");
  process.exit(2);
}

const r = spawnSync(process.execPath, [cli, "install", "chromium"], {
  stdio: "inherit",
});
process.exit(r.status ?? 1);
