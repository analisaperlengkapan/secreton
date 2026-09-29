#!/usr/bin/env node
// Preflight for the screenshot tooling: prove `playwright-core` resolves and that a
// Chromium it can actually launch is available, with an actionable message when either is
// missing. Run it before a capture session (`npm run screenshots:check`); it touches the
// network only when Playwright decides it needs to download a browser.
//
// It launches and immediately closes a browser, so a broken binary or a missing system
// library is reported here rather than halfway through a capture.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

let chromium;
try {
  ({ chromium } = require("playwright-core"));
} catch {
  console.error(
    [
      "playwright-core is not installed.",
      "",
      "  npm install                    # installs the pinned version from package.json",
      "",
      "Do not point NODE_PATH at an unknown global install; the pin is what makes a",
      "capture reproducible.",
    ].join("\n")
  );
  process.exit(2);
}

const executablePath = process.env.CHROMIUM_PATH || undefined;
const args = ["--no-sandbox", "--disable-dev-shm-usage"];

let browser;
try {
  browser = await chromium.launch(executablePath ? { executablePath, args } : { args });
} catch (e) {
  console.error(
    [
      "playwright-core resolved, but its Chromium could not be launched.",
      "",
      executablePath
        ? `CHROMIUM_PATH is set to ${executablePath}. Check that it exists and is executable.`
        : "Install the browser the pinned Playwright expects:",
      executablePath ? "" : "  npm run browser:install",
      "",
      "Or point at a system Chromium you already have:",
      "  CHROMIUM_PATH=/usr/bin/chromium npm run screenshots",
      "",
      `Underlying error: ${e}`,
    ]
      .filter(Boolean)
      .join("\n")
  );
  process.exit(3);
}

const version = browser.version();
await browser.close();
console.log(`OK: playwright-core resolves and Chromium ${version} launches.`);
