#!/usr/bin/env node
// Capture every Secreton frontend view into docs/screenshots/ and assert each one is
// actually usable.
//
// A screenshot is only evidence if it shows the page working. This script therefore fails
// (non-zero exit) when a view is blank, unexpectedly errored, overflows horizontally, has
// a control too small to click, or logs a console error that is not the expected 404.
//
// Usage:
//   npm install                              # installs the pinned playwright-core
//   npm run browser:install                  # once, to fetch the matching Chromium
//   cargo leptos serve                       # in one terminal
//   npm run screenshots                      # in another
//
// The dependency is declared and pinned in the root `package.json`; nothing here is part
// of the Rust build. `npm run screenshots:check` verifies the setup without capturing.
// If you already have a Chromium, skip the download and set CHROMIUM_PATH to it.
//
// Environment:
//   BASE_URL            default http://127.0.0.1:3000
//   CHROMIUM_PATH       browser binary; default is the one Playwright installed
//   SCREENSHOT_USER     demo account username (default "demo")
//   SCREENSHOT_PASSWORD password for that account (required; the capture signs in for real)

import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MIN_TARGET_PX, measureLayout, undersizedTargets } from "./layout.mjs";

const require = createRequire(import.meta.url);
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(REPO, "docs/screenshots");
const BASE = process.env.BASE_URL ?? "http://127.0.0.1:3000";
const USER = process.env.SCREENSHOT_USER ?? "demo";
const PASSWORD = process.env.SCREENSHOT_PASSWORD;
const DESKTOP = { width: 1280, height: 800 };
const MOBILE = { width: 390, height: 844 };

// Every run signs in for real — the session lives in an `HttpOnly` cookie, so driving the
// form is the only way to reach the authenticated views. A default password would either
// be a credential in the repository or a plausible-looking value that silently produces a
// signed-out capture of the whole authenticated set. Refuse to start without one.
if (!PASSWORD) {
  console.error(
    [
      "SCREENSHOT_PASSWORD is not set.",
      "",
      "The capture signs in with a real account, so it needs the password for",
      `SCREENSHOT_USER (currently ${JSON.stringify(USER)}).`,
      "",
      "Set both variables and re-run:",
      "  SCREENSHOT_USER=someone SCREENSHOT_PASSWORD=... npm run screenshots",
    ].join("\n")
  );
  process.exit(4);
}

let chromium;
try {
  ({ chromium } = require("playwright-core"));
} catch {
  console.error(
    "playwright-core not found. Run `npm install` in the repository root, then " +
      "`npm run screenshots:check` to verify the browser is available."
  );
  process.exit(2);
}

const EXECUTABLE = process.env.CHROMIUM_PATH ?? undefined;

function launchOptions() {
  const args = ["--no-sandbox", "--disable-dev-shm-usage"];
  return EXECUTABLE ? { executablePath: EXECUTABLE, args } : { args };
}

const results = [];

// Measure the layout properties a screenshot must satisfy. Shared by every view so the
// denial path is held to exactly the same standard as the others: an overflow or an
// undersized control that only appears once the error alert renders must fail the run just
// as it would on a healthy view.
//
// The threshold and the inline-link exemption live in `./layout.mjs`, where the threshold
// test exercises them without a browser.
async function probeLayout(page) {
  const measured = await measureLayout(page);
  const tiny = undersizedTargets(measured.controls);
  return {
    text: measured.text,
    overflowX: measured.overflowX,
    tinyControls: tiny,
  };
}

async function shoot(page, name, urlPath, expectedStatus) {
  const errors = [];
  const onError = (e) => errors.push(String(e));
  const onConsole = (m) => m.type() === "error" && errors.push(m.text());
  page.on("pageerror", onError);
  page.on("console", onConsole);

  const resp = await page.goto(BASE + urlPath, { waitUntil: "networkidle" });
  await page.waitForTimeout(1800);

  const probe = await probeLayout(page);

  const file = path.join(OUT, `${name}.png`);
  // `animations: "disabled"` settles CSS transitions before capture; without it a
  // running animation can stall the screenshot on some Chromium builds. The explicit
  // timeout keeps a hung capture from blocking the whole run.
  await page.screenshot({
    path: file,
    fullPage: true,
    animations: "disabled",
    timeout: 30000,
  });
  page.off("pageerror", onError);
  page.off("console", onConsole);

  results.push({
    view: name,
    status: resp.status(),
    expectedStatus,
    bytes: fs.statSync(file).size,
    overflowX: probe.overflowX,
    tinyTargets: probe.tinyControls,
    jsErrors: errors,
    textLength: probe.text.length,
  });
  console.log(`  ${name.padEnd(16)} HTTP ${resp.status()}  ${fs.statSync(file).size} bytes`);
}

async function signIn(page) {
  // A fresh context starts on about:blank; the form only exists on the login page.
  await page.goto(BASE + "/login", { waitUntil: "networkidle" });
  await page.waitForSelector('input[name="credentials[username]"]', { timeout: 20000 });
  await page.fill('input[name="credentials[username]"]', USER);
  await page.fill('input[name="credentials[password]"]', PASSWORD);
  // The submit control carries no `type` attribute, so `form button` is the selector.
  await page.locator("form button").click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 20000 });
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  let browser;
  try {
    browser = await chromium.launch(launchOptions());
  } catch (e) {
    console.error(
      [
        "Could not launch Chromium.",
        "",
        EXECUTABLE
          ? `CHROMIUM_PATH is set to ${EXECUTABLE}; check that it exists and is executable.`
          : "Install the browser the pinned Playwright expects: npm run browser:install",
        "Or set CHROMIUM_PATH to a system Chromium you already have.",
        "",
        `Underlying error: ${e}`,
      ].join("\n")
    );
    process.exit(3);
  }

  console.log("signed-out views");
  const anon = await browser.newContext({ viewport: DESKTOP });
  const page = await anon.newPage();

  await shoot(page, "login", "/login", 200);

  // The denial path: a rejected sign-in must show a plain message and leave the form usable.
  await page.waitForSelector('input[name="credentials[username]"]', { timeout: 20000 });
  await page.fill('input[name="credentials[username]"]', USER);
  await page.fill('input[name="credentials[password]"]', "definitely-not-the-password");

  // Collect errors for the denial path too, rather than asserting an empty list. The
  // server function answers 500 for a rejected sign-in (that is how Leptos reports a
  // `ServerFnError`), so the browser logs exactly one failed resource; anything beyond that
  // is a real defect and fails the run.
  //
  // The console text alone ("Failed to load resource: ... 500 ...") does not name the URL,
  // so the location is appended. That lets the whitelist below key on the actual
  // server-function request rather than on any error that happens to mention 500.
  const denialErrors = [];
  const onDenialError = (e) => denialErrors.push(String(e));
  const onDenialConsole = (m) => {
    if (m.type() !== "error") return;
    const loc = m.location();
    denialErrors.push(loc && loc.url ? `${m.text()} @ ${loc.url}` : m.text());
  };
  page.on("pageerror", onDenialError);
  page.on("console", onDenialConsole);

  // Record the *actual* HTTP status of the rejected sign-in's server-function POST. The
  // result used to hard-code `200`, so the status assertion could not notice that request
  // changing. Leptos answers a `ServerFnError` with a 500, which the console-error
  // whitelist already keys on; capture it here so the result carries the real status and
  // the assertion below is meaningful.
  let denialStatus = null;
  const onDenialResponse = (resp) => {
    if (resp.url().includes("/api/") && resp.request().method() === "POST") {
      denialStatus = resp.status();
    }
  };
  page.on("response", onDenialResponse);

  await page.locator("form button").click();
  // The response is a server-function round trip, so the alert appears after a beat.
  await page.waitForSelector('[role="alert"]', { timeout: 20000 });
  await page.waitForTimeout(500);
  page.off("pageerror", onDenialError);
  page.off("console", onDenialConsole);
  page.off("response", onDenialResponse);
  if (denialStatus === null) {
    throw new Error(
      "the rejected sign-in did not produce an observable server-function response"
    );
  }

  // Measure the settled DOM, not a hard-coded "looks fine". The alert is on screen by now,
  // so an overflow or an undersized control introduced by the error state is caught here
  // exactly as it would be on any other view.
  const errProbe = await probeLayout(page);

  await page.screenshot({
    path: path.join(OUT, "login-error.png"),
    fullPage: true,
    animations: "disabled",
    timeout: 30000,
  });
  const errFile = path.join(OUT, "login-error.png");
  const alertText = (await page.locator('[role="alert"]').innerText()).trim();
  results.push({
    view: "login-error",
    status: denialStatus,
    expectedStatus: 500,
    bytes: fs.statSync(errFile).size,
    overflowX: errProbe.overflowX,
    tinyTargets: errProbe.tinyControls,
    jsErrors: denialErrors,
    alertText,
    textLength: errProbe.text.length,
  });
  console.log(`  login-error      HTTP ${denialStatus}  ${fs.statSync(errFile).size} bytes`);

  const nf = await anon.newPage();
  await shoot(nf, "not-found", "/no-such-page", 404);

  // Mobile signed-out.
  const mob = await browser.newContext({ viewport: MOBILE });
  const mLogin = await mob.newPage();
  await shoot(mLogin, "mobile-login", "/login", 200);

  console.log("signed-in views");
  // The session lives only in an httpOnly cookie, so the real form is the only way in.
  //
  // Each signed-in view signs in on its own fresh context. Signing in twice through the
  // same page and then capturing a full-page screenshot wedged the capture on a headless
  // Chromium build — the screenshot never completed even with animations disabled, while
  // the identical sequence on a fresh context returned immediately. A clean context per
  // view is also closer to what a real visitor does.
  const desk = await browser.newContext({ viewport: DESKTOP });
  const dPage = await desk.newPage();
  await signIn(dPage);
  await shoot(dPage, "dashboard", "/", 200);

  const phone = await browser.newContext({ viewport: MOBILE });
  const pPage = await phone.newPage();
  await signIn(pPage);
  await shoot(pPage, "mobile-dashboard", "/", 200);

  await browser.close();

  // Two console errors are part of the design and are whitelisted by name; every other
  // error fails the run.
  //   - the 404 page: the browser logs its own document request as a failed resource.
  //   - the rejected sign-in: Leptos reports a `ServerFnError` as an HTTP 500, so the
  //     failed server-function POST shows up once. The match is deliberately narrow — it
  //     requires the failed *fetch* of the server-function endpoint alongside the 500, so an
  //     unrelated error that merely mentions 500 is still a failure.
  const expectedError = (r, e) => {
    if (r.status === 404 && e.includes("404")) return true;
    if (r.view === "login-error" && e.includes("500") && e.includes("/api/")) return true;
    return false;
  };

  const bad = results.filter(
    (r) =>
      r.status !== r.expectedStatus ||
      r.bytes < 5000 ||
      r.textLength < 20 ||
      r.overflowX > 2 ||
      r.tinyTargets.length > 0 ||
      r.jsErrors.filter((e) => !expectedError(r, e)).length ||
      // A rejected sign-in must not distinguish "no such user" from "wrong password".
      (r.view === "login-error" && r.alertText !== "invalid credentials")
  );

  if (bad.length) {
    console.error("\nFAILED: " + bad.map((b) => b.view).join(", "));
    console.error(JSON.stringify(bad, null, 2));
    process.exit(1);
  }
  console.log(
    `\nOK: ${results.length} views captured and verified ` +
      `(clickable targets >= ${MIN_TARGET_PX}px, inline text links exempt)`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
