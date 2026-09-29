// Regression tests for the screenshot layout assertions.
//
// The capture script only runs with a live server and a browser, so it is not part of
// `cargo test` and nothing here exercises the *rule* it applies. These tests do, without a
// browser: they pin the minimum target size, prove the rule flags the exact defect the
// sign-out control had, and read the real `layout.rs` to prove the control's own markup
// keeps it above the threshold. Reverting the button to a bare `px-2 text-sm` (20px tall)
// fails the last test, which is the falsification this guards.
//
// Run with `npm run test:screenshots`.

import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MIN_TARGET_PX, undersizedTargets } from "./layout.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LAYOUT_RS = path.join(REPO, "crates/ui/src/components/layout.rs");
const NOT_FOUND_RS = path.join(REPO, "crates/ui/src/pages/not_found.rs");

test("the minimum target size is the WCAG 2.5.8 figure", () => {
  // 24 CSS px is the AA minimum; the sign-out control's 20px line-height was the defect.
  assert.equal(MIN_TARGET_PX, 24);
});

test("a control one pixel under the minimum is flagged", () => {
  assert.equal(
    undersizedTargets([{ width: 200, height: 20 }]).length,
    1,
    "a 20px-tall control must be reported, or the sign-out defect would pass"
  );
  assert.equal(undersizedTargets([{ width: 24, height: 24 }]).length, 0);
  assert.equal(undersizedTargets([{ width: 23, height: 200 }]).length, 0 + 1);
});

test("inline text links are exempt, block links are not", () => {
  // WCAG 2.5.8 exempts links laid out inline, whose box is the line they sit in.
  assert.equal(
    undersizedTargets([{ width: 120, height: 18, inlineTextLink: true }]).length,
    0
  );
  // The same element laid out as a block is a target and must be measured.
  assert.equal(
    undersizedTargets([{ width: 120, height: 18, inlineTextLink: false }]).length,
    1
  );
});

test("hidden elements are not mistaken for unclickable ones", () => {
  assert.equal(undersizedTargets([{ width: 0, height: 0 }]).length, 0);
});

// Tailwind's spacing scale, for the tokens the button uses. Enough to compute the box
// height the browser will produce: the line box plus the vertical padding.
const LINE_HEIGHT_PX = { "text-xs": 16, "text-sm": 20, "text-base": 24, "text-lg": 28 };
const SPACING_UNIT_PX = 4;

function verticalPaddingPx(classes) {
  const token = classes.match(/\bpy-([0-9.]+)\b/);
  if (!token) return 0;
  return Number(token[1]) * SPACING_UNIT_PX * 2;
}

/// The class attribute of the `<button>` whose text is `Sign out`.
function signOutButtonClasses() {
  const source = fs.readFileSync(LAYOUT_RS, "utf8");
  const button = source.match(/<button[\s\S]*?<\/button>/g)?.find((b) => b.includes("Sign out"));
  assert.ok(button, "the sign-out button must exist in layout.rs");
  const classAttr = button.match(/class="([^"]+)"/);
  assert.ok(classAttr, "the sign-out button must carry a class attribute");
  return classAttr[1];
}

test("the sign-out control is tall enough to click", () => {
  // This is the falsifiable one. The control was `px-2 text-sm` — 20px, the line-height
  // alone, no vertical padding — which the probe flags. Reverting it fails here.
  const classes = signOutButtonClasses();
  const line = Object.entries(LINE_HEIGHT_PX).find(([tok]) => classes.includes(tok));
  assert.ok(line, `sign-out must set an explicit text size: ${classes}`);

  const height = line[1] + verticalPaddingPx(classes);
  assert.ok(
    height >= MIN_TARGET_PX,
    `the sign-out control renders ${height}px tall, below the ${MIN_TARGET_PX}px minimum ` +
      `(classes: ${classes})`
  );

  // And the same computation applied to the pre-fix classes must be flagged, so the
  // assertion above cannot be satisfied by a change that only moves the goalposts.
  const before = classes.replace(/\bpy-([0-9.]+)\b/, "");
  const beforeHeight = line[1] + verticalPaddingPx(before);
  assert.equal(
    undersizedTargets([{ width: 200, height: beforeHeight }]).length,
    1,
    "the pre-fix control shape must be flagged, or this test proves nothing"
  );
});

/// The `class` attribute of the anchor whose text is `Back to the dashboard`.
function backLinkClasses() {
  const source = fs.readFileSync(NOT_FOUND_RS, "utf8");
  const anchor = source
    .match(/<a[\s\S]*?<\/a>/g)
    ?.find((a) => a.includes("Back to the dashboard"));
  assert.ok(anchor, "the 404 page must link back to the dashboard");
  const classAttr = anchor.match(/class="([^"]+)"/);
  assert.ok(classAttr, "the back link must carry a class attribute");
  return classAttr[1];
}

test("the 404 back-link is tall enough to click", () => {
  // The capture failed on the 404 view once the threshold moved from 8px to 24px: the link
  // was `text-sm` with no vertical padding — 20px, the line-height alone. Its flex parent
  // blockifies it, so WCAG 2.5.8's inline exception does not cover it and it is a real
  // navigation target. Reverting the padding must fail here.
  const classes = backLinkClasses();
  const line = Object.entries(LINE_HEIGHT_PX).find(([tok]) => classes.includes(tok));
  assert.ok(line, `the back link must set an explicit text size: ${classes}`);

  const height = line[1] + verticalPaddingPx(classes);
  assert.ok(
    height >= MIN_TARGET_PX,
    `the 404 back-link renders ${height}px tall, below the ${MIN_TARGET_PX}px minimum ` +
      `(classes: ${classes})`
  );

  const before = classes.replace(/\bpy-([0-9.]+)\b/, "");
  const beforeHeight = line[1] + verticalPaddingPx(before);
  assert.equal(
    undersizedTargets([{ width: 158, height: beforeHeight, inlineTextLink: false }]).length,
    1,
    "the pre-fix back-link shape must be flagged, or this test proves nothing"
  );
});
