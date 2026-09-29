// Layout assertions shared by the screenshot capture and its threshold test.
//
// Kept separate from `screenshots.mjs` so the *rule* can be exercised on its own, with a
// fixture, without a running server. The capture script imports `measureLayout`; the
// threshold test imports `undersizedTargets` and feeds it hand-built rectangles.

// WCAG 2.5.8 (Target Size (Minimum), AA) asks for a 24×24 CSS pixel target. This is the
// threshold the undo of the sign-out fix is measured against: the control used to be 20px
// tall (its line-height alone, no vertical padding), which is below it.
export const MIN_TARGET_PX = 24;

/**
 * Which of the measured targets are too small to click.
 *
 * Inline text links are exempt: they are constrained by the line-height of the sentence
 * they sit in, which is exactly the exception WCAG 2.5.8 carves out. Excluding them is not
 * a way to pass — an `<a>` that is laid out as a block (a card, a button-styled link) is
 * measured like any other control, and the capture script records the count so a change in
 * what is exempted is visible in the run's output.
 *
 * @param {Array<{width:number,height:number,inlineTextLink?:boolean}>} rects
 * @returns {Array<{width:number,height:number}>} the undersized, non-exempt targets
 */
export function undersizedTargets(rects) {
  return rects.filter((r) => {
    // A zero-area element is hidden, not an unclickable control.
    if (r.width <= 0 || r.height <= 0) return false;
    if (r.inlineTextLink) return false;
    return r.width < MIN_TARGET_PX || r.height < MIN_TARGET_PX;
  });
}

/**
 * Measure the layout properties a screenshot must satisfy, in the page.
 *
 * Runs inside `page.evaluate`, so it must be self-contained: no imports, no closure over
 * the module. `undefined` is returned for elements with no layout box.
 */
export async function measureLayout(page) {
  return page.evaluate(() => {
    const text = (document.body.innerText || "").trim();
    const de = document.documentElement;

    const controls = [...document.querySelectorAll("button, a, input")].map((e) => {
      const r = e.getBoundingClientRect();
      const display = getComputedStyle(e).display;
      return {
        width: r.width,
        height: r.height,
        // A text link laid out inline is exempt under WCAG 2.5.8's inline exception.
        // `display: inline` is the marker for that; a link styled as a block is not.
        inlineTextLink: e.tagName === "A" && display === "inline",
      };
    });

    return {
      text,
      overflowX: de.scrollWidth - de.clientWidth,
      // Raw rectangles; the caller applies the shared threshold. Keeping the rule out of
      // the page context is what lets the threshold test run without a browser.
      controls,
    };
  });
}
