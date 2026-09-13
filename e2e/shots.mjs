// Photograph the product for the Chrome Web Store listing.
//
//   npm --prefix e2e run shots
//
// Taken from the running thing rather than mocked up, and through the same harness the checks
// use — so a screenshot cannot show a version of the product that never passed. If a listing
// is going to claim something, the claim may as well be a photograph of it happening.
//
// Writes 1280×800 images to e2e/shots/, which is one of the two sizes the store accepts.
//
// The control token is read from the daemon's own output and never printed here. In the popup
// shot its field is `type="password"`, so it photographs as dots.

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { chromium } from "playwright";

import {
  ALIAS,
  SUFFIX,
  TOKEN_HEADER,
  browserOptions,
  connectThroughPopup,
  extensionWithPermissionGranted,
  loadExtension,
  startDaemon,
} from "./harness.mjs";

const PORT = Number(process.env["SSH_BROWSER_E2E_PORT"] ?? 17392);
const OUT = join(import.meta.dirname, "shots");

/// The store's smaller accepted size. Large enough to read, small enough that the panel is
/// not a speck in one corner.
const VIEW = { width: 1280, height: 800 };

// The fuller of the two fixtures: a heading, an image and a script that ran.
const DOC = "index.html";

const { child, token } = await startDaemon(PORT);
const profile = await mkdtemp(join(tmpdir(), "ssh-browser-shots-"));
const extension = await extensionWithPermissionGranted();
let browser;

try {
  await mkdir(OUT, { recursive: true });
  browser = await chromium.launchPersistentContext(profile, {
    ...browserOptions(),
    viewport: VIEW,
    proxy: { server: `http://127.0.0.1:${PORT}` },
    args: loadExtension(extension),
  });

  const { popup } = await connectThroughPopup(browser, PORT, token);

  // The popup is 320px wide by design, so a raw screenshot would be a narrow strip on a wide
  // canvas. Centring it on a neutral ground is presentation rather than fiction: every pixel
  // of the popup is the real one, laid out by its own stylesheet.
  await popup.setViewportSize(VIEW);
  await popup.addStyleTag({
    content: `
      html { background: #eceae3; }
      body { margin: 240px auto; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.18); border-radius: 8px; }
    `,
  });
  await popup.screenshot({ path: join(OUT, "1-connect.png") });
  console.log("  shots/1-connect.png    the popup, connected");

  // A note to photograph. Written through the control API rather than by driving the panel,
  // because the picture wanted is of a note being *shown*; how it got there is the subject of
  // the checks rather than of a listing.
  const posted = await fetch(`http://127.0.0.1:${PORT}/_control/annotations`, {
    method: "POST",
    headers: { [TOKEN_HEADER]: token, "content-type": "application/json" },
    body: JSON.stringify({
      doc: `${ALIAS}/${encodeURIComponent(DOC)}`,
      op: "add",
      body: "the quoted words are highlighted, and the note sits beside them",
      selectors: [{ type: "TextQuoteSelector", exact: "served over ssh" }],
    }),
  });
  if (!posted.ok) {
    throw new Error(`could not write the note to photograph: ${posted.status}`);
  }

  const page = await browser.newPage();
  await page.setViewportSize(VIEW);
  await page.goto(`http://${ALIAS}.${SUFFIX}/${encodeURIComponent(DOC)}`, {
    waitUntil: "networkidle",
  });
  // The highlight is the evidence the note arrived and anchored, so waiting for it is also
  // what stops the shot being taken half a beat early.
  await page.waitForFunction(() => CSS.highlights.size > 0, { timeout: 20_000 });
  await page.screenshot({ path: join(OUT, "2-annotated.png") });
  console.log("  shots/2-annotated.png  a page served over ssh, with a note on it");

  const listing = await browser.newPage();
  await listing.setViewportSize(VIEW);
  await listing.goto(`http://${ALIAS}.${SUFFIX}/assets/`, { waitUntil: "networkidle" });
  await listing.screenshot({ path: join(OUT, "3-listing.png") });
  console.log("  shots/3-listing.png    a directory, at its own origin");
} finally {
  await browser?.close();
  child.kill();
  await once(child, "exit").catch(() => {});
  await rm(profile, { recursive: true, force: true }).catch(() => {});
  await rm(extension, { recursive: true, force: true }).catch(() => {});
}
