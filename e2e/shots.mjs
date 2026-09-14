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
// The control token is read from the daemon's own output and never printed here. In the dashboard
// shot its field is `type="password"`, so it photographs as dots.

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { chromium } from "playwright";

import {
  ALIAS,
  HOST,
  SUFFIX,
  browserOptions,
  connectThroughDashboard,
  extensionWithPermissionGranted,
  loadExtension,
  startDaemon,
} from "./harness.mjs";

const PORT = Number(process.env["SSH_BROWSER_E2E_PORT"] ?? 17392);
const OUT = join(import.meta.dirname, "shots");

/// The store's smaller accepted size. Large enough to read, small enough that the panel is
/// not a speck in one corner.
const VIEW = { width: 1280, height: 800 };

// Refused against anything but a local host, and this is not tidiness.
//
// The dashboard's second section lists the hosts ssh can reach, with the user, address, port
// and jump host `ssh -G` resolved for each; the first lists what is being served, with the
// account and path it is rooted at. Run against a real machine that is six accounts, three
// addresses, two jump hosts and somebody's home directory — in an image whose destination is a
// public store page. It was run that way once, which is why this is here.
//
// `shots.yml` runs it on a fresh runner with a throwaway sshd and the invented ssh_config in
// `shots-config/`, so the picture is of the product rather than of whoever took it.
if (HOST !== "localhost" && HOST !== "127.0.0.1" && !process.env["SSH_BROWSER_SHOTS_ANY_HOST"]) {
  console.error(
    `refusing to photograph ${HOST}: these images go on a public listing, and the dashboard\n` +
      `shows the accounts, addresses, ports and jump hosts of every host your ssh can reach.\n\n` +
      `Run them where everything is invented:\n` +
      `  gh workflow run shots.yml\n\n` +
      `To override anyway, knowing what is in frame: SSH_BROWSER_SHOTS_ANY_HOST=1`,
  );
  process.exit(2);
}

const { child } = await startDaemon(PORT);
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

  const { dashboard } = await connectThroughDashboard(browser, PORT);

  // The dashboard lays itself out on a full page, so there is nothing to centre and no
  // stylesheet to add. Every pixel is the real one.
  await dashboard.setViewportSize(VIEW);
  await dashboard.waitForSelector("#view button");
  await dashboard.screenshot({ path: join(OUT, "1-sites.png") });
  console.log("  shots/1-sites.png      the dashboard: what is served, and what could be");

  // And one site's own page, which is where the per-site things are.
  await dashboard.click(`#view button[data-alias="${ALIAS}"]`);
  await dashboard.waitForSelector("#open-site");
  await dashboard.screenshot({ path: join(OUT, "2-site.png") });
  console.log("  shots/2-site.png       one site: its URL, its root, and how to stop it");

  await dashboard.click("#to-config");
  await dashboard.waitForSelector("#theme");
  await dashboard.screenshot({ path: join(OUT, "3-settings.png") });
  console.log("  shots/3-settings.png   settings: what listings look like, and which daemon");

  const listing = await browser.newPage();
  await listing.setViewportSize(VIEW);
  await listing.goto(`http://${ALIAS}.${SUFFIX}/assets/`, { waitUntil: "networkidle" });
  await listing.screenshot({ path: join(OUT, "4-listing.png") });
  console.log("  shots/4-listing.png    a directory, at its own origin");
} finally {
  await browser?.close();
  child.kill();
  await once(child, "exit").catch(() => {});
  await rm(profile, { recursive: true, force: true }).catch(() => {});
  await rm(extension, { recursive: true, force: true }).catch(() => {});
}
