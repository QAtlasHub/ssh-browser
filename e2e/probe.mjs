// Point the daemon at a real site and report everything the browser complained about.
//
//   node e2e/probe.mjs <ssh-host> <remote-dir> [path]
//   node e2e/probe.mjs Panza '~/work/Vault/lib/QAtlas.jl/docs/build'
//
// Not a test, and it asserts nothing. `run.mjs` checks the claims against `e2e/tree/`, which
// this repository wrote and which therefore cannot surprise it. This points the same daemon at
// a site nobody wrote for it — Documenter output, a generated report, whatever is on the host —
// and prints the failed requests, the console errors and what the page actually became.
//
// The loop it is for: run it, read the output, write a check in `run.mjs` for whatever it
// found. Anything it reports is a fact about a real page, which is the kind that has been
// worth more here than any amount of reasoning about the spec.

import { mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { chromium } from "playwright";

const [host, dir, path = "/"] = process.argv.slice(2);
if (!host || !dir) {
  console.error("usage: node e2e/probe.mjs <ssh-host> <remote-dir> [path]");
  process.exit(2);
}

// The harness reads these at import, so they have to be set before it is loaded. Taking them
// as arguments rather than making the caller export three variables is the whole point of
// having a separate entry point.
process.env["SSH_BROWSER_E2E_HOST"] = host;
process.env["SSH_BROWSER_E2E_BASE"] = dir;

const {
  ALIAS,
  SUFFIX,
  TOKEN_HEADER,
  browserOptions,
  connectThroughDashboard,
  extensionWithPermissionGranted,
  loadExtension,
  startDaemon,
} = await import("./harness.mjs");

const PORT = Number(process.env["SSH_BROWSER_E2E_PORT"] ?? 17393);

const { child, token } = await startDaemon(PORT);
const profile = await mkdtemp(join(tmpdir(), "ssh-browser-probe-"));
const extension = await extensionWithPermissionGranted();
let browser;

try {
  // Through the extension and its PAC, not through a blanket `proxy:` setting. A real site
  // pulls fonts and KaTeX off a CDN, and a blanket proxy sends those to the daemon too,
  // where they fail as `ERR_TUNNEL_CONNECTION_FAILED` and drown the findings. The PAC sends
  // anything that is not an alias host DIRECT, which is also what a reader would have.
  browser = await chromium.launchPersistentContext(profile, {
    ...browserOptions(),
    args: loadExtension(extension),
  });
  await connectThroughDashboard(browser, PORT);

  const page = await browser.newPage();

  // Kept in three lists rather than one, because a 404 for a favicon and a module that threw
  // are different news and reading them interleaved hides the second.
  const noise = [];
  const failed = [];
  const statuses = [];
  page.on("console", (m) => {
    if (m.type() !== "error" && m.type() !== "warning") return;
    // With the URL it came from. "Failed to load resource" on its own names nothing, and the
    // request behind it is often one `page.on("response")` never sees — the browser fetches
    // a favicon outside the renderer, so it appears here and in no other list.
    const at = m.location()?.url;
    noise.push(`${m.type()}: ${m.text()}${at ? `  <- ${at}` : ""}`);
  });
  page.on("pageerror", (e) => noise.push(`pageerror: ${e.message}`));
  page.on("requestfailed", (r) => failed.push(`${r.url()} — ${r.failure()?.errorText}`));
  page.on("response", (r) => statuses.push([r.status(), r.url()]));

  const url = `http://${ALIAS}.${SUFFIX}${path}`;
  console.log(`\n${url}\n  -> ${host}:${dir}\n`);

  // Read from the daemon rather than counted here. What a browser asks for and what the
  // remote is asked for are different numbers by design — the whole point is that the second
  // does not follow the first — so counting requests in this process would measure the thing
  // that is supposed to be large.
  // Off `hello`, the cheap route: `hosts` runs `ssh -G` once per configured host, which takes
  // long enough to expire the listings between two samples and so perturbs what it measures.
  const trips = async () => {
    const res = await fetch(`http://127.0.0.1:${PORT}/_control/hello`, {
      headers: { [TOKEN_HEADER]: token },
    });
    if (!res.ok) throw new Error(`/_control/hello said ${res.status}`);
    return (await res.json()).trips;
  };
  const tripsBefore = await trips();

  const started = Date.now();
  let landed = "networkidle";
  try {
    await page.goto(url, { waitUntil: "networkidle", timeout: 120_000 });
  } catch (e) {
    // Reported rather than thrown: a page that never goes idle is itself a finding, and
    // everything below still says something about what did load.
    landed = `never went idle — ${e.message.split("\n")[0]}`;
  }
  const elapsed = Date.now() - started;

  const seen = await page.evaluate(() => ({
    title: document.title,
    url: location.href,
    // Enough to tell a rendered page from an error page, and no more.
    text: (document.body?.innerText ?? "").slice(0, 300).replace(/\s+/g, " ").trim(),
    scripts: document.querySelectorAll("script").length,
    // A stylesheet that 404s is still a StyleSheet object. Only its rule count says whether
    // any bytes arrived.
    sheets: document.styleSheets.length,
    rules: [...document.styleSheets].reduce((n, s) => {
      try {
        return n + s.cssRules.length;
      } catch {
        // A cross-origin sheet throws on access rather than reporting zero.
        return n;
      }
    }, 0),
    broken: [...document.images].filter((i) => !i.naturalWidth).length,
    images: document.images.length,
  }));

  console.log(`loaded in ${elapsed} ms (${landed})`);
  console.log(`  title       ${seen.title}`);
  console.log(`  url         ${seen.url}`);
  console.log(`  scripts     ${seen.scripts}`);
  console.log(`  stylesheets ${seen.sheets} (${seen.rules} rules)`);
  console.log(`  images      ${seen.images}, broken: ${seen.broken}`);
  console.log(`  text        ${seen.text.slice(0, 160)}`);

  // The two numbers the product is about, side by side. The browser's request count is what
  // a naive server would have paid the remote; the round trips are what this one actually did.
  const tripsAfter = await trips();
  const cost = tripsAfter - tripsBefore;
  // Snapshotted before the reload below, which would otherwise double it.
  const asked = statuses.length;

  // A revisit must cost nothing at all, which is the half of the invariant one load cannot
  // show. Same page, same session, straight after.
  await page.reload({ waitUntil: "networkidle" }).catch(() => {});
  const onRevisit = (await trips()) - tripsAfter;

  console.log(
    `\nbrowser requests ${asked}  ->  remote round trips ${cost}` +
      `  (${(asked / Math.max(cost, 1)).toFixed(1)}x), revisit ${onRevisit}`,
  );

  const bad = statuses.filter(([s]) => s >= 400);
  console.log(`\n>=400: ${bad.length}`);
  for (const [s, u] of bad.slice(0, 40)) console.log(`  ${s}  ${u}`);

  console.log(`\nfailed outright: ${failed.length}`);
  for (const f of failed.slice(0, 40)) console.log(`  ${f}`);

  console.log(`\nconsole: ${noise.length}`);
  for (const c of noise.slice(0, 40)) console.log(`  ${c}`);
} finally {
  await browser?.close();
  if (child.exitCode === null && child.signalCode === null) {
    child.kill();
    await once(child, "exit").catch(() => {});
  }
  await rm(profile, { recursive: true, force: true }).catch(() => {});
  await rm(extension, { recursive: true, force: true }).catch(() => {});
}
