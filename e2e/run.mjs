// End to end, in a real browser, against a real SSH host.
//
// Everything else in this repository tests a piece. This tests the claim: that a file on a
// host reachable only over SSH renders in a browser exactly as it would anywhere else. No unit
// test can make that claim, because the thing being claimed is about a browser.
//
// The same bytes are opened twice — once through the daemon and once over `file://` — and the
// difference between the two results is the entire reason this project exists. A `file://`
// document has an opaque origin, so its ES module import fails and its `fetch` is refused. The
// second half of this script is therefore not a control for tidiness; it is the statement of
// the problem, kept beside the statement of the solution so that neither can quietly stop
// being true.
//
// Run it with:
//
//   npm --prefix e2e ci
//   npm --prefix e2e run e2e
//
// SSH_BROWSER_E2E_HOST and SSH_BROWSER_E2E_BASE point it at a host. The defaults serve this
// directory over `localhost`, which is what CI does; a developer can point it at a real host
// instead, which is the arrangement that has found the bugs a loopback never would.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");

const HOST = process.env["SSH_BROWSER_E2E_HOST"] ?? "localhost";
const BASE = process.env["SSH_BROWSER_E2E_BASE"] ?? join(here, "tree");
const ALIAS = "e2e";
const SUFFIX = "ssh-browser";
// Not the daemon's default: a developer running this must not have it collide with the daemon
// they already have open on 7391.
const PORT = Number(process.env["SSH_BROWSER_E2E_PORT"] ?? 17391);

const DAEMON =
  process.env["SSH_BROWSER_E2E_BIN"] ??
  join(repo, "target", "debug", process.platform === "win32" ? "ssh-browser.exe" : "ssh-browser");

/// Start the daemon and wait until it says it is listening.
///
/// Waiting for the line rather than sleeping: a fixed sleep is either too short on a loaded
/// runner, which makes the suite flaky, or too long everywhere else.
async function startDaemon() {
  const child = spawn(
    DAEMON,
    ["serve", "--port", String(PORT), "--suffix", SUFFIX, `${ALIAS}=${HOST}:${BASE}`],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  let log = "";
  const ready = new Promise((ok, no) => {
    const onData = (chunk) => {
      log += String(chunk);
      if (log.includes(`listening on 127.0.0.1:${PORT}`)) {
        ok();
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", (code) => {
      no(new Error(`the daemon exited with ${code} before listening:\n${log}`));
    });
    setTimeout(() => no(new Error(`the daemon never listened:\n${log}`)), 30_000);
  });

  await ready;
  return { child, log: () => log };
}

/// Run the PAC the daemon serves and ask it where a URL should go.
///
/// Checked here rather than by watching a browser consume it, because Playwright overrides
/// `--proxy-pac-url` with its own proxy configuration — a browser that loaded the page would
/// therefore prove nothing about the script. Evaluating it directly is also the stronger test:
/// it can ask about hosts the browser is never pointed at, which is where the interesting
/// answer is.
async function routeAccordingToPac(url, host) {
  const res = await fetch(`http://127.0.0.1:${PORT}/proxy.pac`);
  assert.ok(res.ok, `the daemon would not serve a PAC (${res.status})`);
  const sandbox = {
    // The one PAC helper this script uses. Implemented per the original Netscape
    // specification: true when `host` ends with `domain`.
    dnsDomainIs: (h, domain) => h.length >= domain.length && h.endsWith(domain),
  };
  vm.createContext(sandbox);
  vm.runInContext(await res.text(), sandbox);
  return vm.runInContext(
    `FindProxyForURL(${JSON.stringify(url)}, ${JSON.stringify(host)})`,
    sandbox,
  );
}

/// What the page ended up being, as the browser sees it.
///
/// Read out of the DOM rather than out of the network log, because the claim is about what the
/// page became and not about which requests were made.
async function inspect(page) {
  return page.evaluate(() => ({
    origin: location.origin,
    module: document.getElementById("module")?.textContent ?? "",
    fetched: document.getElementById("fetched")?.textContent ?? "",
    headingColour: getComputedStyle(document.getElementById("heading")).color,
    // A broken image still has an element. Only its intrinsic width says whether bytes
    // arrived and decoded.
    picWidth: document.getElementById("pic")?.naturalWidth ?? 0,
  }));
}

async function main() {
  const { child, log } = await startDaemon();
  const profile = await mkdtemp(join(tmpdir(), "ssh-browser-e2e-"));
  let browser;
  let failures = 0;

  const check = (what, fn) => {
    try {
      fn();
      console.log(`  ok    ${what}`);
    } catch (e) {
      failures += 1;
      // The whole message, not its first line. `assert.equal` puts the two values on the
      // lines after the summary, and those are the only part worth reading.
      const detail = String(e.message)
        .split("\n")
        .map((l) => `        ${l}`)
        .join("\n");
      console.log(`  FAIL  ${what}\n${detail}`);
    }
  };

  try {
    console.log("\nthe PAC the daemon serves");
    const toAlias = await routeAccordingToPac(`http://${ALIAS}.${SUFFIX}/`, `${ALIAS}.${SUFFIX}`);
    const toElsewhere = await routeAccordingToPac("https://example.com/", "example.com");
    // A host that merely contains the suffix is somebody else's. This is the routing-layer
    // counterpart of refusing a rebinding Host, and it is the case a naive substring test
    // would get wrong.
    const toLookalike = await routeAccordingToPac(
      `http://${SUFFIX}.evil.example/`,
      `${SUFFIX}.evil.example`,
    );

    check("an alias host routes to the daemon", () =>
      assert.equal(toAlias, `PROXY 127.0.0.1:${PORT}`),
    );
    check("everything else goes direct", () => assert.equal(toElsewhere, "DIRECT"));
    check("a host that only contains the suffix goes direct", () =>
      assert.equal(toLookalike, "DIRECT"),
    );

    browser = await chromium.launchPersistentContext(profile, {
      headless: true,
      // Not `--proxy-pac-url`: Playwright replaces it with its own proxy configuration, so a
      // page that loaded under it would prove nothing. Pointing at the daemon directly is
      // what the PAC resolves to anyway, and the PAC itself is checked above.
      proxy: { server: `http://127.0.0.1:${PORT}` },
      ...(process.env["SSH_BROWSER_E2E_BROWSER"]
        ? { executablePath: process.env["SSH_BROWSER_E2E_BROWSER"] }
        : {}),
    });

    const page = await browser.newPage();
    // Kept so that a failure says what the browser complained about rather than only that a
    // marker was not set. A CORS refusal and a 404 look identical in the DOM.
    const complaints = [];
    page.on("console", (m) => {
      if (m.type() === "error") {
        complaints.push(m.text());
      }
    });
    page.on("pageerror", (e) => complaints.push(String(e.message)));
    page.on("response", (r) => {
      if (r.status() >= 400) {
        complaints.push(`${r.status()} ${r.url()}`);
      }
    });

    console.log(`\nthrough the daemon — http://${ALIAS}.${SUFFIX}/`);
    await page.goto(`http://${ALIAS}.${SUFFIX}/`, { waitUntil: "networkidle" });
    const served = await inspect(page);
    console.log(`  (${JSON.stringify(served)})`);
    if (complaints.length > 0) {
      console.log(`  (browser said: ${complaints.join(" | ")})`);
    }

    check("the origin is the alias, not 127.0.0.1", () =>
      assert.equal(served.origin, `http://${ALIAS}.${SUFFIX}`),
    );
    check("the ES module executed, so its relative import resolved", () =>
      assert.equal(served.module, "module executed"),
    );
    check("fetch() of a relative path succeeded", () =>
      assert.equal(served.fetched, "fetch succeeded"),
    );
    check("the stylesheet applied", () => assert.equal(served.headingColour, "rgb(0, 128, 64)"));
    check("the image decoded", () => assert.equal(served.picWidth, 1));

    console.log("\nthe same bytes over file:// — what this project exists to avoid");
    const asFile = pathToFileURL(join(here, "tree", "index.html")).href;
    await page.goto(asFile, { waitUntil: "load" });
    // No networkidle here: nothing loads, so there is no network to go idle. A short settle is
    // enough for the module to have failed.
    await page.waitForTimeout(500);
    const local = await inspect(page);

    // Chromium spells a file URL's origin `file://` rather than `null`. That string is not
    // the evidence of opacity — the two checks below it are, because a module that cannot
    // import and a fetch that is refused are what opacity actually costs.
    check("the origin is not an http origin", () => assert.equal(local.origin, "file://"));
    check("the ES module did NOT execute", () => assert.equal(local.module, "module did not run"));
    check("fetch() did NOT succeed", () => assert.equal(local.fetched, "fetch did not run"));
    // The contrast is about origin, not about whether files can be read at all: a stylesheet
    // and an image load fine from `file://`. Scripts and fetch are what break, which is
    // exactly the set of things a modern page is built out of.
    check("but the stylesheet still applied, so this is about origin and not about access", () =>
      assert.equal(local.headingColour, "rgb(0, 128, 64)"),
    );
  } catch (e) {
    failures += 1;
    console.error(`\nthe run itself failed: ${e.message}`);
    console.error(log());
  } finally {
    await browser?.close();
    child.kill();
    await once(child, "exit").catch(() => {});
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }

  console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
