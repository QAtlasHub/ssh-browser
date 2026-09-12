// End to end, in a real browser, against a real SSH host.
//
// Everything else in this repository tests a piece. This tests the claims: that a file on a
// host reachable only over SSH renders in a browser exactly as it would anywhere else, that
// the daemon refuses what it says it refuses, and that the extension can read back what it
// writes. No unit test can stand in for the first or the last, because both are about a
// browser.
//
// The central comparison is that the same bytes are opened twice — once through the daemon and
// once over `file://`. A `file://` document has an opaque origin, so its ES module import fails
// and its `fetch` is refused. That half is not a control for tidiness; it is the statement of
// the problem, kept beside the statement of the solution so that neither can quietly stop
// being true.
//
// Run it with:
//
//   npm --prefix e2e ci && npm --prefix e2e run browser
//   npm --prefix e2e run e2e
//
// SSH_BROWSER_E2E_HOST and SSH_BROWSER_E2E_BASE point it at a host. The defaults serve this
// directory over `localhost`, which is what CI does; a developer can point it at a real host
// instead, which is the arrangement that has found the bugs a loopback never would.

import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import vm from "node:vm";

import { chromium } from "playwright";

import {
  ALIAS,
  SUFFIX,
  TOKEN_HEADER,
  connectThroughPopup,
  extensionWithPermissionGranted,
  loadExtension,
  startDaemon,
} from "./harness.mjs";

const here = join(import.meta.dirname);

// Not the daemon's default: a developer running this must not have it collide with the daemon
// they already have open on 7391.
const PORT = Number(process.env["SSH_BROWSER_E2E_PORT"] ?? 17391);

let failures = 0;

function check(what, fn) {
  try {
    fn();
    console.log(`  ok    ${what}`);
  } catch (e) {
    failures += 1;
    // The whole message, not its first line: `assert.equal` puts the two values on the lines
    // after the summary, and those are the only part worth reading.
    const detail = String(e.message)
      .split("\n")
      .map((l) => `        ${l}`)
      .join("\n");
    console.log(`  FAIL  ${what}\n${detail}`);
  }
}

/// One raw HTTP request, with whatever Host and method are wanted.
///
/// `fetch` refuses to set a Host header, and the Host header is what one of the two
/// load-bearing guards is made of — so the check that matters most here needs the lower-level
/// client.
function request({ method = "GET", path = "/", host, headers = {} }) {
  return new Promise((ok, no) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: PORT,
        method,
        path,
        headers: { ...(host ? { Host: host } : {}), ...headers },
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c) => {
          body += c;
        });
        res.on("end", () => ok({ status: res.statusCode, headers: res.headers, body }));
      },
    );
    req.on("error", no);
    req.end();
  });
}

const alias = (path, extra = {}) => request({ path, host: `${ALIAS}.${SUFFIX}`, ...extra });

/// Run the PAC the daemon serves and ask it where a URL should go.
///
/// Checked here rather than by watching a browser consume it, because Playwright overrides
/// `--proxy-pac-url` with its own proxy configuration — a browser that loaded the page would
/// prove nothing about the script. Evaluating it directly is also the stronger test: it can ask
/// about hosts the browser is never pointed at, which is where the interesting answer is.
async function routeAccordingToPac(url, host) {
  const res = await fetch(`http://127.0.0.1:${PORT}/proxy.pac`);
  assert.ok(res.ok, `the daemon would not serve a PAC (${res.status})`);
  const sandbox = {
    // The one PAC helper this script uses, per the original Netscape specification: true when
    // `host` ends with `domain`.
    dnsDomainIs: (h, domain) => h.length >= domain.length && h.endsWith(domain),
  };
  vm.createContext(sandbox);
  vm.runInContext(await res.text(), sandbox);
  return vm.runInContext(
    `FindProxyForURL(${JSON.stringify(url)}, ${JSON.stringify(host)})`,
    sandbox,
  );
}

/// What a page ended up being, as the browser sees it.
///
/// Read out of the DOM rather than out of the network log, because the claim is about what the
/// page became and not about which requests were made.
async function inspect(page) {
  return page.evaluate(() => ({
    origin: location.origin,
    module: document.getElementById("module")?.textContent ?? "",
    fetched: document.getElementById("fetched")?.textContent ?? "",
    headingColour: getComputedStyle(document.getElementById("heading")).color,
    // A broken image still has an element. Only its intrinsic width says whether bytes arrived
    // and decoded.
    picWidth: document.getElementById("pic")?.naturalWidth ?? 0,
  }));
}

async function main() {
  const { child, token, log } = await startDaemon(PORT);
  const profile = await mkdtemp(join(tmpdir(), "ssh-browser-e2e-"));
  const extension = await extensionWithPermissionGranted();
  let browser;

  try {
    console.log("\nthe PAC the daemon serves");
    const toAlias = await routeAccordingToPac(`http://${ALIAS}.${SUFFIX}/`, `${ALIAS}.${SUFFIX}`);
    const toElsewhere = await routeAccordingToPac("https://example.com/", "example.com");
    // A host that merely contains the suffix is somebody else's. This is the routing-layer
    // counterpart of refusing a rebinding Host, and the case a naive substring test gets wrong.
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

    console.log("\nwhat the daemon refuses");
    const rebinding = await request({ path: "/", host: "evil.example" });
    const traversal = await alias("/%2e%2e/%2e%2e/etc/passwd");
    const writing = await alias("/index.html", { method: "PUT" });
    const noToken = await request({ path: "/_control/hello", host: `127.0.0.1:${PORT}` });
    const preflight = await request({
      method: "OPTIONS",
      path: "/_control/hello",
      host: `127.0.0.1:${PORT}`,
      headers: { [TOKEN_HEADER]: token },
    });

    check("a rebinding Host is refused", () => assert.equal(rebinding.status, 403));
    check("traversal is refused in its percent-encoded spelling", () =>
      assert.equal(traversal.status, 403),
    );
    check("the alias origin is read-only", () => assert.equal(writing.status, 405));
    check("the control API needs its token", () => assert.equal(noToken.status, 401));
    // The boundary: a page that could negotiate CORS could start talking to the control API.
    check("a preflight is refused even with a valid token", () =>
      assert.equal(preflight.status, 405),
    );
    check("no control response carries CORS headers", () =>
      assert.equal(
        Object.keys(noToken.headers).find((h) => h.startsWith("access-control-")),
        undefined,
      ),
    );

    console.log("\nserving");
    const first = await alias("/index.html");
    const etag = first.headers["etag"];
    // Conditional only when there is something to be conditional on. Without this guard, a
    // tree that is not where it was configured to be produced `Invalid value "undefined" for
    // header "If-None-Match"` and took the whole run down — an error about the harness,
    // standing where "the page was a 404" should have been.
    const revisit = etag
      ? await alias("/index.html", { headers: { "If-None-Match": etag } })
      : { status: 0, headers: {}, body: "" };
    const listing = await alias("/assets/");
    const redirect = await alias("/assets");
    const ranged = await alias("/assets/app.mjs", { headers: { Range: "bytes=0-9" } });

    check("a page is served", () => assert.equal(first.status, 200));
    check("it carries a weak validator", () => assert.match(etag ?? "", /^W\//));
    // Invariant 2 from the outside: the conditional GET never leaves the daemon.
    check("a revisit holding the validator gets a 304", () => assert.equal(revisit.status, 304));
    check("a directory lists", () => {
      assert.equal(listing.status, 200);
      assert.match(listing.body, /app\.mjs/);
    });
    // Without this, every relative link on the page below resolves one level too high.
    check("a directory without its trailing slash redirects", () =>
      assert.equal(redirect.status, 301),
    );
    check("a byte range is served as one", () => {
      assert.equal(ranged.status, 206);
      assert.equal(ranged.body.length, 10);
      assert.match(ranged.headers["content-range"] ?? "", /^bytes 0-9\//);
    });

    browser = await chromium.launchPersistentContext(profile, {
      // channel: "chromium" rather than the bundled headless shell: an MV3 service worker
      // does not start in the old headless mode at all, so the extension half of this harness
      // silently has nothing to talk to.
      channel: "chromium",
      headless: true,
      // Not `--proxy-pac-url`: Playwright replaces it with its own proxy configuration, so a
      // page that loaded under it would prove nothing. Pointing at the daemon directly is what
      // the PAC resolves to anyway, and the PAC itself is checked above.
      proxy: { server: `http://127.0.0.1:${PORT}` },
      args: loadExtension(extension),
      ...(process.env["SSH_BROWSER_E2E_BROWSER"]
        ? { executablePath: process.env["SSH_BROWSER_E2E_BROWSER"] }
        : {}),
    });

    const page = await browser.newPage();
    // Kept so a failure says what the browser complained about rather than only that a marker
    // was not set: a CORS refusal and a 404 look identical in the DOM.
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
    // No networkidle: nothing loads, so there is no network to go idle. A short settle is
    // enough for the module to have failed.
    await page.waitForTimeout(500);
    const local = await inspect(page);

    // Chromium spells a file URL's origin `file://` rather than `null`. That string is not the
    // evidence of opacity — the two checks below it are, because a module that cannot import
    // and a fetch that is refused are what opacity actually costs.
    check("the origin is not an http origin", () => assert.equal(local.origin, "file://"));
    check("the ES module did NOT execute", () => assert.equal(local.module, "module did not run"));
    check("fetch() did NOT succeed", () => assert.equal(local.fetched, "fetch did not run"));
    // The contrast is about origin, not about whether files can be read at all: a stylesheet
    // and an image load fine from `file://`. Scripts and fetch are what break, which is exactly
    // the set of things a modern page is built out of.
    check("but the stylesheet still applied, so this is about origin and not about access", () =>
      assert.equal(local.headingColour, "rgb(0, 128, 64)"),
    );

    console.log("\nthe extension");
    const { popup } = await connectThroughPopup(browser, PORT, token);
    const status = await popup.textContent("#status");
    const links = await popup.$$eval("#aliases a", (as) => as.map((a) => a.textContent));

    check("the popup connects and names the daemon", () =>
      assert.match(status ?? "", /connected to ssh-browser/),
    );
    check("it lists the alias as a link", () =>
      assert.deepEqual(links, [`http://${ALIAS}.${SUFFIX}/`]),
    );

    // A filename that needs percent-escaping, which is where the two directions of the
    // annotation API can disagree about which document they mean. They did: a note was written
    // under one name and looked for under another, and the panel showed nothing at all.
    const spaced = "spaced name.html";
    const posted = await fetch(`http://127.0.0.1:${PORT}/_control/annotations`, {
      method: "POST",
      headers: { [TOKEN_HEADER]: token, "content-type": "application/json" },
      body: JSON.stringify({
        doc: `${ALIAS}/${encodeURIComponent(spaced)}`,
        op: "add",
        body: "written by the harness",
        selectors: [{ type: "TextQuoteSelector", exact: "anchor me here" }],
      }),
    });
    check("the control API accepts a note on an escaped filename", () =>
      assert.equal(posted.status, 200),
    );

    const noted = await browser.newPage();
    await noted.goto(`http://${ALIAS}.${SUFFIX}/${encodeURIComponent(spaced)}`, {
      waitUntil: "networkidle",
    });
    // The panel is a closed shadow root, so its text is deliberately unreachable from the page
    // — that is the point of it. What is observable is that the host element exists, and that a
    // highlight got registered, which happens only once a note has been fetched *and* anchored.
    await noted
      .waitForFunction(() => CSS.highlights.size > 0, { timeout: 20_000 })
      .catch(() => {});
    const panel = await noted.evaluate(() => ({
      host: document.getElementById("ssh-browser-panel-host") !== null,
      highlights: CSS.highlights.size,
      // Nothing may be added to the document the reader came for.
      styleTags: document.querySelectorAll("style").length,
    }));

    check("the content script ran on the alias page", () => assert.equal(panel.host, true));
    check("the note was fetched and anchored", () => assert.equal(panel.highlights, 1));
    check("no <style> element was added to the document", () => assert.equal(panel.styleTags, 0));
  } catch (e) {
    failures += 1;
    console.error(`\nthe run itself failed: ${e.message}`);
    console.error(log());
  } finally {
    await browser?.close();
    child.kill();
    await once(child, "exit").catch(() => {});
    await rm(profile, { recursive: true, force: true }).catch(() => {});
    await rm(extension, { recursive: true, force: true }).catch(() => {});
  }

  console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
