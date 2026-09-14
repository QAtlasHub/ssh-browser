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
  browserOptions,
  connectThroughDashboard,
  HOST,
  BASE,
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
    const got = fn();
    // Refused rather than awaited. This helper is synchronous, so an `async` body used to
    // report `ok` before it had run anything — a check that cannot fail, which is worse
    // than no check. Making it loud costs one line and closes the whole class; awaiting
    // instead would mean every one of the call sites below had to remember to.
    if (got !== undefined && typeof got?.then === "function") {
      throw new Error("check() is synchronous — await the value before calling it");
    }
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

/// Stop the daemon and wait for it to actually go.
///
/// Idempotent on purpose. The cleanup in `finally` runs whether or not a check stopped it
/// already, and `once(child, "exit")` on a process that has already exited waits for an
/// event that will never fire again: the run printed every check as passing and then exited
/// 13 for an unsettled top-level await, which is a red CI run naming no failure.
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await once(child, "exit").catch(() => {});
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
      ...browserOptions(),
      // Not `--proxy-pac-url`: Playwright replaces it with its own proxy configuration, so a
      // page that loaded under it would prove nothing. Pointing at the daemon directly is what
      // the PAC resolves to anyway, and the PAC itself is checked above.
      proxy: { server: `http://127.0.0.1:${PORT}` },
      args: loadExtension(extension),
    });

    const page = await browser.newPage();
    // Kept so a failure says what the browser complained about rather than only that a marker
    // was not set: a CORS refusal and a 404 look identical in the DOM.
    const complaints = [];
    // Every browser asks for a favicon nobody put there, and the daemon correctly answers 404.
    // Reported, that line appears on every single run and looks exactly like a real 404 would
    // — so the noise would be the thing hiding the signal.
    const expected = (url) => url.endsWith("/favicon.ico");
    page.on("console", (m) => {
      // The generic "Failed to load resource" carries no URL, so it cannot be told apart from
      // the favicon. The response handler below reports the same failures with one attached.
      if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) {
        complaints.push(m.text());
      }
    });
    page.on("pageerror", (e) => complaints.push(String(e.message)));
    page.on("response", (r) => {
      if (r.status() >= 400 && !expected(r.url())) {
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

    console.log("\ninvariant 2, over a real transport");
    // The unit test for this holds a fake remote and a three-byte fixture. This is the same
    // claim against whatever host the run is pointed at, through the real SFTP transport.
    //
    // Not through the browser, deliberately. A browser revisit is a *different and stronger*
    // claim — that a whole page costs nothing the second time — and it is not true: against a
    // real host this fixture costs four round trips on a browser revisit, because a page
    // fetches things no HTML scan can see and the freshness window is a wall clock a test has
    // to race. A check asserting zero there asserts something nobody established. What
    // invariant 2 actually says is about a request, and about a request it is exact.
    //
    // The count comes off `hello`, not `hosts`. `hosts` runs `ssh -G` once per configured
    // host; sampled either side of a measurement it takes long enough to expire the very
    // listings being measured. Not a hypothesis — the first version of this check used
    // `hosts`, passed against a real host, and failed in CI for exactly that reason.
    const remoteTrips = async () => {
      const res = await fetch(`http://127.0.0.1:${PORT}/_control/hello`, {
        headers: { [TOKEN_HEADER]: token },
      });
      assert.ok(res.ok, `/_control/hello said ${res.status}`);
      return (await res.json()).trips;
    };

    /// What one request cost the remote, and what came back.
    const costOf = async (path, headers = {}) => {
      const before = await remoteTrips();
      const res = await alias(path, { headers });
      return { spent: (await remoteTrips()) - before, status: res.status, headers: res.headers };
    };

    // A file nothing else in this run reads, and nothing links to. Asserting on index.html
    // made the first read cold only on a machine slow enough for the freshness window to
    // expire between sections: it passed against a real host and failed in CI, which is the
    // worst way round. The file itself says why it has to stay unread.
    const cold = await costOf("/cold-read.txt");
    const warm = await costOf("/cold-read.txt");
    const sliced = await costOf("/cold-read.txt", { Range: "bytes=0-15" });
    const validated = await costOf("/cold-read.txt", { "If-None-Match": cold.headers["etag"] });

    check("the first read of a file costs the remote something", () =>
      assert.ok(cold.spent > 0, `nothing was fetched at all (${cold.spent})`),
    );
    check("reading it again costs nothing", () => assert.equal(warm.spent, 0));
    // Sliced out of the body already held rather than fetched.
    check("and a range out of it costs nothing", () => {
      assert.equal(sliced.status, 206);
      assert.equal(sliced.spent, 0);
    });
    check("the browser's own validator is answered here, not there", () => {
      assert.equal(validated.status, 304);
      assert.equal(validated.spent, 0);
    });

    console.log("\nwhat an http origin does not buy");
    // Measured rather than reasoned about, and pinned in both directions, because the README
    // used to imply this fixes everything `file://` breaks. It does not: an alias origin is
    // plain http on a name that is not loopback, so it is not a potentially trustworthy
    // origin and the secure-context APIs are simply absent from it.
    //
    // The comparison that makes it sharp is the no-proxy fallback on 127.0.0.1, which *is*
    // loopback and therefore *is* a secure context. The two modes trade against each other:
    // aliases give origin separation, loopback gives secure context, and neither gives both
    // until the https mode is built.
    const surface = () => ({
      secure: window.isSecureContext,
      serviceWorker: "serviceWorker" in navigator,
      subtle: typeof crypto !== "undefined" && crypto.subtle !== undefined,
      caches: typeof caches !== "undefined",
      indexedDB: typeof indexedDB !== "undefined",
    });

    const ctx = await browser.newPage();
    await ctx.goto(`http://${ALIAS}.${SUFFIX}/`, { waitUntil: "domcontentloaded" });
    const onAlias = await ctx.evaluate(surface);
    await ctx.goto(`http://127.0.0.1:${PORT}/${ALIAS}/`, { waitUntil: "domcontentloaded" });
    const onLoopback = await ctx.evaluate(surface);
    await ctx.close();

    check("an alias origin is not a secure context, so these are absent", () => {
      assert.equal(onAlias.secure, false);
      assert.equal(onAlias.serviceWorker, false);
      assert.equal(onAlias.subtle, false);
      assert.equal(onAlias.caches, false);
    });
    // Said separately because it is the part that still works, and a page relying on it is
    // fine either way.
    check("but storage that is not gated on it still is", () =>
      assert.equal(onAlias.indexedDB, true),
    );
    check("the loopback fallback is a secure context, and has all of them", () => {
      assert.equal(onLoopback.secure, true);
      assert.equal(onLoopback.serviceWorker, true);
      assert.equal(onLoopback.subtle, true);
      assert.equal(onLoopback.caches, true);
    });

    console.log("\nthe tree");
    const tree = await browser.newPage();
    await tree.goto(`http://${ALIAS}.${SUFFIX}/assets/`, { waitUntil: "domcontentloaded" });

    const opened = await tree.evaluate(() => ({
      // The whole path is expanded, so the root's other entries are there beside it.
      rows: [...document.querySelectorAll("a.row")].map((a) => a.getAttribute("href")),
      here: document.querySelector("a.row.here")?.getAttribute("href") ?? null,
    }));
    check("a directory opens as a tree with its whole path expanded", () => {
      assert.ok(opened.rows.includes("/assets/"), `no assets row: ${opened.rows}`);
      assert.ok(opened.rows.includes("/index.html"), `the root is not shown: ${opened.rows}`);
      assert.ok(opened.rows.includes("/assets/style.css"), `not expanded: ${opened.rows}`);
    });
    check("and the directory you asked for is the selected one", () =>
      assert.equal(opened.here, "/assets/"),
    );

    // The load-bearing interaction: a folder that is not on the path has no children in the
    // page, so opening it has to go and get them.
    //
    // The document is marked first, because every row is a real link and the tree works
    // without any script at all — clicking one simply loads that directory's page, which
    // ends up looking almost the same. Counting rows could not tell the two apart, and the
    // first version of this check passed with the script deleted. What distinguishes them
    // is that the enhanced one never navigates, so the mark survives.
    const before = opened.rows.length;
    await tree.evaluate(() => {
      Object.assign(window, { sameDocument: true });
    });
    await tree.click(`a.row[href="/assets/nested/"]`);
    await tree.waitForSelector(`a.row[href="/assets/nested/deep.txt"]`, { timeout: 15_000 });
    const after = await tree.evaluate(() => ({
      rows: document.querySelectorAll("a.row").length,
      here: document.querySelector("a.row.here")?.getAttribute("href") ?? null,
      path: location.pathname,
      same: window.sameDocument === true,
    }));
    check("expanding a folder fetches its level and puts it in place", () => {
      assert.ok(after.rows > before, `${before} rows before, ${after.rows} after`);
      assert.equal(after.same, true, "the page navigated instead of expanding in place");
    });
    check("and the address bar follows, so a reload lands where you are", () => {
      assert.equal(after.here, "/assets/nested/");
      assert.equal(after.path, "/assets/nested/");
    });
    await tree.close();

    console.log("\nthe dashboard");
    const { dashboard } = await connectThroughDashboard(browser, PORT);
    // Waited for, not assumed. `connectThroughDashboard` returns once the daemon line
    // names the port; the sites are fetched after that, so reading the rows straight
    // afterwards is a race that passes most of the time.
    const rowFor = `#view button[data-alias="${ALIAS}"]`;
    await dashboard.waitForSelector(rowFor);

    const daemonLine = await dashboard.textContent("#daemon");
    check("it connects and names the daemon", () =>
      assert.match(daemonLine ?? "", /connected to ssh-browser/),
    );

    // The alias is served but is named in no ssh_config -- `e2e` is not a Host, it is a
    // name given on the command line. Listing only ssh_config's hosts would leave it live
    // and visible nowhere, which is the sort of invisible state this is meant not to have.
    // So the check is that what is *being served* appears, not that a host does.
    const row = (await dashboard.textContent(rowFor)) ?? "";
    // Against the *resolved* root, not the configured one: `~/x` is served at `/home/you/x`,
    // and the row should name where the site actually is rather than repeating what was
    // typed. Dropping the tilde makes the tail comparable whichever form was given.
    const tail = BASE.startsWith("~") ? BASE.slice(1) : BASE;
    check("the site is listed with its URL and where it is served from", () => {
      assert.ok(
        row.includes(`http://${ALIAS}.${SUFFIX}/`),
        `the row should carry the site URL: ${row}`,
      );
      assert.ok(row.endsWith(tail), `the row should name the root ${tail}: ${row}`);
    });

    // Nothing to paste is the point: the dashboard asked the daemon for the token, and the
    // daemon hands it to anything that is not a page. A field for it would mean the old
    // flow had merely been hidden.
    const tokenField = await dashboard.$("#token");
    check("there is no token field to fill in", () => assert.equal(tokenField, null));

    // souta's flow: dashboard -> the alias -> the thing you do with it.
    await dashboard.click(rowFor);
    await dashboard.waitForSelector("#open-site");
    const facts = (await dashboard.textContent("#view")) ?? "";
    const rootValue = await dashboard.inputValue("#root");
    const aliasHash = new URL(dashboard.url()).hash;
    check("clicking a site opens its own page", () => {
      assert.equal(aliasHash, `#${ALIAS}`);
      assert.ok(facts.includes(HOST), `the page should name the ssh host: ${facts}`);
      // The root box is pre-filled with where it is actually rooted, so changing it is an
      // edit rather than a retype. An empty box would invite `~` being typed over a root
      // that was not the home directory.
      assert.ok(rootValue.endsWith(tail), `the root box should hold ${tail}: ${rootValue}`);
    });

    const siteTab = browser.waitForEvent("page", { timeout: 30_000 });
    await dashboard.click("#open-site");
    const site = await siteTab;
    await site.waitForLoadState("domcontentloaded");
    const siteHost = new URL(site.url()).host;
    // What the root serves is the site's own `index.html` when there is one, and a listing
    // when there is not -- which is what a host does, and is the whole claim. The listing
    // case is checked in "serving" above; this is the other one.
    const landed = await site.evaluate(() => ({
      heading: document.querySelector("h1")?.textContent ?? "",
      title: document.title,
    }));
    check("and the site opens on the alias origin", () =>
      assert.equal(siteHost, `${ALIAS}.${SUFFIX}`),
    );
    check("serving the remote's own index page at the root", () => {
      assert.equal(landed.heading, "served over ssh");
      assert.equal(landed.title, "ssh-browser e2e");
    });
    await site.close();

    // Clicking a host that is not being served yet makes the daemon ssh to it, which is a
    // real side effect on somebody's real machine. So it is opt-in by name rather than
    // picking whatever happened to be first in the config, and says so when it is not run
    // -- a check that quietly does nothing is worse than one that is absent.
    const clickable = process.env["SSH_BROWSER_E2E_OPEN_HOST"];
    if (clickable === undefined) {
      console.log(
        "  skip  serving a host by clicking it, and stopping it again " +
          "(set SSH_BROWSER_E2E_OPEN_HOST=<ssh_config host> to run it)",
      );
    } else {
      await dashboard.click(".back");
      const hostRow = `#view button[data-alias="${clickable}"]`;
      await dashboard.waitForSelector(hostRow);
      await dashboard.click(hostRow);
      await dashboard.waitForSelector("#open-site", { timeout: 60_000 });
      const servedHash = new URL(dashboard.url()).hash;
      check("serving a host by clicking it lands on its own page", () =>
        assert.equal(servedHash, `#${clickable}`),
      );

      // The toggle that makes it come back after a restart. Checked here rather than in its
      // own section because it needs a host that is genuinely servable, which is exactly what
      // this opt-in supplies -- and because turning it on and off again is the only way to run
      // it without leaving somebody's machine reconnecting to a host every morning.
      await dashboard.waitForSelector("#enabled");
      const before = await dashboard.getAttribute("#enabled", "data-enabled");
      await dashboard.click("#enabled");
      await dashboard.waitForFunction(
        () => document.getElementById("enabled")?.dataset["enabled"] === "true",
        undefined,
        { timeout: 60_000 },
      );
      check("a host can be set to open every run", () => assert.equal(before, "false"));
      // Turned straight back off, and the assertion is on the way back: a toggle that reported
      // success and did not move would pass a check that only looked once.
      await dashboard.click("#enabled");
      await dashboard.waitForSelector(hostRow, { timeout: 60_000 });
      const stillEnabled = await dashboard.$("#enabled");
      check("and turning it off closes it, rather than waiting for a restart", () =>
        assert.equal(stillEnabled, null, "the site page should be gone, because it is not served"),
      );
      // Turning it off closed the session, so re-open it for the stop check below.
      await dashboard.click(hostRow);
      await dashboard.waitForSelector("#open-site", { timeout: 60_000 });

      // And taking it down puts it back among the hosts. The run must not leave a
      // connection open that it started.
      await dashboard.click("#stop");
      await dashboard.waitForSelector(hostRow);
      const afterStop = (await dashboard.textContent("#view")) ?? "";
      check("stopping it puts it back among the hosts you can serve", () =>
        assert.ok(
          afterStop.includes("hosts you can serve"),
          `expected the list again, got: ${afterStop.slice(0, 120)}`,
        ),
      );
    }

    // The theme is the daemon's setting, chosen from the dashboard, and what it decides is
    // what a *listing* looks like. So the check goes the whole way: pick one here, then
    // read the colour off a directory served on the alias origin. Anything short of that
    // would pass with the choice going nowhere.
    await dashboard.click("#to-config");
    await dashboard.waitForSelector("#theme");
    await dashboard.selectOption("#theme", "gruvbox-dark-hard");
    await dashboard.waitForFunction(
      () => (document.getElementById("status")?.textContent ?? "").includes("gruvbox"),
      null,
      { timeout: 10_000 },
    );

    // `assets/` rather than the root: the root has an index.html, so it serves that page
    // rather than a listing, and a listing is what carries the theme.
    const themed = await browser.newPage();
    await themed.goto(`http://${ALIAS}.${SUFFIX}/assets/`, { waitUntil: "domcontentloaded" });
    // From the root element, not the body: the theme paints `html` so the whole viewport is
    // covered even when the listing is shorter than the window. Reading the body gives
    // `rgba(0, 0, 0, 0)`, which is what this asked for first.
    const painted = await themed.evaluate(
      () => getComputedStyle(document.documentElement).backgroundColor,
    );
    await themed.close();
    check("choosing a theme changes what a listing looks like", () =>
      // gruvbox-dark-hard's base00, which base16 defines as the background. Read off the
      // rendered page, so this fails if the variable is set and the layout does not use it
      // just as surely as if the choice never arrived.
      assert.equal(painted, "rgb(29, 32, 33)"),
    );

    await dashboard.click(".back").catch(() => {});

    // The screen somebody sees before any of this works, which on a first run is the only
    // screen there is — including for whoever reviews the extension for the store, who will
    // install it with no daemon anywhere. It used to be one red line naming a command they
    // had never heard of.
    //
    // Two things have to be true at once, and each needs arranging. Nothing may be
    // answering — so the harness's own daemon is stopped, rather than hoping no daemon is
    // running, which on a developer's box is usually false. And nothing may be remembered —
    // so storage is cleared, since a stored suffix is what tells a first run from a daemon
    // that has merely stopped.
    //
    // The port is then put back deliberately. Clearing storage alone would send the
    // dashboard to the default 7391, which is exactly the port a developer's own daemon is
    // on: the check would pass in CI and fail on the machine where it was written. Pointing
    // it at the port we just released is the only one guaranteed to refuse.
    //
    // This goes last because it throws that state away.
    await stop(child);
    const worker =
      browser.serviceWorkers()[0] ??
      (await browser.waitForEvent("serviceworker", { timeout: 20_000 }));
    await worker.evaluate(async (port) => {
      await chrome.storage.local.clear();
      await chrome.storage.local.set({ port });
    }, PORT);
    await dashboard.goto(dashboard.url().replace(/#.*$/, ""));
    await dashboard.waitForSelector(".cmd", { timeout: 20_000 });
    const firstRun = await dashboard.evaluate(() => ({
      view: document.getElementById("view")?.textContent ?? "",
      cmd: document.querySelector(".cmd")?.textContent ?? "",
      repo: document.querySelector('a[href*="github.com"]')?.getAttribute("href") ?? "",
      status: document.getElementById("status")?.textContent ?? "",
    }));
    check("with no daemon, the first run says what this is and what to run", () => {
      assert.match(firstRun.view, /daemon is not running/);
      assert.match(firstRun.cmd, /cargo install ssh-browser/);
      assert.match(firstRun.cmd, /ssh-browser serve/);
      assert.ok(firstRun.repo.includes("QAtlasHub/ssh-browser"), `no source link: ${firstRun.repo}`);
    });
    // Two versions of the same bad news, one of them in red, reads as two problems.
    check("and does not also shout it in red", () => assert.equal(firstRun.status, ""));

  } catch (e) {
    failures += 1;
    console.error(`\nthe run itself failed: ${e.message}`);
    console.error(log());
  } finally {
    await browser?.close();
    await stop(child);
    await rm(profile, { recursive: true, force: true }).catch(() => {});
    await rm(extension, { recursive: true, force: true }).catch(() => {});
  }

  console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
