// Starting a daemon and preparing the extension, for the two scripts that need both.
//
// `run.mjs` checks the product and `shots.mjs` photographs it, and neither should own the
// setup. One copy, because two would drift — and the one that drifted would be the one whose
// screenshots stopped matching what the tests were passing against.

import { spawn } from "node:child_process";
import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = resolve(here, "..");

export const HOST = process.env["SSH_BROWSER_E2E_HOST"] ?? "localhost";
export const BASE = process.env["SSH_BROWSER_E2E_BASE"] ?? join(here, "tree");
export const ALIAS = "e2e";
export const SUFFIX = "ssh-browser";
export const TOKEN_HEADER = "x-ssh-browser-token";

export const DAEMON =
  process.env["SSH_BROWSER_E2E_BIN"] ??
  join(repo, "target", "debug", process.platform === "win32" ? "ssh-browser.exe" : "ssh-browser");

/// Start the daemon on `port` and wait until it says it is listening.
///
/// Waiting for the line rather than sleeping: a fixed sleep is either too short on a loaded
/// runner, which makes the caller flaky, or too long everywhere else. The line is printed only
/// once the port has been taken and every host is connected, so it means what it says.
export async function startDaemon(port) {
  // An empty config file, named explicitly. Without it the daemon reads whatever
  // `<config dir>/ssh-browser/config.toml` happens to hold, so a run on a machine that
  // uses ssh-browser for real would connect to every host configured there: slower, and
  // failing for reasons that have nothing to do with the change under test.
  const empty = join(await mkdtemp(join(tmpdir(), "ssh-browser-e2e-")), "config.toml");
  await writeFile(empty, "");

  const child = spawn(
    DAEMON,
    // prettier-ignore
    [
      "serve", "--config", empty, "--port", String(port),
      "--suffix", SUFFIX, `${ALIAS}=${HOST}:${BASE}`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  let log = "";
  await new Promise((ok, no) => {
    const onData = (chunk) => {
      log += String(chunk);
      if (log.includes(`listening on 127.0.0.1:${port}`)) {
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

  const token = /control token: ([0-9a-f]+)/.exec(log)?.[1];
  if (!token) {
    throw new Error(`the daemon printed no control token:\n${log}`);
  }
  return { child, token, log: () => log };
}

/// A copy of the built extension with the alias hosts already granted.
///
/// The shipped manifest asks for them through `optional_host_permissions`, and the popup
/// requests them on the Connect click. That request raises a permission bubble, which is
/// browser chrome and not something a script can click.
///
/// Worth being plain about what this covers. Everything downstream of the grant is exercised
/// for real: the worker, the token header, the content script, the annotation round trip. The
/// act of *requesting* the permission is not, and stays a manual step.
export async function extensionWithPermissionGranted() {
  const dist = join(repo, "extension", "dist");
  let manifest;
  try {
    manifest = JSON.parse(await readFile(join(dist, "manifest.json"), "utf8"));
  } catch {
    throw new Error(
      `no built extension at ${dist} — run: npm --prefix extension ci && npm --prefix extension run build`,
    );
  }

  const dir = await mkdtemp(join(tmpdir(), "ssh-browser-ext-"));
  await cp(dist, dir, { recursive: true });
  manifest.host_permissions = [...(manifest.host_permissions ?? []), `http://*.${SUFFIX}/*`];
  delete manifest.optional_host_permissions;
  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  return dir;
}

/// Which browser to launch, and whether to show it.
///
/// `channel` and `executablePath` are mutually exclusive in Playwright, so naming a browser
/// *replaces* the channel rather than joining it. Passing both is an error — which is exactly
/// what pointing this at a real Brave used to produce, because the option was spread onto a
/// launch that already named a channel. It had therefore never once worked.
///
/// Naming a browser also turns headless off unless told otherwise, because the reason to point
/// this at the browser you actually use is to watch it. `SSH_BROWSER_E2E_HEADLESS=1` overrides
/// that, and `SSH_BROWSER_E2E_HEADED=1` shows the bundled one.
///
/// Either way the profile is a fresh temporary directory and your own is never opened. This
/// loads an unpacked extension and points the browser's proxy at a local daemon, and neither
/// belongs in the browser you keep your life in.
export function browserOptions() {
  const named = process.env["SSH_BROWSER_E2E_BROWSER"];
  const headless = named
    ? process.env["SSH_BROWSER_E2E_HEADLESS"] === "1"
    : process.env["SSH_BROWSER_E2E_HEADED"] !== "1";

  return {
    // The bundled default resolves to a headless shell that cannot run an extension at all,
    // and an MV3 service worker does not start in the old headless mode either — so when
    // nothing is named, ask for the full browser by channel.
    ...(named ? { executablePath: named } : { channel: "chromium" }),
    headless,
  };
}

/// Chromium arguments that load an unpacked extension.
///
/// Paired with `channel: "chromium"` at every call site, because an MV3 service worker does
/// not start in the old headless mode at all — the extension would be loaded and inert, which
/// looks exactly like an extension that is broken.
export function loadExtension(dir) {
  return [`--disable-extensions-except=${dir}`, `--load-extension=${dir}`];
}

/// The id `background.ts` registers the annotation script under.
const CONTENT_SCRIPT_ID = "alias-pages";

/// Open the popup, point it at the daemon, and wait until the content script is registered.
///
/// No token is typed. The popup asks the daemon for one, which the daemon hands over to
/// anything that is not a page — so the first-run paste is gone, and so is the field the
/// old version of this filled in.
///
/// Waiting on the registration rather than on the popup's text, because the text is set
/// before the registration happens. A wait that accepted the first status line won a race
/// most of the time and lost it whenever anything else was slow — a flake that looks
/// exactly like a broken content script.
///
/// The registration is the thing the caller depends on, so it is the thing to wait for.
export async function connectThroughPopup(browser, port) {
  const worker =
    browser.serviceWorkers()[0] ??
    (await browser.waitForEvent("serviceworker", { timeout: 20_000 }));
  const extensionId = new URL(worker.url()).host;

  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${extensionId}/panel.html`);
  // The port lives behind a disclosure, because the ordinary run never touches it. Opening
  // it is what a reader would do, so it is what this does rather than reaching past it.
  await popup.click("summary");
  await popup.fill("#port", String(port));
  // Dispatched rather than relied upon: the popup re-runs on `change`, and whether `fill`
  // emits one is Playwright's business rather than something this should depend on.
  await popup.dispatchEvent("#port", "change");

  const deadline = Date.now() + 20_000;
  for (;;) {
    const ids = await worker.evaluate(() =>
      chrome.scripting.getRegisteredContentScripts().then((s) => s.map((x) => x.id)),
    );
    if (ids.includes(CONTENT_SCRIPT_ID)) {
      break;
    }
    if (Date.now() > deadline) {
      const said = await popup.textContent("#status");
      throw new Error(`the content script was never registered; the popup said: ${said}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  return { popup, extensionId };
}
