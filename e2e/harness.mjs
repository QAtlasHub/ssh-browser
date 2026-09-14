// Starting a daemon and preparing the extension, for the two scripts that need both.
//
// `run.mjs` checks the product and `shots.mjs` photographs it, and neither should own the
// setup. One copy, because two would drift — and the one that drifted would be the one whose
// screenshots stopped matching what the tests were passing against.

import { spawn } from "node:child_process";
import { cp, mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
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

/// Refuse to run a daemon older than the source it is supposed to be.
///
/// Nothing here builds the binary, so the default one is whatever `cargo build` last left —
/// and a run against yesterday's binary checks yesterday's code and prints `ok` for all of it.
/// That is this project's own defined failure mode arriving through its test harness, and it
/// has already happened once: a field added to a control response came back `undefined` and
/// the measurement printed `NaN`. `NaN` is a lucky shape. A changed *behaviour* would have
/// read as a passing test.
///
/// The ordinary way to get here on a developer's machine is a daemon they started themselves
/// still holding the binary, because `cargo build` then fails with an access error and leaves
/// the old one in place.
///
/// Compared by modification time rather than by content, so it is approximate in one
/// direction only: it can ask for a rebuild that changes nothing, and cannot pass a binary
/// that is genuinely behind.
async function refuseIfStale() {
  // Somebody who named a binary chose it. Only the default is guessed, so only the default is
  // second-guessed.
  if (process.env["SSH_BROWSER_E2E_BIN"]) return;

  const built = await stat(DAEMON).catch(() => null);
  if (!built) throw new Error(`no daemon at ${DAEMON} — run: cargo build`);

  let newest = 0;
  let culprit = "";
  for (const root of [join(repo, "crates"), join(repo, "Cargo.toml"), join(repo, "Cargo.lock")]) {
    for (const file of await sources(root)) {
      const { mtimeMs } = await stat(file);
      if (mtimeMs > newest) {
        newest = mtimeMs;
        culprit = file;
      }
    }
  }

  if (newest > built.mtimeMs) {
    throw new Error(
      `the daemon at ${DAEMON} is older than ${culprit}.\n` +
        `  Run: cargo build\n` +
        `  If that fails with an access error, a daemon you started is still holding it.\n` +
        `  Or set SSH_BROWSER_E2E_BIN to a binary built elsewhere.`,
    );
  }
}

/// Every `.rs` and `.toml` under `root`, or `root` itself if it is a file.
async function sources(root) {
  const found = [];
  const info = await stat(root).catch(() => null);
  if (!info) return found;
  if (!info.isDirectory()) {
    found.push(root);
    return found;
  }
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      // Build output is skipped: it holds copies of the sources, and its own artifacts are
      // newer than the binary by construction.
      if (entry.isDirectory()) {
        if (entry.name !== "target") await walk(path);
      } else if (entry.name.endsWith(".rs") || entry.name.endsWith(".toml")) {
        found.push(path);
      }
    }
  };
  await walk(root);
  return found;
}

/// Start the daemon on `port` and wait until it says it is listening.
///
/// Waiting for the line rather than sleeping: a fixed sleep is either too short on a loaded
/// runner, which makes the caller flaky, or too long everywhere else. The line is printed only
/// once the port has been taken and every host is connected, so it means what it says.
/// `scheme` defaults to the daemon's own default, which is http. Passing `"https"` makes it
/// generate a certificate authority inside the isolated state directory below — where it is
/// thrown away with everything else, and where it is trusted by nothing.
export async function startDaemon(port, { scheme } = {}) {
  await refuseIfStale();

  // An empty config file, named explicitly. Without it the daemon reads whatever
  // `<config dir>/ssh-browser/config.toml` happens to hold, so a run on a machine that
  // uses ssh-browser for real would connect to every host configured there: slower, and
  // failing for reasons that have nothing to do with the change under test.
  const state = await mkdtemp(join(tmpdir(), "ssh-browser-e2e-"));
  const empty = join(state, "config.toml");
  await writeFile(empty, "");

  const child = spawn(
    DAEMON,
    // prettier-ignore
    [
      "serve", "--config", empty, "--port", String(port),
      "--suffix", SUFFIX,
      ...(scheme ? ["--scheme", scheme] : []),
      `${ALIAS}=${HOST}:${BASE}`,
    ],
    {
      stdio: ["ignore", "pipe", "pipe"],
      // The daemon remembers things between runs — the control token, and now the chosen
      // theme — under whichever of these it finds first. Pointed at a temporary directory
      // so a test run cannot change what the daemon somebody actually uses will start with.
      env: {
        ...process.env,
        XDG_RUNTIME_DIR: state,
        XDG_CONFIG_HOME: state,
        LOCALAPPDATA: state,
      },
    },
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

/// A copy of the built extension, in a directory of its own.
///
/// Copied rather than loaded in place so that a run cannot leave anything behind in the
/// checkout. Nothing is patched into the manifest any more: the extension asks for
/// `http://127.0.0.1/*` and nothing else, so there is no permission bubble to get past.
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
  // Read only to fail early and clearly when the build is missing; nothing is changed.
  void manifest;
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

/// Open the dashboard, point it at the daemon, and wait until it has connected.
///
/// No token is typed. The dashboard asks the daemon for one, which the daemon hands over to
/// anything that is not a page.
///
/// Waiting on the daemon line rather than on a fixed delay, and by *port*: on a machine
/// already running a daemon on the default port the dashboard connects to that one on load,
/// so "there is a daemon line" is true before the click and a wait for it returns
/// immediately — with the wrong daemon's sites behind it.
export async function connectThroughDashboard(browser, port) {
  const worker =
    browser.serviceWorkers()[0] ??
    (await browser.waitForEvent("serviceworker", { timeout: 20_000 }));
  const extensionId = new URL(worker.url()).host;

  // Navigated to directly rather than by clicking the toolbar icon, which is browser chrome
  // and not something a script can reach. What the click does is open this page, so this is
  // the same arrival by the only route a test has.
  const dashboard = await browser.newPage();
  await dashboard.goto(`chrome-extension://${extensionId}/dashboard.html`);
  // The port lives in settings now, which is where a reader would go to change it.
  await dashboard.click("#to-config");
  await dashboard.fill("#port", String(port));
  await dashboard.click("#use-port");
  // Waited for by port, not merely by the line being non-empty. On a machine already
  // running a daemon on the default port the dashboard connects to *that* one on load, so
  // "there is a daemon line" is true before the click and the wait returns immediately —
  // and the list that follows is the other daemon's. Naming the port is what makes this
  // wait about the thing it is waiting for.
  await dashboard.waitForFunction(
    (want) => (document.getElementById("daemon")?.textContent ?? "").includes(`:${want}`),
    port,
    { timeout: 20_000 },
  );
  // Connecting from settings leaves you in settings, which is right for a reader and wrong
  // for a test that wants the sites. Going back is the click they would make.
  await dashboard.click(".back");

  return { dashboard, extensionId };
}
