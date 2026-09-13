// The dashboard: every site this daemon is serving, and every host it could serve.
//
// The framing is deployment, because that is what the product is. A directory on a machine
// you can only reach over ssh is made to look like a site on a host, without being deployed
// to one. So a site has a URL, a place it is served from, and a way to be taken down — and
// the dashboard is where those live.
//
// It never calls the daemon itself. The token belongs in the service worker, and a second
// caller would be a second place to leak it from.

interface OpenAlias {
  alias: string;
  host: string;
  base: string;
  url: string;
}

interface KnownHost {
  alias: string;
  host: string;
  user?: string;
  hostname?: string;
  port?: number;
  proxyJump?: string | null;
  served: boolean;
  unresolved?: string;
}

interface Reply {
  ok: boolean;
  detail: string;
  suffix?: string;
  open?: OpenAlias[];
  hosts?: KnownHost[];
  unusable?: { host: string; why: string }[];
  url?: string;
  current?: string;
  themes?: { name: string; label: string }[];
}

function el<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`the dashboard is missing #${id}`);
  }
  return found as T;
}

async function send(message: unknown): Promise<Reply> {
  return (await chrome.runtime.sendMessage(message)) as Reply;
}

function say(detail: string, bad = false): void {
  const status = el("status");
  status.textContent = detail;
  status.classList.toggle("bad", bad);
}

/// `souta@157.82.60.8:10019, via Panza` — what `ssh -G` resolved, so it describes what
/// connecting will actually do rather than what a second reading of the config concluded.
function describe(h: KnownHost): string {
  const who = h.user === undefined ? "" : `${h.user}@`;
  const where = h.hostname ?? h.host;
  const port = h.port === undefined || h.port === 22 ? "" : `:${h.port}`;
  const via = h.proxyJump ? `, via ${h.proxyJump}` : "";
  return `${who}${where}${port}${via}`;
}

/// Everything is built through the DOM rather than by assembling markup, so nothing the
/// daemon reports — a host name, a path, an error out of ssh — can become markup here.
function node(tag: string, className: string, text: string): HTMLElement {
  const e = document.createElement(tag);
  e.className = className;
  e.textContent = text;
  return e;
}

function clear(): HTMLElement {
  const view = el("view");
  view.textContent = "";
  return view;
}

/// What the daemon last said it was serving, held between renders so the alias view has
/// something to read.
///
/// Re-fetched after anything that changes it rather than patched in place: the daemon is
/// the one that knows what is open, and two ideas about that is one more than can be right.
let latest: Reply = { ok: false, detail: "" };

/// Which daemon to talk to.
///
/// Held here rather than read out of an input, because the input only exists on the
/// settings view now. A page that had to find a field in order to know where to connect
/// would stop being able to as soon as it was showing something else.
let currentPort = 7391;

/// Which render is the current one.
///
/// A view that awaits can finish after the reader has already gone somewhere else, and
/// writing into the page then replaces whatever they are now looking at. Clicking back
/// immediately after Connect did exactly that: the list appeared and was then overwritten
/// by the settings screen the previous render was still finishing.
///
/// Every route bumps this; every render checks it is still the one before touching the DOM.
let generation = 0;

// ---------------------------------------------------------------------------
// The list

function renderList(): void {
  const view = clear();
  const open = latest.open ?? [];
  const hosts = latest.hosts ?? [];

  view.append(node("h2", "", "sites"));
  if (open.length === 0) {
    view.append(node("p", "empty", "Nothing is being served yet. Pick a host below."));
  } else {
    const list = document.createElement("ul");
    for (const site of open) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset["alias"] = site.alias;
      button.append(
        node("div", "name", site.alias),
        node("div", "url", site.url),
        node("div", "where", `${site.host}:${site.base}`),
      );
      button.addEventListener("click", () => {
        location.hash = `#${site.alias}`;
      });
      const item = document.createElement("li");
      item.append(button);
      list.append(item);
    }
    view.append(list);
  }

  const spare = hosts.filter((h) => !open.some((o) => o.alias === h.alias));
  view.append(node("h2", "", "hosts you can serve"));
  if (spare.length === 0) {
    view.append(
      node(
        "p",
        "empty",
        hosts.length === 0
          ? "No hosts in your ~/.ssh/config."
          : "Every host in your ~/.ssh/config is already being served.",
      ),
    );
  } else {
    const list = document.createElement("ul");
    for (const h of spare) {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset["alias"] = h.alias;
      button.append(
        node("div", "name", h.alias),
        // A host ssh could not describe is still offered, with the reason where the address
        // would be. Hiding it would make a misconfigured host look like one that is not in
        // the file, and those have different fixes.
        node("div", h.unresolved === undefined ? "where" : "bad-host", h.unresolved ?? describe(h)),
      );
      button.addEventListener("click", () => {
        void serve(h, button);
      });
      const item = document.createElement("li");
      item.append(button);
      list.append(item);
    }
    view.append(list);
  }

  for (const u of latest.unusable ?? []) {
    view.append(node("p", "note", `${u.host}: ${u.why}`));
  }

  view.append(settingsLink());
}

/// The way into settings, and it has to exist on every screen.
///
/// Including the one that says nothing is listening: the port lives in settings, so a
/// dashboard that hid the link when it could not connect would be unreachable for exactly
/// the reader who needed it. That is how it first shipped, and the e2e run found it.
function settingsLink(): HTMLElement {
  const settings = document.createElement("a");
  settings.className = "back";
  settings.href = "#/config";
  settings.id = "to-config";
  settings.textContent = "Settings";
  const line = document.createElement("p");
  line.append(settings);
  return line;
}

// ---------------------------------------------------------------------------
// Settings

/// The daemon's settings, not the extension's.
///
/// Which is why they are here rather than in a browser preference: the theme decides what
/// *the daemon* renders a directory listing as, and those pages are served to any browser
/// pointed at it. Keeping the choice in one place is what stops two browsers disagreeing
/// about what the same URL looks like.
async function renderConfig(): Promise<void> {
  const mine = generation;
  const view = clear();

  const back = document.createElement("a");
  back.className = "back";
  back.href = "#";
  back.textContent = "← all sites";
  view.append(back);

  view.append(node("h2", "site-name", "settings"));

  view.append(node("h2", "", "daemon"));
  const port = document.createElement("div");
  port.className = "act";
  const input = document.createElement("input");
  input.id = "port";
  input.type = "number";
  input.min = "1";
  input.max = "65535";
  input.value = String(currentPort);
  input.setAttribute("aria-label", "port");
  const use = document.createElement("button");
  use.type = "button";
  use.id = "use-port";
  use.textContent = "Connect";
  use.addEventListener("click", () => {
    currentPort = Number(input.value);
    // `start` routes when it is done, which re-renders whatever the reader is looking at by
    // then. Calling `renderConfig` here instead would put the settings back over a list
    // they had already navigated to.
    void start();
  });
  port.append(input, use);
  view.append(port);
  view.append(node("p", "note", "Where the daemon is listening. The default is 7391."));

  // Everything below needs the daemon, so it is below rather than above: a reader who came
  // here because nothing was listening should meet the port field first, not an error.
  const themes = await send({ kind: "theme" });
  if (mine !== generation) {
    return;
  }
  if (!themes.ok) {
    view.append(node("p", "note", themes.detail));
    return;
  }

  view.append(node("h2", "", "listings"));
  const picker = document.createElement("div");
  picker.className = "act";
  const select = document.createElement("select");
  select.id = "theme";
  select.setAttribute("aria-label", "theme");
  for (const t of themes.themes ?? []) {
    const option = document.createElement("option");
    option.value = t.name;
    option.textContent = t.label;
    option.selected = t.name === themes.current;
    select.append(option);
  }
  select.addEventListener("change", () => {
    void (async () => {
      const chose = await send({ kind: "setTheme", name: select.value });
      say(chose.detail, !chose.ok);
    })();
  });
  picker.append(select);
  view.append(picker);
  view.append(
    node(
      "p",
      "note",
      "What a directory listing looks like. It is the daemon's setting, so it applies to " +
        "every site it serves and to any browser pointed at them.",
    ),
  );

  view.append(node("h2", "", "address bar"));
  view.append(node("p", "note", "Type ssh, then Tab, then an alias and a path."));
}

/// Start serving a host, then go to its page.
///
/// Its page rather than the site itself: souta asked for the dashboard to lead to the
/// alias, and the alias to be where the per-site things are. Jumping straight to the tree
/// would skip the one screen that says where it is rooted.
async function serve(h: KnownHost, button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  say(`connecting to ${h.host} over ssh…`);
  const reply = await send({ kind: "open", host: h.host });
  button.disabled = false;
  if (!reply.ok) {
    say(reply.detail, true);
    return;
  }
  await refresh();
  location.hash = `#${h.alias}`;
}

// ---------------------------------------------------------------------------
// One site

function renderAlias(alias: string): void {
  const site = (latest.open ?? []).find((o) => o.alias === alias);
  const view = clear();

  const back = document.createElement("a");
  back.className = "back";
  back.href = "#";
  back.textContent = "← all sites";
  view.append(back);

  if (!site) {
    // Reachable by going back to a site that has since been stopped, or by editing the
    // fragment. Saying which alias is missing beats an empty page.
    view.append(node("p", "empty", `${alias} is not being served.`));
    view.append(settingsLink());
    return;
  }

  view.append(node("h2", "site-name", site.alias));

  const link = document.createElement("a");
  link.className = "site-url";
  link.href = site.url;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = site.url;
  const urlLine = document.createElement("p");
  urlLine.append(link);
  view.append(urlLine);

  const open = document.createElement("a");
  open.className = "open-site";
  open.id = "open-site";
  open.href = site.url;
  open.target = "_blank";
  open.rel = "noreferrer";
  open.textContent = "Open the site";
  const opening = document.createElement("p");
  opening.append(open);
  view.append(opening);

  view.append(node("h2", "", "served from"));
  const facts = document.createElement("dl");
  const host = (latest.hosts ?? []).find((h) => h.alias === site.alias);
  const pairs: [string, string][] = [
    ["host", site.host],
    ["root", site.base],
  ];
  if (host && host.unresolved === undefined) {
    pairs.push(["ssh", describe(host)]);
  }
  for (const [term, value] of pairs) {
    facts.append(node("dt", "", term), node("dd", "", value));
  }
  view.append(facts);

  view.append(node("h2", "", "root"));
  const form = document.createElement("div");
  form.className = "act";
  const input = document.createElement("input");
  input.id = "root";
  input.value = site.base;
  input.spellcheck = false;
  input.setAttribute("aria-label", "root");
  const change = document.createElement("button");
  change.type = "button";
  change.id = "change-root";
  change.textContent = "Change root";
  change.addEventListener("click", () => {
    void reroot(site, input.value.trim(), change);
  });
  form.append(input, change);
  view.append(form);
  view.append(
    node(
      "p",
      "note",
      "An absolute path, or ~ and a path under the home directory. Changing it stops the " +
        "site and starts it again, so a tab already open on it will be showing a different " +
        "tree afterwards.",
    ),
  );

  view.append(node("h2", "", "stop"));
  const stopping = document.createElement("div");
  stopping.className = "act";
  const stop = document.createElement("button");
  stop.type = "button";
  stop.id = "stop";
  stop.className = "danger";
  stop.textContent = "Stop serving";
  stop.addEventListener("click", () => {
    void takeDown(site.alias, stop);
  });
  stopping.append(stop);
  view.append(stopping);
  view.append(
    node("p", "note", "Closes the ssh session. The site stops answering until it is served again."),
  );
  view.append(settingsLink());
}

/// Close and reopen under a new root.
///
/// Two calls rather than one, deliberately. The daemon refuses to reopen an alias under a
/// second base while the first is live, because that would change what an origin means
/// underneath any page already open in it. Closing first is what makes it something
/// somebody chose, and it is why the note above says so plainly.
async function reroot(site: OpenAlias, base: string, button: HTMLButtonElement): Promise<void> {
  if (base === "" || base === site.base) {
    return;
  }
  button.disabled = true;
  say(`moving ${site.alias} to ${base}…`);

  const closed = await send({ kind: "close", alias: site.alias });
  if (!closed.ok) {
    button.disabled = false;
    say(closed.detail, true);
    return;
  }

  const opened = await send({ kind: "open", host: site.host, base });
  button.disabled = false;
  await refresh();
  if (!opened.ok) {
    // The old session is already gone, so this cannot be undone by retrying the same
    // thing. Saying both halves is the difference between a reader knowing to serve it
    // again and a reader thinking nothing happened.
    say(`${site.alias} was stopped, but reopening at ${base} failed: ${opened.detail}`, true);
    route();
    return;
  }
  say(opened.detail);
  route();
}

async function takeDown(alias: string, button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  say(`stopping ${alias}…`);
  const reply = await send({ kind: "close", alias });
  button.disabled = false;
  if (!reply.ok) {
    say(reply.detail, true);
    return;
  }
  say(reply.detail);
  await refresh();
  // Assigning the hash only fires `hashchange` when it changes, and it has not if this was
  // reached from the list. `route` is called outright so the page never keeps showing a
  // site that has just been stopped.
  location.hash = "";
  route();
}

// ---------------------------------------------------------------------------

function route(): void {
  generation += 1;
  const hash = location.hash.replace(/^#/, "");
  if (hash === "/config") {
    void renderConfig();
    return;
  }
  const alias = decodeURIComponent(hash);
  if (alias === "") {
    renderList();
  } else {
    renderAlias(alias);
  }
}

/// Ask the daemon what it is serving. The one source of that answer.
async function refresh(): Promise<boolean> {
  const hosts = await send({ kind: "hosts" });
  if (!hosts.ok) {
    say(hosts.detail, true);
    return false;
  }
  latest = hosts;
  return true;
}

async function start(): Promise<void> {
  const port = currentPort;
  await chrome.storage.local.set({ port });
  say("looking for the daemon…");

  const reply = await send({ kind: "connect", port });
  if (!reply.ok || reply.suffix === undefined) {
    say(reply.detail, true);
    el("daemon").textContent = "";
    // Only when there is nothing else on screen. Calling this while the settings view is
    // open would wipe the port field out from under somebody typing in it.
    if (location.hash.replace(/^#/, "") !== "/config") {
      const view = clear();
      view.append(settingsLink());
    }
    return;
  }
  el("daemon").textContent = `${reply.detail} on 127.0.0.1:${port}`;
  say("");

  // Registered only if the permission is already held. Asking for it needs a user gesture,
  // which a page load is not, so the request is made on the first click instead — and kept
  // out of here so that a refusal does not stop the sites appearing. Reading a site works
  // without it.
  const origins = [`http://*.${reply.suffix}/*`];
  if (await chrome.permissions.contains({ origins })) {
    await send({ kind: "register", suffix: reply.suffix });
  }

  if (await refresh()) {
    route();
  }
}

// Asked on a click rather than on load, because a permission request needs a user gesture.
el("view").addEventListener(
  "click",
  () => {
    void (async () => {
      const { suffix } = (await chrome.storage.local.get("suffix")) as { suffix?: string };
      if (suffix === undefined || suffix === "") {
        return;
      }
      const origins = [`http://*.${suffix}/*`];
      if (await chrome.permissions.contains({ origins })) {
        return;
      }
      if (await chrome.permissions.request({ origins })) {
        await send({ kind: "register", suffix });
      }
    })();
  },
  { capture: true, once: true },
);

window.addEventListener("hashchange", route);

// The port is read back first because it says *which* daemon to look for; checking before
// reading it would check the wrong one and report it as absent.
void (async () => {
  const { port } = (await chrome.storage.local.get("port")) as { port?: number };
  if (typeof port === "number") {
    currentPort = port;
  }
  await start();
})();
