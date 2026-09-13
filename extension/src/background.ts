// The service worker: where the control token lives, and the only place it lives.
//
// A content script shares a process with the page it runs in, and a page served from an
// alias origin is untrusted code. Content scripts therefore ask this worker to act on their
// behalf rather than being handed the token. That is the difference between "the page cannot
// write" and "the page cannot write unless it reads a variable".

/// The protocol version this extension speaks.
///
/// Negotiated against the daemon's range rather than assumed to match. This half ships
/// through a store review and the daemon ships through cargo, so on any real machine the two
/// will not be the same age.
const PROTOCOL = 1;

const TOKEN_HEADER = "x-ssh-browser-token";

interface Settings {
  port: number;
  token: string;
  /// Needed to turn a page URL into a document name. Stored rather than asked for each
  /// time, so a content script never has to know it.
  suffix: string;
  /// What the daemon reported at connect time, for the omnibox to suggest from.
  ///
  /// Held here rather than fetched per keystroke: the address bar fires on every character
  /// typed, and a request to the daemon for each one would be absurd. It is refreshed
  /// whenever the popup opens, which re-runs `connect`.
  aliases: string[];
}

interface Hello {
  daemon: string;
  protocol: { min: number; max: number };
  aliases: string[];
  suffix?: string;
}

export interface Reply {
  ok: boolean;
  detail: string;
  aliases?: string[];
  suffix?: string;
  open?: OpenAlias[];
  current?: string;
  themes?: { name: string; label: string }[];
  hosts?: KnownHost[];
  unusable?: { host: string; why: string }[];
  url?: string;
}

export interface OpenAlias {
  alias: string;
  host: string;
  base: string;
  url: string;
}

export interface KnownHost {
  alias: string;
  host: string;
  user?: string;
  hostname?: string;
  port?: number;
  proxyJump?: string | null;
  served: boolean;
  unresolved?: string;
}

type Request =
  | { kind: "connect"; port: number }
  | { kind: "hosts" }
  | { kind: "open"; host: string; base?: string }
  | { kind: "close"; alias: string }
  | { kind: "theme" }
  | { kind: "setTheme"; name: string }
  | { kind: "disconnect" }
  | { kind: "status" };

async function stored(): Promise<Settings | null> {
  const got = await chrome.storage.local.get(["port", "token", "suffix", "aliases"]);
  const port = got["port"];
  const token = got["token"];
  const suffix = got["suffix"];
  if (
    typeof port !== "number" ||
    typeof token !== "string" ||
    token === "" ||
    typeof suffix !== "string" ||
    suffix === ""
  ) {
    return null;
  }
  // Missing aliases are an empty list rather than a refusal: they only feed the omnibox, and
  // state written by a build from before they were stored must not stop the daemon connecting.
  const raw: unknown = got["aliases"];
  const aliases = Array.isArray(raw) ? raw.filter((a): a is string => typeof a === "string") : [];
  return { port, token, suffix, aliases };
}

/// Every call to the daemon goes through here, so the token is attached in exactly one place
/// and cannot be forgotten at a call site.
async function callDaemon(s: Settings, path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set(TOKEN_HEADER, s.token);
  return fetch(`http://127.0.0.1:${s.port}${path}`, { ...init, headers });
}

/// Escape a decoded document path exactly once, for either direction.
///
/// `encodeURIComponent` over the whole string would escape the separator that divides the
/// alias from the path, and the daemon splits on it. Per segment keeps a filename containing
/// `&` or `=` from breaking the query while leaving the separator alone.
///
/// The input must be decoded — see `docOfUrl`. Handing this an already-escaped path escapes
/// it twice, and the daemon decodes once by design, so the two would never meet.
function encodeDoc(doc: string): string {
  return doc.split("/").map(encodeURIComponent).join("/");
}

/// The PAC comes from the daemon rather than being generated here.
///
/// One generator means the two halves cannot disagree about which hosts are routed, and a
/// changed suffix needs no extension release — which matters when an extension release goes
/// through a store review and a daemon release does not.
async function applyPac(s: Settings): Promise<void> {
  // Fetched without the token: a PAC is not a secret, and it is served on the loopback path
  // that an alias page cannot reach in any case.
  const res = await fetch(`http://127.0.0.1:${s.port}/proxy.pac`);
  if (!res.ok) {
    throw new Error(`the daemon would not serve a PAC (${res.status})`);
  }
  const data = await res.text();
  await chrome.proxy.settings.set({
    value: { mode: "pac_script", pacScript: { data, mandatory: false } },
    scope: "regular",
  });
}

/// Ask the daemon for its control token.
///
/// This is why there is nothing to paste. An extension cannot read a file, so before this
/// the first run meant copying sixty-four hex characters out of a terminal.
///
/// It is safe to hand over because the daemon refuses this route to anything page-shaped,
/// and it knows which is which from `Sec-Fetch-Site` — a forbidden header name, so page
/// script can neither set it nor remove it. An extension fetch arrives as `none`; a page,
/// including one the daemon itself serves in fallback mode, arrives as `same-origin` or
/// `cross-site` and is refused. A caller that is not a browser at all could read the token
/// file directly, so refusing it would protect nothing.
async function handshake(port: number): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${port}/_control/token`);
  if (res.status === 404) {
    throw new Error(
      "that daemon is too old to hand over its token; update it with: cargo install ssh-browser",
    );
  }
  if (!res.ok) {
    throw new Error(`the daemon would not hand over its token (${res.status})`);
  }
  const token = (await res.text()).trim();
  if (!/^[0-9a-f]{64}$/.test(token)) {
    // Refused rather than stored. A token that is not one would be sent on every later
    // call and produce a 401 whose cause was several steps back.
    throw new Error("the daemon answered with something that is not a token");
  }
  return token;
}

async function connect(port: number): Promise<Reply> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, detail: `${port} is not a port` };
  }

  let token: string;
  try {
    token = await handshake(port);
  } catch (e) {
    if (e instanceof TypeError) {
      // A refused connection is the ordinary case of "the daemon is not running", so say
      // that rather than surfacing a network error the reader cannot act on.
      return {
        ok: false,
        detail: `nothing is listening on 127.0.0.1:${port}. Start it with: ssh-browser serve`,
      };
    }
    return { ok: false, detail: String(e instanceof Error ? e.message : e) };
  }
  // Neither the suffix nor the aliases are known until `hello` answers, so these placeholders
  // only have to be good enough to reach the daemon; the real ones are stored below.
  const s: Settings = { port, token, suffix: "", aliases: [] };

  let res: Response;
  try {
    res = await callDaemon(s, "/_control/hello");
  } catch {
    return { ok: false, detail: `127.0.0.1:${port} stopped answering` };
  }

  if (!res.ok) {
    return { ok: false, detail: `the daemon answered ${res.status}` };
  }

  const hello = (await res.json()) as Hello;
  if (PROTOCOL < hello.protocol.min || PROTOCOL > hello.protocol.max) {
    return {
      ok: false,
      detail:
        `this extension speaks protocol ${PROTOCOL}; ssh-browser ${hello.daemon} speaks ` +
        `${hello.protocol.min}-${hello.protocol.max}. Update whichever is older.`,
    };
  }

  try {
    await applyPac(s);
  } catch (e) {
    return {
      ok: false,
      detail: `connected, but the proxy could not be set: ${String(e)}`,
    };
  }

  await chrome.storage.local.set({
    port,
    token,
    suffix: hello.suffix ?? "",
    aliases: hello.aliases,
  });
  const reply: Reply = {
    ok: true,
    detail: `connected to ssh-browser ${hello.daemon}`,
    aliases: hello.aliases,
  };
  if (hello.suffix !== undefined) {
    reply.suffix = hello.suffix;
  }
  return reply;
}

/// Clears the PAC as well as the token.
///
/// Leaving a PAC in place with no daemon behind it would make every alias host fail
/// confusingly rather than simply not existing.
async function disconnect(): Promise<Reply> {
  await chrome.proxy.settings.clear({ scope: "regular" });
  await chrome.storage.local.remove(["port", "token", "suffix", "aliases"]);
  return { ok: true, detail: "disconnected, and the proxy setting is cleared" };
}

async function status(): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  return connect(s.port);
}

/// The hosts ssh already knows how to reach.
async function listHosts(): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const res = await callDaemon(s, "/_control/hosts");
  if (!res.ok) {
    return { ok: false, detail: `${res.status}: ${await res.text()}` };
  }
  const body = (await res.json()) as {
    open: OpenAlias[];
    hosts: KnownHost[];
    unusable: { host: string; why: string }[];
  };
  return {
    ok: true,
    detail:
      body.hosts.length === 0 && body.open.length === 0 ? "no hosts in your ~/.ssh/config" : "",
    // What is being served right now, which is not the same question as what could be: an
    // alias need not be named after its host, so one opened as `docs=myhost:/srv` matches
    // no row in ssh_config at all and would otherwise be live and visible nowhere.
    open: body.open,
    hosts: body.hosts,
    // Carried through rather than dropped. A host missing from the list with no reason
    // reads as ssh-browser having failed to find it, which has a different fix.
    unusable: body.unusable,
  };
}

/// Start serving one of them, and report the URL it is at.
async function openHost(host: string, base?: string): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const payload: Record<string, unknown> = { host };
  if (base !== undefined && base !== "") {
    payload["base"] = base;
  }
  const res = await callDaemon(s, "/_control/open", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    return { ok: false, detail: `${await res.text()}` };
  }
  const opened = (await res.json()) as {
    alias: string;
    base: string;
    url: string;
  };
  // The alias list feeds the omnibox, and a host just opened should be suggestible without
  // waiting for the popup to be opened again.
  if (!s.aliases.includes(opened.alias)) {
    await chrome.storage.local.set({
      aliases: [...s.aliases, opened.alias].sort(),
    });
  }
  return {
    ok: true,
    detail: `${opened.alias} is at ${opened.base}`,
    url: opened.url,
  };
}

/// Stop serving an alias.
///
/// The other half of `open`, and the way a root gets changed: close, then open again.
/// Reopening under a second base while the first is live is refused by the daemon, because
/// it would change what an origin means underneath any page open in it — so closing first
/// is what makes it an act somebody chose.
async function closeAlias(alias: string): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const res = await callDaemon(s, "/_control/close", {
    method: "POST",
    body: JSON.stringify({ alias }),
  });
  if (!res.ok) {
    return { ok: false, detail: await res.text() };
  }
  await chrome.storage.local.set({ aliases: s.aliases.filter((a) => a !== alias) });
  return { ok: true, detail: `${alias} is no longer served` };
}

/// What listings look like, and what else they could.
///
/// The list of themes comes from the daemon rather than being written out again here. Two
/// copies of it is how a theme gets added and stays invisible.
async function getTheme(): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const res = await callDaemon(s, "/_control/theme");
  if (!res.ok) {
    return { ok: false, detail: `${res.status}: ${await res.text()}` };
  }
  const body = (await res.json()) as { current: string; themes: { name: string; label: string }[] };
  return { ok: true, detail: "", current: body.current, themes: body.themes };
}

async function setTheme(name: string): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const res = await callDaemon(s, "/_control/theme", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  if (!res.ok) {
    return { ok: false, detail: await res.text() };
  }
  const body = (await res.json()) as { current: string; remembered: boolean };
  return {
    ok: true,
    // Said outright when it will not survive a restart, because a setting that silently
    // forgets is worse than one that was never offered.
    detail: body.remembered
      ? `listings are ${body.current}`
      : `listings are ${body.current}, but it could not be remembered for next time`,
    current: body.current,
  };
}

function isRequest(message: unknown): message is Request {
  return (
    typeof message === "object" &&
    message !== null &&
    typeof (message as { kind?: unknown }).kind === "string"
  );
}

async function dispatch(message: unknown): Promise<Reply> {
  if (!isRequest(message)) {
    return { ok: false, detail: "unrecognised request" };
  }
  switch (message.kind) {
    case "connect":
      return connect(message.port);
    case "hosts":
      return listHosts();
    case "open":
      return openHost(message.host, message.base);
    case "close":
      return closeAlias(message.alias);
    case "theme":
      return getTheme();
    case "setTheme":
      return setTheme(message.name);
    case "disconnect":
      return disconnect();
    case "status":
      return status();
  }
}

/// Split `docs/a/b.html` into the alias and the rest.
function splitTyped(text: string): { alias: string; path: string } {
  const trimmed = text.trim();
  const cut = trimmed.indexOf("/");
  return cut === -1
    ? { alias: trimmed, path: "" }
    : { alias: trimmed.slice(0, cut), path: trimmed.slice(cut + 1) };
}

/// The omnibox renders its descriptions as markup, so anything from the address bar has to be
/// escaped before it goes in one. An alias cannot contain these — the daemon refuses an alias
/// that is not a hostname label — but a path is whatever was typed.
function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function urlFor(alias: string, path: string, suffix: string): string {
  return `http://${alias}.${suffix}/${encodeDoc(path)}`;
}

/// Typing the keyword in the address bar, then an alias and a path.
///
/// The suggestions come from the aliases the daemon reported, so they are the hosts that
/// actually exist rather than a list this extension keeps its own copy of.
///
/// Deliberately adds no permission. `chrome.omnibox` needs only its manifest key, and setting
/// a tab's URL does not need `tabs` — that is for reading a tab's URL or title. An address-bar
/// shortcut is not worth asking a reviewer, or a reader, for the right to see their browsing.
function installOmnibox(): void {
  // Neither listener has a reply channel to fail through: a rejection here would otherwise
  // be a suggestion list that stops appearing, or an Enter that navigates nowhere, with the
  // reason visible only in a service-worker console nobody has open. The badge is the one
  // surface this worker owns, so a failure gets put there rather than nowhere.
  const complain = (what: string) => (e: unknown) => {
    console.error(`ssh-browser: ${what} failed`, e);
    void chrome.action.setBadgeText({ text: "!" });
    void chrome.action.setTitle({
      title: `ssh-browser: ${what} failed — ${String(e)}`,
    });
  };

  chrome.omnibox.setDefaultSuggestion({
    description: "ssh-browser: %s",
  });

  chrome.omnibox.onInputChanged.addListener((text, suggest) => {
    void (async () => {
      const s = await stored();
      if (!s) {
        return;
      }
      const { alias, path } = splitTyped(text);
      // Once a slash has been typed the alias is settled, so the only useful suggestion is
      // the one URL. Before that, every alias the typing could still become.
      const names = text.includes("/")
        ? s.aliases.filter((a) => a === alias)
        : s.aliases.filter((a) => a.startsWith(alias));
      suggest(
        names.map((a) => ({
          content: path === "" ? a : `${a}/${path}`,
          description: escapeXml(urlFor(a, path, s.suffix)),
        })),
      );
    })().catch(complain("omnibox suggestions"));
  });

  chrome.omnibox.onInputEntered.addListener((text, disposition) => {
    void (async () => {
      const s = await stored();
      if (!s) {
        return;
      }
      const { alias, path } = splitTyped(text);
      // An unknown alias is still navigated to. The daemon answers with a 404 naming it,
      // which tells the reader more than this extension silently doing nothing would.
      if (!/^[a-z0-9-]+$/.test(alias)) {
        return;
      }
      const url = urlFor(alias, path, s.suffix);
      switch (disposition) {
        case "newForegroundTab":
          await chrome.tabs.create({ url });
          break;
        case "newBackgroundTab":
          await chrome.tabs.create({ url, active: false });
          break;
        default:
          await chrome.tabs.update({ url });
      }
    })().catch(complain("omnibox navigation"));
  });
}

/// Where the dashboard is, and how not to end up with six of them.
///
/// The tab id is remembered rather than searched for. Finding it with
/// `chrome.tabs.query({url})` would need the `tabs` permission, which is the right to read
/// every tab's URL and title — far more than is needed to raise one page, and not something
/// to ask a reader for in exchange for a convenience.
///
/// Session storage rather than a variable, because the service worker is evicted when idle
/// and a variable would be gone by the next click.
const DASHBOARD = "dashboard.html";

async function showDashboard(): Promise<void> {
  const url = chrome.runtime.getURL(DASHBOARD);
  const { dashboardTab } = (await chrome.storage.session.get("dashboardTab")) as {
    dashboardTab?: number;
  };

  if (typeof dashboardTab === "number") {
    try {
      // Raises the existing one, and also puts it back to the top level: clicking the
      // icon is how you ask for the dashboard, not for whichever alias you left it on.
      await chrome.tabs.update(dashboardTab, { active: true, url });
      return;
    } catch {
      // Closed since. Falling through to open a new one is the whole point of catching.
    }
  }

  const tab = await chrome.tabs.create({ url });
  if (tab.id !== undefined) {
    await chrome.storage.session.set({ dashboardTab: tab.id });
  }
}

// Fires only because the manifest declares no `default_popup`. A popup is 340px of chrome
// with no address bar, which is the wrong shape for a page you navigate within.
chrome.action.onClicked.addListener(() => {
  void showDashboard().catch((e: unknown) => {
    console.error("ssh-browser: opening the dashboard failed", e);
  });
});

installOmnibox();

chrome.runtime.onMessage.addListener((message, _sender, reply) => {
  dispatch(message)
    .then(reply)
    .catch((e: unknown) => reply({ ok: false, detail: String(e) }));
  // Keeps the message channel open for the asynchronous reply above.
  return true;
});
