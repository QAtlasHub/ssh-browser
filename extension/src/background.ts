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

const CONTENT_SCRIPT_ID = "alias-pages";

/// Which pages the content script should run in, for a given suffix.
function matchesFor(suffix: string): string[] {
  return [`http://*.${suffix}/*`];
}

interface Settings {
  port: number;
  token: string;
  /// Needed to turn a page URL into a document name. Stored rather than asked for each
  /// time, so a content script never has to know it.
  suffix: string;
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
  annotations?: unknown[];
  skipped?: number;
  id?: string;
}

type Request =
  | { kind: "connect"; port: number; token: string }
  | { kind: "disconnect" }
  | { kind: "status" }
  | { kind: "register"; suffix: string }
  | { kind: "annotations"; url: string }
  | { kind: "annotate"; url: string; body: string; selectors?: unknown };

async function stored(): Promise<Settings | null> {
  const got = await chrome.storage.local.get(["port", "token", "suffix"]);
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
  return { port, token, suffix };
}

/// `http://docs.ssh-browser/a/b.html` becomes `docs/a/b.html`.
///
/// Derived here rather than in the content script, so the suffix stays knowledge this worker
/// holds. A content script that had to know the suffix would need telling again every time it
/// changed, and the page it runs in is not somewhere to keep configuration.
function docOfUrl(href: string, suffix: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  if (url.protocol !== "http:") {
    return null;
  }
  const tail = `.${suffix}`;
  if (!url.hostname.endsWith(tail)) {
    return null;
  }
  const alias = url.hostname.slice(0, -tail.length);
  // A single label only. `a.b.ssh-browser` is not an alias the daemon serves, and sending it
  // one would be asking for a refusal we can predict.
  if (alias === "" || alias.includes(".")) {
    return null;
  }
  return `${alias}${url.pathname}`;
}

/// Every call to the daemon goes through here, so the token is attached in exactly one place
/// and cannot be forgotten at a call site.
async function callDaemon(s: Settings, path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set(TOKEN_HEADER, s.token);
  return fetch(`http://127.0.0.1:${s.port}${path}`, { ...init, headers });
}

/// `encodeURIComponent` would escape the separator that divides the alias from the path, and
/// the daemon splits on it. Encoding each segment separately keeps a filename containing `&`
/// or `=` from breaking the query while leaving the separator alone.
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

async function connect(port: number, token: string): Promise<Reply> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, detail: `${port} is not a port` };
  }
  // The suffix is not known until `hello` answers, so this placeholder only has to be good
  // enough to reach the daemon; the real one is stored below.
  const s: Settings = { port, token, suffix: "" };

  let res: Response;
  try {
    res = await callDaemon(s, "/_control/hello");
  } catch {
    // A refused connection is the ordinary case of "the daemon is not running", so say that
    // rather than surfacing a network error the reader cannot act on.
    return {
      ok: false,
      detail:
        `nothing is listening on 127.0.0.1:${port}. Start it with: ` +
        `ssh-browser serve <alias>=<host>:<path>`,
    };
  }

  if (res.status === 401) {
    return { ok: false, detail: "the daemon refused that token" };
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
    return { ok: false, detail: `connected, but the proxy could not be set: ${String(e)}` };
  }

  await chrome.storage.local.set({ port, token, suffix: hello.suffix ?? "" });
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
  await chrome.storage.local.remove(["port", "token", "suffix"]);
  return { ok: true, detail: "disconnected, and the proxy setting is cleared" };
}

async function status(): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  return connect(s.port, s.token);
}

/// Register the content script for the daemon's suffix, and only for it.
///
/// Registered at runtime rather than declared in the manifest, because the suffix is
/// configurable: a manifest entry would have to match every http site in order to cover
/// whatever suffix was chosen, and that is a permission this extension has no reason to hold.
///
/// The permission itself is requested from the popup, because a request needs a user gesture.
async function registerContent(suffix: string): Promise<Reply> {
  const matches = matchesFor(suffix);
  if (!(await chrome.permissions.contains({ origins: matches }))) {
    return {
      ok: false,
      detail: `not allowed to run on ${matches[0]} yet — grant it from the popup`,
    };
  }

  await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] }).catch(() => {
    // Nothing registered yet, which is the ordinary first run.
  });
  await chrome.scripting.registerContentScripts([
    {
      id: CONTENT_SCRIPT_ID,
      matches,
      js: ["content.js"],
      runAt: "document_idle",
    },
  ]);
  return { ok: true, detail: `annotating pages under *.${suffix}` };
}

async function listAnnotations(url: string): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const doc = docOfUrl(url, s.suffix);
  if (doc === null) {
    return { ok: false, detail: "this page is not served by ssh-browser" };
  }
  const res = await callDaemon(s, `/_control/annotations?doc=${encodeDoc(doc)}`);
  if (!res.ok) {
    return { ok: false, detail: `${res.status}: ${await res.text()}` };
  }
  const body = (await res.json()) as { annotations: unknown[]; skipped: number };
  return {
    ok: true,
    // Surfaced rather than dropped: a line the daemon could not parse means an annotation
    // somebody wrote is not being shown, and silence about that is the worst outcome.
    detail:
      body.skipped > 0
        ? `${body.annotations.length} annotations, ${body.skipped} unreadable lines`
        : `${body.annotations.length} annotations`,
    annotations: body.annotations,
    skipped: body.skipped,
  };
}

async function addAnnotation(url: string, body: string, selectors?: unknown): Promise<Reply> {
  const s = await stored();
  if (!s) {
    return { ok: false, detail: "not connected" };
  }
  const doc = docOfUrl(url, s.suffix);
  if (doc === null) {
    return { ok: false, detail: "this page is not served by ssh-browser" };
  }
  // No author and no id: the daemon decides both, so no caller — including this extension —
  // can write as somebody else or choose an identity.
  const payload: Record<string, unknown> = { doc, op: "add", body };
  if (selectors !== undefined) {
    payload["selectors"] = selectors;
  }
  const res = await callDaemon(s, "/_control/annotations", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    return { ok: false, detail: `${res.status}: ${await res.text()}` };
  }
  const added = (await res.json()) as { id: string };
  return { ok: true, detail: "saved", id: added.id };
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
      return connect(message.port, message.token);
    case "disconnect":
      return disconnect();
    case "status":
      return status();
    case "register":
      return registerContent(message.suffix);
    case "annotations":
      return listAnnotations(message.url);
    case "annotate":
      return addAnnotation(message.url, message.body, message.selectors);
  }
}

chrome.runtime.onMessage.addListener((message, _sender, reply) => {
  dispatch(message)
    .then(reply)
    .catch((e: unknown) => reply({ ok: false, detail: String(e) }));
  // Keeps the message channel open for the asynchronous reply above.
  return true;
});
