// The popup: the hosts your ssh already knows, and a click to open one.
//
// Deliberately thin. It never calls the daemon itself, because the token belongs in exactly
// one place and a second caller would be a second place to leak it from. There is no token
// field either — the worker asks the daemon for it, and the daemon answers that to anything
// except a page.

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
  aliases?: string[];
  suffix?: string;
  open?: OpenAlias[];
  hosts?: KnownHost[];
  unusable?: { host: string; why: string }[];
  url?: string;
}

function el<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`the popup is missing #${id}`);
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

/// `souta@157.82.60.8:10019, via Panza` — the line souta asked to see beside each host.
///
/// Every part is what `ssh -G` resolved, so it describes what connecting will actually do
/// rather than what a second reading of the config file concluded.
function describe(h: KnownHost): string {
  const who = h.user === undefined ? "" : `${h.user}@`;
  const where = h.hostname ?? h.host;
  // Port 22 is not worth the width; anything else is the whole point of showing this.
  const port = h.port === undefined || h.port === 22 ? "" : `:${h.port}`;
  const via = h.proxyJump ? `, via ${h.proxyJump}` : "";
  return `${who}${where}${port}${via}`;
}

/// Open a host, then go to it.
///
/// The tab is opened only after the daemon has answered, because the URL is the daemon's
/// answer: an alias the config file roots somewhere is served there rather than at the home
/// directory, and building the URL here would be a second opinion about it.
async function pick(h: KnownHost, button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  say(`connecting to ${h.host} over ssh…`);
  const reply = await send({ kind: "open", host: h.host });
  button.disabled = false;
  if (!reply.ok || reply.url === undefined) {
    say(reply.detail, true);
    return;
  }
  await chrome.tabs.create({ url: reply.url });
  window.close();
}

/// One row: a bold name, an optional tag, and a line of detail under it.
///
/// Built through the DOM rather than by assembling markup, so nothing the daemon reports
/// can become markup here.
function row(name: string, tag: string | null, detail: string, detailClass: string): HTMLLIElement {
  const button = document.createElement("button");
  button.type = "button";
  // A handle that is the name itself. Matching on the visible text picks the wrong row,
  // because an open alias names its ssh host in the line underneath it.
  button.dataset["alias"] = name;

  const label = document.createElement("span");
  label.className = "alias";
  label.textContent = name;
  button.append(label);

  if (tag !== null) {
    const badge = document.createElement("span");
    badge.className = "served";
    badge.textContent = tag;
    button.append(badge);
  }

  const under = document.createElement("div");
  under.className = detailClass;
  under.textContent = detail;
  button.append(under);

  const item = document.createElement("li");
  item.append(button);
  return item;
}

function render(reply: Reply): void {
  const list = el("hosts");
  list.textContent = "";

  const open = reply.open ?? [];
  // What is already being served comes first, and it is a plain link: it is there, so
  // there is nothing to ask the daemon before going to it.
  for (const o of open) {
    const item = row(o.alias, "open", `${o.host}:${o.base}`, "where");
    const button = item.querySelector("button");
    button?.addEventListener("click", () => {
      void chrome.tabs.create({ url: o.url }).then(() => {
        window.close();
      });
    });
    list.append(item);
  }

  // Then what could be opened, minus anything already above. A host listed twice would
  // read as two different things to click.
  for (const h of reply.hosts ?? []) {
    if (open.some((o) => o.alias === h.alias)) {
      continue;
    }
    // A host ssh could not describe is still offered, with the reason where the address
    // would be. Hiding it would make a misconfigured host look like one that is not in the
    // file, and those have different fixes.
    const item = row(
      h.alias,
      null,
      h.unresolved ?? describe(h),
      h.unresolved === undefined ? "where" : "bad-host",
    );
    const button = item.querySelector("button");
    button?.addEventListener("click", () => {
      void pick(h, button);
    });
    list.append(item);
  }

  const skipped = el("skipped");
  skipped.textContent =
    reply.unusable && reply.unusable.length > 0
      ? reply.unusable.map((u) => `${u.host}: ${u.why}`).join("\n")
      : "";
}

/// Connect, register the content script if it is already allowed, then list hosts.
async function start(): Promise<void> {
  const port = Number(el<HTMLInputElement>("port").value);
  // Remembered, because the field is behind a disclosure now. A port typed once and then
  // forgotten on the next open would make a non-default daemon look like an absent one
  // every single time the popup is opened.
  await chrome.storage.local.set({ port });
  say("looking for the daemon…");

  const reply = await send({ kind: "connect", port });
  if (!reply.ok || reply.suffix === undefined) {
    say(reply.detail, true);
    return;
  }
  say(reply.detail);

  const origins = [`http://*.${reply.suffix}/*`];
  if (await chrome.permissions.contains({ origins })) {
    const registered = await send({ kind: "register", suffix: reply.suffix });
    if (!registered.ok) {
      say(`${reply.detail}; ${registered.detail}`, true);
    }
  }

  const hosts = await send({ kind: "hosts" });
  if (!hosts.ok) {
    say(hosts.detail, true);
    return;
  }
  // Only if there is something to say. An empty detail means "nothing went wrong and
  // there is nothing to add", and writing it over the connect line would leave the popup
  // reporting nothing at all about a daemon it just talked to.
  if (hosts.detail !== "") {
    say(hosts.detail);
  }
  render(hosts);
}

// Asked on a click rather than when the popup opens, because a permission request needs a
// user gesture and opening a popup is not reliably one. Kept out of `start` so a refusal
// does not stop the host list appearing: reading pages works without it, and only notes do
// not.
el("hosts").addEventListener(
  "click",
  () => {
    void (async () => {
      const { suffix } = (await chrome.storage.local.get("suffix")) as {
        suffix?: string;
      };
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

el<HTMLInputElement>("port").addEventListener("change", () => {
  void start();
});

// Opening the popup re-checks rather than showing a remembered verdict. A daemon that has
// since stopped, or been restarted, should read as disconnected here rather than looking
// fine until something else fails.
//
// The port is the one thing read back from storage first: it says *which* daemon to check,
// so checking before reading it would check the wrong one and report it as absent.
void (async () => {
  const { port } = (await chrome.storage.local.get("port")) as {
    port?: number;
  };
  if (typeof port === "number") {
    el<HTMLInputElement>("port").value = String(port);
  }
  await start();
})();
