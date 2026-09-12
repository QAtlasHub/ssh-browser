// The popup.
//
// Deliberately thin: it collects a port and a token, asks the worker to connect, and shows
// what came back. It never calls the daemon itself, because the token belongs in exactly one
// place and a second caller would be a second place to leak it from.

interface Reply {
  ok: boolean;
  detail: string;
  aliases?: string[];
  suffix?: string;
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

function show(reply: Reply): void {
  const status = el("status");
  status.textContent = reply.detail;
  status.classList.toggle("bad", !reply.ok);

  const list = el("aliases");
  list.textContent = "";
  const suffix = reply.suffix;
  if (!reply.ok || suffix === undefined) {
    return;
  }
  for (const alias of reply.aliases ?? []) {
    const href = `http://${alias}.${suffix}/`;
    const link = document.createElement("a");
    // Built through the DOM rather than by assembling markup, so an alias name cannot become
    // markup even if the daemon were somehow made to report a strange one.
    link.href = href;
    link.textContent = href;
    link.target = "_blank";
    link.rel = "noreferrer";
    const item = document.createElement("li");
    item.append(link);
    list.append(item);
  }
}

async function connect(): Promise<void> {
  const port = Number(el<HTMLInputElement>("port").value);
  const token = el<HTMLInputElement>("token").value.trim();
  el("status").textContent = "connecting…";

  const reply = await send({ kind: "connect", port, token });
  show(reply);
  if (!reply.ok || reply.suffix === undefined) {
    return;
  }

  // Asked for here because a permission request needs a user gesture, and clicking Connect is
  // the one this extension gets. Only the configured suffix is requested, never every site.
  const origins = [`http://*.${reply.suffix}/*`];
  const granted = await chrome.permissions.request({ origins });
  if (!granted) {
    el("status").textContent =
      `${reply.detail}, but without permission for ${origins[0]} pages will not show notes`;
    return;
  }

  const registered = await send({ kind: "register", suffix: reply.suffix });
  el("status").textContent = `${reply.detail}; ${registered.detail}`;
}

el<HTMLButtonElement>("connect").addEventListener("click", () => {
  void connect();
});

el<HTMLInputElement>("token").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    void connect();
  }
});

// Opening the popup re-checks rather than showing a remembered verdict. A daemon that has
// since stopped, or been restarted with a new token, should read as disconnected here rather
// than looking fine until something else fails.
void send({ kind: "status" }).then(show);
