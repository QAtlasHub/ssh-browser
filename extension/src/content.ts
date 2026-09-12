// Runs inside an alias page, in the isolated world.
//
// It holds no token. Everything that touches the daemon is a message to the service worker,
// because this script shares a process with the page and the page is untrusted code.
//
// It also tries hard not to change the document. The whole product is "the page renders as it
// would anywhere else", and an annotation layer that rewrote the DOM would break that in ways
// the reader would blame on the page.

import {
  createTextPositionSelectorMatcher,
  createTextQuoteSelectorMatcher,
  describeTextPosition,
  describeTextQuote,
} from "@apache-annotator/dom";

/// The two selector shapes, per the W3C Web Annotation Data Model.
///
/// Declared here rather than imported, so the stored format is this extension's own
/// commitment rather than a library's. The daemon stores them opaquely, so a third kind could
/// be added without either side needing a release.
interface TextQuoteSelector {
  type: "TextQuoteSelector";
  exact: string;
  prefix?: string;
  suffix?: string;
}

interface TextPositionSelector {
  type: "TextPositionSelector";
  start: number;
  end: number;
}

type Selector = TextQuoteSelector | TextPositionSelector;

interface Annotation {
  id: string;
  author: string;
  at: number;
  body: string;
  selectors?: Selector[];
  reply_to?: string;
}

interface Reply {
  ok: boolean;
  detail: string;
  annotations?: Annotation[];
  skipped?: number;
}

interface Placed {
  annotation: Annotation;
  anchored: boolean;
}

/// TypeScript's DOM library declares `HighlightRegistry` with only `forEach`, while the spec
/// gives it the full maplike interface. Stated once here rather than cast away at each call
/// site, so the gap is visible and does not turn into a scattering of `as any`.
declare global {
  interface HighlightRegistry {
    set(name: string, highlight: Highlight): HighlightRegistry;
    delete(name: string): boolean;
    clear(): void;
  }
}

const HIGHLIGHT = "ssh-browser-annotation";

async function send(message: unknown): Promise<Reply> {
  return (await chrome.runtime.sendMessage(message)) as Reply;
}

async function first<T>(source: AsyncIterable<T>): Promise<T | null> {
  for await (const item of source) {
    return item;
  }
  return null;
}

/// Anchor one annotation, preferring the quote.
///
/// Two selectors are stored and tried in order because they fail in different ways. A quote
/// survives the document being reflowed but not its text changing; a position survives the
/// text changing but not a character being inserted ahead of it. Neither is reliable alone,
/// and on a page of computed results — where the numbers themselves are what change — the
/// quote is the one that breaks.
///
/// Returning null rather than a guess is the point. An annotation that cannot be placed is
/// shown as unanchored, because dropping it silently would make somebody's note vanish with no
/// sign it ever existed.
async function anchor(selectors: Selector[]): Promise<Range | null> {
  const quote = selectors.find((s): s is TextQuoteSelector => s.type === "TextQuoteSelector");
  if (quote) {
    const found = await first(createTextQuoteSelectorMatcher(quote)(document.body));
    if (found) {
      return found;
    }
  }
  const position = selectors.find(
    (s): s is TextPositionSelector => s.type === "TextPositionSelector",
  );
  if (position) {
    const found = await first(createTextPositionSelectorMatcher(position)(document.body));
    if (found) {
      return found;
    }
  }
  return null;
}

/// Drawn with the CSS Custom Highlight API rather than by wrapping text in elements.
///
/// Wrapping mutates the page: it would be visible to any script that walks the DOM, it would
/// change which CSS selectors match, and it would make the annotation part of the document the
/// reader came for. A highlight registry is invisible to all three.
///
/// It also sidesteps Apache Annotator's own warning that editing the DOM while its matcher is
/// still searching can loop forever (incubator-annotator#112). Nothing here edits the DOM at
/// all, so the hazard does not arise.
function draw(ranges: Range[]): void {
  if (ranges.length === 0) {
    CSS.highlights.delete(HIGHLIGHT);
    return;
  }
  CSS.highlights.set(HIGHLIGHT, new Highlight(...ranges));
}

/// Styles the highlight without adding a node to the document.
///
/// `adoptedStyleSheets` leaves no `<style>` element for a page script to find or for a CSS
/// selector to match.
function installHighlightStyle(): void {
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(`::highlight(${HIGHLIGHT}) { background-color: rgba(255, 214, 0, 0.35); }`);
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
}

/// One host element with a closed shadow root.
///
/// The page can see that an element exists but cannot reach inside it, and styles cannot leak
/// in either direction. Both matter: the page is untrusted code, and the panel must not
/// restyle the document the reader came for.
function makePanel(): ShadowRoot {
  const host = document.createElement("div");
  host.id = "ssh-browser-panel-host";
  const shadow = host.attachShadow({ mode: "closed" });

  const style = document.createElement("style");
  style.textContent = `
    .panel {
      background: #fffdf5;
      border: 1px solid #d8d2bf;
      border-radius: 6px;
      bottom: 12px;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
      color: #1a1a1a;
      font: 12px/1.45 system-ui, sans-serif;
      max-height: 40vh;
      overflow: auto;
      padding: 8px 10px;
      position: fixed;
      right: 12px;
      width: 260px;
      z-index: 2147483647;
    }
    .head { display: flex; gap: 8px; justify-content: space-between; }
    .head strong { font-weight: 600; }
    button { font: inherit; padding: 2px 8px; }
    ul { list-style: none; margin: 6px 0 0; padding: 0; }
    li { border-top: 1px solid #eee6d0; padding: 5px 0; }
    .who { color: #6b6450; }
    .orphan { color: #8a6d00; }
  `;

  const panel = document.createElement("div");
  panel.className = "panel";

  const head = document.createElement("div");
  head.className = "head";
  const title = document.createElement("strong");
  title.textContent = "ssh-browser";
  const add = document.createElement("button");
  add.id = "add";
  add.textContent = "Add note";
  add.disabled = true;
  head.append(title, add);

  const count = document.createElement("div");
  count.id = "count";
  const list = document.createElement("ul");
  list.id = "list";

  panel.append(head, count, list);
  shadow.append(style, panel);
  document.documentElement.append(host);
  return shadow;
}

function render(shadow: ShadowRoot, items: Placed[], skipped: number): void {
  const count = shadow.getElementById("count");
  const list = shadow.getElementById("list");
  if (!count || !list) {
    return;
  }

  const unanchored = items.filter((i) => !i.anchored).length;
  const parts = [`${items.length} note${items.length === 1 ? "" : "s"}`];
  if (unanchored > 0) {
    // Said out loud rather than hidden. An annotation whose text has since changed is exactly
    // the case where the reader most needs to know something was written here.
    parts.push(`${unanchored} unanchored`);
  }
  if (skipped > 0) {
    parts.push(`${skipped} unreadable`);
  }
  count.textContent = parts.join(", ");

  list.textContent = "";
  for (const { annotation, anchored } of items) {
    const item = document.createElement("li");

    const who = document.createElement("span");
    who.className = "who";
    who.textContent = `${annotation.author}: `;

    // textContent throughout: an annotation body is text somebody typed, and it is being shown
    // inside a privileged shadow root.
    const body = document.createElement("span");
    body.textContent = annotation.body;

    item.append(who, body);
    if (!anchored) {
      const flag = document.createElement("div");
      flag.className = "orphan";
      flag.textContent = "could not be placed on this page";
      item.append(flag);
    }
    list.append(item);
  }
}

async function refresh(shadow: ShadowRoot): Promise<void> {
  const reply = await send({ kind: "annotations", url: location.href });
  const count = shadow.getElementById("count");
  if (!reply.ok) {
    if (count) {
      count.textContent = reply.detail;
    }
    return;
  }

  const annotations = reply.annotations ?? [];
  // Every anchor is resolved before anything is drawn. The matcher walks the DOM lazily, and
  // collecting first keeps the search and the drawing from ever overlapping.
  const placed: Placed[] = [];
  const ranges: Range[] = [];
  for (const annotation of annotations) {
    const range = annotation.selectors ? await anchor(annotation.selectors) : null;
    if (range) {
      ranges.push(range);
    }
    placed.push({ annotation, anchored: range !== null });
  }

  draw(ranges);
  render(shadow, placed, reply.skipped ?? 0);
}

async function addForSelection(shadow: ShadowRoot): Promise<void> {
  const selection = document.getSelection();
  if (!selection || selection.isCollapsed || selection.rangeCount === 0) {
    return;
  }
  const range = selection.getRangeAt(0);

  // `prompt` from the isolated world, so a page that has replaced `window.prompt` can neither
  // see nor intercept what is typed. A proper editor belongs inside the shadow root for the
  // same reason, not in the page.
  const typed = window.prompt("Note");
  if (typed === null || typed.trim() === "") {
    return;
  }

  // Both selectors, from the same range, for the reasons in `anchor`.
  const quote = await describeTextQuote(range, document.body);
  const position = await describeTextPosition(range, document.body);

  const reply = await send({
    kind: "annotate",
    url: location.href,
    body: typed.trim(),
    selectors: [quote, position],
  });

  if (!reply.ok) {
    const count = shadow.getElementById("count");
    if (count) {
      count.textContent = reply.detail;
    }
    return;
  }
  await refresh(shadow);
}

function main(): void {
  installHighlightStyle();
  const shadow = makePanel();

  const add = shadow.getElementById("add") as HTMLButtonElement | null;
  if (add) {
    add.addEventListener("click", () => {
      void addForSelection(shadow);
    });
    document.addEventListener("selectionchange", () => {
      const selection = document.getSelection();
      add.disabled = !selection || selection.isCollapsed;
    });
  }

  // A page can be an alias page with the daemon disconnected, in which case the worker says so
  // and the panel shows that rather than pretending.
  void refresh(shadow);
}

main();
