# Chrome Web Store listing

Everything the submission form asks for, written out so it gets reviewed here rather than
typed into a textarea at midnight. The form is at
<https://chrome.google.com/webstore/devconsole>.

Publishing needs a developer account, which costs five dollars once and is a human step. So is
the upload. Nothing in this repository can do either.

## Building what gets uploaded

```
npm --prefix extension ci
npm --prefix extension run icons     # only if icons/ is missing or the mark changed
npm --prefix extension run build
npm --prefix extension run package
```

That writes `extension/ssh-browser-<version>.zip`. It is reproducible: rebuild from the same
commit and the bytes match, so the upload can be checked against the source rather than taken
on faith.

## Single purpose

> Open files that live on a host reachable only over SSH as real web pages in the browser, and
> annotate them.

The store wants one purpose and this is one. Everything the extension does — routing alias
hostnames, holding the control token, drawing notes — exists to put remote files on a real
origin and let a reader mark them up.

## Short description

The limit is 132 characters; this is 101.

> Read and annotate files on a host reachable only over SSH — rendered as real pages, not
> previews.

## Detailed description

> A file on an HPC login node, or on a VPS with no domain and no certificate, is awkward to
> look at. Opened over `file://` it has an opaque origin, so ES modules, `fetch` and service
> workers all fail — an sshfs mount does not give you a working page. SFTP file managers show
> a preview rather than a page.
>
> ssh-browser runs a small daemon on your own machine that speaks SFTP through your existing
> `ssh` command — so `~/.ssh/config`, ProxyJump, agent keys and certificates all work without
> being reimplemented — and serves what it finds at `http://<alias>.ssh-browser/`. Each alias
> is its own origin, so a page under one cannot read another.
>
> This extension is the browser half. It installs the routing script the daemon serves, so the
> address bar keeps the URL you asked for. It holds the daemon's control token, and it is the
> only thing that does: pages served from a remote host are treated as untrusted code, and ask
> the extension to act on their behalf rather than being handed credentials.
>
> It also draws annotations. Notes are per-author append-only files kept beside the document on
> your own host, so two people annotating one page write to different files and neither can
> lose the other's work. Highlights use the CSS Custom Highlight API and the panel lives in a
> closed shadow root, so the page you came to read is never modified.
>
> Four things are said rather than hidden, because each means a note is not saying what it
> appears to: a note that could not be placed, a note whose quoted text has changed and which
> was placed by position instead, a log whose filename claims an author the file's owner
> contradicts, and a line the daemon could not parse.
>
> The daemon is separate and you run it yourself: `cargo install ssh-browser`. Source for both
> halves is at https://github.com/QAtlasHub/ssh-browser.

## Category

Developer Tools.

## Permission justifications

The form asks for one per permission. Keep these in step with `../PRIVACY.md`.

**`proxy`**

> Installs the proxy auto-config script the user's own local daemon serves, so that hostnames
> under their configured suffix route to it. Without this the user would set the browser's
> proxy by hand instead. The script is fetched from 127.0.0.1 and routes only that suffix;
> everything else is DIRECT.

**`storage`**

> Remembers the local daemon's port, its control token, the configured hostname suffix and the
> alias names the daemon reported, so the user does not retype a 64-character token on every
> page. Local to the profile, and never transmitted anywhere but 127.0.0.1.

**`scripting`**

> Registers the annotation content script at runtime for the user's configured suffix only.
> At runtime rather than declared in the manifest precisely to avoid a static match pattern:
> the suffix is the user's to choose, so anything declared in advance would have to cover
> every site.

**`host_permissions: http://127.0.0.1/*`**

> The extension's only network destination. This is the user's own daemon, which they started
> themselves, listening on loopback.

**`optional_host_permissions: http://*/*`**

> Requested when the user clicks Connect, never at install. The suffix is not known until the
> daemon reports it, so this is the narrowest pattern that can be *declared* in advance. What
> is actually *requested* is `http://*.<the user's suffix>/*` — with the default configuration
> that is `http://*.ssh-browser/*` — and that is what the browser's prompt names. Declining
> leaves reading working and turns annotation off.

**Remote code**

> None. Everything the extension executes is in the uploaded package.

## Data disclosure

Tick these three and explain in the notes. Under-declaring is a policy violation, so anything
arguable is declared; the notes are where the shape of it gets said.

- **Authentication information** — the daemon's control token. Held in the service worker,
  stored in `chrome.storage.local`, sent only to `http://127.0.0.1:<port>` as a request
  header. Never given to a content script, because pages from the remote host are untrusted.
- **Website content** — the text of pages under the configured suffix, read in order to find
  the words a note was attached to. Anchoring cannot be done without reading them. The text is
  not transmitted; only the note and its selectors go to the local daemon.
- **Personal communications** — the notes the user types. They go to the local daemon, which
  writes them to a file on the user's own SSH host. There is no service in between.

Also sent to the local daemon: the path of the page being viewed, which is how a document is
identified. No browsing history is assembled or retained.

All three certifications are true:

- not sold to third parties
- not used or transferred for any purpose unrelated to the single purpose above
- not used or transferred to determine creditworthiness or for lending

## Privacy policy URL

> https://github.com/QAtlasHub/ssh-browser/blob/main/PRIVACY.md

## Screenshots

At least one, 1280×800 or 640×400. `npm --prefix e2e run shots` captures them from the real
product against a live daemon rather than mocking anything up, and writes to `e2e/shots/`.

## Still to do by hand

1. Register the developer account. Five dollars, once.
2. Upload the zip, paste the text above, attach the screenshots.
3. Choose visibility. Unlisted is worth considering first: this extension does nothing without
   a daemon installed separately, and a public listing collects installs from people who have
   not done that and will reasonably report it as broken.
