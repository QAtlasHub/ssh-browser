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

> Open files that live on a host reachable only over SSH as real web pages in the browser.

The store wants one purpose and this is one. Everything the extension does — routing alias
hostnames, holding the control token, listing the hosts ssh already knows — exists to put
remote files on a real origin.

## Short description

The limit is 132 characters; this is 96.

> Open files on a host reachable only over SSH as real web pages, rendered natively rather
> than previewed.

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
> A dashboard lists the hosts your `~/.ssh/config` already reaches, with the user, hostname,
> port and ProxyJump that `ssh -G` resolves for each. Clicking one serves it; clicking a site
> opens it.
>
> Nothing is injected into a page: there is no content script, so what loads is the site,
> unchanged. Nothing is written to your host either — the daemon has no write path at all.
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
> alias names the daemon reported, so the user does not retype a 64-character token every
> time. Local to the profile, and never transmitted anywhere but 127.0.0.1.

**`host_permissions: http://127.0.0.1/*`**

> The extension's only network destination. This is the user's own daemon, which they started
> themselves, listening on loopback.

**`web_accessible_resources: dashboard.html` for `http://ssh-browser/*`**

Not a permission, so the form does not ask — but a reviewer reads the manifest, and this is
the entry that would raise the question.

> The daemon serves a page at the root of the configured suffix whose only job is to hand the
> browser to this extension's dashboard. That navigation is refused unless the page is listed
> here, so exactly one origin is: the bare suffix, which serves nothing but that page. Pages
> served from a host — `docs.ssh-browser`, remote content, untrusted — are not covered by the
> pattern and are refused the same navigation.

**Remote code**

Answered **no** on the form. Not an obvious no, so the reasoning is written here rather than
left in somebody's memory of a decision made while filling in a text box.

> None. Everything the extension executes is in the uploaded package.

What makes it a question: `applyPac` fetches `http://127.0.0.1:<port>/proxy.pac` from the
user's own daemon and hands the text to `chrome.proxy` as `pacScript.data`. Chrome's definition
of remotely hosted code is "anything that is executed by the browser that is loaded from
someplace other than the extension's own files", and a PAC is JavaScript.

Why it is still no:

- It does not run in the extension. `chrome.proxy` is a first-party API whose documented input
  is a PAC string, and the browser's network stack evaluates it — no page, no service worker,
  no `eval`.
- It is not remotely hosted. It comes from loopback, from a program the user installed and
  started. Nothing on the network can serve it and no update of ours can change it.
- The policy exists so that an extension's behaviour cannot be changed after review by a server
  its author controls. Nobody controls this one but the person running the extension.

If a reviewer disagrees, the fix is small and already scoped: the PAC is a function of the
suffix and the port, and the extension knows both. Generating it locally makes the answer
unambiguous and keeps what the fetch was for — the suffix stays data the daemon reports, so
changing it still needs no extension release. What would be lost is having one generator, and
an e2e check that runs both and compares their answers covers that.

## Data disclosure

Tick **one**. Under-declaring is a policy violation, so anything arguable is declared — but
declaring a category the extension has no code for is a false statement on the same form, and
this section had two of them until it was checked against the extension that actually shipped.

- **Authentication information** — the daemon's control token. Held in the service worker,
  stored in `chrome.storage.local`, sent only to `http://127.0.0.1:<port>` as a request
  header. Never given to a page, because pages from the remote host are untrusted code.

Nothing else, and each of these is checkable rather than asserted:

- **Website content** — no. There is no content script — `extension/permissions.json` pins
  that and CI fails if it changes — and no host permission for any site, so there is no code
  path that could read a page.
- **Personal communications** — no. There was going to be an annotation feature; it was
  removed, and with it the only thing the user would have typed.
- **Web history, location, financial, health, personal identifiers, user activity** — no.
  Nothing about the page being viewed is reported anywhere. The extension makes three `fetch`
  calls and all three begin `http://127.0.0.1:`.

All three certifications are true:

- not sold to third parties
- not used or transferred for any purpose unrelated to the single purpose above
- not used or transferred to determine creditworthiness or for lending

## Privacy policy URL

> https://github.com/QAtlasHub/ssh-browser/blob/main/PRIVACY.md

## Screenshots

At least one, 1280×800 or 640×400. Taken from the real product against a live daemon rather
than mocked up — but **not on your own machine**:

```
gh workflow run shots.yml
gh run download <id> -n store-screenshots
```

The dashboard lists every host your ssh can reach, with the user, address, port and jump host
`ssh -G` resolves for each, and above that what is being served, with the account and path it
is rooted at. On a laptop that is your infrastructure in an image destined for a public page;
the first run of this produced exactly that. `shots.yml` runs on a fresh runner against a
throwaway sshd and the invented `ssh_config` in `e2e/shots-config/`, and `shots.mjs` refuses
any host but a local one so it cannot happen by habit.

## The first submission, by hand

Once. The API cannot create a listing — description, screenshots, category and the data
disclosure are not reachable from it, and the extension ID does not exist until the Store
listing and Privacy tabs have been filled in.

1. Register the developer account. Five dollars, once.
2. Upload the zip, paste the text above, attach the screenshots.
3. Choose visibility. Unlisted is worth considering first: this extension does nothing without
   a daemon installed separately, and a public listing collects installs from people who have
   not done that and will reasonably report it as broken.

## Every release after that, by CI

`.github/workflows/store.yml` uploads the release's zip and publishes it. The decision is still
a person's — it is merging the release PR — but nothing is retyped, and what reaches the store
is the package that was built, tested and attached to the release rather than one somebody
dragged into a browser.

Three repository secrets, set once:

| secret | where it comes from |
|---|---|
| `CWS_EXTENSION_ID` | the item's ID, from its dashboard URL, once it exists |
| `CWS_PUBLISHER_ID` | Developer Dashboard → Account |
| `CWS_SERVICE_ACCOUNT` | the JSON key of a Google Cloud service account |

A service account rather than a refresh token: a refresh token issued while the OAuth consent
screen is still in "Testing" expires after a week, so the pipeline would work today and fail
next month having changed nothing.

1. In the Google Cloud console, create a project and enable the **Chrome Web Store API**.
2. Create a service account. It needs no roles.
3. Create a JSON key for it, and put the whole file in `CWS_SERVICE_ACCOUNT`.
4. In the Developer Dashboard, under **Account**, add the service account's email address.
   Only one service account can be attached to a publisher, so this is the one.

Then `gh workflow run store.yml -f tag=v0.5.0` tries it without publishing, and after that
every published release goes on its own.

Two things that will bite:

- **Visibility is not set by this API.** The item publishes at whatever the dashboard says, and
  if visibility is changed by hand the store refuses API publishing until it has been published
  by hand once at the new setting.
- **A version cannot be uploaded twice.** `versions agree` in CI keeps `manifest.json` in step
  with `Cargo.toml`; if that ever drifts, the store rejects the upload rather than quietly
  taking it.
