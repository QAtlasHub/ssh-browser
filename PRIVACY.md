# Privacy

The ssh-browser extension sends nothing to us, because there is no us to send it to. No
server stands behind this project, and there is no account, no analytics, no crash reporting
and no remotely hosted code. Everything below is about data that either stays on your machine
or goes to a host you already had an SSH account on.

This is the extension's policy. The daemon is a program you run yourself, and what it does is
in [SECURITY.md](SECURITY.md).

## What it holds

In `chrome.storage.local`, which is local to your browser profile:

| | what it is |
|---|---|
| port | the TCP port your daemon listens on, e.g. `7391` |
| control token | the token that daemon printed when it started |
| suffix | the hostname suffix you configured, e.g. `ssh-browser` |
| aliases | the alias names the daemon reported, e.g. `docs`, `cluster` |

The control token is the piece worth singling out. It lives in the extension's service worker
and is never handed to a content script, because a page served from an alias origin is code
from the remote host and the extension treats it as untrusted. That is why annotating asks the
worker to act rather than acting inside the page.

## What it reads

On a page under your configured suffix, and on no other page:

- **the page's URL**, which is how the extension knows which document a note belongs to
- **the page's text**, when it places a note — anchoring means finding the quoted words again,
  which cannot be done without reading them

Both stay in the browser except as described next.

## Where anything goes

To `http://127.0.0.1:<your port>`, and nowhere else. That is your own daemon, on your own
machine. It passes what it is given to the SSH host you configured, over your own SSH
connection, as the account you already had.

A note you write is therefore stored on your host, in a file beside the document, under your
own name. Nobody else receives it and nobody else can, because there is no intermediary to
receive it.

You can check rather than take this on trust: `extension/src/background.ts` contains exactly
one `fetch`, in `callDaemon`, and its URL begins `http://127.0.0.1:`.

## What it does not do

- no analytics, no telemetry, no error reporting
- no advertising, no tracking, no profiles
- nothing sold, rented or shared with anyone, since nothing leaves your machine
- no remotely hosted code: everything it runs is in the package you installed

## Permissions, and why each exists

- **`proxy`** — installs the routing script your daemon serves, so `alias.ssh-browser` reaches
  it. Without it you would configure the browser's proxy by hand instead.
- **`storage`** — remembers the four things above, so you do not retype a 64-character token
  on every page.
- **`scripting`** — registers the annotation script at runtime, for your configured suffix
  only. At runtime precisely so the extension need not declare a match pattern covering every
  site: the suffix is yours to choose, and anything declared in advance would have to be broad
  enough for any choice you might make.
- **`http://127.0.0.1/*`** — talking to your daemon.
- **`http://*/*`, optional, requested when you click Connect** — the narrowest pattern that
  can be *declared* ahead of time, because your suffix is not known until you connect. What is
  actually *requested* is `http://*.<your suffix>/*`, and that is what the browser asks you to
  approve. Declining leaves reading working and annotation off.

## Removing it

Uninstalling deletes everything in the table above with it. Notes already written are files on
your own host and stay there; delete them as you would any other file.

## Questions

Open an issue at <https://github.com/QAtlasHub/ssh-browser>. For anything that should not be
public, [SECURITY.md](SECURITY.md) says how to reach us privately.
