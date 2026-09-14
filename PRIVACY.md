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
and nothing else ever holds it, because a page served from an alias origin is code from the
remote host and the extension treats it as untrusted.

## What it reads

Nothing on any page. The extension has no content script: it does not run in, read from, or
modify the sites it helps you open. What loads is the site, unchanged.

## Where anything goes

To `http://127.0.0.1:<your port>`, and nowhere else. That is your own daemon, on your own
machine. It passes what it is given to the SSH host you configured, over your own SSH
connection, as the account you already had.

Nothing is written to your host. The daemon has no write path: the SFTP requests it can issue
are `OPEN`, `CLOSE`, `READ`, `OPENDIR`, `READDIR` and `REALPATH`, and the only open flag it
defines is read.

You can check rather than take this on trust: `extension/src/background.ts` contains three
`fetch` calls — the control API, the proxy script, and the token on first connect — and each
of their URLs begins `http://127.0.0.1:`. There are none anywhere else in the extension.

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
- **`http://127.0.0.1/*`** — talking to your daemon. It is the only host the extension is
  allowed to reach, and there is no optional permission to grant later: it never asks to run
  on the sites you open.

One more manifest entry is worth naming even though it is not a permission. The dashboard is
listed as reachable from `http://<suffix>/` — the page your daemon serves at the root of your
configured suffix, whose only job is to send you to the dashboard. That one origin serves
nothing else. Pages served from a host are a different origin and are refused it, which is the
point of listing one rather than all.

## Removing it

Uninstalling deletes everything in the table above with it. Nothing of yours is left behind
anywhere else, because nothing of yours was written anywhere else.

## Questions

Open an issue at <https://github.com/QAtlasHub/ssh-browser>. For anything that should not be
public, [SECURITY.md](SECURITY.md) says how to reach us privately.
