# ssh-browser

Open files on an SSH host as a real browser origin. No web server on the remote, no domain, no certificate.

## Why not just mount it

Viewing remote HTML is not a file-access problem, it is an origin problem. Under `file://` the origin is
opaque, so ES modules, `fetch` and XHR all fail — an sshfs mount does not give you a working page. SFTP
file managers preview content but hand the page a sandbox rather than an origin. An http origin fixes
all three and needs no certificate.

It does not fix everything, and the limit is worth knowing before you point this at a site — see
[what an http origin does not buy](#what-an-http-origin-does-not-buy).

`rclone serve http :sftp:host:/path` is the closest existing answer. Three gaps:

- It does not read `ssh_config`, so ProxyJump does not work (rclone#6987, rclone#7012). Every host behind
  a jump box is unreachable.
- No `Host` header validation, so a DNS-rebinding site can read the remote through your loopback.
- It fetches a directory listing even to serve a single file (rclone#7880).

ssh-browser borrows the system `ssh` binary as its transport (`ssh <host> -s sftp`). ssh_config,
ProxyJump, non-standard ports, agent keys and certificates therefore work without reimplementation.

## The invariant

Latency targets in milliseconds are meaningless because they move with the network. The claim is about
round trips:

1. Remote round trips for one page are O(1) — independent of subresource count, directory depth and file
   count.
2. A revisit inside the freshness window costs zero remote round trips; the conditional GET is answered
   inside localhost. Outside it, a revisit costs one batched listing refresh and no file reads.

The second used to be written without the window, and that promised something no cache can deliver:
once a listing is not trusted, "is this still the current version?" cannot be answered without asking.
Measured against a real host, a revisit straight after a load costs zero, and the same revisit three
seconds later costs ten — which is the window doing its job, not the cache failing.

`measure-roundtrips` times one round trip (tau) and reports each batch as a multiple of it. Against a
host at roughly 16 ms RTT:

```
tau (one round trip) = 16.2 ms
n=1   open    17.8 ms ( 1.10 tau)   read    26.6 ms ( 1.64 tau)   32768 B
n=8   open    18.2 ms ( 1.12 tau)   read    24.6 ms ( 1.52 tau)   66581 B
n=20  open    14.8 ms ( 0.91 tau)   read    40.5 ms ( 2.50 tau)   201824 B
n=40  open    16.0 ms ( 0.99 tau)   read    30.8 ms ( 1.90 tau)   414707 B

VERDICT pipelined: 1.90 tau at n=40 (serial would cost about 40)
```

Forty opens cost one round trip; serial would cost forty. The reads carry 400 KB, so their extra tau is
bandwidth rather than latency. The same verdict holds across a ProxyJump hop.

That covers the remote. The other half of invariant 1 is the browser, which fetches subresources six at
a time over HTTP/1.1: forty of them is seven waves, and each wave it has to discover is another round
trip. So an HTML page is read for its own `<link>`, `<script>` and `<img>` references, and those are
fetched in one batch before the page is answered. A page with forty subresources costs **87 remote round
trips without that and 0 with it** — measured by serving every subresource one at a time, which is the
worst case any browser can produce.

Those reads go through the ranged path rather than the polling one, because a listing already says how
long each subresource is. Without that a file is read in 32 KB chunks until a short read arrives, which
is a round trip per chunk: against a host at roughly 40 ms, 400 KB read that way takes **571 ms**, while
the same 400 KB fetched as part of the page's own prefetch batch leaves the whole page — script
included — at **368 ms**.

A page is untrusted input, so a reference is resolved and symlink-checked exactly as a real request is,
by the same code rather than a second copy of the rule. The scan itself is a heuristic and can only ever
affect speed: a reference it misses is fetched normally, and one it invents is a read that fails and is
dropped.

## URLs

```
https://<alias>.ssh-browser/<path>
```

The alias, the suffix and the scheme are all configurable. A PAC routes by hostname
and never resolves it, so the suffix does not have to be a real TLD and **no DNS
server or hosts-file entry is needed**. It also leaves the address bar alone,
unlike a `declarativeNetRequest` redirect, which rewrites the URL to `127.0.0.1`
and throws away the origin you asked for.

`http` needs no certificate and is the default. `https` needs one, and the point of it is the
row below that `http` cannot have: an https alias origin is a **secure context**, so service
workers, `crypto.subtle` and `CacheStorage` all work there.

```
ssh-browser trust                        # prints the command; runs nothing
ssh-browser serve --scheme https ...
```

The certificate comes from an authority this daemon generates, carrying `nameConstraints` with
one permitted subtree — the suffix. **If its key leaks it can vouch for `*.ssh-browser` and
nothing else**, which is not true of a stock mkcert CA. It also carries `pathLenConstraint: 0`,
so it cannot sign a second authority, and a `keyUsage` that cannot serve TLS itself.

Measured rather than argued, because a name constraint is worth what the verifier reading it
does with it:

|                                  | `openssl verify`             | Chromium                     |
| -------------------------------- | ---------------------------- | ---------------------------- |
| a name under the suffix          | `OK`                         | loads, `isSecureContext`     |
| `evil.example`, same authority   | `permitted subtree violation` | `net::ERR_CERT_INVALID`     |

Remove the constraint and the same certificate verifies `OK` — that is the mkcert situation.

`ssh-browser trust` prints the install command for your platform and stops. **Nothing here puts
anything in a trust store**: that changes how the whole machine treats the internet, is not undone
by uninstalling this, and is not a decision a background process should make. The command to
remove it again is printed beside the one that installs it.

Firefox and Safari are unmeasured. Firefox keeps its own store and does not read the system one.

## What an http origin does not buy

This is the argument for `--scheme https`, and it is why that exists.

An alias origin over plain http is on a name that is not loopback, so it is not a potentially
trustworthy origin and the secure-context APIs are simply not there. Measured, all three ways:

|                    | `http://alias.ssh-browser` | `http://127.0.0.1:7391` | `https://alias.ssh-browser` |
| ------------------ | -------------------------- | ----------------------- | --------------------------- |
| `isSecureContext`  | no                         | yes                     | **yes**                     |
| service workers    | absent                     | present                 | **present**                 |
| `crypto.subtle`    | absent                     | present                 | **present**                 |
| `caches`           | absent                     | present                 | **present**                 |
| IndexedDB          | present                    | present                 | present                     |
| one origin per host| yes                        | **no**                  | **yes**                     |

The first two columns trade against each other. http aliases give origin separation:
`a.ssh-browser` cannot read `b.ssh-browser`. The loopback fallback is a secure context, because
127.0.0.1 is potentially trustworthy by spec — but it puts every alias in one origin, so any page
on one host can read every other.

**`https` is the column with both**, and needs one manual step: trusting the constrained authority
once. See [URLs](#urls).

`http` is still the default, because a default that silently required a trusted root would fail for
everybody who had not done it, and fail at the TLS layer where the reason is least visible. A page
that only wants ES modules, `fetch`, XHR, `localStorage` or IndexedDB does not need any of this —
that is most of them, and all of what `file://` breaks.

## Usage

```
cargo install ssh-browser
ssh-browser serve docs=myhost:/srv/docs cluster=login-node
```

A host on its own means that account's home directory, which the daemon asks the remote
for. `ssh-browser hosts` prints what your `~/.ssh/config` already knows how to reach —
user, hostname, port and any `ProxyJump` — which is the list worth picking an alias from.

That listens on 127.0.0.1:7391 and prints what to do next. Point the browser at the
PAC the daemon serves,

```
chrome --proxy-pac-url=http://127.0.0.1:7391/proxy.pac
```

then open `http://docs.ssh-browser/`. Each alias is its own origin, so a page under
one alias cannot fetch from another.

Without touching proxy settings at all, `http://127.0.0.1:7391/docs/` serves the
same tree. That is useful for a quick look, but it puts every alias in one origin,
so prefer the PAC.

`ssh-browser serve` with no aliases at all is fine: the extension opens a host when you
pick one, and `POST /_control/open` is what it calls. Only a host named in your ssh_config
can be opened — the list is the menu, and anything else is a config change.

A host you use every day does not have to be picked every time. Turning one on in the
dashboard opens it now *and* every run after this one, so its URL simply works:

```toml
[[host]]
name = "login-node"
base = "~/public_html"
```

Only the name. Which account, which port, which jump host — that is already in your
`~/.ssh/config`, and copying any of it here would mean two answers to one question.
Enabled hosts are connected at startup, all at once, and one that does not answer is
reported rather than fatal: a laptop on the wrong network has half of them unreachable,
and refusing to start then would be refusing exactly when it is wanted.

**Enabled means open, not "opens on demand".** Connecting when a request for an unopened
host arrives would be nicer to describe and much worse to have: every request to an alias
origin arrives through the proxy, so any web page could start ssh sessions by naming a host
in an `<img src>`, and time the answer to learn which hosts you have. The header that would
separate a navigation from a subresource is not available — **Chromium sends no
`Sec-Fetch-*` at all on a proxied request**, measured against a real browser. So a session
is opened by the daemon at startup or by a control call carrying the token, and by nothing
else.

`--port` and `--suffix` change the listener and the hostname suffix. `ssh-browser
pac` prints the script without starting a server.

### A config file, for more than one host

```toml
[server]
port = 7391
suffix = "ssh-browser"

[[alias]]
name = "docs"
host = "myhost"
base = "/srv/docs"

[[alias]]
name = "cluster"
host = "login-node"
base = "~/public_html"

[[alias]]
name = "home"
host = "login-node"
```

`base` may be an absolute path, or `~` and a path under the remote's home directory, or
omitted for the home directory itself. The tilde is resolved by asking the remote, once,
at startup: it is shell syntax and this transport never runs a shell, so expanding it
locally would produce *your* home directory rather than the account's.

Pointing an alias at a home directory is reasonable because **no name beginning with a dot
is ever served**, at any depth, and they are left out of listings. An alias base is one
origin, so a page under it can read everything else under it — see
[SECURITY.md](SECURITY.md).

`--config FILE`, or `<config dir>/ssh-browser/config.toml` if it exists. A file named on
the command line must exist; the default one need not.

The command line wins over the file, and aliases given on the command line are **added**
to the file's rather than replacing them — naming one host should not silently drop the
others. A name defined in both places is an error, not a precedence.

**Unknown keys are refused.** A `suffixx = "dev"` that got quietly dropped would leave the
daemon running on a suffix nobody chose and looking exactly like one that was configured;
instead the error names the key, the line, and what was expected. `scheme = "https"` is
refused too, for the same reason: that mode is designed and not built, and serving http to
a file that asked for https is the one outcome that looks like success.

### The extension

Clicking the toolbar icon opens a dashboard. It lists the sites being served — each with
its URL and where on the remote it is rooted — and under them the hosts your `~/.ssh/config`
can reach, with what `ssh -G` resolved for each.

Clicking a host serves it. Clicking a site opens that site's own page, which is where the
per-site things are: its URL, the host and root it comes from, a box to change the root, and
a button to stop serving it.

There is nothing to paste. The extension asks the daemon for its control token, and the
daemon hands that to anything except a page — see [SECURITY.md](SECURITY.md).

### What a directory looks like

An editor's explorer. The whole path is expanded at once with the rest of every level
beside it, folders have a twisty, each level has an indent guide, and the type is a coloured
chip. Size and modification time on each entry; times are UTC, because SFTP reports seconds
since the epoch and says nothing about a zone, and using this machine's would stamp a file
with an offset belonging to a different computer.

Expanding a folder fetches one level and puts it in place. But every row is a real link to a
real URL, so a browser with no script at all walks the tree one directory at a time — the
script is an enhancement, not the mechanism. Showing the ancestors costs nothing: the walk
that resolved the path already fetched them to check for symlinks.

Directories come first. Within each half the thing you came to open rises: a directory
holding an `index.html` is served as that page, so it leads the directories and is marked as
a **site** — otherwise a board at `out/ft_demo/index.html` never appears at all, since the
directory you are standing in has no HTML in it. An HTML file leads the files for the same
reason.

The palette is a **[base16] scheme**, chosen in the dashboard's settings and applied by the
daemon, so every site it serves looks the same in every browser pointed at it. Seventeen are
vendored, in light and dark pairs — Default, GitHub, Catppuccin, Gruvbox, Solarized, Rosé
Pine, One, plus Nord, Tokyo Night and Dracula — and `auto` follows your system with base16's
own reference pair.

base16 rather than something invented here because it is the standard for exactly this: a
spec, several hundred schemes behind it, and sixteen hex values per file. Adding one is
dropping a `.yaml` into `crates/ssh-browser/themes/` and adding a line, since every rule in
the listing is written against the properties built from those sixteen. What each slot
becomes is written out in [themes/README.md](crates/ssh-browser/themes/README.md).

`[server] theme` sets the starting one; a later choice is remembered beside the control token
rather than written back into your config file.

[base16]: https://github.com/tinted-theming/home/blob/main/styling.md

Finding those costs one extra round trip per listing. It is spent on a directory view and
never on a page load, and it is one batch however many subdirectories there are. The listings
it fetches are the ones the next click needs, so stepping into any of them is free
afterwards: measured on a host 18 ms away, a cold listing of 17 subdirectories is 92 ms and a
revisit is 1 ms.


`extension/` builds with `npm ci && npm run build` and loads unpacked from
`extension/dist`. Give it the port and the control token the daemon printed; it applies
the PAC itself, so `--proxy-pac-url` is not needed as well.

To use it day to day, in Brave or Chrome: turn on Developer mode in `brave://extensions`,
Load unpacked, and point it at `extension/dist`. It stays across restarts. Start the daemon,
click the toolbar icon, paste the port and token, and accept the permission prompt — it asks
for `http://*.<your suffix>/*` and nothing wider.

**That is a one-time paste.** The token is kept in the runtime directory and reused, so a
daemon that comes back is the same daemon as far as the browser is concerned; the banner says
`unchanged since last time` when that is what happened. `--new-token` rotates it, which is
what to reach for if it leaked — and then the extension needs the new one.

The permission prompt is the one step nothing here can test, because a permission bubble is
browser chrome rather than page content. Everything after it is covered.

The control token lives in the service worker and nowhere else. A page served from an
alias origin is untrusted code, so content scripts ask the worker to act for them rather
than being handed the token.

In the address bar, `ssh` then Tab takes an alias and a path — `ssh docs/notes.html`.
Suggestions come from the aliases the daemon reports.

`npm run package` writes the zip a store upload wants. It is reproducible — rebuild from the
same commit and the bytes match — so the upload can be checked against the source rather than
taken on faith. What the listing needs is written out in [extension/STORE.md](extension/STORE.md),
and what the extension does with data is in [PRIVACY.md](PRIVACY.md): it sends nothing anywhere
but `127.0.0.1`, and from there to the host you already had an account on.

## Status

Early, but usable for reading. Verified against a real host through a jump box:
directory listings, `index.html`, MIME types correct enough that ES modules execute,
`301` for a directory missing its trailing slash, `403` for a rebinding `Host`,
`403` for traversal including its percent-encoded spelling, `403` for a symlink at
any component of the path.

Revisits are free. A listing of the parent directory answers existence, kind,
symlink-ness and the validator, so a second request for the same page is served
without touching the remote, and a browser holding the current copy gets a `304`
decided inside this process. Against a host at 18 ms RTT: 184 ms cold, 1.6 ms warm.

Ranges work, so video and PDF seek. A file over 8 MB is served by range and not
cached, so a seek does not pull the whole file and does not evict the page bodies that
make revisits free. `If-Range` is never honoured, because the only validator on offer
is weak and the whole representation is the specified answer to that.

**Nothing is written to your remote.** Not restricted, absent: the SFTP requests this can
issue are `OPEN`, `CLOSE`, `READ`, `OPENDIR`, `READDIR` and `REALPATH`, and the only open
flag it defines is `FXF_READ`. Nothing is injected into a page either — the extension has no
content script, so what you see is the site, unchanged.

There used to be an annotation feature here, writing per-author logs into a sidecar
directory. It is gone. A site that wants notes should have notes built into it; this is for
seeing that site work.

### Verified in a browser

`e2e/` opens the same bytes twice — once through the daemon and once over `file://` — and
the difference is the whole reason this exists.

| | through the daemon | over `file://` |
|---|---|---|
| origin | `http://e2e.ssh-browser` | `file://` |
| ES module with a relative import | runs | **does not run** |
| `fetch` of a relative path | succeeds | **refused** |
| stylesheet | applies | applies |
| image | decodes | decodes |

The last two rows are the point: this is about **origin**, not about whether files can be
read. A stylesheet and an image load fine from `file://`. Scripts and `fetch` are what
break, and those are what a modern page is built out of.

It runs in CI against a local `sshd` and can be pointed at a real host with
`SSH_BROWSER_E2E_HOST` and `SSH_BROWSER_E2E_BASE`, and at a browser you actually use with
`SSH_BROWSER_E2E_BROWSER` — which then runs visibly, because the reason to point it at your own
Brave is to watch it. It always uses a throwaway profile: loading an unpacked extension and
repointing the proxy are not things to do to the browser you keep your life in.

Verified that way against Brave 152 and against a real host, extension included. Run against one, it caught the daemon
announcing `listening on 127.0.0.1:PORT` before it had taken the port.

The extension is in the harness too, loaded unpacked into the same browser. The dashboard
connects and lists what is served, clicking a site opens its page, and clicking through to the
site lands on the alias origin with the remote's own index page.

The harness covers, in one run: the PAC's routing decisions; the refusals (`403` for a
rebinding `Host`, `403` for percent-encoded traversal, `405` for writing to an alias origin,
`401` without a control token, `405` for a preflight, and no CORS headers anywhere); serving
(weak validator, `304` on revisit, directory listing, `301` for a missing trailing slash,
`206` for a byte range); the browser comparison above; what an alias origin does and does not
get, against the loopback fallback in the same run; and the extension.

There is no permission prompt to leave uncovered: the extension asks for `http://127.0.0.1/*`
at install and nothing else, ever.

```
cargo run --example measure-roundtrips -- <ssh-host> [remote-dir]
```

On Git Bash, prefix commands with `MSYS_NO_PATHCONV=1` or a remote path is rewritten
into a Windows path.

## License

MIT
