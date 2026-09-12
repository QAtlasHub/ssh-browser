# ssh-browser

Open files on an SSH host as a real browser origin. No web server on the remote, no domain, no certificate.

## Why not just mount it

Viewing remote HTML is not a file-access problem, it is an origin problem. Under `file://` the origin is
opaque, so ES modules, `fetch`, XHR and service workers all fail — an sshfs mount does not give you a
working page. SFTP file managers preview content but hand the page a sandbox rather than an origin.
`http://127.0.0.1` is a potentially-trustworthy origin by spec, so a local HTTP server needs no
certificate and still unlocks all of it.

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
2. A revisit costs zero remote round trips; conditional GET is answered inside localhost.

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

`http` needs no certificate. `https` does, so it arrives separately and behind a CA
whose `nameConstraints` limit it to the suffix: a leaked key then cannot
impersonate anything else, which is not true of a stock mkcert CA.

## Usage

```
ssh-browser serve docs=myhost:/srv/docs cluster=login-node:/home/me/public_html
```

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

`--port` and `--suffix` change the listener and the hostname suffix. `ssh-browser
pac` prints the script without starting a server.

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

Annotations work through the control API, though nothing draws them yet — that is the
extension's job. They are per-author append-only logs beside the document, so two people
annotating one page write to different files and neither can lose the other's work.

```
curl -H "x-ssh-browser-token: $TOKEN" -X POST   --data '{"doc":"docs/index.html","op":"add","body":"a note"}'   http://127.0.0.1:7391/_control/annotations
```

Not there yet: the extension, collaborative editing of documents themselves.

```
cargo run --bin measure-roundtrips -- <ssh-host> [remote-dir]
```

On Git Bash, prefix commands with `MSYS_NO_PATHCONV=1` or a remote path is rewritten
into a Windows path.

## License

MIT
