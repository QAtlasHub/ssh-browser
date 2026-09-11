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
`403` for traversal including its percent-encoded spelling, `403` for a symlink.

Revisits are free. A listing of the parent directory answers existence, kind,
symlink-ness and the validator, so a second request for the same page is served
without touching the remote, and a browser holding the current copy gets a `304`
decided inside this process. Against a host at 18 ms RTT: 184 ms cold, 1.6 ms warm.

Not there yet: `Range`, a symlinked *directory* higher up a path (the final
component is checked), annotations, collaborative editing.

```
cargo run --bin measure-roundtrips -- <ssh-host> [remote-dir]
```

On Git Bash, prefix commands with `MSYS_NO_PATHCONV=1` or a remote path is rewritten
into a Windows path.

## License

MIT
