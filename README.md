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

## Status

Early. The SFTP transport and the measurement harness exist. The HTTP origin layer does not yet.

```
cargo run --bin measure-roundtrips -- <ssh-host> [remote-dir]
```

On Git Bash, prefix with `MSYS_NO_PATHCONV=1` or the remote path is rewritten into a Windows path.

## License

MIT OR Apache-2.0
