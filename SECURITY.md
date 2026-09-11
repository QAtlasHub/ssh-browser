# Security

## Reporting a vulnerability

Use [private vulnerability reporting](https://github.com/QAtlasHub/ssh-browser/security/advisories/new).
Please do not open a public issue for a vulnerability.

## What this tool exposes

The daemon puts files from a remote host behind a local HTTP origin. Three
consequences are worth knowing before pointing it at anything.

**A remote page is untrusted code running in an origin you granted it.** Anything
served under `<alias>.<suffix>` can fetch anything else under the same alias. Scope
each alias to the smallest base path that is useful. Do not point one at `/`, or at a
home directory you would not hand to a web page.

**The listener refuses requests by `Host`, and that check is load-bearing.** Binding
to `127.0.0.1` does not stop a site that resolves its own name to loopback; only
refusing its `Host` does. Requests are accepted for `<alias>.<suffix>` and for this
listener's own address and port, and for nothing else. If you touch that code, keep
the check.

**Paths are resolved as strings, and symlinks are refused rather than followed.**
Requests are percent-decoded and then normalised, so neither `..` nor `%2e%2e` can
leave an alias base. Every component of the path is then checked against its parent's
listing, and any component that is a symlink is refused -- not only the last one.
Reaching a real file *through* a symlinked directory is therefore refused too.

Nothing is followed and nothing is resolved: a symlink's target is never examined,
because examining it would need a REALPATH per request and that breaks the
round-trip invariant the project is built on. The consequence, stated plainly, is
that a symlink pointing *inside* the base is refused along with one pointing
outside. That is a deliberate trade of capability for a check that cannot be wrong.

## Credentials

The daemon never handles a key or a passphrase. Its transport is `ssh <host> -s
sftp`, so authentication is entirely OpenSSH's: `ssh_config`, the agent, keys and
certificates. It runs ssh with `BatchMode=yes`, so it cannot prompt and cannot
consume an interactive credential.

## The control API

Writes will go through a control API. It exists now, even though nothing writes yet,
because the boundary is easier to get right before there is something behind it than
after. Three things keep it away from the pages this daemon serves.

**It is routed only for requests whose Host is the loopback listener.** That is a
different classification from an alias request, so a page served under an alias origin
cannot reach it however the path is spelled -- it gets a file lookup and a 404.

**It requires a token in a custom header.** A custom header is not CORS-safelisted, so a
page attempting to send one triggers a preflight.

**It refuses the preflight and emits no CORS headers at all.** A refused preflight means
the request is never made, and no CORS headers means a response could not be read even if
one somehow were. An extension is outside CORS by virtue of its host permissions, so none
of this impedes it.

The read side is read-only in the ordinary HTTP sense too: anything other than `GET` or
`HEAD` on an alias origin is a `405`, rather than being quietly served as a `GET`.

The token is 32 bytes of OS entropy, compared in constant time, and written to a file
under your runtime or configuration directory with mode `0600` on Unix. Any process
running as you can read that file. That is the limit of what a loopback listener can
promise, and no arrangement of headers changes it.

## What the control API writes

Exactly one shape of path:

```
<dir>/.ssh-browser/<filename>/ann/<author>.jsonl
```

Nothing else. The path is computed from the document rather than taken from the request,
so a caller cannot name a destination at all. The document is resolved through the same
guards the read path uses — normalised after percent-decoding, and refused if any
component is a symlink — and the symlink rule matters more here than on the read side,
because a write that reached through a symlinked directory could place a file outside the
alias base entirely.

**The author is this daemon's configuration, not the request's.** A caller cannot write as
somebody else however it words the request. The id of a new annotation is minted by the
daemon and carries the author within it, and the timestamp is the daemon's clock: a caller
able to choose either could name someone else or reorder their log.

Writes are appends. A log has exactly one writer by construction, which is the only
arrangement that is safe without a lock, and it is why the format is per-author logs
rather than one shared file.

What is **not** checked yet: that the configured author is the remote account actually
doing the writing. The SFTP transport never runs a shell, so the remote account name is
not something this process can ask for, and inferring it from a home directory path would
be a guess presented as a fact. A later version will compare it against the uid a listing
reports; until then it is the operator's word.
