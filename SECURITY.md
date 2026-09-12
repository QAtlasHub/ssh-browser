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

## Who a log really belongs to

A log's filename is the only thing naming its author, so the filename is checked against
the file's owner. Two different problems show up in the same place.

The first is a misconfiguration: this daemon is set to write as `souta` while the SSH
account it reaches the host as is somebody else. Every note it writes then carries a name
nobody can support.

The second is a forgery. On a group-writable annotation directory, whoever gets there
first creates the file. If bob creates `alice.jsonl`, he can write records whose ids begin
`alice:` — and those ids are exactly what the merge accepts as alice's. POSIX permissions
are what should prevent this; the check is what notices when they did not.

The owner comes from the `longname` field of a listing, which is the only place SFTP v3
carries an owner's *name*. The numeric `uid` in the attrs cannot answer the question at
all: turning a number into an account name needs a passwd lookup, and the transport never
runs a shell. The parse declines anything that is not clearly a listing line, and a remote
that prints a number where a name should go is reported as unchecked rather than as a
mismatch — reading it as a mismatch would accuse whoever the number belongs to.

Three outcomes, and **"not checked" is kept apart from "checked and fine"**. The check is
worthless if a reader cannot tell those apart, and a daemon talking to a server that
reports owners differently would otherwise look as though it had verified something.

It costs nothing. The owner arrives on the listing a load already performs, so there is no
faster variant of this that works by skipping it.

**This is detection, not prevention.** By the time a mismatch is visible the records are
already written, and nothing here deletes them: hiding somebody's annotations on the
strength of a parsed `ls -l` line would be the worse failure. The mismatch is shown beside
the note, naming both the author the log claims and the account that owns the file.
