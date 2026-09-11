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

**Path resolution is string-only, and the symlink check is partial.** Requests are
percent-decoded and then normalised, so neither `..` nor `%2e%2e` can leave an alias
base. The listing cache also refuses a request whose final component is a symlink,
and it does so without paying a REALPATH per request.

What is still open is a symlinked *directory* higher up a path. In `/a/b.html` the
`b.html` component is checked, but if `/a` is itself a symlink pointing outside the
base, that is not caught. Batched listings make the full walk affordable and it is
the next thing to land here. Until then, treat an alias base whose directories you
do not control as readable in full.

## Credentials

The daemon never handles a key or a passphrase. Its transport is `ssh <host> -s
sftp`, so authentication is entirely OpenSSH's: `ssh_config`, the agent, keys and
certificates. It runs ssh with `BatchMode=yes`, so it cannot prompt and cannot
consume an interactive credential.

## What does not exist yet

There is no write path. Annotations and collaborative editing will add one, and the
scope it is granted will be documented here when they do.
