# Changelog

All notable changes to ssh-browser will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet: the version in `Cargo.toml` is `0.0.1` and no surface is
stable.

## [Unreleased]

### Added

- SFTP transport over `ssh <host> -s sftp`, so ssh_config, ProxyJump,
  non-standard ports, agent keys and certificates all work without
  reimplementation.
- A batch-first `RemoteFs` and a demultiplexing SFTP backend: any number of
  concurrent callers share one stream and their requests coalesce into one flush.
- `measure-roundtrips`, which times one round trip and reports each batch as a
  multiple of it, failing on a serial verdict.
- An HTTP origin at `http://<alias>.<suffix>/`, reached through a PAC the daemon
  serves itself. Host validation, traversal guard, MIME types, `index.html`,
  directory listings, and a `301` for a directory missing its trailing slash.
- Development environment ported from doiget: CI with SHA-pinned actions,
  `cargo deny` / `cargo audit`, CodeQL, coverage, typos, MSRV drift, sign-off
  enforcement, issue and PR templates.
- A listing cache and a body cache, which together make a revisit cost no remote
  round trips and let a conditional `GET` be answered inside the process. 184 ms
  cold, 1.6 ms warm against a host at 18 ms RTT.
- `RemoteFs::list_dirs`, the batch form of a listing, with `list_dir` defined as its
  n=1 case.
- Which selector placed a note is kept rather than discarded. A note the quote could not place
  but the position could is shown as drifted: the text it was written about is gone, and it is
  now sitting on whatever occupies those character offsets. On a page of computed results that
  is the common case, because the numbers people annotate are the numbers that change.
- An omnibox keyword: `ssh` then Tab, then an alias and a path, with suggestions from the
  aliases the daemon reports. It adds no permission — `chrome.omnibox` needs only its manifest
  key, and setting a tab's URL does not require `tabs`.
- An HTML page is read for its own `<link>`, `<script>` and `<img>` references, and those are
  fetched in one batch before the page is answered. This is the browser half of invariant 1:
  HTTP/1.1 allows six connections per origin, so forty subresources are seven waves of
  requests and each wave is a round trip. Measured by serving every subresource one at a
  time — the worst case any browser can produce — a forty-subresource page costs 87 remote
  round trips without this and 0 with it.
- A page is untrusted input, so a scanned reference is resolved and symlink-checked by the
  same code a real request uses. Symlinks are settled against listings already held before
  anything new is listed, so naming one on a page cannot get the directory it points at
  listed. The scan is capped at 64 references per document.
- An annotation log's filename is checked against the file's owner, which catches both a
  daemon configured to write as an account it does not actually reach the host as, and a
  forged log created by somebody else on a group-writable directory. The owner comes from a
  listing's `longname`, the only place SFTP v3 carries an owner's name; the numeric `uid`
  cannot answer this without a passwd lookup the transport cannot perform.
- "Not checked" is reported separately from "checked and fine", so a remote that reports
  owners in an unfamiliar shape never reads as verification. The check rides the listing a
  load already performs, so it costs no extra round trips — pinned by a test that compares
  the cost with and without an owner rather than against a fixed number.
- The panel names a mismatch beside the note: the author the log claims, and the account that
  owns the file. Records are never hidden on the strength of a parsed `ls -l` line.
- The extension draws annotations. Anchoring uses Apache Annotator with two selectors per
  note — a quote and a position — tried in that order, because they fail in different ways and
  neither is reliable alone. A note that cannot be placed is shown as unanchored rather than
  dropped.
- Highlights use the CSS Custom Highlight API and the panel lives in a closed shadow root, so
  the document the reader came for is never modified. That also sidesteps Apache Annotator's
  warning that editing the DOM mid-search can loop forever.
- The content script is registered at runtime for the configured suffix only, so the extension
  never holds permission for every http site. The permission is requested from the popup,
  where there is a user gesture to attach it to.
- `@apache-annotator/selector` is a direct dependency because `@apache-annotator/dom` imports
  types from it without declaring it, which leaves `Matcher` resolving to `{}`.
- A browser extension, so far just enough to connect: it holds the control token, asks the
  daemon for its PAC rather than generating one, and negotiates the protocol version. The
  token lives in the service worker and nowhere else — content scripts will ask the worker
  to act for them rather than being handed it.
- `hello` reports the configured suffix, so the extension can build an alias URL without
  being told it separately. Additive, so the protocol range stays 1..=1.
- `GET` and `POST /_control/annotations`, which is the first write path in the product.
  The author is the daemon's configuration rather than the request's, the id of a new
  annotation is minted by the daemon, and the timestamp is the daemon's clock — a caller
  able to choose any of the three could write as somebody else or reorder their log.
  `--author NAME` sets it, defaulting to the local account name.
- The symlink walk is now shared between the read and write paths, so the two cannot drift
  apart. A write reaching through a symlinked directory could place a file outside the
  alias base, which is worse than reading through one.
- Annotations as per-author append-only logs, at
  `<dir>/.ssh-browser/<file>/ann/<author>.jsonl`. Merging is a set union of lines, so it is
  commutative, idempotent and needs no lock; an id carries its author, so a log touching
  someone else's record is ignored rather than obeyed. Nothing calls this yet — the control
  route comes next.
- `RemoteFs::append` and `RemoteFs::mkdirs`, the first writes in the codebase. Append
  rather than write, because a log has exactly one writer by construction and that is the
  only arrangement safe without a lock.
- A control API on the loopback path, with a 32-byte token compared in constant time,
  protocol version negotiation, and no CORS participation at all. Nothing writes through
  it yet; it exists so the boundary is settled before there is something behind it.
- The alias origin answers anything other than `GET` or `HEAD` with a `405`, rather than
  serving a write as though it were a read.
- `Range` requests, so video and PDF can seek. A file over 8 MB is fetched by range
  and not cached; anything smaller is fetched whole, held, and sliced. `If-Range` is
  never honoured because the only validator offered is weak, and a multi-range request
  is answered whole rather than as `multipart/byteranges`.
- `RemoteFs::read_ranges`, which chunks and issues a whole set of ranges together, so
  a one-megabyte range costs one round trip rather than the thirty-two its chunks
  would suggest.
- Symlinks are refused rather than followed, at every component of a path rather
  than only the last, so reaching a file through a symlinked directory is refused
  too. Decided from batched ancestor listings, so a path of depth d costs one round
  trip rather than d: measured at 6 round trips for depth 4 against 5 for depth 1.

### Fixed

- A directory read came back as an empty `200`. SFTP `OPEN` succeeds on a
  directory and `READ` then fails, and every `STATUS` was being treated as EOF.
- The same fault in `readdir`: any `STATUS` ended the listing, so a directory we
  were refused read as an empty directory.
- The `roundtrips` verdict judged reads as well as opens. A read carries the file, so
  under injected per-packet latency it reported transfer time as round trips, and the
  gate failed on how much data the chosen directory happened to hold.
