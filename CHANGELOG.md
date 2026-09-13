# Changelog

All notable changes to ssh-browser will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The two halves ship through different channels, and only one of them has shipped. The daemon
is on crates.io as [`ssh-browser`](https://crates.io/crates/ssh-browser); the extension goes
through a browser store and has not been submitted. No surface is stable.

## [Unreleased]

### Added

- Releases are cut by `release-plz`. It opens a pull request on `main` that bumps the
  version; merging it publishes to crates.io, tags, and creates the GitHub release, and
  `release-assets.yml` attaches the extension zip and its SHA256 to that same release. One
  tag ships both halves, and CI refuses a version where `Cargo.toml` and the extension's
  `manifest.json` disagree.
  crates.io Trusted Publishing rather than a stored token: `release-plz` exchanges GitHub's
  OIDC identity for one that lives thirty minutes, so there is no `CARGO_REGISTRY_TOKEN` in
  the repository to leak or rotate. It needs a trusted publisher registered once on
  crates.io. The changelog stays hand-written — `changelog_update = false` — so cutting a
  release means renaming `## [Unreleased]` in the release pull request. See CONTRIBUTING.md.

- `base` may be omitted, or written as `~` or `~/path`, and means the remote account's
  home directory. Resolved by asking the remote with SFTP `REALPATH` once at startup,
  because `~` is shell syntax and this transport never runs a shell — expanding it
  locally would produce the wrong machine's home directory. An absolute base still costs
  no round trip.
- `ssh-browser hosts` lists what `~/.ssh/config` already knows how to reach, with the
  user, hostname, port and `ProxyJump` that `ssh -G` resolves for each. `Include` is
  followed; patterns like `Host *` are not hosts and are skipped; a name that cannot be a
  hostname label is reported rather than silently dropped.
- The extension opens a dashboard rather than a popup. It lists the sites being served,
  each with its URL and the host and root it comes from, and under them the hosts your
  ssh_config could reach with what `ssh -G` resolved for each. Clicking a host serves it;
  clicking a site opens that site's own page, where its root can be changed and it can be
  stopped. The framing is deployment because that is what the product is: a directory only
  reachable over ssh, made to look like a site on a host without being deployed to one.
- A directory is an editor's explorer rather than a listing. The whole path is expanded at
  once with the rest of every level beside it, folders have a twisty, each level has an
  indent guide, and the type is a coloured chip. Directories come first; within each half
  the thing you came to open rises, so a site leads the directories and an HTML file leads
  the files.
  Expanding a folder fetches one level and puts it in place — `?ls` on a directory returns
  that level as the HTML fragment that goes inside it, so there is exactly one thing that
  knows how a row is written rather than a second renderer in the page's script. It adds no
  capability: a page under an alias can already read every path under it.
  Every row is a real link, so a browser with no script walks the tree one directory at a
  time exactly as before. Showing the ancestors costs nothing: the walk that resolved the
  path already fetched them to check for symlinks.
- **Themes are base16 schemes**, vendored from `tinted-theming/schemes` under its MIT
  licence, with the mapping from base16's sixteen slots to this listing's custom properties
  written out in `crates/ssh-browser/themes/README.md`. Seventeen to start, in light and
  dark pairs: Default, GitHub, Catppuccin, Gruvbox, Solarized, Rosé Pine, One, plus Nord,
  Tokyo Night and Dracula. `auto` follows the system with base16's own reference pair.
  Adding a scheme is dropping a file in and adding a line — the stylesheet is written
  entirely against the properties, so a palette is never a second copy of the layout.
  `[server] theme` sets the starting one; `GET`/`POST /_control/theme` reads and changes it
  while the daemon runs, and a change is remembered beside the control token rather than
  written back into the hand-written config file.
- The dashboard has a settings screen: the theme, and which port the daemon is on. Reachable
  from every screen, including the one that says nothing is listening — the port lives there,
  so hiding the link when the daemon is unreachable locked out exactly the reader who needed
  it. Found by the e2e run.
- Directory listings were laid out rather than bulleted: breadcrumbs for every level, a type
  label, size and modification time per entry, and a dark mode. Sizes are binary multiples
  with the labels that mean them (`KiB`), and times are UTC because the remote's zone is not
  something this transport can ask for.
- **HTML comes first in a listing**, in a `pages` section above the folders and files. A
  directory holding an `index.html` is served *as* that page, so it is listed as a site and
  sorted with the pages: without that, a generated board at `out/ft_demo/index.html` never
  appears, because the directory you are standing in has no HTML in it at all.
  Finding them costs one extra round trip per listing, spent on a directory view and never
  on a page load, and bounded to one batch however many subdirectories there are. It is not
  purely a cost either: the listings it fetches are the ones the next click needs, so
  stepping into any of them afterwards is free.
- `POST /_control/close` stops serving an alias. It is also how a root gets changed: the
  daemon refuses to reopen under a second base while the first is live, so closing first is
  what makes that an act somebody chose rather than one that happened to them.
- **Nothing to paste.** `GET /_control/token` hands the token over, and the whole control
  API now refuses any request a browser says came from a page. `Sec-Fetch-Site` is a
  forbidden header name, so page script can neither set it nor remove it; the values were
  measured rather than assumed. This is stronger than the token alone was: a page holding a
  leaked token, or a same-origin page in the no-proxy fallback mode, could previously have
  used the API and now cannot reach it.
- `GET /_control/hosts` also reports the aliases open right now. An alias need not be named
  after its host, so one opened as `docs=myhost:/srv` matches no row in ssh_config and would
  otherwise be served and visible nowhere.
- `POST /_control/open` starts serving one of those hosts, so a host can be opened by
  picking it rather than by configuring it first. Only a host named in ssh_config can be
  opened: "ssh to an arbitrary host on request" is a larger primitive than this needs, and
  the list is already the menu. Asking twice for the same base is an answer rather than an
  error; asking for a different one is a 409, because reconnecting under it would change
  what an origin means underneath any page open in it.
- `serve` now starts with no aliases at all, which is the ordinary case once hosts are
  opened on demand.
- `GET /_control/hosts` answers the same list, plus whether this daemon is currently
  serving each one. Answering it connects to nothing.

- Names beginning with a dot are never served, at any depth, and do not appear in listings.
  An alias base is one origin, so a page under it can read everything else under it — the base
  is the blast radius, and on a home directory nearly everything worth stealing is behind a
  dot. Refusing them is what makes pointing an alias at a home directory reasonable at all.
  The prefetcher applies the same rule, so a page cannot get `.ssh` read by naming it in an
  `<img src>`.

### Fixed

- A path could 404 with "cannot list" naming a directory that plainly existed. The walk
  asked the cache whether a listing was there and then asked it for the listing, which is
  two questions with a gap between them, and the listing cache expires after two seconds —
  a request landing on the boundary got yes and then no. The listings are taken once and
  held for the request now, so the gap is gone rather than narrowed. It showed up as about
  one e2e run in six; a unit test with a zero-length TTL reproduces it every time.
- A directory the remote refuses now answers with ssh's own reason and a `502` rather than
  a `404` saying "cannot list", which was this daemon reporting that it did not know. A
  component that is simply absent is still a plain `404`: absence is not a failure, and
  blaming the remote for a path somebody typed wrong helps nobody.

- The control token is reused across daemon restarts instead of being regenerated every time.
  It was already written to disk, so minting a new one each run took the risk of keeping it
  there and threw away the only thing that risk buys — and it meant pasting sixty-four
  characters into the extension every time the daemon came back, which made daily use of the
  browser half impractical. `--new-token` rotates it deliberately, and the banner says which of
  the two happened rather than leaving a reader to compare hex by eye.
- A token file holding something that is not a token is replaced rather than trusted. Accepting
  one would have produced a daemon nothing could authenticate against: a locked door with no
  key, visible only as a 401 on every request.

## [0.0.1] - 2026-09-13

Published to reserve the name, which also makes it the first version anyone can install.
Everything below is in it except the extension, which is not part of the crate: the published
archive holds `src/`, one example and the README, and nothing from `extension/`.

### Added

- The extension has icons, drawn by a script rather than checked in as four blobs nobody can
  edit. The mark is a shell prompt, because at sixteen pixels one idea is all that survives.
  Re-running produces byte-identical files, so regenerating them puts nothing in a diff.
- `npm --prefix extension run package` writes the zip a Chrome Web Store upload wants. The ZIP
  is written by hand from `zlib` rather than by a dependency: this half ships to a store, and
  every tool in its chain is one more thing a reviewer has to take on trust. Entries are
  sorted and timestamps fixed, so the artifact is reproducible and can be checked against the
  source instead of believed.
- `PRIVACY.md`, which the store requires as a URL, and `extension/STORE.md`, which is every
  field of the submission form written out where it can be reviewed rather than typed into a
  textarea. The data disclosure names what is genuinely handled — the control token, page text
  read for anchoring, and the notes themselves — and says in each case that the destination is
  the reader's own machine.
- `npm --prefix e2e run shots` photographs the product for that listing, through the same
  harness the checks use, so a screenshot cannot show a version that never passed.
- `measure-roundtrips` is an example rather than a binary. `cargo install` puts every `[[bin]]`
  on the reader's PATH, and a command by that name means nothing outside this project and
  could collide with anything. It is also, literally, a program that uses this library.
- Crate metadata for publishing: a readme, keywords and categories.
- Prefetched subresources are read by range rather than by polling, since the listing already
  says how long each one is. `read_batch` cannot know a length, so it asks in 32 KB chunks
  until a short read arrives — a round trip per chunk, which made a one-megabyte bundle
  thirty-two of them. Against a host at roughly 40 ms RTT, 400 KB read that way takes 571 ms,
  while the same file fetched in the page's own prefetch batch leaves the whole page at 368 ms.
- A subresource the listing calls empty is no longer prefetched. A ranged read asks for exactly
  what it was told, so a listing that understates a length would have cached a short body and
  served it — the empty `200` this project forbids, arriving through a new door. Nothing is
  lost: there is nothing to warm at zero bytes.
- Tests for three things nothing exercised: that a large subresource costs what a small one
  costs, that an oversized one is skipped rather than pulled across and discarded, and that
  `Origin::bind` takes the port before it connects any host — the last checkable without any
  ssh infrastructure, because the port failing first is exactly why the host is never reached.
- The command line and the configuration file are merged by a function rather than inside
  `main`, so the precedence can be tested. It is three `or`s and an `extend`, any one of which
  could be turned around without a single test noticing, and the result decides which host a
  URL reaches.
- The e2e harness covers the product rather than one claim of it: the PAC's routing decisions,
  every refusal `SECURITY.md` promises, conditional `GET`, ranges, directory listings and the
  trailing-slash redirect, and — for the first time — the extension itself, loaded unpacked
  into the same browser. A note written through the control API is fetched and anchored by the
  content script on a filename with a space in it, which is the exact shape of the read/write
  disagreement fixed above. It also asserts that no `<style>` element appears in the document,
  since never modifying the page is a claim and not a preference.
- The extension half runs under `channel: "chromium"`, because an MV3 service worker does not
  start in the old headless mode at all — the harness would have had nothing to talk to and no
  way to say so.

### Fixed

- A listing that failed for any reason other than absence came back as "no annotations".
  Every refusal — a dropped session, a permission problem — was folded into the same empty
  answer as the ordinary case of a document nobody has annotated, hiding whatever anybody had
  written, mismatch warnings included, behind a page that looked perfectly normal. The wire
  layer now decodes the SFTP status instead of discarding it, and only `SSH_FX_NO_SUCH_FILE`
  reads as absence.
- `Alias::new` accepted a name `guard::classify` then refused on every request. `-docs` passed
  the constructor's copy of the rule, so the daemon connected over ssh, printed the route and
  advertised a link that answered 403. It calls `guard::is_label` now, which is the rule
  requests are actually held to.
- `Origin::bind` silently dropped an alias whose name was already taken, because
  `HashMap::insert`'s return value went unread. The check is now where the map is built, so it
  cannot be skipped by a caller that forgets the earlier one.
- A numeric author matching an unresolved uid read as verified. `attribution` compared names
  before noticing the owner was a number, so `author = "1000"` against a uid of 1000 reported
  `owned` on the strength of two numerals coinciding. The number is recognised first.
- `suffix` was validated only when generating a PAC, and `author` only at the first write. A
  daemon could therefore start on a suffix no URL could match, or serve pages for an hour
  before answering a reader's first note with a 500. Both are configuration and are refused
  with the rest of it.
- A note written against a filename needing percent-escapes could not be read back. The
  extension derived the document from `location.pathname`, which keeps its escapes, then
  escaped it a second time on the read path and not on the write path; the daemon decodes
  exactly once by design, so the two looked in different places. A note on
  `Weekly Report.html` was saved under that name and then searched for under
  `Weekly%20Report.html`, so it vanished from the panel the moment it was saved. The path is
  now decoded once when it is derived and escaped once in both directions. Verified against a
  real host for a space, an `&`, a literal `%` and non-ASCII.
- A page could get the daemon to list a directory a symlink points at, by naming a path one
  level below the deepest listing held. The symlink check can only see what is cached, and
  the batch that would have revealed the symlink contained the symlink's own path — SFTP v3
  `OPENDIR` has no `O_NOFOLLOW`, so the remote resolved it. Nothing was ever served through
  it, but reading it is the act the alias base exists to forbid. A directory is now listed
  only when the cache can already prove no step down to it is a symlink. Round trips could
  not detect this, since one `list_dirs` is one flush however many directories are in it, so
  the test asserts on what the cache ends up holding.
- The annotation panel showed an empty shell, indistinguishable from a document with no
  notes, whenever the extension reloaded while a page was open: `chrome.runtime.sendMessage`
  rejects with "Extension context invalidated" and nothing caught it. It now reports losing
  contact through the same line it uses for every other failure.
- The omnibox listeners had no rejection handler, so a failure was a suggestion list that
  stopped appearing or an Enter that navigated nowhere, with the reason only in a
  service-worker console. They now report through the toolbar badge.
- The startup banner said `connecting over ssh...` before taking the port, so a port already
  in use produced that line directly above an error about the port. It names both now.

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
- A TOML config file: `--config FILE`, or `<config dir>/ssh-browser/config.toml` if it exists,
  with `[server]` and `[[alias]]` tables. The command line wins over the file, and aliases
  given on the command line are added to the file's rather than replacing them — naming one
  host should not silently drop the others. A name defined twice is an error rather than a
  precedence, because which one survived would otherwise depend on the order they were added.
- Unknown config keys are refused, so `suffixx = "dev"` names itself in an error instead of
  leaving the daemon on a suffix nobody chose. `scheme = "https"` is refused for the same
  reason: that mode is designed and not built, and quietly serving http would look like
  success.
- `Alias` now has private fields and a validating constructor, so the configuration file and
  the command line cannot disagree about what a valid alias is. The rules previously lived in
  the command-line parser, where a second entry point could not reach them.
- `e2e/`, which opens the same bytes through the daemon and over `file://` in a real browser
  and asserts the difference. Over the daemon an ES module runs and `fetch` of a relative path
  succeeds; over `file://` neither does, while the stylesheet and image load fine in both —
  so the harness states that this is about origin and not about access to files. It runs in CI
  against a local `sshd` and can be pointed at a real host.
- The startup banner no longer says `listening on 127.0.0.1:PORT` before the port has been
  taken. Binding and connecting every host both happened after that line was printed, so a
  reader who acted on it met a refused connection, and a port already in use produced the
  announcement followed by the error contradicting it. `Origin::bind` now takes the port first
  — the failure an operator can act on, and the one that should not cost a set of ssh
  handshakes to discover — and returns a `Bound` that holds the listener.
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
