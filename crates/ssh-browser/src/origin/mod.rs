//! The HTTP origin: what the browser actually talks to.
//!
//! The daemon answers two shapes of request on one loopback listener. A proxied
//! request arrives in absolute form because a PAC sent it here, and its Host is
//! `<alias>.<suffix>`; that is the path which gives the page a real origin under
//! the URL the user typed. A direct request arrives by address and exists so the
//! daemon is usable without touching proxy settings at all.
//!
//! Every request starts at the listing cache, not at the remote. One fresh listing
//! of a parent directory answers four questions locally -- does this name exist, is
//! it a directory, is it a symlink, and is the copy the browser already holds still
//! current -- and only a body the cache does not hold costs a round trip.

pub mod guard;
pub mod mime;
pub mod pac;
pub mod range;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_RANGE, CONTENT_TYPE, ETAG, HOST, HeaderName,
    IF_NONE_MATCH, IF_RANGE, LOCATION, RANGE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::annot;
use crate::cache::{self, Cache};
use crate::control::{self, Token};
use crate::fs::sftp::SftpFs;
use crate::fs::{Entry, RangeReq, RemoteFs};
use crate::prefetch;
use crate::sftp::wire::Attrs;

/// A file worth holding whole. Anything larger is served by range and not cached: a
/// seek into a video must not pull the entire file, and holding one would evict every
/// page body that makes a revisit free.
const CACHE_WHOLE_MAX: u64 = 8 * 1024 * 1024;

/// The request headers that change what is served rather than what is found.
struct Conditions {
    if_none_match: Option<String>,
    range: Option<String>,
    if_range: Option<String>,
    /// Only ever consulted on the control path, which only a loopback request reaches.
    control_token: Option<String>,
}

/// One alias, checked.
///
/// The fields are private and [`Alias::new`] is the only way to make one, so there is no
/// route into the daemon that skips these checks. That matters now that aliases can come
/// from a configuration file as well as from the command line: two entry points and one
/// validating constructor is fine, two entry points and two copies of the rules is how the
/// looser copy becomes the one that gets used.
#[derive(Debug)]
pub struct Alias {
    name: String,
    host: String,
    base: String,
}

impl Alias {
    pub fn new(name: &str, host: &str, base: &str) -> Result<Self> {
        ensure!(!host.is_empty(), "alias {name:?} has no ssh host");
        // The alias becomes a hostname label, and this is the very function that decides
        // whether an arriving request's label is acceptable. Asking it, rather than writing
        // the rule out again, is what stops the two from disagreeing — and they already had:
        // `-docs` satisfied the copy here and was then refused by `classify` on every single
        // request, after the daemon had paid for the ssh connection and advertised the route.
        ensure!(
            guard::is_label(name),
            "alias {name:?} must be lowercase letters, digits and hyphens, and may not start or end with a hyphen: it becomes a hostname label"
        );
        ensure!(
            base.starts_with('/'),
            "alias {name:?} needs an absolute base path, got {base:?}"
        );
        Ok(Self {
            name: name.to_string(),
            host: host.to_string(),
            base: base.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn base(&self) -> &str {
        &self.base
    }
}

struct Session {
    base: String,
    fs: SftpFs,
}

pub struct Origin {
    suffix: String,
    port: u16,
    sessions: HashMap<String, Session>,
    cache: Cache,
    token: Token,
    /// Whose annotations this daemon writes.
    ///
    /// Configured rather than discovered. The SFTP transport never runs a shell, so the
    /// remote account name is not something this process can ask for; guessing it from a
    /// home directory path would be a guess presented as a fact. What it is checked
    /// against is the owner a listing reports, which catches a configured name the remote
    /// does not actually write as — see `annot::Attribution`.
    author: String,
}

/// A listening socket and the origin that will answer on it.
///
/// Separate from [`Origin`] so that "the port is ours" is a thing the caller holds rather
/// than something it hopes for. A caller cannot announce that the daemon is up before it
/// is, because it has nothing to announce until this exists.
pub struct Bound {
    origin: Arc<Origin>,
    listener: TcpListener,
}

impl Origin {
    /// Take the port, then connect every alias.
    ///
    /// The port first, deliberately. It is the thing that fails immediately and for a
    /// reason the operator can do something about — another daemon already has it — and a
    /// handful of ssh handshakes paid before discovering that is time spent to learn
    /// nothing.
    ///
    /// The aliases are connected here rather than on first use so that the first page
    /// request does not also pay for an ssh handshake.
    pub async fn bind(
        aliases: Vec<Alias>,
        suffix: String,
        port: u16,
        token: Token,
        author: String,
    ) -> Result<Bound> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind {addr}"))?;

        // Held to the same rule the PAC is, and here rather than only there: a suffix the
        // PAC would refuse is one no alias URL can ever match, so starting with it produces a
        // daemon that listens and serves nothing.
        ensure!(
            pac::is_suffix(&suffix),
            "suffix {suffix:?} must be lowercase letters, digits, hyphens and dots"
        );
        // The author becomes a filename, and the only check on it used to live inside the
        // write path. A typo therefore started a daemon that read pages perfectly well and
        // then answered the reader's first note with a 500. It is configuration, so it is
        // refused where the rest of the configuration is.
        ensure!(
            annot::is_safe_name(&author),
            "author {author:?} must be letters, digits, dots, dashes or underscores: it becomes a filename"
        );

        let mut sessions = HashMap::new();
        for a in aliases {
            let fs = SftpFs::connect(&a.host)
                .await
                .with_context(|| format!("alias {} -> ssh host {}", a.name, a.host))?;
            // Checked where the map is built, so there is no way to reach a session map with
            // a name silently missing from it. A caller may have checked earlier and should;
            // `insert` returning the displaced value is the check that cannot be skipped.
            ensure!(
                sessions
                    .insert(a.name.clone(), Session { base: a.base, fs })
                    .is_none(),
                "alias {:?} is defined twice",
                a.name
            );
        }
        Ok(Bound {
            origin: Arc::new(Self {
                suffix,
                port,
                sessions,
                cache: Cache::default(),
                token,
                author,
            }),
            listener,
        })
    }
}

impl Bound {
    pub async fn serve(self) -> Result<()> {
        let Bound { origin, listener } = self;
        let self_ = origin;

        loop {
            let (stream, _) = listener.accept().await?;
            let me = Arc::clone(&self_);
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let me = Arc::clone(&me);
                    async move { Ok::<_, std::convert::Infallible>(me.handle(req).await) }
                });
                // Keep-alive is not a nicety here: a page pulls many subresources
                // and a fresh connection each time would add a local handshake per
                // request on top of the remote cost.
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }
}

impl Origin {
    /// Generic over the body type so a test can drive it without constructing
    /// hyper's `Incoming`, which only a real connection can produce.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: hyper::body::Body,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Some(host) = host_of(&req) else {
            return fail(StatusCode::BAD_REQUEST, "request carries no Host");
        };
        let path = req.uri().path().to_string();
        let cond = Conditions {
            if_none_match: header(&req, IF_NONE_MATCH),
            range: header(&req, RANGE),
            if_range: header(&req, IF_RANGE),
            control_token: req
                .headers()
                .get(control::TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        };
        let method = req.method().clone();
        let query = req.uri().query().map(str::to_string);

        // The body is read for the control prefix and nowhere else. Reading it on every
        // request would let any caller make the daemon hold memory it has no use for.
        let control_body = if path.starts_with(control::PATH_PREFIX) {
            match read_body(req.into_body()).await {
                Ok(b) => b,
                Err(e) => return fail(StatusCode::BAD_REQUEST, e),
            }
        } else {
            Bytes::new()
        };

        match guard::classify(&host, &path, &self.suffix, self.port) {
            // Refusing by Host is the DNS-rebinding defence, not a malfunction, so
            // it says why rather than failing blankly.
            Err(e) => fail(StatusCode::FORBIDDEN, format!("{e:#}")),
            Ok(guard::Target::Direct { path }) => {
                self.direct(&method, path, &cond, query.as_deref(), &control_body)
                    .await
            }
            Ok(guard::Target::Alias { alias, path }) => {
                self.alias(&method, alias, path, &cond).await
            }
        }
    }

    async fn direct(
        &self,
        method: &Method,
        path: &str,
        cond: &Conditions,
        query: Option<&str>,
        body: &[u8],
    ) -> Response<Full<Bytes>> {
        // Reachable only from a loopback Host, which `guard::classify` has already
        // separated from alias requests. An alias page cannot arrive here.
        if path.starts_with(control::PATH_PREFIX) {
            // Every control route goes through the gate, and there is no way past it.
            if let Some(refusal) = control::gate(method, cond.control_token.as_deref(), &self.token)
            {
                return refusal;
            }
            return self.control(method, path, query, body).await;
        }

        if path == "/proxy.pac" {
            return match pac::script(&self.suffix, self.port) {
                Ok(body) => plain_ok("application/x-ns-proxy-autoconfig", Bytes::from(body)),
                Err(e) => fail(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
            };
        }

        let rest = path.trim_start_matches('/');
        if rest.is_empty() {
            return plain_ok("text/html; charset=utf-8", Bytes::from(self.alias_index()));
        }

        let (alias, sub) = rest.split_once('/').unwrap_or((rest, ""));
        self.alias(method, alias, &format!("/{sub}"), cond).await
    }

    async fn alias(
        &self,
        method: &Method,
        alias: &str,
        path: &str,
        cond: &Conditions,
    ) -> Response<Full<Bytes>> {
        // The alias origin is read-only, and says so rather than quietly serving a POST
        // as if it were a GET. The shape of this answer is part of the boundary: there
        // is no write path on this origin and there will not be one. Writes go through
        // the control API, which a page served from here cannot reach.
        if !matches!(*method, Method::GET | Method::HEAD) {
            return fail(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("{method} is not allowed: this origin is read-only"),
            );
        }

        let Some(session) = self.sessions.get(alias) else {
            return fail(StatusCode::NOT_FOUND, format!("no alias named {alias:?}"));
        };
        let resolved = match guard::resolve(&session.base, path) {
            Ok(p) => p,
            Err(e) => return fail(StatusCode::FORBIDDEN, format!("{e:#}")),
        };

        let wants_dir = path.ends_with('/');
        let file = if wants_dir {
            format!("{resolved}/index.html")
        } else {
            resolved.clone()
        };

        // Every component between the alias base and the file, base first. The base
        // itself is not checked: it is what the operator configured, and no request
        // can change it.
        let chain = components(&session.base, &file);
        if chain.is_empty() {
            return self.autoindex_of(session, path, &resolved).await;
        }
        let last = chain.len() - 1;

        // Settled before anything is asked of the remote, because unlike a symlink this needs
        // nothing from the remote to decide — and deciding it later would mean asking the
        // remote to open `.ssh` in order to then refuse it.
        if let Some((_, name)) = chain.iter().find(|(_, n)| hidden(n)) {
            return fail(
                StatusCode::FORBIDDEN,
                format!("refusing {name}: names beginning with a dot are not served"),
            );
        }

        self.warm_ancestor_listings(session, &chain).await;

        // Symlinks are settled before anything else, so the answer cannot depend on
        // whether the target happens to exist: a symlink is refused either way, and
        // checking it separately is what lets the write path share exactly this rule.
        if let Some(at) = self.first_symlink(&chain) {
            return fail(
                StatusCode::FORBIDDEN,
                format!("refusing symlink at {at} (its target is not checked)"),
            );
        }

        let mut found_last = None;
        for (i, (dir, name)) in chain.iter().enumerate() {
            if !self.cache.has_listing(dir) {
                return fail(StatusCode::NOT_FOUND, format!("{path}: cannot list {dir}"));
            }
            let Some(attrs) = self.cache.attrs_of(dir, name) else {
                // Absent. For a directory request that only means there is no
                // index.html, so fall through to a listing of the directory itself.
                if i == last && wants_dir {
                    return self.autoindex_of(session, path, &resolved).await;
                }
                return fail(StatusCode::NOT_FOUND, format!("not found: {path}"));
            };

            if i < last && !attrs.is_dir() {
                return fail(
                    StatusCode::NOT_FOUND,
                    format!("{path}: {dir}/{name} is not a directory"),
                );
            }
            if i == last {
                found_last = Some(attrs);
            }
        }
        let attrs = found_last.expect("the walk assigns on its final iteration");

        if attrs.is_dir() {
            if wants_dir {
                // `<dir>/index.html` is itself a directory. Fall back to a listing.
                return self.autoindex_of(session, path, &resolved).await;
            }
            // Without the trailing slash every relative link on the page below
            // would resolve one level too high.
            return redirect(&format!("{path}/"));
        }

        let tag = cache::etag(&attrs);

        // The conditional GET never leaves this process: the validator came from the
        // cached listing, so a browser already holding the current copy is answered
        // with zero remote round trips. That is invariant 2.
        //
        // Nested rather than written as a let-chain: those stabilised in 1.88 and the
        // declared MSRV here is 1.85.
        if let (Some(tag), Some(header)) = (tag.as_deref(), cond.if_none_match.as_deref()) {
            if cache::etag_matches(header, tag) {
                return not_modified(tag);
            }
        }

        // Size comes from the listing, which is what makes a range answerable without
        // first fetching the file to discover how long it is.
        let size = attrs.size.unwrap_or(0);
        let wanted = match cond.range.as_deref() {
            Some(header) => range::resolve(header, cond.if_range.as_deref(), size),
            None => range::Resolved::Whole,
        };
        if wanted == range::Resolved::Unsatisfiable {
            return unsatisfiable(size);
        }

        // A body already held answers a range by slicing, with no round trip at all.
        if let Some(body) = self.cache.body(&file, &attrs) {
            return respond(&file, body, tag.as_deref(), &wanted, size);
        }

        // Too large to hold: fetch only what was asked for. This branch is what makes
        // seeking in a video possible. Without it a seek pulls the whole file, and
        // holding that file would evict every page body that makes a revisit free.
        if let range::Resolved::Part { start, end } = wanted {
            if size > CACHE_WHOLE_MAX {
                let req = RangeReq {
                    path: file.clone(),
                    offset: start,
                    len: end - start + 1,
                };
                let mut got = session.fs.read_ranges(std::slice::from_ref(&req)).await;
                return match got.pop() {
                    Some(Ok(body)) => partial(
                        mime::guess(&file),
                        Bytes::from(body),
                        tag.as_deref(),
                        start,
                        end,
                        size,
                    ),
                    Some(Err(e)) => {
                        self.cache.forget_listing(&chain[last].0);
                        fail(StatusCode::NOT_FOUND, format!("{path}: {e:#}"))
                    }
                    None => fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "read_ranges returned no result",
                    ),
                };
            }
        }

        let mut got = session.fs.read_batch(std::slice::from_ref(&file)).await;
        match got.pop() {
            Some(Ok(body)) => {
                let body = Bytes::from(body);
                self.cache.put_body(&file, &attrs, body.clone());
                // Before answering, not after. The browser will ask for this page's
                // subresources six at a time, and each wave it has to discover is a round
                // trip; fetching them here costs one and makes the waves cache hits. Waiting
                // also makes the invariant a guarantee rather than a race with the browser.
                if mime::guess(&file).starts_with("text/html") {
                    self.warm_subresources(session, path, &body).await;
                }
                respond(&file, body, tag.as_deref(), &wanted, size)
            }
            // The listing promised this file and the remote refused it, so the listing
            // is wrong. Holding it for the rest of its TTL would repeat the same wrong
            // answer.
            Some(Err(e)) => {
                self.cache.forget_listing(&chain[last].0);
                fail(StatusCode::NOT_FOUND, format!("{path}: {e:#}"))
            }
            None => fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "read_batch returned no result",
            ),
        }
    }

    async fn control(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        body: &[u8],
    ) -> Response<Full<Bytes>> {
        match (method, control::route_of(path)) {
            (&Method::GET, "hello") => {
                let mut aliases: Vec<String> = self.sessions.keys().cloned().collect();
                aliases.sort();
                control::hello(&aliases, &self.suffix)
            }
            (&Method::GET, "annotations") => self.list_annotations(query).await,
            (&Method::POST, "annotations") => self.add_annotation(body).await,
            (&Method::GET, route) => {
                control::text(StatusCode::NOT_FOUND, format!("no control route {route:?}"))
            }
            (_, route) => control::text(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("{method} is not allowed on {route:?}"),
            ),
        }
    }

    /// Turn `<alias>/<path>` into a session and an absolute path.
    ///
    /// Runs the same guards the read path runs, and the symlink one matters more here: a
    /// write that reached through a symlinked directory could place a file outside the
    /// alias base entirely.
    async fn resolve_doc(&self, doc: &str) -> Result<(&Session, String), (StatusCode, String)> {
        let (alias, rest) = doc.split_once('/').unwrap_or((doc, ""));
        let Some(session) = self.sessions.get(alias) else {
            return Err((StatusCode::NOT_FOUND, format!("no alias named {alias:?}")));
        };
        let resolved = match guard::resolve(&session.base, &format!("/{rest}")) {
            Ok(p) => p,
            Err(e) => return Err((StatusCode::FORBIDDEN, format!("{e:#}"))),
        };

        let chain = components(&session.base, &resolved);
        self.warm_ancestor_listings(session, &chain).await;
        if let Some(at) = self.first_symlink(&chain) {
            return Err((StatusCode::FORBIDDEN, format!("refusing symlink at {at}")));
        }
        Ok((session, resolved))
    }

    /// `GET /_control/annotations?doc=<alias>/<path>`
    async fn list_annotations(&self, query: Option<&str>) -> Response<Full<Bytes>> {
        let Some(doc) = param(query, "doc") else {
            return control::text(
                StatusCode::BAD_REQUEST,
                "annotations needs a doc parameter, e.g. ?doc=docs/index.html",
            );
        };
        let (session, resolved) = match self.resolve_doc(doc).await {
            Ok(v) => v,
            Err((status, detail)) => return control::text(status, detail),
        };

        match annot::Store::new(&session.fs).load(&resolved).await {
            Ok(loaded) => control::json(&AnnotationsBody {
                doc: resolved,
                annotations: loaded.annotations,
                skipped: loaded.skipped,
            }),
            Err(e) => control::text(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        }
    }

    /// `POST /_control/annotations`
    ///
    /// The request carries no author. The author is this daemon's, so a caller cannot
    /// write as somebody else however it words the request.
    async fn add_annotation(&self, body: &[u8]) -> Response<Full<Bytes>> {
        let request: AddBody = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return control::text(StatusCode::BAD_REQUEST, format!("malformed request: {e}"));
            }
        };

        let (session, resolved) = match self.resolve_doc(&request.doc).await {
            Ok(v) => v,
            Err((status, detail)) => return control::text(status, detail),
        };

        // The id is minted here when adding, rather than accepted, so it cannot name an
        // author other than the one doing the writing. For an update or a delete the
        // caller has to name the record, and the store checks that the name belongs to
        // this author before anything is written.
        let id = match (request.op, request.id) {
            (annot::Op::Add, None) => match annot::new_id(&self.author) {
                Ok(id) => id,
                Err(e) => {
                    return control::text(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"));
                }
            },
            (annot::Op::Add, Some(_)) => {
                return control::text(
                    StatusCode::BAD_REQUEST,
                    "an id is minted by the daemon; do not send one when adding",
                );
            }
            (_, Some(id)) => id,
            (_, None) => {
                return control::text(StatusCode::BAD_REQUEST, "an update or a delete needs an id");
            }
        };

        // The timestamp is the daemon's too. A caller that could choose it could reorder
        // someone's log, and position in the file is what actually decides anything.
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let record = annot::Record {
            op: request.op,
            id: id.clone(),
            at,
            body: request.body,
            selectors: request.selectors,
            reply_to: request.reply_to,
        };

        match annot::Store::new(&session.fs)
            .append(&resolved, &self.author, &record)
            .await
        {
            Ok(()) => control::json(&AddedBody {
                id,
                at,
                author: &self.author,
            }),
            Err(e) => control::text(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        }
    }

    async fn autoindex_of(
        &self,
        session: &Session,
        path: &str,
        resolved: &str,
    ) -> Response<Full<Bytes>> {
        if let Some(entries) = self.cache.listing_entries(resolved) {
            return plain_ok(
                "text/html; charset=utf-8",
                Bytes::from(autoindex(path, &entries)),
            );
        }
        match session.fs.list_dir(resolved).await {
            Ok(entries) => {
                self.cache.put_listing(resolved, &entries);
                plain_ok(
                    "text/html; charset=utf-8",
                    Bytes::from(autoindex(path, &entries)),
                )
            }
            Err(e) => fail(StatusCode::NOT_FOUND, format!("{path}: {e:#}")),
        }
    }

    /// Read what an HTML page is about to ask for, in one batch.
    ///
    /// One round trip to list the directories they live in, then one batch of reads — and
    /// neither grows with the number of subresources. When they sit beside the document, which
    /// is what a generated report looks like, the listing is already held and the listing round
    /// disappears.
    ///
    /// Two at most, and it really is two. The reads go through `read_ranges` rather than
    /// `read_batch` precisely so that this holds: `read_batch` has to poll in 32 KiB chunks
    /// because it does not know how long a file is, which made a one-megabyte bundle
    /// thirty-two round trips here. The listing already says how long each one is.
    ///
    /// Every reference goes through the same resolution and the same symlink rule as a real
    /// request, on purpose. A page is untrusted input, and a prefetcher that skipped those
    /// checks could be told to read a file the operator's configuration says is out of
    /// bounds. Serving it would still be refused, but reading it is already the wrong act.
    ///
    /// Failures are dropped in silence here, which is the one place in this codebase that is
    /// right: a reference that cannot be read is about to be requested for real, and that
    /// request reports the failure properly. Saying anything now would be guessing at whether
    /// the reader was going to care.
    async fn warm_subresources(&self, session: &Session, doc_path: &str, html: &[u8]) {
        let refs = prefetch::scan(html, prefetch::MAX_SUBRESOURCES);
        if refs.is_empty() {
            return;
        }
        // The directory the document is in, in URL terms, which is what a relative reference
        // on the page is relative to.
        let dir_of_doc = match doc_path.rsplit_once('/') {
            Some((head, _)) => head,
            None => "",
        };

        // Resolved first, so that a reference climbing out of the base is gone before it can
        // contribute a directory to list.
        let mut wanted: Vec<(String, Vec<(String, String)>)> = Vec::new();
        for r in &refs {
            let url = if r.starts_with('/') {
                r.clone()
            } else {
                format!("{dir_of_doc}/{r}")
            };
            let Ok(resolved) = guard::resolve(&session.base, &url) else {
                continue;
            };
            let chain = components(&session.base, &resolved);
            if chain.is_empty() {
                continue;
            }
            // The same rule the request path applies, applied here too — a page naming
            // `.ssh/id_ed25519` in an `<img src>` must not get it read into the cache on the
            // strength of the request that would refuse it never being made.
            if chain.iter().any(|(_, n)| hidden(n)) {
                continue;
            }
            // Checked against what is already known before anything new is listed. Without
            // this a page could get a directory behind a symlink listed purely by naming it,
            // and the symlink rule exists precisely so that the daemon does not go there.
            // The check runs again after the listings, for components not yet known.
            if self.first_symlink(&chain).is_some() {
                continue;
            }
            // And every directory this reference would cause to be listed has to be one the
            // cache can already prove is not behind a symlink. `first_symlink` alone is not
            // enough: it sees only what is cached, so a symlink one level below the deepest
            // listing held is invisible to it and would be opened by the very batch meant to
            // discover it.
            if !chain
                .iter()
                .all(|(dir, _)| self.listable(&session.base, dir))
            {
                continue;
            }
            wanted.push((resolved, chain));
        }

        let all: Vec<(String, String)> = wanted.iter().flat_map(|(_, c)| c.clone()).collect();
        self.warm_ancestor_listings(session, &all).await;

        let mut to_read = Vec::new();
        for (resolved, chain) in &wanted {
            if self.first_symlink(chain).is_some() {
                continue;
            }
            let (dir, name) = &chain[chain.len() - 1];
            let Some(attrs) = self.cache.attrs_of(dir, name) else {
                continue;
            };
            if attrs.is_dir() {
                continue;
            }
            // The size has to be known, and not merely defaulted to zero, because it is what
            // the read below asks for. A listing that did not report one leaves nothing to
            // ask for, and requesting zero bytes would cache an empty body for a file that
            // has contents.
            let Some(size) = attrs.size else {
                continue;
            };
            // Nothing to warm at zero, and warming it is where a listing that lies about the
            // size does damage: a ranged read asks for exactly what it was told, so a file
            // reported as empty is fetched as empty and then served that way. A real empty
            // file loses nothing by being read on request.
            //
            // A file too large to hold, at the other end, would be read only to be declined
            // by the cache and read again by the real request anyway.
            if size == 0 || size > CACHE_WHOLE_MAX {
                continue;
            }
            if self.cache.body(resolved, &attrs).is_some() {
                continue;
            }
            to_read.push((resolved.clone(), attrs, size));
        }
        if to_read.is_empty() {
            return;
        }

        // `read_ranges` rather than `read_batch`, because the size is already known.
        //
        // `read_batch` cannot know how long a file is, so it polls in 32 KiB chunks until it
        // sees a short read: one round trip per chunk index, which makes a one-megabyte
        // bundle thirty-two of them. `read_ranges` is handed the length, so it computes every
        // chunk before issuing any and the whole file costs one. The listing this function
        // already depends on is what supplies the length, so nothing extra is asked for.
        let reqs: Vec<RangeReq> = to_read
            .iter()
            .map(|(path, _, size)| RangeReq {
                path: path.clone(),
                offset: 0,
                len: *size,
            })
            .collect();

        for ((path, attrs, size), got) in to_read.iter().zip(session.fs.read_ranges(&reqs).await) {
            let Ok(body) = got else {
                continue;
            };
            // Short of what the listing promised means the file changed underneath us. The
            // cache key records the old size, so holding a body that no longer matches it
            // would serve the next reader a length the bytes do not have. Leaving it out
            // costs one prefetch; the real request reads it afresh.
            if body.len() as u64 != *size {
                continue;
            }
            self.cache.put_body(path, attrs, Bytes::from(body));
        }
    }

    /// Fetch every ancestor listing not already held, in one batch.
    ///
    /// One round trip regardless of depth, which is the whole reason `list_dirs` is a batch
    /// rather than a loop. A directory that cannot be listed is simply left absent from the
    /// cache; the caller diagnoses that against the path the request actually named.
    async fn warm_ancestor_listings(&self, session: &Session, chain: &[(String, String)]) {
        let mut missing: Vec<String> = chain
            .iter()
            .map(|(dir, _)| dir.clone())
            .filter(|dir| !self.cache.has_listing(dir))
            .collect();
        // Deduplicated because the prefetcher passes the chains of many files at once, and
        // several of them normally share a directory. Listing one twice in a batch costs no
        // extra round trip but it does cost the remote the work.
        missing.sort();
        missing.dedup();
        if missing.is_empty() {
            return;
        }
        for (dir, result) in missing.iter().zip(session.fs.list_dirs(&missing).await) {
            if let Ok(entries) = result {
                self.cache.put_listing(dir, &entries);
            }
        }
    }

    /// Can this directory be listed without asking the remote to walk through a symlink?
    ///
    /// True only when every step from the alias base down to it is already known — from a
    /// listing already held — to be a real directory. A step that is not known yet is not
    /// assumed safe, because SFTP v3 `OPENDIR` has no `O_NOFOLLOW`: asking the remote to
    /// list a path *is* asking it to follow whatever symlinks are in that path, and the
    /// answer arrives too late to un-ask. The base itself is operator configuration, not
    /// something a request reaches, so it is the one directory taken on trust.
    fn listable(&self, base: &str, dir: &str) -> bool {
        if dir.trim_end_matches('/') == base.trim_end_matches('/') {
            return true;
        }
        components(base, dir).iter().all(|(parent, name)| {
            self.cache
                .attrs_of(parent, name)
                .is_some_and(|a| a.is_dir() && !a.is_symlink())
        })
    }

    /// The first component of a chain that is a symlink, if any.
    ///
    /// Shared between reading and writing deliberately. A write that reached through a
    /// symlinked directory could place a file outside the alias base entirely, which is
    /// strictly worse than reading through one, so the two must not be able to drift apart.
    fn first_symlink(&self, chain: &[(String, String)]) -> Option<String> {
        chain.iter().find_map(|(dir, name)| {
            self.cache
                .attrs_of(dir, name)
                .filter(Attrs::is_symlink)
                .map(|_| format!("{dir}/{name}"))
        })
    }

    fn alias_index(&self) -> String {
        let mut names: Vec<&String> = self.sessions.keys().collect();
        names.sort();
        let mut s = String::from(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>ssh-browser</title></head><body><h1>ssh-browser</h1><ul>",
        );
        for name in names {
            let href = format!("http://{name}.{}/", self.suffix);
            s.push_str("<li><a href=\"");
            s.push_str(&escape(&href));
            s.push_str("\">");
            s.push_str(&escape(&href));
            s.push_str("</a></li>");
        }
        s.push_str("</ul></body></html>");
        s
    }
}

#[derive(Serialize)]
struct AnnotationsBody {
    doc: String,
    annotations: Vec<annot::Annotation>,
    /// Lines that could not be parsed, reported rather than hidden.
    skipped: usize,
}

#[derive(Serialize)]
struct AddedBody<'a> {
    id: String,
    at: u64,
    author: &'a str,
}

/// No author field, deliberately: see `add_annotation`.
#[derive(Deserialize)]
struct AddBody {
    doc: String,
    op: annot::Op,
    /// Absent when adding — the daemon mints it. Required when updating or deleting.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    selectors: Option<serde_json::Value>,
    #[serde(default)]
    reply_to: Option<String>,
}

/// One raw value out of a query string.
///
/// Deliberately not percent-decoded here: `guard::resolve` decodes the path it is handed,
/// and decoding twice would turn a literal `%2e%2e` in a filename into a traversal.
fn param<'q>(query: Option<&'q str>, want: &str) -> Option<&'q str> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == want).then_some(value)
    })
}

/// Every step from the alias base down to the file, as `(directory to list, name to
/// check inside it)`, base first.
///
/// The base is the first directory listed and is never itself a checked name: it is
/// operator configuration, not something a request reaches.
fn components(base: &str, file: &str) -> Vec<(String, String)> {
    let base = base.trim_end_matches('/');
    let relative = file
        .strip_prefix(base)
        .unwrap_or("")
        .trim_start_matches('/');

    let mut out = Vec::new();
    let mut dir = base.to_string();
    for name in relative.split('/').filter(|s| !s.is_empty()) {
        out.push((dir.clone(), name.to_string()));
        dir = format!("{dir}/{name}");
    }
    out
}

/// An annotation is a note, not a file upload.
///
/// `Limited` errors once the cap is passed rather than truncating, so a body that was too
/// large cannot be quietly parsed as a shorter one.
const MAX_CONTROL_BODY: usize = 256 * 1024;

async fn read_body<B>(body: B) -> Result<Bytes, String>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::{BodyExt, Limited};
    Limited::new(body, MAX_CONTROL_BODY)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| format!("reading the request body: {e}"))
}

fn header<B>(req: &Request<B>, name: HeaderName) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Serve a body already in hand, whole or sliced.
fn respond(
    file: &str,
    body: Bytes,
    tag: Option<&str>,
    wanted: &range::Resolved,
    size: u64,
) -> Response<Full<Bytes>> {
    match wanted {
        range::Resolved::Part { start, end } => {
            // Clamped against the body actually held rather than the advertised size,
            // so a listing that disagrees with the file cannot panic the slice.
            let lo = usize::try_from(*start)
                .unwrap_or(usize::MAX)
                .min(body.len());
            let hi = usize::try_from(end.saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(body.len())
                .max(lo);
            partial(
                mime::guess(file),
                body.slice(lo..hi),
                tag,
                *start,
                *end,
                size,
            )
        }
        _ => served(mime::guess(file), body, tag),
    }
}

fn partial(
    content_type: &str,
    body: Bytes,
    tag: Option<&str>,
    start: u64,
    end: u64,
    size: u64,
) -> Response<Full<Bytes>> {
    let mut b = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, "no-cache")
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    if let Some(tag) = tag {
        b = b.header(ETAG, tag);
    }
    b.body(Full::new(body))
        .unwrap_or_else(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "malformed 206"))
}

/// A 416 has to carry the real size, or a client cannot work out what it should have
/// asked for instead.
fn unsatisfiable(size: u64) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_RANGE, format!("bytes */{size}"))
        .body(Full::new(Bytes::from_static(b"range not satisfiable")))
        .unwrap_or_else(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "malformed 416"))
}

fn host_of<B>(req: &Request<B>) -> Option<String> {
    // A proxied request has an absolute-form target; a direct one only has the
    // header. Prefer the header, since that is what the browser actually sent.
    req.headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().host().map(str::to_string))
}

fn served(content_type: &str, body: Bytes, tag: Option<&str>) -> Response<Full<Bytes>> {
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        // `no-cache` means revalidate, not "do not store". With an ETag attached
        // that revalidation is a 304 answered from the listing cache, so the
        // browser keeps its copy and the remote is never touched.
        .header(CACHE_CONTROL, "no-cache")
        // Advertised on every full response: a client that does not know ranges are
        // available will never try to seek.
        .header(ACCEPT_RANGES, "bytes");
    if let Some(tag) = tag {
        b = b.header(ETAG, tag);
    }
    b.body(Full::new(body))
        .unwrap_or_else(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "malformed response"))
}

/// For responses with no validator to offer: the PAC, the alias index, a listing.
fn plain_ok(content_type: &str, body: Bytes) -> Response<Full<Bytes>> {
    served(content_type, body, None)
}

/// No `Last-Modified` anywhere, deliberately.
///
/// Emitting it would oblige us to honour `If-Modified-Since`, whose comparison is
/// second-resolution -- the same resolution SFTP reports mtime at, which is exactly
/// where it stops being able to tell two versions apart. The ETag carries the same
/// information without that ambiguity, so it is the only validator offered.
fn not_modified(tag: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(ETAG, tag)
        .header(CACHE_CONTROL, "no-cache")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "malformed 304"))
}

fn fail(status: StatusCode, detail: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(detail.into())))
        .expect("a plain-text body with static headers always builds")
}

fn redirect(to: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(LOCATION, to)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "bad redirect target"))
}

/// Listing for a directory that has no index.html.
/// A name this daemon will not serve.
///
/// Anything beginning with a dot. An alias base is one origin, so a page under it can read
/// everything else under it with `fetch` — the base is the blast radius. On a home directory
/// almost everything worth stealing sits behind a dot: `.ssh`, `.aws`, `.netrc`, a `.git`
/// whose remote URL carries a token. Refusing them costs a reader nearly nothing, and it is
/// what makes pointing an alias at a home directory a reasonable thing to do at all.
///
/// The annotation sidecar is itself a dot directory and is unaffected, because annotations are
/// read through the control API and never arrive here.
fn hidden(name: &str) -> bool {
    name.starts_with('.')
}

fn autoindex(path: &str, entries: &[Entry]) -> String {
    let mut visible: Vec<&Entry> = entries
        .iter()
        // `.` and `..` are already gone by the time a path resolves; these are the real
        // dot-names. Listing what the next click would be refused is worse than silence.
        .filter(|e| e.name != "." && e.name != ".." && !hidden(&e.name))
        .collect();
    visible.sort_by(|a, b| (!a.attrs.is_dir(), &a.name).cmp(&(!b.attrs.is_dir(), &b.name)));

    let mut s = String::from("<!doctype html><html><head><meta charset=\"utf-8\"><title>");
    s.push_str(&escape(path));
    s.push_str("</title></head><body><h1>");
    s.push_str(&escape(path));
    s.push_str("</h1><ul><li><a href=\"../\">../</a></li>");
    for e in visible {
        let slash = if e.attrs.is_dir() { "/" } else { "" };
        s.push_str("<li><a href=\"");
        s.push_str(&url_escape(&e.name));
        s.push_str(slash);
        s.push_str("\">");
        s.push_str(&escape(&e.name));
        s.push_str(slash);
        s.push_str("</a></li>");
    }
    s.push_str("</ul></body></html>");
    s
}

/// Remote filenames are untrusted input that lands inside our own origin, so the
/// listing escapes them. Skipping this would be self-inflicted XSS.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// HTML-escaping is not enough inside an href: a space or a hash in a filename
/// would still produce a broken or a wrong link.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::wire::Attrs;
    use crate::testing::{FakeRemote, dir_attrs, file_attrs, symlink_attrs};
    use http_body_util::{BodyExt, Empty};

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn body_of(res: Response<Full<Bytes>>) -> Bytes {
        res.into_body()
            .collect()
            .await
            .expect("a Full body always collects")
            .to_bytes()
    }

    /// A request arriving by address rather than through the PAC.
    fn loopback(path: &str, token: Option<&str>) -> Request<Empty<Bytes>> {
        let mut b = Request::builder().uri(path).header(HOST, "127.0.0.1:7391");
        if let Some(t) = token {
            b = b.header(control::TOKEN_HEADER, t);
        }
        b.body(Empty::<Bytes>::new()).expect("request builds")
    }

    fn control_post(path: &str, token: Option<&str>, body: &str) -> Request<Full<Bytes>> {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HOST, "127.0.0.1:7391");
        if let Some(t) = token {
            b = b.header(control::TOKEN_HEADER, t);
        }
        b.body(Full::new(Bytes::from(body.to_string())))
            .expect("request builds")
    }

    async fn json_of(res: Response<Full<Bytes>>) -> serde_json::Value {
        let bytes = body_of(res).await;
        serde_json::from_slice(&bytes).expect("a control response is json")
    }

    fn ranged(path: &str, range: &str) -> Request<Empty<Bytes>> {
        Request::builder()
            .uri(format!("http://docs.ssh-browser{path}"))
            .header(HOST, "docs.ssh-browser")
            .header(RANGE, range)
            .body(Empty::new())
            .expect("request builds")
    }

    /// Build an origin over an in-memory remote. The session is a real `SftpFs`, so
    /// the round trips counted below are the same ones production would pay.
    async fn origin_with(remote: FakeRemote) -> Origin {
        let fs = remote.spawn().await;
        let mut sessions = HashMap::new();
        sessions.insert(
            "docs".to_string(),
            Session {
                base: "/srv".to_string(),
                fs,
            },
        );
        Origin {
            suffix: "ssh-browser".to_string(),
            port: 7391,
            sessions,
            cache: Cache::default(),
            token: Token::from_hex(TEST_TOKEN),
            author: "souta".to_string(),
        }
    }

    fn get(path: &str, if_none_match: Option<&str>) -> Request<Empty<Bytes>> {
        let mut b = Request::builder()
            .uri(format!("http://docs.ssh-browser{path}"))
            .header(HOST, "docs.ssh-browser");
        if let Some(tag) = if_none_match {
            b = b.header(IF_NONE_MATCH, tag);
        }
        b.body(Empty::new()).expect("request builds")
    }

    fn trips(origin: &Origin) -> u64 {
        origin.sessions.values().map(|s| s.fs.round_trips()).sum()
    }

    fn one_page() -> FakeRemote {
        FakeRemote::new()
            .dir("/srv", vec![("a.html", file_attrs(5, 100))])
            .file("/srv/a.html", b"hello")
    }

    /// A page with subresources in a sibling directory, which is the shape a generated
    /// report has: one HTML file and an `assets/` beside it.
    fn page_with_subresources(n: usize) -> FakeRemote {
        let mut html = String::from(
            "<!doctype html><html><head><link rel=\"stylesheet\" href=\"assets/style.css\"><script src=\"assets/app.js\"></script></head><body>",
        );
        for i in 0..n {
            html.push_str(&format!("<img src=\"assets/{i}.png\">"));
        }
        html.push_str("</body></html>");

        let mut assets = vec!["style.css".to_string(), "app.js".to_string()];
        assets.extend((0..n).map(|i| format!("{i}.png")));

        let mut remote = FakeRemote::new()
            .dir(
                "/srv",
                vec![
                    ("index.html", file_attrs(html.len() as u64, 100)),
                    ("assets", dir_attrs()),
                ],
            )
            .dir(
                "/srv/assets",
                assets
                    .iter()
                    .map(|name| (name.as_str(), file_attrs(3, 1)))
                    .collect(),
            )
            .file("/srv/index.html", html.as_bytes());
        for name in &assets {
            remote = remote.file(&format!("/srv/assets/{name}"), b"xxx");
        }
        remote
    }

    /// The subresource half of invariant 1, which is about the browser rather than the
    /// remote. HTTP/1.1 allows six connections per origin, so forty subresources are seven
    /// waves of requests and each wave the browser has to discover is a round trip.
    ///
    /// Asking for them one at a time is the worst case any browser can produce. If that
    /// costs nothing, no arrangement of waves can cost anything either.
    #[tokio::test]
    async fn a_pages_subresources_are_already_held_when_the_browser_asks_for_them() {
        const N: usize = 40;
        let origin = origin_with(page_with_subresources(N)).await;

        let res = origin.handle(get("/index.html", None)).await;
        assert_eq!(res.status(), StatusCode::OK);

        let before = trips(&origin);
        for i in 0..N {
            let path = format!("/assets/{i}.png");
            let res = origin.handle(get(&path, None)).await;
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(&body_of(res).await[..], b"xxx", "{path}");
        }
        for name in ["style.css", "app.js"] {
            let res = origin.handle(get(&format!("/assets/{name}"), None)).await;
            assert_eq!(res.status(), StatusCode::OK, "{name}");
        }

        assert_eq!(
            trips(&origin) - before,
            0,
            "reading the page's own references is what makes these free"
        );
    }

    /// And the page itself does not get more expensive as it gains subresources: the
    /// listings are one batch and the reads are another, whatever the count.
    #[tokio::test]
    async fn serving_a_page_costs_the_same_however_many_subresources_it_has() {
        async fn cost(n: usize) -> u64 {
            let origin = origin_with(page_with_subresources(n)).await;
            let before = trips(&origin);
            let res = origin.handle(get("/index.html", None)).await;
            assert_eq!(res.status(), StatusCode::OK);
            trips(&origin) - before
        }
        assert_eq!(cost(4).await, cost(40).await);
    }

    /// One HTML page naming whatever it likes, for the two tests below. The page is
    /// untrusted input, and prefetching is the first thing in this daemon that acts on what
    /// a page says rather than on what the reader asked for.
    fn page_referring_to(refs: &[&str], extra: Vec<(&'static str, Attrs)>) -> FakeRemote {
        let mut html = String::from("<!doctype html><html><body>");
        for r in refs {
            html.push_str(&format!("<img src=\"{r}\">"));
        }
        html.push_str("</body></html>");

        let mut entries = vec![("index.html", file_attrs(html.len() as u64, 100))];
        entries.extend(extra);
        FakeRemote::new()
            .dir("/srv", entries)
            .file("/srv/index.html", html.as_bytes())
    }

    async fn cost_of_serving(refs: &[&str], extra: Vec<(&'static str, Attrs)>) -> u64 {
        let origin = origin_with(page_referring_to(refs, extra)).await;
        let before = trips(&origin);
        let res = origin.handle(get("/index.html", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        trips(&origin) - before
    }

    /// A reference that climbs out of the alias base must not be read. The check is the
    /// same `resolve` the request path uses, not a second copy that could drift from it.
    #[tokio::test]
    async fn a_page_cannot_prefetch_its_way_out_of_the_alias_base() {
        let baseline = cost_of_serving(&[], vec![]).await;
        assert_eq!(
            cost_of_serving(&["../../../etc/passwd", "/../../etc/shadow"], vec![]).await,
            baseline,
            "an escaping reference is gone before anything is listed or read"
        );
    }

    /// Nor through a symlink — and not even as far as listing it. A page that could get the
    /// directory a symlink points at listed would have defeated the rule by naming it.
    #[tokio::test]
    async fn a_page_cannot_prefetch_through_a_symlink() {
        let link = || vec![("link", symlink_attrs())];
        let baseline = cost_of_serving(&[], link()).await;
        assert_eq!(
            cost_of_serving(&["link/inside.png"], link()).await,
            baseline,
            "the symlink is known from the listing the page itself needed"
        );

        // And the ordinary request for it is still refused, which is the guarantee the
        // prefetcher is being held to rather than a separate one.
        let origin = origin_with(page_referring_to(&["link/inside.png"], link())).await;
        assert_eq!(
            origin.handle(get("/index.html", None)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            origin.handle(get("/link/inside.png", None)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// The hole the shallow symlink test did not cover: a symlink one level below the
    /// deepest listing the cache holds.
    ///
    /// `first_symlink` can only see what is cached, so at the moment the batch is assembled
    /// it has no opinion about `assets/link` — and the batch that would tell it includes the
    /// symlink's own path. SFTP v3 `OPENDIR` has no `O_NOFOLLOW`, so the remote resolves it
    /// and hands back a listing of wherever it points. Nothing is ever served through it,
    /// but the daemon has already read it, which is the act the alias base exists to forbid.
    ///
    /// Round trips cannot detect this — `list_dirs` is one flush however many directories
    /// are in it — so the assertion is on what the cache ends up holding.
    #[tokio::test]
    async fn a_page_cannot_get_a_symlink_below_an_unlisted_directory_opened() {
        let html = "<!doctype html><html><body><img src=\"assets/link/secret.txt\"></body></html>";
        let origin = origin_with(
            FakeRemote::new()
                .dir(
                    "/srv",
                    vec![
                        ("index.html", file_attrs(html.len() as u64, 100)),
                        ("assets", dir_attrs()),
                    ],
                )
                .dir("/srv/assets", vec![("link", symlink_attrs())])
                // What the remote returns once it has followed the symlink for us.
                .dir("/srv/assets/link", vec![("secret.txt", file_attrs(9, 1))])
                .file("/srv/index.html", html.as_bytes())
                .file("/srv/assets/link/secret.txt", b"elsewhere"),
        )
        .await;

        assert_eq!(
            origin.handle(get("/index.html", None)).await.status(),
            StatusCode::OK
        );
        assert!(
            !origin.cache.has_listing("/srv/assets/link"),
            "the daemon listed the directory a symlink points at"
        );

        // And the ordinary request for it is still refused, so closing the prefetch route
        // did not quietly become the only thing stopping it.
        assert_eq!(
            origin
                .handle(get("/assets/link/secret.txt", None))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    /// The other half: a reference one level down is still prefetched, because the listing
    /// the page's own request already fetched proves that step is a real directory. Closing
    /// the hole above must not turn prefetching off for the ordinary `assets/` layout.
    #[tokio::test]
    async fn a_reference_in_a_real_subdirectory_is_still_prefetched() {
        let html = "<!doctype html><html><body><img src=\"assets/x.png\"></body></html>";
        let origin = origin_with(
            FakeRemote::new()
                .dir(
                    "/srv",
                    vec![
                        ("index.html", file_attrs(html.len() as u64, 100)),
                        ("assets", dir_attrs()),
                    ],
                )
                .dir("/srv/assets", vec![("x.png", file_attrs(3, 1))])
                .file("/srv/index.html", html.as_bytes())
                .file("/srv/assets/x.png", b"xxx"),
        )
        .await;

        assert_eq!(
            origin.handle(get("/index.html", None)).await.status(),
            StatusCode::OK
        );
        let before = trips(&origin);
        let res = origin.handle(get("/assets/x.png", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(&body_of(res).await[..], b"xxx");
        assert_eq!(
            trips(&origin) - before,
            0,
            "a subdirectory one level down must still be warmed"
        );
    }

    /// A subresource larger than one read chunk costs the same as a small one.
    ///
    /// This is what `read_ranges` buys over `read_batch` here: a read whose length is known
    /// can have all its chunks issued together, and a read whose length is not has to poll.
    /// Before, a bundle of any real size cost one round trip per 32 KiB — invisible to every
    /// other test, because they all use three-byte fixtures.
    #[tokio::test]
    async fn a_large_subresource_costs_what_a_small_one_costs() {
        async fn cost(bytes: usize) -> u64 {
            let html = "<!doctype html><html><body><img src=\"assets/big.bin\"></body></html>";
            let origin = origin_with(
                FakeRemote::new()
                    .dir(
                        "/srv",
                        vec![
                            ("index.html", file_attrs(html.len() as u64, 100)),
                            ("assets", dir_attrs()),
                        ],
                    )
                    .dir(
                        "/srv/assets",
                        vec![("big.bin", file_attrs(bytes as u64, 1))],
                    )
                    .file("/srv/index.html", html.as_bytes())
                    .file("/srv/assets/big.bin", &vec![b'x'; bytes]),
            )
            .await;

            let before = trips(&origin);
            assert_eq!(
                origin.handle(get("/index.html", None)).await.status(),
                StatusCode::OK
            );
            let spent = trips(&origin) - before;

            // And it really was warmed, so the comparison is between two prefetches rather
            // than between a prefetch and a skip.
            let at = trips(&origin);
            let res = origin.handle(get("/assets/big.bin", None)).await;
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(body_of(res).await.len(), bytes);
            assert_eq!(
                trips(&origin) - at,
                0,
                "{bytes} bytes should have been held"
            );

            spent
        }

        // Either side of the 32 KiB chunk, and well past it.
        assert_eq!(cost(1024).await, cost(200 * 1024).await);
    }

    /// A listing that understates a file's length must not turn into an empty `200`.
    ///
    /// The prefetch reads a range, and a range is exactly as long as it was told to be. A
    /// listing reporting zero bytes for a file that has some would therefore cache an empty
    /// body — and the reader would be served it, because the cache is consulted first. This
    /// is the failure mode `CONTRIBUTING.md` names, arriving through a new door.
    ///
    /// Caught by the fake reporting a size of zero where a size was not set, which is what a
    /// real listing does when it is wrong rather than silent.
    #[tokio::test]
    async fn a_subresource_the_listing_calls_empty_is_not_prefetched() {
        let html = "<!doctype html><html><body><img src=\"assets/x.png\"></body></html>";
        let sizeless = Attrs {
            permissions: Some(0o100644),
            mtime: Some(1),
            ..Attrs::default()
        };
        let origin = origin_with(
            FakeRemote::new()
                .dir(
                    "/srv",
                    vec![
                        ("index.html", file_attrs(html.len() as u64, 100)),
                        ("assets", dir_attrs()),
                    ],
                )
                .dir("/srv/assets", vec![("x.png", sizeless)])
                .file("/srv/index.html", html.as_bytes())
                .file("/srv/assets/x.png", b"xxx"),
        )
        .await;

        assert_eq!(
            origin.handle(get("/index.html", None)).await.status(),
            StatusCode::OK
        );
        let res = origin.handle(get("/assets/x.png", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            &body_of(res).await[..],
            b"xxx",
            "the real request must still serve the whole file"
        );
    }

    /// A subresource over the hold-whole limit is skipped rather than read and discarded.
    #[tokio::test]
    async fn an_oversized_subresource_is_not_prefetched() {
        async fn cost(size: u64) -> u64 {
            let html =
                "<!doctype html><html><body><video src=\"assets/film.mp4\"></video></body></html>";
            let origin = origin_with(
                FakeRemote::new()
                    .dir(
                        "/srv",
                        vec![
                            ("index.html", file_attrs(html.len() as u64, 100)),
                            ("assets", dir_attrs()),
                        ],
                    )
                    .dir("/srv/assets", vec![("film.mp4", file_attrs(size, 1))])
                    .file("/srv/index.html", html.as_bytes())
                    .file("/srv/assets/film.mp4", b"xxx"),
            )
            .await;
            let before = trips(&origin);
            assert_eq!(
                origin.handle(get("/index.html", None)).await.status(),
                StatusCode::OK
            );
            trips(&origin) - before
        }

        // The listing is fetched either way; only the read differs. A film the cache would
        // decline must not be pulled across the network first to find that out.
        let read_it = cost(3).await;
        let skipped = cost(CACHE_WHOLE_MAX + 1).await;
        assert!(
            skipped < read_it,
            "an oversized subresource cost {skipped} against {read_it} for a small one"
        );
    }

    /// The port is taken before any host is connected.
    ///
    /// This ordering is the whole of what a previous change set out to fix, and nothing
    /// tested it: every other test here builds an `Origin` directly and never goes through
    /// `bind` at all. A regression that put the ssh handshakes first would pass the entire
    /// suite, and would cost a full set of connections before reporting the one failure an
    /// operator can actually act on.
    ///
    /// Cheap to check without any ssh infrastructure, precisely because the port failing
    /// first means the host is never reached: the error naming the bind and *not* naming the
    /// host is the evidence.
    #[tokio::test]
    async fn the_port_is_taken_before_any_host_is_connected() {
        let held = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a free port");
        let port = held.local_addr().expect("its address").port();

        const NOWHERE: &str = "a-host-that-cannot-resolve.invalid";
        let result = Origin::bind(
            vec![Alias::new("docs", NOWHERE, "/srv").expect("a valid alias")],
            "ssh-browser".to_string(),
            port,
            Token::from_hex(TEST_TOKEN),
            "souta".to_string(),
        )
        .await;

        let Err(e) = result else {
            panic!("binding a port that is already held must fail");
        };
        let text = format!("{e:#}");
        assert!(
            text.contains(&format!("bind 127.0.0.1:{port}")),
            "the error should name the port, got: {text}"
        );
        assert!(
            !text.contains(NOWHERE),
            "the ssh host was reached before the port was taken: {text}"
        );
    }

    /// What makes a home directory a reasonable base: the things worth stealing there are
    /// behind a dot, and a dot is refused at any depth.
    #[tokio::test]
    async fn a_dot_name_is_never_served() {
        let origin = origin_with(
            FakeRemote::new()
                .dir(
                    "/srv",
                    vec![
                        ("Vault", dir_attrs()),
                        (".ssh", dir_attrs()),
                        (".netrc", file_attrs(9, 1)),
                    ],
                )
                .dir("/srv/.ssh", vec![("id_ed25519", file_attrs(9, 1))])
                .dir("/srv/Vault", vec![(".git", dir_attrs())])
                .dir("/srv/Vault/.git", vec![("config", file_attrs(9, 1))])
                .file("/srv/.ssh/id_ed25519", b"a-secret-")
                .file("/srv/.netrc", b"a-secret-")
                .file("/srv/Vault/.git/config", b"a-secret-"),
        )
        .await;

        for path in [
            "/.ssh/id_ed25519",
            "/.netrc",
            // At depth, and behind a directory that is itself perfectly ordinary.
            "/Vault/.git/config",
            // The directory itself, not only what is under it.
            "/.ssh/",
        ] {
            assert_eq!(
                origin.handle(get(path, None)).await.status(),
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
    }

    /// And they are not advertised either. Listing what the next click would refuse is worse
    /// than not listing it.
    #[tokio::test]
    async fn a_listing_does_not_mention_dot_names() {
        let origin = origin_with(FakeRemote::new().dir(
            "/srv",
            vec![
                ("Vault", dir_attrs()),
                (".ssh", dir_attrs()),
                (".obsidian", dir_attrs()),
            ],
        ))
        .await;

        let body = body_of(origin.handle(get("/", None)).await).await;
        let listing = String::from_utf8_lossy(&body);
        assert!(listing.contains("Vault"), "the ordinary entry is listed");
        assert!(!listing.contains(".ssh"), "got: {listing}");
        assert!(!listing.contains(".obsidian"), "got: {listing}");
    }

    /// The prefetcher must not become the way around it. A page is untrusted input, and this
    /// is the one part of the daemon that acts on what a page says.
    #[tokio::test]
    async fn a_page_cannot_prefetch_a_dot_name() {
        let html = "<!doctype html><html><body><img src=\".ssh/id_ed25519\"></body></html>";
        let origin = origin_with(
            FakeRemote::new()
                .dir(
                    "/srv",
                    vec![
                        ("index.html", file_attrs(html.len() as u64, 100)),
                        (".ssh", dir_attrs()),
                    ],
                )
                .dir("/srv/.ssh", vec![("id_ed25519", file_attrs(9, 1))])
                .file("/srv/index.html", html.as_bytes())
                .file("/srv/.ssh/id_ed25519", b"a-secret-"),
        )
        .await;

        assert_eq!(
            origin.handle(get("/index.html", None)).await.status(),
            StatusCode::OK
        );
        assert!(
            !origin.cache.has_listing("/srv/.ssh"),
            "the page got the daemon to list a directory it will not serve"
        );
        assert_eq!(
            origin.handle(get("/.ssh/id_ed25519", None)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// The same single file, four directories down.
    fn deep_tree() -> FakeRemote {
        FakeRemote::new()
            .dir("/srv", vec![("a", dir_attrs())])
            .dir("/srv/a", vec![("b", dir_attrs())])
            .dir("/srv/a/b", vec![("c", dir_attrs())])
            .dir("/srv/a/b/c", vec![("d.html", file_attrs(5, 100))])
            .file("/srv/a/b/c/d.html", b"deep!")
    }

    fn entry(name: &str, dir: bool) -> Entry {
        Entry {
            name: name.to_string(),
            attrs: Attrs {
                permissions: Some(if dir { 0o040755 } else { 0o100644 }),
                ..Attrs::default()
            },
            owner: None,
        }
    }

    #[test]
    fn a_hostile_filename_cannot_inject_script_into_our_origin() {
        let page = autoindex("/", &[entry("<script>alert(1)</script>", false)]);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;"));
    }

    #[test]
    fn listings_put_directories_first_then_sort_by_name() {
        let page = autoindex(
            "/",
            &[
                entry("b.txt", false),
                entry("z-dir", true),
                entry("a.txt", false),
            ],
        );
        let dir = page.find("z-dir").expect("dir listed");
        let a = page.find("a.txt").expect("a listed");
        let b = page.find("b.txt").expect("b listed");
        assert!(dir < a, "directories come first");
        assert!(a < b, "files sort by name");
    }

    #[test]
    fn hrefs_are_url_escaped() {
        let page = autoindex("/", &[entry("a b#c.html", false)]);
        assert!(page.contains("href=\"a%20b%23c.html\""));
    }

    #[test]
    fn the_component_chain_walks_from_the_base_down() {
        assert_eq!(
            components("/srv", "/srv/a/b/c.html"),
            vec![
                ("/srv".to_string(), "a".to_string()),
                ("/srv/a".to_string(), "b".to_string()),
                ("/srv/a/b".to_string(), "c.html".to_string()),
            ]
        );
        assert_eq!(
            components("/srv", "/srv/index.html"),
            vec![("/srv".to_string(), "index.html".to_string())]
        );
        // A trailing slash on the base must not produce an empty first component.
        assert_eq!(
            components("/srv/", "/srv/a.html"),
            vec![("/srv".to_string(), "a.html".to_string())]
        );
        // The file *is* the base: nothing between them to check.
        assert!(components("/srv", "/srv").is_empty());
    }

    /// Invariant 2. The listing and the body are both held, so the second request
    /// has nothing left to ask the remote.
    #[tokio::test]
    async fn a_revisit_costs_no_remote_round_trips() {
        let origin = origin_with(one_page()).await;

        let first = origin.handle(get("/a.html", None)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let after_first = trips(&origin);
        assert!(after_first > 0, "the first request has to fetch something");

        let second = origin.handle(get("/a.html", None)).await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            trips(&origin),
            after_first,
            "a revisit must be answered entirely from cache"
        );
    }

    /// Invariant 2 through the browser's own validator: the ETag came from the
    /// cached listing, so the 304 is decided inside this process.
    #[tokio::test]
    async fn a_conditional_get_is_answered_without_the_remote() {
        let origin = origin_with(one_page()).await;

        let first = origin.handle(get("/a.html", None)).await;
        let tag = first
            .headers()
            .get(ETAG)
            .expect("a validator is offered")
            .to_str()
            .expect("ascii")
            .to_string();
        let after_first = trips(&origin);

        let second = origin.handle(get("/a.html", Some(&tag))).await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            trips(&origin),
            after_first,
            "a 304 must not touch the remote"
        );
    }

    /// A name the listing does not contain needs no fetch to answer.
    #[tokio::test]
    async fn a_missing_file_is_a_404_from_the_cached_listing() {
        let origin = origin_with(one_page()).await;

        // Warm the listing.
        origin.handle(get("/a.html", None)).await;
        let warm = trips(&origin);

        let missing = origin.handle(get("/nope.html", None)).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            trips(&origin),
            warm,
            "a 404 for a listed-but-absent name must cost nothing"
        );
    }

    /// The guard SECURITY.md promises, decided from the listing rather than from a
    /// REALPATH per request.
    #[tokio::test]
    async fn a_symlink_is_refused() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("link.html", symlink_attrs())])
                .file("/srv/link.html", b"whatever the target is"),
        )
        .await;

        let res = origin.handle(get("/link.html", None)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// The listing knows it is a directory, so this costs no failed open first.
    #[tokio::test]
    async fn a_directory_without_a_trailing_slash_redirects() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("sub", dir_attrs())])
                .dir("/srv/sub", vec![("b.html", file_attrs(1, 1))]),
        )
        .await;

        let res = origin.handle(get("/sub", None)).await;
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            res.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
            Some("/sub/")
        );
    }

    /// A listing that promises a file the remote then refuses must not be kept, or
    /// the same wrong answer is served for a whole TTL.
    #[tokio::test]
    async fn a_listing_proven_wrong_is_forgotten() {
        // Listed, but no body declared: the open fails.
        let origin =
            origin_with(FakeRemote::new().dir("/srv", vec![("ghost.html", file_attrs(5, 100))]))
                .await;

        let res = origin.handle(get("/ghost.html", None)).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(
            !origin.cache.has_listing("/srv"),
            "a listing contradicted by the remote must be dropped"
        );
    }

    /// A directory with no index.html is listed rather than 404'd.
    #[tokio::test]
    async fn a_directory_without_an_index_is_listed() {
        let origin =
            origin_with(FakeRemote::new().dir("/srv", vec![("only.txt", file_attrs(2, 1))])).await;

        let res = origin.handle(get("/", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    /// The hole SECURITY.md used to describe. `/link/inside.html` names a file that
    /// exists and is not itself a symlink, but every route to it passes through one.
    #[tokio::test]
    async fn a_symlinked_directory_higher_up_the_path_is_refused() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("link", symlink_attrs())])
                .dir("/srv/link", vec![("inside.html", file_attrs(2, 1))])
                .file("/srv/link/inside.html", b"hi"),
        )
        .await;

        let res = origin.handle(get("/link/inside.html", None)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// Depth must not buy itself round trips. Every ancestor listing is issued
    /// together, so a path four deep costs what a path one deep costs.
    #[tokio::test]
    async fn a_deep_path_costs_what_a_shallow_one_costs() {
        let deep = origin_with(deep_tree()).await;
        assert_eq!(
            deep.handle(get("/a/b/c/d.html", None)).await.status(),
            StatusCode::OK
        );

        let shallow = origin_with(one_page()).await;
        assert_eq!(
            shallow.handle(get("/a.html", None)).await.status(),
            StatusCode::OK
        );

        let (d, sh) = (trips(&deep), trips(&shallow));
        // The slack absorbs one flush of fire-and-forget CLOSE requests landing on
        // either side of the measurement. A walk that listed one ancestor at a time
        // would cost about three times as many at this depth, and worse deeper.
        assert!(
            d <= sh + 2,
            "depth 4 cost {d} round trips against depth 1's {sh}"
        );
    }

    /// A component that exists but is not a directory.
    #[tokio::test]
    async fn a_file_used_as_a_directory_is_a_404() {
        let origin = origin_with(one_page()).await;
        let res = origin.handle(get("/a.html/b.html", None)).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// A deep path is served, not merely checked: the walk must not lose the file it
    /// was walking towards.
    #[tokio::test]
    async fn a_deep_path_serves_its_body() {
        let origin = origin_with(deep_tree()).await;
        let res = origin.handle(get("/a/b/c/d.html", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    /// A range out of a body already held costs nothing: the slice happens here.
    #[tokio::test]
    async fn a_range_is_sliced_out_of_the_cached_body() {
        let origin = origin_with(one_page()).await;
        assert_eq!(
            origin.handle(get("/a.html", None)).await.status(),
            StatusCode::OK
        );
        let warm = trips(&origin);

        let res = origin.handle(ranged("/a.html", "bytes=1-3")).await;
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            res.headers()
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 1-3/5")
        );
        assert_eq!(&body_of(res).await[..], b"ell");
        assert_eq!(
            trips(&origin),
            warm,
            "slicing a held body must cost no round trip"
        );
    }

    /// A range on a file not yet held still works, and the file ends up held.
    #[tokio::test]
    async fn a_range_on_a_cold_small_file_works_and_warms_the_cache() {
        let origin = origin_with(one_page()).await;

        let res = origin.handle(ranged("/a.html", "bytes=0-1")).await;
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_of(res).await[..], b"he");

        let warm = trips(&origin);
        let again = origin.handle(ranged("/a.html", "bytes=2-4")).await;
        assert_eq!(&body_of(again).await[..], b"llo");
        assert_eq!(
            trips(&origin),
            warm,
            "a small file fetched for a range should be held whole"
        );
    }

    /// The 416 has to name the real size, or a client cannot correct itself.
    #[tokio::test]
    async fn a_range_past_the_end_is_a_416_carrying_the_real_size() {
        let origin = origin_with(one_page()).await;
        let res = origin.handle(ranged("/a.html", "bytes=99-")).await;
        assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            res.headers()
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes */5")
        );
    }

    /// A client that is not told ranges exist will never seek.
    #[tokio::test]
    async fn a_full_response_advertises_ranges() {
        let origin = origin_with(one_page()).await;
        let res = origin.handle(get("/a.html", None)).await;
        assert_eq!(
            res.headers()
                .get(ACCEPT_RANGES)
                .and_then(|v| v.to_str().ok()),
            Some("bytes")
        );
    }

    /// The validator on offer is weak, so `If-Range` cannot be honoured. The whole
    /// representation is the specified answer, not a 412 and not a 206.
    #[tokio::test]
    async fn if_range_yields_the_whole_file() {
        let origin = origin_with(one_page()).await;
        let req = Request::builder()
            .uri("http://docs.ssh-browser/a.html")
            .header(HOST, "docs.ssh-browser")
            .header(RANGE, "bytes=1-3")
            .header(IF_RANGE, "W/\"64-5\"")
            .body(Empty::<Bytes>::new())
            .expect("request builds");

        let res = origin.handle(req).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(&body_of(res).await[..], b"hello");
    }

    /// The branch that makes a video seekable: a file too big to hold is fetched by
    /// range and not cached, so a seek does not pull the whole thing.
    #[tokio::test]
    async fn a_large_file_is_served_by_range_and_not_held() {
        let body: Vec<u8> = (0..64u8).collect();
        let origin = origin_with(
            FakeRemote::new()
                // Declared far larger than the cache threshold; the body behind it is
                // small because what is under test is the branch, not the bytes.
                .dir("/srv", vec![("big.bin", file_attrs(9 * 1024 * 1024, 7))])
                .file("/srv/big.bin", &body),
        )
        .await;

        let res = origin.handle(ranged("/big.bin", "bytes=0-9")).await;
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_of(res).await[..], &body[0..10]);

        let after = trips(&origin);
        let second = origin.handle(ranged("/big.bin", "bytes=10-19")).await;
        assert_eq!(&body_of(second).await[..], &body[10..20]);
        assert!(
            trips(&origin) > after,
            "a file over the threshold must not be held"
        );
    }

    /// The boundary, from the side that matters. A page served under an alias origin
    /// names the control path and gets a file lookup, not the control router: the 404
    /// proves it was never routed there. A 401 would mean the router saw it.
    #[tokio::test]
    async fn an_alias_origin_has_no_control_api_on_it() {
        let origin = origin_with(one_page()).await;
        let res = origin.handle(get("/_control/hello", None)).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_ne!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "a 401 would mean the control router was reached from an alias origin"
        );
    }

    /// Even with the right token in hand, an alias origin must not route to control.
    /// This is the case a compromised page would actually try.
    #[tokio::test]
    async fn an_alias_origin_with_a_valid_token_still_has_no_control_api() {
        let origin = origin_with(one_page()).await;
        let req = Request::builder()
            .uri("http://docs.ssh-browser/_control/hello")
            .header(HOST, "docs.ssh-browser")
            .header(control::TOKEN_HEADER, TEST_TOKEN)
            .body(Empty::<Bytes>::new())
            .expect("request builds");
        assert_eq!(origin.handle(req).await.status(), StatusCode::NOT_FOUND);
    }

    /// There is no write path on the read side, and a POST is told so rather than being
    /// quietly served as a GET.
    #[tokio::test]
    async fn the_alias_origin_refuses_writes() {
        let origin = origin_with(one_page()).await;
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let req = Request::builder()
                .method(method.clone())
                .uri("http://docs.ssh-browser/a.html")
                .header(HOST, "docs.ssh-browser")
                .body(Empty::<Bytes>::new())
                .expect("request builds");
            assert_eq!(
                origin.handle(req).await.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} should be refused on the read-only origin"
            );
        }
    }

    #[tokio::test]
    async fn the_control_api_answers_on_loopback_with_the_token() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(loopback("/_control/hello", Some(TEST_TOKEN)))
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_of(res).await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("\"protocol\""),
            "hello must negotiate: {text}"
        );
        assert!(text.contains("\"docs\""), "hello must list aliases: {text}");
    }

    #[tokio::test]
    async fn the_control_api_refuses_loopback_without_the_token() {
        let origin = origin_with(one_page()).await;
        assert_eq!(
            origin
                .handle(loopback("/_control/hello", None))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            origin
                .handle(loopback("/_control/hello", Some("wrong")))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// The direct browsing path still works alongside the control prefix.
    #[tokio::test]
    async fn the_loopback_path_still_serves_files() {
        let origin = origin_with(one_page()).await;
        let res = origin.handle(loopback("/docs/a.html", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(&body_of(res).await[..], b"hello");
    }

    /// The round trip the extension will make: write one, read it back.
    #[tokio::test]
    async fn an_annotation_written_through_control_comes_back_out() {
        let origin = origin_with(one_page()).await;

        let added = origin
            .handle(control_post(
                "/_control/annotations",
                Some(TEST_TOKEN),
                r#"{"doc":"docs/a.html","op":"add","body":"a note"}"#,
            ))
            .await;
        assert_eq!(added.status(), StatusCode::OK);
        let added = json_of(added).await;
        let id = added["id"].as_str().expect("an id was minted").to_string();
        assert!(
            id.starts_with("souta:"),
            "the id must name the daemon's author, got {id}"
        );
        assert_eq!(added["author"], "souta");

        let listed = origin
            .handle(loopback(
                "/_control/annotations?doc=docs/a.html",
                Some(TEST_TOKEN),
            ))
            .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json_of(listed).await;
        assert_eq!(listed["skipped"], 0);
        let annotations = listed["annotations"].as_array().expect("an array");
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["body"], "a note");
        assert_eq!(annotations[0]["id"], id.as_str());
        assert_eq!(annotations[0]["author"], "souta");
        // This fixture's remote reports no owner, so the honest answer is that nobody
        // checked. The field must be there saying so rather than absent, because an
        // extension cannot tell an absent field from a daemon that verified and approved.
        assert_eq!(annotations[0]["attribution"]["state"], "unchecked");
    }

    /// The wire shape the extension reads for a forged log: a tagged state and the name of
    /// the account that actually owns the file.
    #[tokio::test]
    async fn a_mismatched_author_reaches_the_extension_as_json() {
        let dir = "/srv/.ssh-browser/a.html/ann";
        let log = b"{\"op\":\"add\",\"id\":\"alice:1\",\"at\":10,\"body\":\"is this alice?\"}\n";
        let origin = origin_with(
            one_page()
                .dir(dir, vec![("alice.jsonl", file_attrs(log.len() as u64, 1))])
                .owner(&format!("{dir}/alice.jsonl"), "bob")
                .file(&format!("{dir}/alice.jsonl"), log),
        )
        .await;

        let listed = origin
            .handle(loopback(
                "/_control/annotations?doc=docs/a.html",
                Some(TEST_TOKEN),
            ))
            .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json_of(listed).await;
        let annotations = listed["annotations"].as_array().expect("an array");
        assert_eq!(annotations.len(), 1, "the note is served, not censored");
        assert_eq!(annotations[0]["author"], "alice");
        assert_eq!(annotations[0]["attribution"]["state"], "mismatched");
        assert_eq!(annotations[0]["attribution"]["owner"], "bob");
    }

    #[tokio::test]
    async fn writing_an_annotation_without_the_token_is_refused() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/annotations",
                None,
                r#"{"doc":"docs/a.html","op":"add","body":"a note"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    /// An id chosen by the caller could name a different author, which the store would
    /// then refuse. Refusing the id outright removes the possibility instead of catching
    /// it later.
    #[tokio::test]
    async fn an_add_may_not_carry_an_id() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/annotations",
                Some(TEST_TOKEN),
                r#"{"doc":"docs/a.html","op":"add","id":"alice:1","body":"x"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_update_without_an_id_is_refused() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/annotations",
                Some(TEST_TOKEN),
                r#"{"doc":"docs/a.html","op":"update","body":"x"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn listing_annotations_needs_a_doc() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(loopback("/_control/annotations", Some(TEST_TOKEN)))
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unknown_alias_is_a_404() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(loopback(
                "/_control/annotations?doc=nope/a.html",
                Some(TEST_TOKEN),
            ))
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// A traversal in the doc parameter must not place a log outside the alias base.
    #[tokio::test]
    async fn a_traversal_in_the_doc_parameter_is_refused() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/annotations",
                Some(TEST_TOKEN),
                r#"{"doc":"docs/../../etc/passwd","op":"add","body":"x"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// The same symlink rule the read path uses, and it matters more here: a write that
    /// reached through a symlinked directory could place a file outside the base entirely.
    #[tokio::test]
    async fn writing_through_a_symlinked_directory_is_refused() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("link", symlink_attrs())])
                .dir("/srv/link", vec![("inside.html", file_attrs(2, 1))])
                .file("/srv/link/inside.html", b"hi"),
        )
        .await;

        let res = origin
            .handle(control_post(
                "/_control/annotations",
                Some(TEST_TOKEN),
                r#"{"doc":"docs/link/inside.html","op":"add","body":"x"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// A document nobody has annotated is an empty list, not an error.
    #[tokio::test]
    async fn an_unannotated_document_lists_empty() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(loopback(
                "/_control/annotations?doc=docs/a.html",
                Some(TEST_TOKEN),
            ))
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = json_of(res).await;
        assert_eq!(body["annotations"].as_array().expect("array").len(), 0);
    }
}
