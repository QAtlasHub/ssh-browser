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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

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
use crate::ssh_config;
use crate::theme;

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
    /// What the browser said about who started this request, if a browser started it.
    ///
    /// A forbidden header name, so a page can neither set it nor suppress it. See
    /// `control::from_a_page`.
    fetch_site: Option<String>,
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
    /// Where this alias is rooted, or `None` for the remote's home directory.
    ///
    /// Deferred rather than filled in with a guess, because the answer lives on the
    /// remote. `~` is shell syntax and this transport never runs a shell; expanding it
    /// here would produce this machine's home directory, which is a different computer's.
    /// It is resolved once in `bind`, by asking.
    base: Option<String>,
}

impl Alias {
    pub fn new(name: &str, host: &str, base: Option<&str>) -> Result<Self> {
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
        if let Some(base) = base {
            ensure!(
                is_base(base),
                "alias {name:?} needs a base that is an absolute path, or `~`, or `~/` and a path under the home directory with no `..` in it, got {base:?}"
            );
        }
        Ok(Self {
            name: name.to_string(),
            host: host.to_string(),
            base: base.map(str::to_string),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Where this alias is rooted, or `None` for the remote's home directory.
    pub fn base(&self) -> Option<&str> {
        self.base.as_deref()
    }
}

/// One line of the host list: a host ssh knows, and what this daemon is doing with it.
#[derive(serde::Serialize)]
struct KnownHost {
    alias: String,
    host: String,
    #[serde(flatten)]
    settings: ssh_config::Settings,
    /// Whether this daemon has an alias for it right now.
    ///
    /// Named for what it is rather than "connected": what the extension needs to know is
    /// whether a URL for this alias will answer, and that is a question about routing.
    served: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved: Option<String>,
}

/// An alias being served right now.
///
/// A separate list from the hosts, because it answers a different question and the two do
/// not line up: an alias need not be named after its host, so a session opened as
/// `docs=myhost:/srv` matches no row in ssh_config at all. Reporting only the hosts would
/// leave it being served and visible nowhere, which is the kind of invisible live state
/// this daemon is supposed not to have.
#[derive(serde::Serialize)]
struct OpenAlias {
    alias: String,
    host: String,
    base: String,
    url: String,
}

#[derive(serde::Serialize)]
struct KnownHosts {
    open: Vec<OpenAlias>,
    hosts: Vec<KnownHost>,
    unusable: Vec<ssh_config::Unusable>,
}

/// Whether a configured base is one this daemon can resolve.
///
/// `~` is accepted here and nowhere else in the codebase. It is shell syntax, and this
/// transport never runs a shell, so it is not passed through to anything: it is a
/// stand-in for an answer only the remote has, substituted in `bind` once the session
/// exists. Writing the home path out by hand is the alternative, and it means knowing
/// another machine's account layout in order to name a directory you can already `cd` to.
///
/// `..` is refused rather than normalised. `~/..` quietly meaning the parent of the home
/// directory is the kind of surprise that belongs in a base path least of all, since the
/// base is the blast radius of every page served under it.
fn is_base(base: &str) -> bool {
    if base.starts_with('/') {
        return true;
    }
    let Some(rest) = base.strip_prefix('~') else {
        return false;
    };
    match rest {
        "" => true,
        rest => match rest.strip_prefix('/') {
            Some(under) => {
                !under.is_empty()
                    && under
                        .split('/')
                        .all(|c| !c.is_empty() && c != "." && c != "..")
            }
            None => false,
        },
    }
}

/// The absolute base an alias is rooted at, asking the remote only when the answer needs
/// asking.
///
/// Separated from `bind` because `bind` starts an ssh subprocess, which no test can, and
/// this is the part of it with a decision in it.
async fn resolve_base(base: Option<&str>, fs: &SftpFs) -> Result<String> {
    let under = match base {
        None | Some("~") => "",
        Some(b) => match b.strip_prefix("~/") {
            Some(under) => under,
            // Already absolute. Nothing to ask the remote, and asking anyway would put an
            // ssh round trip in front of every startup for no answer.
            None => return Ok(b.to_string()),
        },
    };
    let home = fs.home().await?;
    let home = home.trim_end_matches('/');
    // A home of `/` would otherwise produce `//work`, which is not the same path
    // everywhere: POSIX leaves a leading double slash implementation-defined.
    let home = if home.is_empty() { "" } else { home };
    Ok(match under {
        "" if home.is_empty() => "/".to_string(),
        "" => home.to_string(),
        under => format!("{home}/{under}"),
    })
}

/// One alias's session, or nothing if no such alias is open.
///
/// The guard is dropped before returning, so nothing a caller does afterwards holds up
/// another request.
impl Origin {
    async fn session(&self, alias: &str) -> Option<Arc<Session>> {
        self.sessions.read().await.get(alias).cloned()
    }

    async fn alias_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.sessions.read().await.keys().cloned().collect();
        names.sort();
        names
    }
}

struct Session {
    /// The ssh_config name this was reached by.
    ///
    /// Kept because an alias need not be named after its host — `docs=myhost:/srv` is one
    /// of each — so without it the only thing that could be reported about a live session
    /// is a name that appears nowhere in ssh_config.
    host: String,
    base: String,
    fs: SftpFs,
}

pub struct Origin {
    suffix: String,
    port: u16,
    /// The aliases being served right now.
    ///
    /// Behind a lock because the set changes while the daemon runs: a host is opened when
    /// somebody picks it, not when the daemon starts. Starting six ssh sessions so that a
    /// popup could list six hosts would make looking at the list cost more than using one.
    ///
    /// The values are `Arc`d so a request can take its session and let go of the lock.
    /// Holding a read guard across the awaits a page costs would block every open for the
    /// length of a remote read, and `Session` owns the ssh child — dropping one kills the
    /// connection, so it cannot simply be cloned out.
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    cache: Cache,
    token: Token,
    /// What a directory listing looks like.
    ///
    /// Behind a lock because it is chosen from the dashboard while the daemon runs, and it
    /// is one setting for every alias: an origin that looked different from its neighbour
    /// for no reason the reader chose would be a bug rather than a feature.
    theme: RwLock<String>,
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
    routes: Vec<String>,
}

impl Bound {
    /// One line per alias, naming where it actually points.
    ///
    /// Only available once bound, which is the point: an alias rooted at the home
    /// directory has no printable base until the remote has been asked.
    pub fn routes(&self) -> &[String] {
        &self.routes
    }
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
        theme: String,
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
        // Refused here rather than at the first listing, for the same reason the author name
        // is: it is configuration, so it is refused where the rest of the configuration is.
        theme::check(&theme)?;
        ensure!(
            annot::is_safe_name(&author),
            "author {author:?} must be letters, digits, dots, dashes or underscores: it becomes a filename"
        );

        let mut sessions = HashMap::new();
        let mut routes = Vec::new();
        for a in aliases {
            let fs = SftpFs::connect(&a.host)
                .await
                .with_context(|| format!("alias {} -> ssh host {}", a.name, a.host))?;
            // Asked here, once, rather than per request. An alias written without a base
            // means the account's home, and only the remote knows where that is.
            let base = resolve_base(a.base.as_deref(), &fs)
                .await
                .with_context(|| {
                    format!(
                        "alias {} -> ssh host {}: working out where {} is",
                        a.name,
                        a.host,
                        a.base.as_deref().unwrap_or("the home directory")
                    )
                })?;
            // Built from the resolved base, so what is announced is where requests will
            // actually go. Formatting it from the alias beforehand would print the word
            // "home" and leave the reader to find out which directory that was.
            routes.push(format!(
                "  http://{}.{suffix}/  ->  {}:{base}",
                a.name, a.host
            ));
            // Checked where the map is built, so there is no way to reach a session map with
            // a name silently missing from it. A caller may have checked earlier and should;
            // `insert` returning the displaced value is the check that cannot be skipped.
            ensure!(
                sessions
                    .insert(
                        a.name.clone(),
                        Arc::new(Session {
                            host: a.host.clone(),
                            base,
                            fs,
                        }),
                    )
                    .is_none(),
                "alias {:?} is defined twice",
                a.name
            );
        }
        Ok(Bound {
            routes,
            origin: Arc::new(Self {
                suffix,
                port,
                sessions: RwLock::new(sessions),
                cache: Cache::default(),
                token,
                theme: RwLock::new(theme),
                author,
            }),
            listener,
        })
    }
}

impl Bound {
    pub async fn serve(self) -> Result<()> {
        let Bound {
            origin, listener, ..
        } = self;
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
            fetch_site: req
                .headers()
                .get(control::FETCH_SITE_HEADER)
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
                self.alias(&method, alias, path, &cond, query.as_deref())
                    .await
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
            // First, and separately from the token: no page reaches this API at all,
            // whatever it has got hold of.
            if control::from_a_page(cond.fetch_site.as_deref()) {
                return control::text(
                    StatusCode::FORBIDDEN,
                    "the control API is not reachable from a page",
                );
            }
            // The handshake, and the only route that does not need the token -- it is
            // where the token comes from. Handing it over is safe precisely because the
            // line above has already established that nothing page-shaped is asking, and
            // a caller that is not a browser at all could read the token file anyway.
            //
            // This is what removes the paste. An extension cannot read a file, so before
            // this the first run meant copying sixty-four hex characters out of a terminal.
            if method == Method::GET && control::route_of(path) == "token" {
                return control::text(StatusCode::OK, self.token.as_str());
            }
            // Every other control route goes through the gate, and there is no way past
            // it. The gate repeats the page check rather than trusting the branch above to
            // have run, so that no future route can reach it having skipped one.
            if let Some(refusal) = control::gate(
                method,
                cond.fetch_site.as_deref(),
                cond.control_token.as_deref(),
                &self.token,
            ) {
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
            return plain_ok(
                "text/html; charset=utf-8",
                Bytes::from(self.alias_index().await),
            );
        }

        let (alias, sub) = rest.split_once('/').unwrap_or((rest, ""));
        self.alias(method, alias, &format!("/{sub}"), cond, query)
            .await
    }

    async fn alias(
        &self,
        method: &Method,
        alias: &str,
        path: &str,
        cond: &Conditions,
        query: Option<&str>,
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

        let Some(session) = self.session(alias).await else {
            return fail(StatusCode::NOT_FOUND, format!("no alias named {alias:?}"));
        };
        let session = session.as_ref();
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
            return self
                .autoindex_of(session, alias, path, &resolved, query)
                .await;
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

        let held = match self.listings_along(session, &chain).await {
            Ok(held) => held,
            // Whatever ssh said, rather than this daemon's word for not knowing.
            Err((at, why)) => {
                return fail(
                    StatusCode::BAD_GATEWAY,
                    format!("{path}: listing {at} failed: {why}"),
                );
            }
        };

        // Symlinks are settled before anything else, so the answer cannot depend on
        // whether the target happens to exist: a symlink is refused either way, and
        // checking it separately is what lets the write path share exactly this rule.
        if let Some(at) = first_symlink(&held, &chain) {
            return fail(
                StatusCode::FORBIDDEN,
                format!("refusing symlink at {at} (its target is not checked)"),
            );
        }

        let mut found_last = None;
        for (i, (dir, name)) in chain.iter().enumerate() {
            let Some(attrs) = attrs_in(&held, dir, name) else {
                // Absent. For a directory request that only means there is no
                // index.html, so fall through to a listing of the directory itself.
                if i == last && wants_dir {
                    return self
                        .autoindex_of(session, alias, path, &resolved, query)
                        .await;
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
                return self
                    .autoindex_of(session, alias, path, &resolved, query)
                    .await;
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
                let aliases = self.alias_names().await;
                control::hello(&aliases, &self.suffix)
            }
            (&Method::GET, "hosts") => self.list_hosts().await,
            (&Method::POST, "open") => self.open_host(body).await,
            (&Method::POST, "close") => self.close_alias(body).await,
            (&Method::GET, "theme") => self.show_theme().await,
            (&Method::POST, "theme") => self.set_theme(body).await,
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
    async fn resolve_doc(&self, doc: &str) -> Result<(Arc<Session>, String), (StatusCode, String)> {
        let (alias, rest) = doc.split_once('/').unwrap_or((doc, ""));
        let Some(session) = self.session(alias).await else {
            return Err((StatusCode::NOT_FOUND, format!("no alias named {alias:?}")));
        };
        let resolved = match guard::resolve(&session.base, &format!("/{rest}")) {
            Ok(p) => p,
            Err(e) => return Err((StatusCode::FORBIDDEN, format!("{e:#}"))),
        };

        let chain = components(&session.base, &resolved);
        // A failure here shows up as the symlink check below finding nothing to check,
        // and then as the write failing with the remote's own reason. There is no better
        // answer to give from here.
        let held = self.held_listings(&session, &chain).await;
        if let Some(at) = first_symlink(&held, &chain) {
            return Err((StatusCode::FORBIDDEN, format!("refusing symlink at {at}")));
        }
        Ok((session, resolved))
    }

    /// `GET /_control/hosts`
    ///
    /// What ssh already knows how to reach, which is the list the extension offers. It
    /// comes from `~/.ssh/config` rather than from this daemon's own configuration,
    /// because a host you can already `ssh` to is a host you should be able to open
    /// without writing it down a second time.
    ///
    /// Answering this connects to nothing. It is a list of what could be opened, and a
    /// daemon that opened six ssh sessions to answer a popup would make looking at the
    /// list cost more than using it.
    async fn list_hosts(&self) -> Response<Full<Bytes>> {
        let found = match ssh_config::read() {
            Ok(found) => found,
            Err(e) => {
                return control::text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reading ssh_config: {e:#}"),
                );
            }
        };

        // Every `ssh -G` at once. One subprocess per host is cheap, but run in sequence
        // the list would take the sum of them, and this is the request a reader waits on
        // before they can do anything at all.
        let described: Vec<_> = found
            .hosts
            .iter()
            .map(|h| {
                let host = h.host.clone();
                tokio::spawn(async move { ssh_config::describe(&host).await })
            })
            .collect();

        let open = {
            let sessions = self.sessions.read().await;
            let mut open: Vec<OpenAlias> = sessions
                .iter()
                .map(|(alias, s)| OpenAlias {
                    alias: alias.clone(),
                    host: s.host.clone(),
                    base: s.base.clone(),
                    url: format!("http://{alias}.{}/", self.suffix),
                })
                .collect();
            open.sort_by(|a, b| a.alias.cmp(&b.alias));
            open
        };
        let mut hosts = Vec::with_capacity(found.hosts.len());
        for (h, task) in found.hosts.iter().zip(described) {
            // A host ssh cannot describe is still listed, with the reason attached.
            // Dropping it would make a misconfigured host look like one that is not in
            // the file, and those have different fixes.
            let (settings, unresolved) = match task.await {
                Ok(Ok(settings)) => (settings, None),
                Ok(Err(e)) => (ssh_config::Settings::default(), Some(format!("{e:#}"))),
                Err(e) => (ssh_config::Settings::default(), Some(e.to_string())),
            };
            hosts.push(KnownHost {
                alias: h.alias.clone(),
                host: h.host.clone(),
                settings,
                served: open.iter().any(|o| o.alias == h.alias),
                unresolved,
            });
        }
        control::json(&KnownHosts {
            open,
            hosts,
            unusable: found.unusable,
        })
    }

    /// `POST /_control/open` -- start serving one of the hosts ssh already knows.
    ///
    /// This is what replaces configuring an alias before you can look at anything. The
    /// host is picked from the list, the daemon connects, and the URL comes back.
    ///
    /// **Only a host named in ssh_config can be opened.** Not because the token is
    /// insufficient, but because "ssh to an arbitrary host on request" is a larger
    /// primitive than this needs to be, and the list the extension offers is already the
    /// menu. A host that is not on it is a config change, which is a deliberate act.
    async fn open_host(&self, body: &[u8]) -> Response<Full<Bytes>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ask {
            host: String,
            /// Absolute, or `~`, or `~/path`. Absent means the home directory.
            #[serde(default)]
            base: Option<String>,
        }

        let ask: Ask = match serde_json::from_slice(body) {
            Ok(ask) => ask,
            Err(e) => {
                return control::text(
                    StatusCode::BAD_REQUEST,
                    format!("open needs a JSON body naming a host: {e}"),
                );
            }
        };

        let found = match ssh_config::read() {
            Ok(found) => found,
            Err(e) => {
                return control::text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reading ssh_config: {e:#}"),
                );
            }
        };
        // Matched against ssh_config rather than trusted, and matched case-insensitively
        // because that is how hostnames compare: the extension shows `panza` and the file
        // says `Panza`.
        let Some(known) = found
            .hosts
            .iter()
            .find(|h| h.host.eq_ignore_ascii_case(&ask.host) || h.alias == ask.host)
        else {
            return control::text(
                StatusCode::NOT_FOUND,
                format!("{:?} is not a host in your ssh_config", ask.host),
            );
        };

        let alias = match Alias::new(&known.alias, &known.host, ask.base.as_deref()) {
            Ok(alias) => alias,
            Err(e) => return control::text(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };

        // Already open is an answer, not an error: two tabs asking at once should both
        // get the URL. A *different* base is refused, though. Reconnecting under one
        // would change what an origin means underneath any page already open in it,
        // which is the one thing an origin must not do.
        if let Some(open) = self.session(&known.alias).await {
            // Asking for no base is asking for no particular one, so an alias already
            // open is simply the answer. The popup relies on this: it opens a host by
            // naming it, and a host the config file already roots somewhere would
            // otherwise answer a plain click with a conflict about a base nobody asked for.
            let Some(asked) = alias.base() else {
                return self.opened(&known.alias, &known.host, &open.base);
            };
            // Resolved against the session that is already there, rather than compared as
            // written. `~/work` and `/home/souta/work` are the same base, and a check that
            // could not tell would either refuse an identical request or -- worse -- accept
            // a different one, handing back a URL rooted somewhere the caller did not ask
            // for. The round trip is paid on a path that is not a page load.
            let wanted = match resolve_base(Some(asked), &open.fs).await {
                Ok(base) => base,
                Err(e) => {
                    return control::text(
                        StatusCode::BAD_GATEWAY,
                        format!("working out where to root {}: {e:#}", known.alias),
                    );
                }
            };
            if wanted != open.base {
                return control::text(
                    StatusCode::CONFLICT,
                    format!(
                        "{} is already open at {}, and {} is not the same place; a second base would change what that origin means underneath any page open in it",
                        known.alias, open.base, wanted
                    ),
                );
            }
            return self.opened(&known.alias, &known.host, &open.base);
        }

        let fs = match SftpFs::connect(&known.host).await {
            Ok(fs) => fs,
            Err(e) => {
                // The reason is passed through rather than flattened to "could not
                // connect". It is ssh's, and ssh's reasons are the ones with a fix in
                // them: a jump host that is down, a key that is not loaded, a name that
                // does not resolve.
                return control::text(
                    StatusCode::BAD_GATEWAY,
                    format!("ssh to {}: {e:#}", known.host),
                );
            }
        };
        let base = match resolve_base(alias.base(), &fs).await {
            Ok(base) => base,
            Err(e) => {
                return control::text(
                    StatusCode::BAD_GATEWAY,
                    format!("working out where to root {}: {e:#}", known.alias),
                );
            }
        };

        // Inserted under the write lock, and a session that lost the race is dropped
        // rather than replacing the winner. Dropping it closes that ssh child, which is
        // the right end for a connection nothing is using; replacing the winner would
        // close one that requests are already going through.
        let session = {
            let mut sessions = self.sessions.write().await;
            Arc::clone(sessions.entry(known.alias.clone()).or_insert_with(|| {
                Arc::new(Session {
                    host: known.host.clone(),
                    base,
                    fs,
                })
            }))
        };
        self.opened(&known.alias, &known.host, &session.base)
    }

    /// `POST /_control/close` -- stop serving an alias.
    ///
    /// The other half of `open`, and what makes changing where an alias is rooted possible
    /// at all: reopening under a second base is refused while the first is live, because
    /// it would change what an origin means underneath any page open in it. Closing first
    /// makes that an act somebody chose rather than something that happened to them.
    ///
    /// Also the only way to give back an ssh connection without stopping the daemon.
    async fn close_alias(&self, body: &[u8]) -> Response<Full<Bytes>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ask {
            alias: String,
        }

        let ask: Ask = match serde_json::from_slice(body) {
            Ok(ask) => ask,
            Err(e) => {
                return control::text(
                    StatusCode::BAD_REQUEST,
                    format!("close needs a JSON body naming an alias: {e}"),
                );
            }
        };

        // Removed under the write lock, so two callers cannot both believe they closed it.
        // Dropping the `Arc` is what ends the ssh session, and a request already in flight
        // holds one — so the connection goes when the last reader is done with it rather
        // than out from under them.
        let gone = self.sessions.write().await.remove(&ask.alias);
        match gone {
            Some(session) => {
                #[derive(serde::Serialize)]
                struct Closed<'a> {
                    alias: &'a str,
                    host: &'a str,
                    base: &'a str,
                }
                control::json(&Closed {
                    alias: &ask.alias,
                    host: &session.host,
                    base: &session.base,
                })
            }
            // Distinguished from success on purpose. "Closed something" and "there was
            // nothing to close" look identical to a caller that is told neither, and the
            // second usually means the alias was spelled wrong.
            None => control::text(
                StatusCode::NOT_FOUND,
                format!("no alias named {:?} is open", ask.alias),
            ),
        }
    }

    fn opened(&self, alias: &str, host: &str, base: &str) -> Response<Full<Bytes>> {
        #[derive(serde::Serialize)]
        struct Opened<'a> {
            alias: &'a str,
            host: &'a str,
            base: &'a str,
            url: String,
        }
        control::json(&Opened {
            alias,
            host,
            base,
            url: format!("http://{alias}.{}/", self.suffix),
        })
    }

    /// `GET /_control/theme` -- what listings look like, and what else they could.
    async fn show_theme(&self) -> Response<Full<Bytes>> {
        #[derive(serde::Serialize)]
        struct Choice {
            name: &'static str,
            label: &'static str,
        }
        #[derive(serde::Serialize)]
        struct Themes<'a> {
            current: &'a str,
            themes: Vec<Choice>,
        }
        // The list comes from the daemon rather than being written out again in the
        // dashboard. Two copies of it is how a theme gets added and stays invisible.
        control::json(&Themes {
            current: &self.theme.read().await,
            themes: theme::all()
                .iter()
                .map(|t| Choice {
                    name: t.name,
                    label: t.label,
                })
                .collect(),
        })
    }

    /// `POST /_control/theme` -- choose one, and remember it.
    async fn set_theme(&self, body: &[u8]) -> Response<Full<Bytes>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ask {
            name: String,
        }
        let ask: Ask = match serde_json::from_slice(body) {
            Ok(ask) => ask,
            Err(e) => {
                return control::text(
                    StatusCode::BAD_REQUEST,
                    format!("theme needs a JSON body naming one: {e}"),
                );
            }
        };
        // Checked before anything is changed, so a typo leaves the daemon as it was rather
        // than half-moved to a theme that does not exist.
        if let Err(e) = theme::check(&ask.name) {
            return control::text(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }

        *self.theme.write().await = ask.name.clone();
        // Remembered on a best effort. Failing to write a file under the runtime directory
        // must not undo a change the reader can already see on the next listing, so it is
        // reported beside the result rather than instead of it.
        let remembered = theme::remember(&ask.name).is_ok();
        #[derive(serde::Serialize)]
        struct Chose<'a> {
            current: &'a str,
            remembered: bool,
        }
        control::json(&Chose {
            current: &ask.name,
            remembered,
        })
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
        alias: &str,
        path: &str,
        resolved: &str,
        query: Option<&str>,
    ) -> Response<Full<Bytes>> {
        // Taken from the resolved path rather than from the request, so the tree shows a
        // filename as it is spelled on disk rather than percent-escaped. `resolved` always
        // begins with the base, because that is what resolving it against the base means.
        let rel = resolved
            .strip_prefix(&session.base)
            .unwrap_or("")
            .to_string();
        let entries = match self.listing_of(session, resolved).await {
            Ok(entries) => entries,
            Err(e) => return fail(StatusCode::NOT_FOUND, format!("{path}: {e:#}")),
        };
        let sites = self.sites_among(session, resolved, &entries).await;

        // `?ls` is one level of the same tree, as the HTML fragment that goes inside it.
        // It is what the tree fetches when a folder is expanded.
        //
        // A fragment rather than JSON so that there is exactly one thing that knows how a
        // row is written. A JSON reply would mean a second renderer in the page's script,
        // in another language, which is two places for a class name to be spelled and one
        // of them to be spelled wrong.
        //
        // It is not a new capability either: a page under this alias can already read every
        // path under it, and this says no more than the listing below does.
        if query == Some("ls") {
            let mut out = String::new();
            render_level(&mut out, &rel, &rows_of(&entries, &sites), &[]);
            return plain_ok("text/html; charset=utf-8", Bytes::from(out));
        }

        // The ancestors are already in the cache: the walk that resolved this path warmed
        // every one of them to check for symlinks. So a tree opened four levels down costs
        // no more round trips than the listing it replaces.
        let mut levels = Vec::new();
        let mut at = session.base.clone();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            if let Some(entries) = self.cache.listing_entries(&at) {
                let here = at.strip_prefix(&session.base).unwrap_or("").to_string();
                // Only the level the reader is standing in is scanned for sites, so only it
                // can mark them. Scanning every level would multiply the one extra round
                // trip by the depth of the path, which is the thing this is careful not to
                // do; expanding a folder scans it, so a mark appears where you look.
                levels.push((here, rows_of(&entries, &HashSet::new())));
            }
            at.push('/');
            at.push_str(part);
        }
        levels.push((rel.clone(), rows_of(&entries, &sites)));

        plain_ok(
            "text/html; charset=utf-8",
            Bytes::from(autoindex(alias, &rel, &levels, &self.theme.read().await)),
        )
    }

    /// A directory's entries, from the cache when they are there.
    async fn listing_of(&self, session: &Session, dir: &str) -> Result<Vec<Entry>> {
        if let Some(entries) = self.cache.listing_entries(dir) {
            return Ok(entries);
        }
        let entries = session.fs.list_dir(dir).await?;
        self.cache.put_listing(dir, &entries);
        Ok(entries)
    }

    /// Which of these subdirectories are themselves sites.
    ///
    /// A directory holding an `index.html` is served *as* that page, so it is a site rather
    /// than a folder, and saying so is what souta actually asked for. Grouping the HTML in
    /// one listing does not find a Pinax board, because a board is `out/ft_demo/index.html`
    /// and the directory you are standing in has no HTML in it at all.
    ///
    /// One extra round trip, because every listing is issued together -- not one per
    /// subdirectory. It is spent on a directory listing and never on a page load, so the
    /// round-trip invariant for serving a page is untouched.
    ///
    /// It is also not purely a cost: the listings it fetches are the ones the next click
    /// needs, so stepping into any of these subdirectories afterwards costs nothing.
    async fn sites_among(
        &self,
        session: &Session,
        dir: &str,
        entries: &[Entry],
    ) -> HashSet<String> {
        /// Beyond this, the scan is buying less than it costs: a directory with hundreds of
        /// subdirectories is not one somebody is scanning by eye for a report.
        const MAX_SCAN: usize = 64;

        let names: Vec<&str> = entries
            .iter()
            .filter(|e| e.attrs.is_dir() && e.name != "." && e.name != ".." && !hidden(&e.name))
            .map(|e| e.name.as_str())
            .take(MAX_SCAN)
            .collect();
        if names.is_empty() {
            return HashSet::new();
        }

        let paths: Vec<String> = names.iter().map(|n| format!("{dir}/{n}")).collect();
        // Already-known listings are not asked for again. Going back up a level is the
        // ordinary case and would otherwise re-list every sibling.
        let missing: Vec<String> = paths
            .iter()
            .filter(|p| self.cache.listing_entries(p).is_none())
            .cloned()
            .collect();
        if !missing.is_empty() {
            for (path, got) in missing.iter().zip(session.fs.list_dirs(&missing).await) {
                if let Ok(entries) = got {
                    self.cache.put_listing(path, &entries);
                }
                // A subdirectory that cannot be listed is simply not a site. It is not an
                // error for this page: the reader asked for the directory they are in, and
                // a permission problem one level down is theirs to meet when they click.
            }
        }

        names
            .iter()
            .zip(paths.iter())
            .filter(|(_, path)| {
                self.cache.listing_entries(path).is_some_and(|listing| {
                    listing
                        .iter()
                        .any(|e| e.name == "index.html" && !e.attrs.is_dir())
                })
            })
            .map(|(name, _)| (*name).to_string())
            .collect()
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
            if self.first_symlink_cached(&chain).is_some() {
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
        // Prefetching only ever makes a page faster, so a directory that would not list is
        // not an error for the request that triggered it: the subresource is fetched the
        // ordinary way afterwards and fails, or does not, on its own terms.
        let held = self.held_listings(session, &all).await;

        let mut to_read = Vec::new();
        for (resolved, chain) in &wanted {
            if first_symlink(&held, chain).is_some() {
                continue;
            }
            let (dir, name) = &chain[chain.len() - 1];
            let Some(attrs) = attrs_in(&held, dir, name) else {
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
    /// Every directory along a path, taken out of the cache once and then held.
    ///
    /// Held, rather than looked up again as the walk goes. The cache has a two-second TTL,
    /// so asking whether a listing is there and then asking for the listing are two
    /// questions with a gap between them, and a request arriving on the boundary got `true`
    /// for the first and `false` for the second. That produced a 404 reading "cannot list"
    /// about a directory that plainly existed, on roughly one e2e run in six. Taking the
    /// entries once removes the gap rather than narrowing it.
    ///
    /// A failure carries the remote's own reason out. It used to be dropped and reported as
    /// "cannot list", which is this daemon saying it does not know rather than ssh saying
    /// why — the difference between a message somebody can act on and one they cannot.
    async fn listings_along(
        &self,
        session: &Session,
        chain: &[(String, String)],
    ) -> Result<HashMap<String, Vec<Entry>>, (String, String)> {
        let mut held: HashMap<String, Vec<Entry>> = HashMap::new();
        let mut missing: Vec<String> = Vec::new();
        for (dir, _) in chain {
            if held.contains_key(dir) {
                continue;
            }
            match self.cache.listing_entries(dir) {
                Some(entries) => {
                    held.insert(dir.clone(), entries);
                }
                // Deduplicated because the prefetcher passes the chains of many files at
                // once and several of them normally share a directory. Listing one twice in
                // a batch costs no extra round trip, but it does cost the remote the work.
                None if !missing.contains(dir) => missing.push(dir.clone()),
                None => {}
            }
        }
        if missing.is_empty() {
            return Ok(held);
        }
        for (dir, result) in missing.iter().zip(session.fs.list_dirs(&missing).await) {
            match result {
                Ok(entries) => {
                    self.cache.put_listing(dir, &entries);
                    held.insert(dir.clone(), entries);
                }
                // Absence is not a failure to report. A component that is not there, or
                // that is a file being used as a directory, is a 404 and the walk says so
                // on its own — answering 502 would blame the remote for a path the reader
                // got wrong. Anything else is the remote refusing, and that reason travels.
                Err(e) if crate::fs::is_absent(&e) => {}
                Err(e) => return Err((dir.clone(), format!("{e:#}"))),
            }
        }
        Ok(held)
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
    /// The same walk for the write path, over listings held for the same reason.
    ///
    /// A failure leaves the symlink check with nothing to check, and the write then fails
    /// with the remote's own reason. There is no better answer to give from here.
    async fn held_listings(
        &self,
        session: &Session,
        chain: &[(String, String)],
    ) -> HashMap<String, Vec<Entry>> {
        self.listings_along(session, chain)
            .await
            .unwrap_or_default()
    }
}

impl Origin {
    /// The symlink check over what is *already* cached and nothing more.
    ///
    /// The prefetcher runs this before it lists anything, so that a page cannot get a
    /// directory behind a symlink listed purely by naming it. Deliberately not the held
    /// version: the question here is what is known without asking.
    fn first_symlink_cached(&self, chain: &[(String, String)]) -> Option<String> {
        chain.iter().find_map(|(dir, name)| {
            self.cache
                .attrs_of(dir, name)
                .filter(Attrs::is_symlink)
                .map(|_| format!("{dir}/{name}"))
        })
    }
}

/// One entry's attrs, out of the listings this request is holding.
fn attrs_in(held: &HashMap<String, Vec<Entry>>, dir: &str, name: &str) -> Option<Attrs> {
    held.get(dir)
        .and_then(|entries| entries.iter().find(|e| e.name == name))
        .map(|e| e.attrs)
}

fn first_symlink(held: &HashMap<String, Vec<Entry>>, chain: &[(String, String)]) -> Option<String> {
    chain.iter().find_map(|(dir, name)| {
        attrs_in(held, dir, name)
            .filter(Attrs::is_symlink)
            .map(|_| format!("{dir}/{name}"))
    })
}

impl Origin {
    async fn alias_index(&self) -> String {
        let names = self.alias_names().await;
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

/// One entry of a directory, ready to be written into a row.
struct Row {
    name: String,
    dir: bool,
    /// Holds an `index.html`, so it is a site rather than a folder.
    site: bool,
    /// Absent for a directory, whose own size is its bookkeeping rather than its contents'.
    size: Option<String>,
    modified: Option<String>,
    /// Which colour its marker takes.
    kind: &'static str,
}

/// The rows of one directory, sorted and with the dot-names already gone.
fn rows_of(entries: &[Entry], sites: &HashSet<String>) -> Vec<Row> {
    let mut visible: Vec<&Entry> = entries
        .iter()
        // `.` and `..` are already gone by the time a path resolves; these are the real
        // dot-names. Listing what the next click would be refused is worse than silence.
        .filter(|e| e.name != "." && e.name != ".." && !hidden(&e.name))
        .collect();
    visible.sort_by(|a, b| (rank(a, sites), &a.name).cmp(&(rank(b, sites), &b.name)));

    visible
        .into_iter()
        .map(|e| {
            let dir = e.attrs.is_dir();
            Row {
                name: e.name.clone(),
                dir,
                site: dir && sites.contains(&e.name),
                size: if dir {
                    None
                } else {
                    e.attrs.size.map(human_size)
                },
                modified: e.attrs.mtime.map(utc_stamp),
                kind: if dir { "dir" } else { family(&e.name) },
            }
        })
        .collect()
}

/// Where an entry sorts, before its name is considered.
///
/// Directories first and no headings over them — souta's call, and it is how a file tree
/// has worked since long before anybody wrote one down. Within each half the thing you came
/// to open rises: a directory that *is* a page, and then an HTML file.
///
/// A Pinax board is `out/ft_demo/index.html`, so the directory holding it is what has to
/// rise. Sorting the HTML alone would never move anything, because the directory you are
/// standing in has no HTML in it at all.
fn rank(e: &Entry, sites: &HashSet<String>) -> (u8, u8) {
    if e.attrs.is_dir() {
        (0, u8::from(!sites.contains(&e.name)))
    } else {
        (1, u8::from(!is_page(&e.name)))
    }
}

fn is_page(name: &str) -> bool {
    matches!(extension_of(name).as_deref(), Some("html" | "htm"))
}

/// Which colour an entry's marker takes.
///
/// Families rather than extensions, because the point is to be readable without being read:
/// a `.toml` and a `.png` should not look the same, but `.toml` and `.json` may. This is
/// the one thing an editor's file tree does that a plain list does not.
fn family(name: &str) -> &'static str {
    match extension_of(name).as_deref() {
        Some("html" | "htm") => "k-page",
        Some("md" | "txt" | "rst" | "tex" | "bib" | "pdf" | "org" | "adoc") => "k-doc",
        Some("json" | "toml" | "yaml" | "yml" | "csv" | "tsv" | "xml" | "ini" | "lock") => "k-data",
        Some(
            "rs" | "jl" | "py" | "ts" | "js" | "mjs" | "sh" | "c" | "h" | "cpp" | "go" | "rb"
            | "lua" | "css" | "scss" | "lean" | "hs" | "java" | "kt" | "swift" | "sql",
        ) => "k-code",
        Some(
            "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "avif" | "ico" | "mp4" | "webm"
            | "mov" | "mp3" | "wav",
        ) => "k-media",
        _ => "k-plain",
    }
}

/// The lowercased extension, taken from the name.
fn extension_of(name: &str) -> Option<String> {
    let dot = name.rfind('.')?;
    // A leading dot is a hidden name rather than an extension, and a trailing one is not an
    // extension at all. Neither is served, but neither should be labelled as a type either.
    if dot == 0 || dot + 1 == name.len() {
        return None;
    }
    Some(name[dot + 1..].to_ascii_lowercase())
}

/// Bytes, the way a file manager shows them.
///
/// Binary multiples with the labels that actually mean them. Calling 1024 bytes `kB` is the
/// lie everyone tells, and this is a tool for people who would notice.
fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    // One decimal below ten and none above, so a column of sizes stays a column:
    // `9.4 MiB` and `312 MiB`, not `312.0 MiB`.
    if v < 10.0 {
        format!("{v:.1} {}", UNITS[unit])
    } else {
        format!("{v:.0} {}", UNITS[unit])
    }
}

/// `2026-09-13 05:44`, in UTC.
///
/// UTC because it is the only thing that can be said truthfully. SFTP reports seconds since
/// the epoch and says nothing about a zone; the remote's zone is not something this
/// transport can ask for, and using *this* machine's would stamp a file with an offset
/// belonging to a different computer. The column says so once, in the footer.
fn utc_stamp(secs: u32) -> String {
    let secs = i64::from(secs);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    let (hh, mm) = (rest / 3600, (rest % 3600) / 60);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

/// Howard Hinnant's `civil_from_days`: exact for every day this could be handed, and it
/// needs no calendar crate. Adding a dependency to print a date in a directory listing
/// would be a poor trade in a daemon that reads other people's filesystems.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The listing's layout.
///
/// Written entirely against the custom properties a theme supplies, so a new palette is a
/// new theme rather than a second copy of these rules. See `crate::theme`.
///
/// An editor's explorer: one line per entry, a twisty on the folders, an indent guide per
/// level, and a coloured chip for the type. souta asked for this twice — a flat list of one
/// directory is a listing, and what makes an explorer is the tree.
const LISTING_CSS: &str = "\
*{box-sizing:border-box}\
html{background:var(--bg)}\
body{color:var(--fg);font:13px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0}\
header{align-items:baseline;background:var(--bg);border-bottom:1px solid var(--line);\
display:flex;gap:6px;padding:7px 12px;position:sticky;top:0;z-index:1}\
header b{font-size:12px;font-weight:600;letter-spacing:.04em}\
header span{color:var(--dim);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\
font-size:11px;overflow-wrap:anywhere}\
#tree{padding:4px 0 40px}\
ul{list-style:none;margin:0;padding:0}\
li ul{border-left:1px solid var(--line);margin-left:15px}\
li>ul{display:none}\
li.open>ul{display:block}\
.row{align-items:center;color:inherit;display:grid;gap:6px;\
grid-template-columns:14px 14px 1fr auto auto;line-height:22px;padding-right:12px;\
text-decoration:none;white-space:nowrap}\
.row:hover{background:var(--hover)}\
.row.here{background:var(--sel)}\
.row:focus-visible{outline:1px solid var(--accent);outline-offset:-1px}\
.tw{color:var(--dim);font-size:11px;line-height:22px;text-align:center;\
transition:transform .1s linear}\
li.open>.row .tw{transform:rotate(90deg)}\
.ico{border-radius:2px;height:9px;justify-self:center;width:9px}\
.dir>.ico{background:var(--dim);border-radius:1px 3px 3px 3px}\
.site>.ico{background:var(--accent);border-radius:1px 3px 3px 3px}\
.site>.name{color:var(--accent)}\
.k-page>.ico{background:var(--k-page)}\
.k-page>.name{color:var(--k-page)}\
.k-doc>.ico{background:var(--k-doc)}\
.k-data>.ico{background:var(--k-data)}\
.k-code>.ico{background:var(--k-code)}\
.k-media>.ico{background:var(--k-media)}\
.k-plain>.ico{background:var(--k-plain)}\
.name{overflow:hidden;text-overflow:ellipsis}\
.size,.when{color:var(--faint);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\
font-size:11px;font-variant-numeric:tabular-nums}\
.size{text-align:right}\
.row.busy .tw{opacity:.4}\
.row.failed .when{color:var(--k-page)}\
.empty{color:var(--faint);padding:10px 16px}\
@media(max-width:620px){.when{display:none}}";

/// Expanding a folder, and nothing else.
///
/// The daemon's own page, so its script is the daemon's too — nothing is ever added to a
/// document the reader came for. It is small because the server renders the rows: this asks
/// for a level and puts it where it goes.
///
/// Without it every level costs a page load, and the tree still works that way: every row is
/// a real link to a real URL, so a browser with no script at all walks the tree one
/// directory at a time, exactly as the old listing did.
const LISTING_JS: &str = "\
const tree=document.getElementById('tree');\
tree.addEventListener('click',async e=>{\
const row=e.target.closest('a.row');\
if(!row||row.dataset.dir!=='1')return;\
e.preventDefault();\
const li=row.parentElement;\
if(li.querySelector(':scope>ul')){li.classList.toggle('open');mark(row);return;}\
row.classList.add('busy');\
try{\
const res=await fetch(row.getAttribute('href')+'?ls');\
if(!res.ok)throw new Error(res.status);\
li.insertAdjacentHTML('beforeend',await res.text());\
li.classList.add('open');mark(row);\
}catch(err){row.classList.add('failed');\
row.querySelector('.when').textContent='could not be listed: '+err.message;}\
finally{row.classList.remove('busy');}\
});\
function mark(row){\
for(const other of tree.querySelectorAll('a.row.here'))other.classList.remove('here');\
row.classList.add('here');\
history.replaceState(null,'',row.getAttribute('href'));\
document.querySelector('header span').textContent=\
decodeURIComponent(new URL(row.href).pathname);\
}";

/// One level of the tree: a `<ul>` of rows, with the one on the path already expanded.
///
/// `open` is the rest of the path from here down, so a level knows which of its folders the
/// reader is inside. Empty means nothing below is expanded, which is what `?ls` hands back
/// for a folder somebody has just clicked.
fn render_level(out: &mut String, path: &str, rows: &[Row], open: &[(String, Vec<Row>)]) {
    out.push_str("<ul>");
    for row in rows {
        let here = format!("{path}/{}", row.name);
        let deeper = open.first().filter(|(next, _)| *next == here);

        out.push_str(if deeper.is_some() {
            "<li class=\"open\">"
        } else {
            "<li>"
        });
        out.push_str("<a class=\"row ");
        out.push_str(match (row.dir, row.site) {
            // A directory holding an `index.html` is served *as* that page, so it is marked
            // as somewhere to read rather than somewhere to look.
            (true, true) => "site",
            (true, false) => "dir",
            (false, _) => row.kind,
        });
        // The deepest expanded folder is where the reader is, so the tree opens with it
        // selected the way an explorer shows the file you have open.
        if deeper.is_some() && open.len() == 1 {
            out.push_str(" here");
        }
        out.push_str("\" href=\"");
        out.push_str(path);
        out.push('/');
        out.push_str(&url_escape(&row.name));
        if row.dir {
            out.push('/');
        }
        // Read by the script to tell a folder from a file without picking through classes.
        out.push_str(if row.dir {
            "\" data-dir=\"1\"><span class=\"tw\">\u{25b8}</span>"
        } else {
            "\"><span class=\"tw\"></span>"
        });
        out.push_str("<span class=\"ico\"></span><span class=\"name\">");
        out.push_str(&escape(&row.name));
        out.push_str("</span><span class=\"size\">");
        out.push_str(row.size.as_deref().unwrap_or(""));
        out.push_str("</span><span class=\"when\">");
        out.push_str(row.modified.as_deref().unwrap_or(""));
        out.push_str("</span></a>");

        if let Some((next, rows)) = deeper {
            render_level(out, next, rows, &open[1..]);
        }
        out.push_str("</li>");
    }
    out.push_str("</ul>");
}

/// A directory, as a tree.
///
/// `levels` runs from the alias base down to where the reader is, each already sorted, so
/// the page opens with the whole path expanded and the rest of every level beside it. They
/// come out of the cache the path walk already filled, so the depth costs no round trips.
fn autoindex(alias: &str, rel: &str, levels: &[(String, Vec<Row>)], theme: &str) -> String {
    let shown = if rel.is_empty() { "/" } else { rel };
    let mut s = String::from("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>");
    s.push_str(&escape(&format!("{shown} \u{b7} {alias}")));
    s.push_str("</title><style>");
    // The palette first, then the layout that reads it.
    s.push_str(&theme::css_for(theme));
    s.push_str(LISTING_CSS);
    s.push_str("</style></head><body><header><b>");
    s.push_str(&escape(alias));
    s.push_str("</b><span>");
    s.push_str(&escape(shown));
    s.push_str("</span></header><div id=\"tree\">");

    match levels.split_first() {
        Some(((path, rows), rest)) if !rows.is_empty() => render_level(&mut s, path, rows, rest),
        // An alias whose base holds nothing. Saying so beats a blank page, which reads as
        // something having gone wrong.
        _ => s.push_str("<p class=\"empty\">This directory is empty.</p>"),
    }

    s.push_str("</div><script>");
    s.push_str(LISTING_JS);
    s.push_str("</script></body></html>");
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

    /// A loopback request carrying no token, and whatever the browser would have said
    /// about who started it.
    fn from_site(path: &str, site: Option<&str>) -> Request<Empty<Bytes>> {
        let mut b = Request::builder().uri(path).header(HOST, "127.0.0.1:7391");
        if let Some(site) = site {
            b = b.header(control::FETCH_SITE_HEADER, site);
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
        origin_with_cache(remote, Cache::default()).await
    }

    async fn origin_with_cache(remote: FakeRemote, cache: Cache) -> Origin {
        let fs = remote.spawn().await;
        let mut sessions = HashMap::new();
        sessions.insert(
            "docs".to_string(),
            Arc::new(Session {
                host: "nowhere".to_string(),
                base: "/srv".to_string(),
                fs,
            }),
        );
        Origin {
            suffix: "ssh-browser".to_string(),
            port: 7391,
            sessions: RwLock::new(sessions),
            cache,
            theme: RwLock::new(theme::DEFAULT.to_string()),
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

    async fn trips(origin: &Origin) -> u64 {
        origin
            .sessions
            .read()
            .await
            .values()
            .map(|s| s.fs.round_trips())
            .sum()
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

        let before = trips(&origin).await;
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
            trips(&origin).await - before,
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
            let before = trips(&origin).await;
            let res = origin.handle(get("/index.html", None)).await;
            assert_eq!(res.status(), StatusCode::OK);
            trips(&origin).await - before
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
        let before = trips(&origin).await;
        let res = origin.handle(get("/index.html", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        trips(&origin).await - before
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
        let before = trips(&origin).await;
        let res = origin.handle(get("/assets/x.png", None)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(&body_of(res).await[..], b"xxx");
        assert_eq!(
            trips(&origin).await - before,
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

            let before = trips(&origin).await;
            assert_eq!(
                origin.handle(get("/index.html", None)).await.status(),
                StatusCode::OK
            );
            let spent = trips(&origin).await - before;

            // And it really was warmed, so the comparison is between two prefetches rather
            // than between a prefetch and a skip.
            let at = trips(&origin).await;
            let res = origin.handle(get("/assets/big.bin", None)).await;
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(body_of(res).await.len(), bytes);
            assert_eq!(
                trips(&origin).await - at,
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
            let before = trips(&origin).await;
            assert_eq!(
                origin.handle(get("/index.html", None)).await.status(),
                StatusCode::OK
            );
            trips(&origin).await - before
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
            vec![Alias::new("docs", NOWHERE, Some("/srv")).expect("a valid alias")],
            "ssh-browser".to_string(),
            port,
            Token::from_hex(TEST_TOKEN),
            "souta".to_string(),
            theme::DEFAULT.to_string(),
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

    /// One directory as a tree with nothing above it, which is every test that is not about
    /// the ancestors or the site scan. Both of those need a remote; these do not.
    fn listing(alias: &str, rel: &str, entries: &[Entry]) -> String {
        let levels = vec![(rel.to_string(), rows_of(entries, &HashSet::new()))];
        autoindex(alias, rel, &levels, theme::DEFAULT)
    }

    #[test]
    fn a_hostile_filename_cannot_inject_script_into_our_origin() {
        let page = listing("docs", "", &[entry("<script>alert(1)</script>", false)]);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;"));
    }

    /// Directories first and no headings, which is souta's call. Within the files the HTML
    /// rises, which is the other half of what they asked for.
    #[test]
    fn directories_come_first_and_pages_lead_the_files() {
        let page = listing(
            "docs",
            "",
            &[
                entry("b.txt", false),
                entry("z-dir", true),
                entry("a.txt", false),
                entry("report.html", false),
            ],
        );
        let dir = page.find("z-dir").expect("dir listed");
        let html = page.find("report.html").expect("page listed");
        let a = page.find("a.txt").expect("a listed");
        let b = page.find("b.txt").expect("b listed");
        assert!(
            dir < html,
            "directories come first, whatever they are called"
        );
        assert!(html < a, "then the pages, ahead of the other files");
        assert!(a < b, "and the rest by name");
        // No headings at all. They are what souta called 「みずらい」.
        assert!(!page.contains("<h2"), "{page}");
    }

    /// A page is decided by what the name *is*, so a file whose extension merely contains
    /// `html` is an ordinary file. `.htm` is the one other spelling worth accepting.
    #[test]
    fn only_html_counts_as_a_page() {
        let page = listing(
            "docs",
            "",
            &[
                entry("a.htm", false),
                entry("b.html.bak", false),
                entry("c.xhtml", false),
            ],
        );
        let htm = page.find("a.htm").expect("htm listed");
        let bak = page.find("b.html.bak").expect("bak listed");
        let xhtml = page.find("c.xhtml").expect("xhtml listed");
        assert!(htm < bak && htm < xhtml, "only the .htm leads: {page}");
        // And it is coloured as one, which is the only signal left now that the headings
        // are gone.
        assert!(
            page.contains("class=\"row k-page\" href=\"/a.htm\""),
            "{page}"
        );
    }

    #[test]
    fn hrefs_are_url_escaped() {
        let page = listing("docs", "", &[entry("a b#c.html", false)]);
        assert!(page.contains("href=\"/a%20b%23c.html\""));
    }

    /// The header says where you are. An explorer does not make you read the address bar
    /// to know which folder you are looking at.
    #[test]
    fn the_header_names_the_alias_and_where_you_are() {
        let page = listing("panza", "/Vault/infra", &[]);
        assert!(page.contains("<b>panza</b>"), "{page}");
        assert!(page.contains("<span>/Vault/infra</span>"), "{page}");
    }

    /// The point of a tree rather than a listing: every level of the path is open at once,
    /// with the rest of each level beside it, and the deepest is the one selected.
    ///
    /// It costs no round trips beyond the listing it replaces, because the walk that
    /// resolved the path warmed every ancestor to check it for symlinks — see
    /// `the_tree_costs_what_one_directory_cost`.
    #[tokio::test]
    async fn the_whole_path_is_expanded_and_the_deepest_is_selected() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("a", dir_attrs()), ("elsewhere", dir_attrs())])
                .dir("/srv/a", vec![("b", dir_attrs()), ("sibling", dir_attrs())])
                .dir("/srv/a/b", vec![("leaf.txt", file_attrs(3, 1))])
                .dir("/srv/elsewhere", vec![])
                .dir("/srv/a/sibling", vec![]),
        )
        .await;

        let body = String::from_utf8(
            body_of(origin.handle(get("/a/b/", None)).await)
                .await
                .to_vec(),
        )
        .expect("utf-8");

        // Both levels of the path are open...
        assert!(body.contains("<li class=\"open\">"), "{body}");
        assert!(body.contains("href=\"/a/\""), "{body}");
        // ...the deepest is the one marked as where the reader is...
        assert!(body.contains("row dir here\" href=\"/a/b/\""), "{body}");
        // ...what is inside it is rendered...
        assert!(body.contains("leaf.txt"), "{body}");
        // ...and so is everything beside it on the way down, which is what makes this a
        // tree rather than one directory at a time.
        assert!(body.contains("elsewhere"), "{body}");
        assert!(body.contains("sibling"), "{body}");
    }

    /// The tree is four levels of listing, and it must cost what one level cost. Every
    /// ancestor was already fetched to check it for symlinks, so showing them is free; a
    /// version that went and asked again would pay for the depth twice.
    #[tokio::test]
    async fn the_tree_costs_what_one_directory_cost() {
        let deep = origin_with(deep_tree()).await;
        let before = trips(&deep).await;
        assert_eq!(
            deep.handle(get("/a/b/c/", None)).await.status(),
            StatusCode::OK
        );
        let four = trips(&deep).await - before;

        let shallow = origin_with(one_page()).await;
        let before = trips(&shallow).await;
        assert_eq!(
            shallow.handle(get("/", None)).await.status(),
            StatusCode::OK
        );
        let one = trips(&shallow).await - before;

        // The slack absorbs a flush of fire-and-forget CLOSE requests landing on either
        // side of the measurement. Asking per level would cost about four times as many.
        assert!(
            four <= one + 2,
            "a tree four deep cost {four} round trips against {one} for one directory"
        );
    }

    /// What the script asks for when a folder is expanded: the same level, as the fragment
    /// that goes inside it. One renderer, so the two cannot disagree about what a row is.
    #[tokio::test]
    async fn asking_for_one_level_answers_with_its_rows() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("sub", dir_attrs())])
                .dir("/srv/sub", vec![("inner.md", file_attrs(4, 1))]),
        )
        .await;

        let req = Request::builder()
            .uri("http://docs.ssh-browser/sub/?ls")
            .header(HOST, "docs.ssh-browser")
            .body(Empty::<Bytes>::new())
            .expect("request builds");
        let res = origin.handle(req).await;
        assert_eq!(res.status(), StatusCode::OK);

        let body = String::from_utf8(body_of(res).await.to_vec()).expect("utf-8");
        // A fragment, so it can be inserted where it belongs rather than replacing a page.
        assert!(body.starts_with("<ul>"), "{body}");
        assert!(!body.contains("<html"), "{body}");
        // Built against the level it was asked about, so the href works from anywhere.
        assert!(body.contains("href=\"/sub/inner.md\""), "{body}");
    }

    /// It adds no capability. Everything `?ls` says is already in the page it belongs to,
    /// and a dot-name is refused here exactly as it is everywhere else.
    #[tokio::test]
    async fn asking_for_one_level_does_not_mention_dot_names() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("sub", dir_attrs())])
                .dir(
                    "/srv/sub",
                    vec![("shown.md", file_attrs(4, 1)), (".hidden", dir_attrs())],
                ),
        )
        .await;

        let req = Request::builder()
            .uri("http://docs.ssh-browser/sub/?ls")
            .header(HOST, "docs.ssh-browser")
            .body(Empty::<Bytes>::new())
            .expect("request builds");
        let body =
            String::from_utf8(body_of(origin.handle(req).await).await.to_vec()).expect("utf-8");
        assert!(body.contains("shown.md"), "{body}");
        assert!(!body.contains(".hidden"), "{body}");
    }

    #[test]
    fn sizes_read_the_way_a_file_manager_shows_them() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        // One decimal below ten and none above, so a column of them stays a column.
        assert_eq!(human_size(10 * 1024 * 1024), "10 MiB");
        assert_eq!(human_size(9_961_472), "9.5 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    /// Checked against dates that are known independently of the algorithm, including the
    /// epoch itself and a leap day, which is where a calendar implementation goes wrong.
    #[test]
    fn timestamps_are_the_utc_civil_date() {
        assert_eq!(utc_stamp(0), "1970-01-01 00:00");
        assert_eq!(utc_stamp(86_399), "1970-01-01 23:59");
        assert_eq!(utc_stamp(86_400), "1970-01-02 00:00");
        // 2000-02-29, a leap day in a century year that is a leap year.
        assert_eq!(utc_stamp(951_782_400), "2000-02-29 00:00");
        // 2100 is divisible by 4 and by 100 but not by 400, so it is *not* a leap year and
        // the day after 2100-02-28 is 2100-03-01. Getting this wrong is the classic way a
        // hand-rolled calendar fails, and the two constants below are one day apart.
        assert_eq!(utc_stamp(4_107_456_000), "2100-02-28 00:00");
        assert_eq!(utc_stamp(4_107_542_400), "2100-03-01 00:00");
        assert_eq!(utc_stamp(1_757_745_840), "2025-09-13 06:44");
    }

    /// A listing of nothing says so. An empty page with a heading over it reads as a
    /// failure rather than as an empty directory.
    #[test]
    fn an_empty_directory_says_it_is_empty() {
        let page = listing("docs", "/nothing", &[]);
        assert!(page.contains("This directory is empty"), "{page}");
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
        let after_first = trips(&origin).await;
        assert!(after_first > 0, "the first request has to fetch something");

        let second = origin.handle(get("/a.html", None)).await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            trips(&origin).await,
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
        let after_first = trips(&origin).await;

        let second = origin.handle(get("/a.html", Some(&tag))).await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            trips(&origin).await,
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
        let warm = trips(&origin).await;

        let missing = origin.handle(get("/nope.html", None)).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            trips(&origin).await,
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

        let (d, sh) = (trips(&deep).await, trips(&shallow).await);
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
        let warm = trips(&origin).await;

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
            trips(&origin).await,
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

        let warm = trips(&origin).await;
        let again = origin.handle(ranged("/a.html", "bytes=2-4")).await;
        assert_eq!(&body_of(again).await[..], b"llo");
        assert_eq!(
            trips(&origin).await,
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

        let after = trips(&origin).await;
        let second = origin.handle(ranged("/big.bin", "bytes=10-19")).await;
        assert_eq!(&body_of(second).await[..], &body[10..20]);
        assert!(
            trips(&origin).await > after,
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

    /// The form souta asked for: bring the home directory into the config rather than
    /// writing out another machine's account layout by hand.
    #[tokio::test]
    async fn a_base_may_be_written_relative_to_the_home_directory() {
        let fs = FakeRemote::new().home("/home/souta").spawn().await;
        assert_eq!(
            resolve_base(Some("~/work"), &fs).await.expect("resolves"),
            "/home/souta/work"
        );
    }

    /// Three spellings of the same thing, and they had better agree.
    #[tokio::test]
    async fn a_bare_tilde_and_no_base_are_both_the_home_directory() {
        let fs = FakeRemote::new().home("/home/souta").spawn().await;
        assert_eq!(
            resolve_base(None, &fs).await.expect("resolves"),
            "/home/souta"
        );
        assert_eq!(
            resolve_base(Some("~"), &fs).await.expect("resolves"),
            "/home/souta"
        );
    }

    /// An absolute base is already the answer, so asking the remote would be a round trip
    /// spent to be told something already written down.
    #[tokio::test]
    async fn an_absolute_base_costs_no_round_trip() {
        let fs = FakeRemote::new().home("/home/souta").spawn().await;
        let before = fs.round_trips();
        assert_eq!(
            resolve_base(Some("/srv/docs"), &fs)
                .await
                .expect("resolves"),
            "/srv/docs"
        );
        assert_eq!(fs.round_trips(), before, "an absolute base must not ask");
    }

    /// The base is the blast radius of every page served under it, so a base that quietly
    /// meant somewhere other than where it reads is the worst place for a surprise.
    #[test]
    fn a_base_that_could_climb_out_of_the_home_directory_is_refused() {
        for bad in [
            "~/..",
            "~/../.ssh",
            "~/work/../..",
            "~/./x",
            "~work",
            "work",
            "",
        ] {
            assert!(!is_base(bad), "should have been refused: {bad:?}");
            assert!(
                Alias::new("docs", "h", Some(bad)).is_err(),
                "should have been refused: {bad:?}"
            );
        }
        for good in ["/", "/srv", "~", "~/work", "~/a/b/c"] {
            assert!(is_base(good), "should have been accepted: {good:?}");
        }
    }

    /// A home of `/` is unusual and not impossible, and `//work` is not portably the same
    /// path as `/work`: POSIX leaves a leading double slash implementation-defined.
    #[tokio::test]
    async fn a_root_home_does_not_produce_a_doubled_slash() {
        let fs = FakeRemote::new().home("/").spawn().await;
        assert_eq!(resolve_base(None, &fs).await.expect("resolves"), "/");
        assert_eq!(
            resolve_base(Some("~/work"), &fs).await.expect("resolves"),
            "/work"
        );
    }

    /// Deliberately asserts nothing about which hosts come back: the answer is whatever
    /// this machine's ssh_config says, and a test that pinned it would pass on one
    /// machine and fail on every other. What it does catch is the route not being wired
    /// up, which is otherwise only visible by hand.
    ///
    /// The token is not checked here because it cannot be reached without one: the gate
    /// runs in `handle` before any route is dispatched, so no control route can have its
    /// own answer to that question.
    #[tokio::test]
    async fn the_host_list_is_a_control_route() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(loopback("/_control/hosts", Some(TEST_TOKEN)))
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        let text = String::from_utf8(body_of(res).await.to_vec()).expect("utf-8");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert!(parsed.get("hosts").is_some_and(|h| h.is_array()), "{text}");
        assert!(
            parsed.get("unusable").is_some_and(|u| u.is_array()),
            "{text}"
        );
    }

    /// The check that keeps `open` from being "ssh to anything on request". The list the
    /// extension offers is the menu, and a host that is not on it is a config change,
    /// which is a deliberate act rather than one request.
    ///
    /// The name is nonsense on purpose, so this asserts the same thing on a machine with
    /// an ssh_config and on one without.
    #[tokio::test]
    async fn opening_a_host_ssh_does_not_know_is_refused() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/open",
                Some(TEST_TOKEN),
                r#"{"host":"not-a-host-in-anyones-ssh-config.invalid"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// A body that does not name a host, and one that names a field this does not have.
    /// The second matters for the same reason the config file refuses unknown keys: a
    /// quietly dropped `base_path` opens an alias at somewhere nobody chose.
    #[tokio::test]
    async fn an_open_request_that_is_not_one_is_refused() {
        let origin = origin_with(one_page()).await;
        for body in [
            "",
            "{}",
            r#"{"base":"/srv"}"#,
            r#"{"host":"docs","base_path":"/srv"}"#,
        ] {
            let res = origin
                .handle(control_post("/_control/open", Some(TEST_TOKEN), body))
                .await;
            assert_eq!(
                res.status(),
                StatusCode::BAD_REQUEST,
                "should have been refused: {body}"
            );
        }
    }

    /// `open` has a side effect, so it is the route where the token matters most: a page
    /// can send a simple POST without a preflight, and could not read the answer but
    /// would still have caused the thing to happen.
    #[tokio::test]
    async fn opening_a_host_needs_the_token() {
        let origin = origin_with(one_page()).await;
        for token in [None, Some("wrong")] {
            let res = origin
                .handle(control_post("/_control/open", token, r#"{"host":"docs"}"#))
                .await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "token {token:?}");
        }
    }

    /// What removes the paste, and the check that makes it safe to.
    ///
    /// The header values are the measured ones: an extension's `fetch` arrives with no
    /// `Sec-Fetch-Site` value this daemon would call a page, and a page the daemon itself
    /// serves in fallback mode arrives as `same-origin` -- the hardest case, because it
    /// shares an origin with the control API.
    #[tokio::test]
    async fn the_token_is_handed_over_to_something_that_is_not_a_page() {
        let origin = origin_with(one_page()).await;
        for site in [None, Some("none")] {
            let res = origin.handle(from_site("/_control/token", site)).await;
            assert_eq!(res.status(), StatusCode::OK, "site {site:?}");
            let body = String::from_utf8(body_of(res).await.to_vec()).expect("utf-8");
            assert_eq!(body.trim(), TEST_TOKEN, "site {site:?}");
        }
    }

    #[tokio::test]
    async fn a_page_is_not_handed_the_token() {
        let origin = origin_with(one_page()).await;
        for site in ["same-origin", "same-site", "cross-site"] {
            let res = origin
                .handle(from_site("/_control/token", Some(site)))
                .await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "site {site}");
            let body = String::from_utf8(body_of(res).await.to_vec()).expect("utf-8");
            assert!(!body.contains(TEST_TOKEN), "the refusal leaked it: {body}");
        }
    }

    /// The case the token alone could not refuse: a page in the no-proxy fallback mode is
    /// same-origin with the control API, so a leaked token would have been enough.
    #[tokio::test]
    async fn a_page_with_the_token_still_cannot_use_the_control_api() {
        let origin = origin_with(one_page()).await;
        let req = Request::builder()
            .uri("http://127.0.0.1:7391/_control/hello")
            .header(HOST, "127.0.0.1:7391")
            .header(control::TOKEN_HEADER, TEST_TOKEN)
            .header(control::FETCH_SITE_HEADER, "same-origin")
            .body(Full::new(Bytes::new()))
            .expect("request builds");
        assert_eq!(origin.handle(req).await.status(), StatusCode::FORBIDDEN);
    }

    /// The other half of `open`, and the way a base gets changed: close, then reopen.
    #[tokio::test]
    async fn an_alias_can_be_closed_and_is_then_gone() {
        let origin = origin_with(one_page()).await;
        assert_eq!(
            origin.handle(get("/a.html", None)).await.status(),
            StatusCode::OK
        );

        let res = origin
            .handle(control_post(
                "/_control/close",
                Some(TEST_TOKEN),
                r#"{"alias":"docs"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::OK);

        // The origin stops answering, rather than answering with stale bytes out of the
        // cache. An alias that is closed but still serving would be the worst of both.
        assert_eq!(
            origin.handle(get("/a.html", None)).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    /// Kept apart from success. Told neither, a caller cannot tell "closed it" from
    /// "there was nothing there", and the second usually means a typo.
    #[tokio::test]
    async fn closing_an_alias_that_is_not_open_says_so() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post(
                "/_control/close",
                Some(TEST_TOKEN),
                r#"{"alias":"nope"}"#,
            ))
            .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn closing_an_alias_needs_the_token() {
        let origin = origin_with(one_page()).await;
        let res = origin
            .handle(control_post("/_control/close", None, r#"{"alias":"docs"}"#))
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        // And it must not have happened anyway.
        assert_eq!(
            origin.handle(get("/a.html", None)).await.status(),
            StatusCode::OK
        );
    }

    /// souta's actual problem, in miniature. `out/` contains no HTML of its own; the board
    /// is `out/ft_demo/index.html`. Grouping the HTML in one listing would never surface
    /// it, so a directory that *is* a page has to say so.
    #[tokio::test]
    async fn a_directory_holding_an_index_is_listed_as_a_site() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("ft-demo", dir_attrs()), ("src", dir_attrs())])
                .dir("/srv/ft-demo", vec![("index.html", file_attrs(5, 1))])
                .dir("/srv/src", vec![("main.jl", file_attrs(5, 1))])
                .file("/srv/ft-demo/index.html", b"board"),
        )
        .await;

        let body = String::from_utf8(body_of(origin.handle(get("/", None)).await).await.to_vec())
            .expect("utf-8");
        // Marked, so it reads as somewhere to open rather than somewhere to look. With no
        // headings left, the class and its colour are the whole signal.
        assert!(
            body.contains("class=\"row site\" href=\"/ft-demo/\""),
            "{body}"
        );
        let demo = body.find("ft-demo/").expect("the site listed");
        let src = body.find("src/").expect("the folder listed");
        assert!(demo < src, "a site leads the other directories: {body}");
    }

    /// The invariant, on the one page that pays for the scan. One listing for the directory
    /// and one batch for all of its subdirectories, whether there are two or twenty -- not
    /// one round trip each, which is what a loop would cost and what would make browsing a
    /// deep tree unusable over a real link.
    #[tokio::test]
    async fn the_site_scan_costs_the_same_however_many_subdirectories() {
        async fn trips_for(n: usize) -> u64 {
            let names: Vec<String> = (0..n).map(|i| format!("d{i:02}")).collect();
            let mut remote = FakeRemote::new().dir(
                "/srv",
                names.iter().map(|s| (s.as_str(), dir_attrs())).collect(),
            );
            for name in &names {
                remote = remote.dir(&format!("/srv/{name}"), vec![("a.txt", file_attrs(1, 1))]);
            }
            let origin = origin_with(remote).await;
            let before = trips(&origin).await;
            assert_eq!(origin.handle(get("/", None)).await.status(), StatusCode::OK);
            trips(&origin).await - before
        }

        let few = trips_for(2).await;
        let many = trips_for(20).await;
        assert_eq!(
            few, many,
            "{many} round trips for twenty subdirectories against {few} for two"
        );
    }

    /// And stepping into one of them is free afterwards, because the scan already fetched
    /// exactly the listing that click needs. The extra round trip is not purely a cost.
    #[tokio::test]
    async fn the_scan_leaves_the_next_click_paid_for() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("sub", dir_attrs())])
                .dir("/srv/sub", vec![("a.txt", file_attrs(1, 1))]),
        )
        .await;
        assert_eq!(origin.handle(get("/", None)).await.status(), StatusCode::OK);

        let before = trips(&origin).await;
        assert_eq!(
            origin.handle(get("/sub/", None)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            trips(&origin).await,
            before,
            "the listing the scan fetched should still be the one that answers"
        );
    }

    /// The race a two-second TTL made possible, forced to happen every time.
    ///
    /// The walk used to ask the cache whether a listing was there and then ask it for the
    /// listing. Those are two questions with a gap between them, and a request landing on
    /// the expiry boundary got yes and then no -- a 404 reading "cannot list" about a
    /// directory that plainly existed, on about one e2e run in six. With a TTL of zero
    /// every read misses, so the gap is guaranteed rather than occasional.
    ///
    /// It passes because the listings are taken once and held for the request. Nothing here
    /// can make them expire, because nothing re-reads them.
    #[tokio::test]
    async fn a_listing_that_expires_mid_request_does_not_lose_the_path() {
        let origin =
            origin_with_cache(deep_tree(), Cache::new(std::time::Duration::ZERO, 1 << 20)).await;
        assert_eq!(
            origin.handle(get("/a/b/c/d.html", None)).await.status(),
            StatusCode::OK,
            "a path four deep must survive its own listings expiring"
        );
        // And a directory too, which is the one that builds a tree out of them.
        assert_eq!(
            origin.handle(get("/a/b/c/", None)).await.status(),
            StatusCode::OK
        );
    }

    /// The other half: a refusal that is not absence carries ssh's own words out, rather
    /// than this daemon's word for not knowing.
    #[tokio::test]
    async fn a_directory_the_remote_refuses_says_why() {
        let origin = origin_with(
            FakeRemote::new()
                .dir("/srv", vec![("locked", dir_attrs())])
                // 3 is SSH_FX_PERMISSION_DENIED: refused, and not for being absent.
                .refuses_listing("/srv/locked", 3),
        )
        .await;

        let res = origin.handle(get("/locked/x.html", None)).await;
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        let said = String::from_utf8(body_of(res).await.to_vec()).expect("utf-8");
        assert!(said.contains("/srv/locked"), "{said}");
        assert!(
            !said.contains("cannot list"),
            "the old wording said nothing the reader could act on: {said}"
        );
    }
}
