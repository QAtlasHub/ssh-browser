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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, HOST, IF_NONE_MATCH, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::cache::{self, Cache};
use crate::fs::sftp::SftpFs;
use crate::fs::{Entry, RemoteFs};

pub struct Alias {
    pub name: String,
    pub host: String,
    pub base: String,
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
}

impl Origin {
    /// Connect every alias up front, so the first page request does not also pay
    /// for an ssh handshake.
    pub async fn bind(aliases: Vec<Alias>, suffix: String, port: u16) -> Result<Arc<Self>> {
        let mut sessions = HashMap::new();
        for a in aliases {
            let fs = SftpFs::connect(&a.host)
                .await
                .with_context(|| format!("alias {} -> ssh host {}", a.name, a.host))?;
            sessions.insert(a.name, Session { base: a.base, fs });
        }
        Ok(Arc::new(Self {
            suffix,
            port,
            sessions,
            cache: Cache::default(),
        }))
    }

    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind {addr}"))?;

        loop {
            let (stream, _) = listener.accept().await?;
            let me = Arc::clone(&self);
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

    /// Generic over the body type so a test can drive it without constructing
    /// hyper's `Incoming`, which only a real connection can produce.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<Full<Bytes>> {
        let Some(host) = host_of(&req) else {
            return fail(StatusCode::BAD_REQUEST, "request carries no Host");
        };
        let path = req.uri().path().to_string();
        let inm = req
            .headers()
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        match guard::classify(&host, &path, &self.suffix, self.port) {
            // Refusing by Host is the DNS-rebinding defence, not a malfunction, so
            // it says why rather than failing blankly.
            Err(e) => fail(StatusCode::FORBIDDEN, format!("{e:#}")),
            Ok(guard::Target::Direct { path }) => self.direct(path, inm.as_deref()).await,
            Ok(guard::Target::Alias { alias, path }) => {
                self.alias(alias, path, inm.as_deref()).await
            }
        }
    }

    async fn direct(&self, path: &str, inm: Option<&str>) -> Response<Full<Bytes>> {
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
        self.alias(alias, &format!("/{sub}"), inm).await
    }

    async fn alias(&self, alias: &str, path: &str, inm: Option<&str>) -> Response<Full<Bytes>> {
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

        // Fetch every ancestor listing not already held, together. This is what
        // `list_dirs` being a batch buys: checking a path of depth d costs one round
        // trip rather than d of them, so depth cannot leak into the per-request
        // budget. Warm, it costs none.
        let missing: Vec<String> = chain
            .iter()
            .map(|(dir, _)| dir.clone())
            .filter(|dir| !self.cache.has_listing(dir))
            .collect();
        if !missing.is_empty() {
            for (dir, result) in missing.iter().zip(session.fs.list_dirs(&missing).await) {
                // A directory that cannot be listed is diagnosed by the walk below,
                // which can report it against the path the request actually named.
                if let Ok(entries) = result {
                    self.cache.put_listing(dir, &entries);
                }
            }
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

            // A symlink may point outside the base, and finding out needs a REALPATH
            // per request. Refusing costs nothing and never lies. Checking *every*
            // component rather than only the last is what closes the hole SECURITY.md
            // used to describe.
            if attrs.is_symlink() {
                return fail(
                    StatusCode::FORBIDDEN,
                    format!("refusing symlink at {dir}/{name} (its target is not checked)"),
                );
            }
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
        // Nested rather than written as a let-chain: those stabilised in 1.88 and
        // the declared MSRV here is 1.85.
        if let (Some(tag), Some(header)) = (tag.as_deref(), inm) {
            if cache::etag_matches(header, tag) {
                return not_modified(tag);
            }
        }

        if let Some(body) = self.cache.body(&file, &attrs) {
            return served(mime::guess(&file), body, tag.as_deref());
        }

        let mut got = session.fs.read_batch(std::slice::from_ref(&file)).await;
        match got.pop() {
            Some(Ok(body)) => {
                let body = Bytes::from(body);
                self.cache.put_body(&file, &attrs, body.clone());
                served(mime::guess(&file), body, tag.as_deref())
            }
            // The listing promised this file and the remote refused it, so the
            // listing is wrong. Holding it for the rest of its TTL would repeat the
            // same wrong answer.
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
        .header(CACHE_CONTROL, "no-cache");
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
fn autoindex(path: &str, entries: &[Entry]) -> String {
    let mut visible: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
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
    use http_body_util::Empty;

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
}
