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
        let (parent, name) = split_parent(&file);

        // One listing of the parent settles existence, kind, symlink-ness and
        // freshness. Everything below is either answered from it or is a single
        // fetch; nothing here costs a round trip per path component.
        if !self.cache.has_listing(parent) {
            match session.fs.list_dir(parent).await {
                Ok(entries) => self.cache.put_listing(parent, &entries),
                // A parent that cannot be listed is not necessarily absent -- it may
                // be unreadable -- but either way there is nothing to serve under it.
                Err(e) => return fail(StatusCode::NOT_FOUND, format!("{path}: {e:#}")),
            }
        }

        let Some(attrs) = self.cache.attrs_of(parent, name) else {
            // The parent was listed and this name is not in it. For a directory
            // request that only means there is no index.html, so fall through to a
            // listing. Otherwise it is a 404 that cost no round trip.
            if wants_dir {
                return self.autoindex_of(session, path, &resolved).await;
            }
            return fail(StatusCode::NOT_FOUND, format!("not found: {path}"));
        };

        // A symlink inside the base may point outside it, and finding out needs a
        // REALPATH per request. Refusing costs nothing and never lies. This covers
        // the final component only: a symlinked *directory* higher up the path is
        // still not caught, which SECURITY.md says plainly.
        if attrs.is_symlink() {
            return fail(
                StatusCode::FORBIDDEN,
                format!("refusing symlink: {path} (its target is not checked)"),
            );
        }

        // Known from the listing, so the wrong-shape cases cost nothing either.
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
                self.cache.forget_listing(parent);
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

/// Split an absolute path into its directory and its final component.
fn split_parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        // A file directly under the root: the parent is "/" and not "".
        Some(("", name)) => ("/", name),
        Some((dir, name)) => (dir, name),
        None => ("/", path),
    }
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
    fn parents_split_correctly_including_at_the_root() {
        assert_eq!(split_parent("/srv/docs/a.html"), ("/srv/docs", "a.html"));
        assert_eq!(split_parent("/a.html"), ("/", "a.html"));
        assert_eq!(split_parent("a.html"), ("/", "a.html"));
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
}
