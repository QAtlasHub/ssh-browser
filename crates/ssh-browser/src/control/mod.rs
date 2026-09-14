//! The control API: the only path that will ever be allowed to write.
//!
//! No CORS headers are emitted anywhere in this module, and `OPTIONS` is refused. That
//! combination is the security boundary, so it is worth spelling out.
//!
//! A page served under an alias origin is untrusted code. If it tries to reach the
//! control API it has to send the token header; a custom header is not CORS-safelisted,
//! so sending it forces a preflight; and a refused preflight means the request is never
//! made. Without the header the request is a 401 instead. An extension is outside CORS
//! by virtue of its host permissions, so none of this impedes it.
//!
//! The listener also only routes here for requests whose Host is the loopback address,
//! which `guard::classify` already separates from alias requests. A proxied request
//! cannot arrive here at all.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Response, StatusCode};
use serde::Serialize;

/// The header the token must arrive in.
///
/// Custom rather than `Authorization` for one reason that matters: a custom header is
/// not CORS-safelisted, so a page attempting to send it triggers a preflight we refuse.
pub const TOKEN_HEADER: &str = "x-ssh-browser-token";

pub const PATH_PREFIX: &str = "/_control/";

/// What a browser says about who started a request.
///
/// A forbidden header name: page script can neither set it nor remove it, so what arrives
/// is the browser's account rather than the caller's.
pub const FETCH_SITE_HEADER: &str = "sec-fetch-site";

/// Protocol versions this daemon can speak.
///
/// Negotiated rather than assumed. The extension ships through a store review and the
/// daemon ships through cargo, so on any given machine the two will not be the same age
/// and a new daemon has to keep talking to an old extension.
pub const PROTOCOL_MIN: u32 = 1;
pub const PROTOCOL_MAX: u32 = 1;

const TOKEN_BYTES: usize = 32;

/// A bearer token for the control API.
///
/// Deliberately neither `Debug` nor `Display`. A token that can be formatted is a token
/// that ends up in a log line eventually; the only way out is [`Token::as_str`], which
/// reads as the deliberate act it is.
pub struct Token(String);

impl Token {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        // `getrandom::Error` does not implement `std::error::Error`, so it cannot be
        // attached with `context`.
        getrandom::fill(&mut bytes)
            .map_err(|e| anyhow!("reading OS entropy for the control token failed: {e}"))?;
        Ok(Self(hex(&bytes)))
    }

    /// Reconstruct a token generated elsewhere, such as one read back from disk.
    pub fn from_hex(s: &str) -> Self {
        Self(s.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compare in constant time.
    ///
    /// A short-circuiting `==` leaks the token one byte at a time to anything that can
    /// time the response, and on loopback that is every process on the machine. The
    /// length is allowed to leak because it is a compile-time constant.
    pub fn matches(&self, presented: &str) -> bool {
        let (want, got) = (self.0.as_bytes(), presented.as_bytes());
        if want.len() != got.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(got) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Write the token where a local tool can find it, returning where it went.
    ///
    /// Best effort. A daemon that cannot write the file still works, because the token
    /// is printed at startup as well, and refusing to start over this would be worse
    /// than the inconvenience it avoids.
    pub fn write_to_disk(&self) -> Option<PathBuf> {
        let path = token_path()?;
        std::fs::create_dir_all(path.parent()?).ok()?;
        write_private(&path, self.0.as_bytes()).ok()?;
        Some(path)
    }

    /// Read a token back, if what is on disk is one.
    ///
    /// Length and alphabet are both checked. A file holding something else is not a token
    /// however much one would like it to be, and accepting it would produce a daemon whose
    /// token nothing can ever match — a locked door with no key, rather than an error.
    fn from_disk(path: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        let trimmed = text.trim();
        let looks_right = trimmed.len() == TOKEN_BYTES * 2
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        looks_right.then(|| Self(trimmed.to_string()))
    }

    /// The token this run will use: last run's, or a new one written down.
    ///
    /// Reused by default, because the alternative is what this did before and it made the
    /// extension unusable. A fresh token every restart means pasting sixty-four characters
    /// into a popup every time the daemon comes back — and the token was already being
    /// written to disk, so regenerating took the risk of keeping it there and discarded the
    /// only thing that risk buys.
    ///
    /// `rotate` mints a new one anyway, which is what to reach for if the old one leaked.
    pub fn load_or_generate(rotate: bool) -> Result<(Self, Source)> {
        if !rotate
            && let Some(path) = token_path()
            && let Some(token) = Self::from_disk(&path)
        {
            return Ok((token, Source::Reused(path)));
        }
        let token = Self::generate()?;
        let written = token.write_to_disk();
        Ok((token, Source::Fresh(written)))
    }
}

/// Where the token this run is using came from.
///
/// Reported rather than left to be inferred, so the startup banner can say which happened.
/// Otherwise a reader has to compare a hex string against whatever their browser is holding
/// in order to find out whether they need to paste it again.
pub enum Source {
    /// Read back from a previous run, so a browser that already has it stays connected.
    Reused(PathBuf),
    /// Newly minted, and written where the path says — or nowhere, if that failed.
    Fresh(Option<PathBuf>),
}

/// Where the token file goes, resolved at runtime rather than compiled in.
///
/// The runtime directory is preferred on Unix because it is cleared on logout. That used to
/// be the whole argument — a token belonging to a running process should not outlive the
/// session — and it still holds, but it now cuts the other way as well: the token survives a
/// daemon restart, so a browser stays connected across one, and stops being valid when the
/// login session that owned it ends. A config directory would keep it indefinitely, which is
/// longer than anything here needs.
fn token_path() -> Option<PathBuf> {
    Some(state_dir()?.join("token"))
}

/// Where this daemon keeps the small things it remembers between runs.
///
/// Shared with anything else that needs one rather than each picking its own: two
/// directories chosen by two copies of this logic is how a setting gets written to one
/// place and read from another.
pub fn state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("ssh-browser"))
}

/// Write a file only this account can read, with the permissions set as it is created.
///
/// Created restricted rather than tightened afterwards. Writing the bytes and then calling
/// `set_permissions` leaves a window in which the file exists and is readable — short, real, and
/// exactly the kind of detail that stays invisible until it matters. The token has always gone
/// through here; the authority key in `crate::tls` has to, because a private key another account
/// on the machine can read is the one thing that makes a constrained CA pointless.
#[cfg(unix)]
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

/// On Windows a file created under the user's own `LOCALAPPDATA` inherits an ACL that already
/// excludes other users, and there is no mode to set.
#[cfg(not(unix))]
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

#[derive(Serialize)]
struct Protocol {
    min: u32,
    max: u32,
}

#[derive(Serialize)]
struct Hello<'a> {
    daemon: &'a str,
    protocol: Protocol,
    aliases: &'a [String],
    /// The hostname suffix, so the extension can build an alias URL without being told it
    /// separately.
    ///
    /// Reported rather than assumed: the suffix is configurable, and an extension that
    /// hardcoded it would break the moment somebody changed it. Additive, so a protocol-1
    /// client that does not read this field is unaffected and the range stays 1..=1.
    suffix: &'a str,
    /// `http` or `https`, so the extension builds a URL in the scheme being served.
    ///
    /// Reported for the same reason the suffix is: it is configurable, and an extension that
    /// assumed would hand somebody a link to a *different origin* than the one being served —
    /// which under https is not a cosmetic difference.
    scheme: &'a str,
    /// Remote round trips every open session has cost, added up.
    ///
    /// Here as well as in `hosts` because this is the cheap route. `hosts` runs `ssh -G` once
    /// per configured host, which is the right cost for a list somebody is about to read and
    /// the wrong cost for a number sampled twice around a page load: the measurement takes
    /// long enough to expire the listings it is measuring. That mistake has been made twice
    /// here already. A counter nobody can read without disturbing is not a counter.
    trips: u64,
}

/// Check the two things that must hold before any control route runs, returning the
/// refusal if there is one.
///
/// Separated from routing so that a caller cannot reach a route without going through it:
/// there is no path to a control route that does not pass this function first.
/// Whether a request could have come from a page.
///
/// Measured rather than assumed. In Chromium an extension's `fetch` arrives with
/// `Sec-Fetch-Site: none` and no `Origin` at all, while a page the daemon itself serves in
/// the no-proxy fallback mode -- which is *same-origin* with the control API, and so the
/// hardest case -- arrives with `same-origin`. Anything from another site is `cross-site`.
///
/// Absent means no browser sent it. That is a local process, which could read the token
/// file directly, so refusing it here would protect nothing.
pub fn from_a_page(site: Option<&str>) -> bool {
    match site {
        None => false,
        Some("none") => false,
        Some(_) => true,
    }
}

pub fn gate(
    method: &Method,
    fetch_site: Option<&str>,
    presented: Option<&str>,
    token: &Token,
) -> Option<Response<Full<Bytes>>> {
    // Refusing the preflight is what keeps an alias page from ever reaching a route.
    // Answering it, even with a restrictive allow-list, would move the decision into the
    // browser's hands rather than ours.
    if method == Method::OPTIONS {
        return Some(text(
            StatusCode::METHOD_NOT_ALLOWED,
            "the control API does not participate in CORS",
        ));
    }

    // Before the token, because it is a stronger statement: no page reaches this API at
    // all, whatever it has got hold of. The token answers "is this caller authorised";
    // this answers "is this caller a page", and a page holding a leaked token was the one
    // case the token alone could not refuse. It matters most in the no-proxy fallback
    // mode, where a page the daemon serves shares an origin with the control API.
    if from_a_page(fetch_site) {
        return Some(text(
            StatusCode::FORBIDDEN,
            "the control API is not reachable from a page",
        ));
    }

    match presented {
        Some(p) if token.matches(p) => None,
        // The same answer either way: distinguishing "no token" from "wrong token" would
        // tell a caller which half it got right.
        _ => Some(text(StatusCode::UNAUTHORIZED, "control token required")),
    }
}

/// The route name within the control namespace, e.g. `hello`.
pub fn route_of(path: &str) -> &str {
    path.strip_prefix(PATH_PREFIX).unwrap_or("")
}

pub fn hello(aliases: &[String], suffix: &str, scheme: &str, trips: u64) -> Response<Full<Bytes>> {
    json(&Hello {
        daemon: env!("CARGO_PKG_VERSION"),
        protocol: Protocol {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        },
        aliases,
        suffix,
        scheme,
        trips,
    })
}

pub fn json<T: Serialize>(value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "malformed response")),
        Err(e) => text(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialising the response failed: {e}"),
        ),
    }
}

pub fn text(status: StatusCode, detail: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(detail.into())))
        .expect("a plain-text body with static headers always builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> Token {
        Token::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn a_generated_token_is_long_and_random() {
        let a = Token::generate().expect("OS entropy");
        let b = Token::generate().expect("OS entropy");
        assert_eq!(a.as_str().len(), TOKEN_BYTES * 2);
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "two tokens from the same process must differ"
        );
    }

    #[test]
    fn the_right_token_passes_the_gate() {
        assert!(gate(&Method::GET, None, Some(token().as_str()), &token()).is_none());
    }

    #[test]
    fn a_missing_or_wrong_token_is_refused_identically() {
        for presented in [None, Some(""), Some("wrong"), Some(&token().as_str()[..10])] {
            let refusal = gate(&Method::GET, None, presented, &token()).expect("refused");
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        }
    }

    /// The boundary. If a preflight ever passes, an untrusted page can start negotiating
    /// with the control API instead of being stopped before the request is even made.
    #[test]
    fn a_preflight_is_refused_even_with_a_valid_token() {
        let refusal =
            gate(&Method::OPTIONS, None, Some(token().as_str()), &token()).expect("refused");
        assert_eq!(refusal.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Nothing here may emit CORS headers: that is what stops a page reading a response
    /// even if it somehow manages to send the request.
    #[test]
    fn no_response_carries_cors_headers() {
        let mut responses = vec![hello(&["docs".to_string()], "ssh-browser", "http", 0)];
        responses.extend(gate(&Method::OPTIONS, None, None, &token()));
        responses.extend(gate(&Method::GET, None, None, &token()));
        responses.push(text(StatusCode::NOT_FOUND, "nope"));

        for res in responses {
            for name in res.headers().keys() {
                let lowered = name.as_str().to_ascii_lowercase();
                assert!(
                    !lowered.starts_with("access-control-"),
                    "a control response carries {lowered}"
                );
            }
        }
    }

    #[test]
    fn hello_reports_a_protocol_range_and_the_aliases() {
        let body = serde_json::to_string(&Hello {
            daemon: env!("CARGO_PKG_VERSION"),
            protocol: Protocol {
                min: PROTOCOL_MIN,
                max: PROTOCOL_MAX,
            },
            aliases: &["docs".to_string()],
            suffix: "ssh-browser",
            scheme: "https",
            trips: 7,
        })
        .expect("serialises");
        assert!(body.contains("\"min\":1"));
        assert!(body.contains("\"max\":1"));
        assert!(body.contains("\"aliases\":[\"docs\"]"));
        assert!(body.contains("\"daemon\":\""));
        // The cheap route carries it too, so a measurement does not have to pay for `hosts`.
        assert!(body.contains("\"trips\":7"), "{body}");
        // The scheme, because the extension builds URLs from it and a wrong one is a link into
        // a different origin than the one being served.
        assert!(body.contains("\"scheme\":\"https\""), "{body}");
    }

    /// A temporary file, named after the test so parallel runs cannot collide.
    fn scratch(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ssh-browser-token-{name}"));
        std::fs::write(&path, contents).expect("a temp file");
        path
    }

    /// The whole point of keeping it: a browser that has the token stays connected across a
    /// restart, so nobody retypes sixty-four characters to get back to where they were.
    #[test]
    fn a_token_survives_the_round_trip_to_disk() {
        let path = scratch("roundtrip", token().as_str());
        let back = Token::from_disk(&path).expect("read back");
        assert!(back.matches(token().as_str()));
        let _ = std::fs::remove_file(&path);
    }

    /// Anything that is not a token is not accepted as one. Taking it would produce a daemon
    /// whose token nothing can ever match — a locked door with no key rather than an error,
    /// and one that only shows up as a 401 on every request.
    #[test]
    fn a_file_that_is_not_a_token_is_refused() {
        let cases = [
            ("empty", ""),
            ("short", "0123456789abcdef"),
            ("long", &"a".repeat(65) as &str),
            ("not-hex", &"z".repeat(64)),
            // Uppercase would compare unequal to everything this ever generates, so it is
            // refused rather than quietly accepted and never matched.
            ("uppercase", &"A".repeat(64)),
            ("a sentence", "this file used to hold a token"),
        ];
        for (name, contents) in cases {
            let path = scratch(name, contents);
            assert!(
                Token::from_disk(&path).is_none(),
                "{name:?} should not have read as a token"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Written with a trailing newline by an editor, or by anyone who opened it to look.
    #[test]
    fn surrounding_whitespace_does_not_spoil_it() {
        let path = scratch("whitespace", &format!("\n  {}\t\n", token().as_str()));
        assert!(
            Token::from_disk(&path)
                .expect("read back")
                .matches(token().as_str())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn routes_are_named_after_the_prefix() {
        assert_eq!(route_of("/_control/hello"), "hello");
        assert_eq!(route_of("/_control/open"), "open");
        assert_eq!(route_of("/not-control"), "");
    }

    /// The measured cases. An extension's fetch arrives as `none` with no `Origin`; a page
    /// the daemon serves in the no-proxy fallback mode arrives as `same-origin`, which is
    /// the hardest one because it shares an origin with the control API; anything from
    /// elsewhere is `cross-site`. Absent is not a browser at all.
    #[test]
    fn a_page_is_told_apart_from_an_extension() {
        assert!(!from_a_page(None));
        assert!(!from_a_page(Some("none")));
        for page in ["same-origin", "same-site", "cross-site"] {
            assert!(from_a_page(Some(page)), "{page} is a page");
        }
    }

    /// Refused before the token is even looked at, because it is the stronger statement:
    /// a page holding a leaked token is the one case the token alone could not refuse.
    #[test]
    fn a_page_cannot_reach_the_control_api_even_with_the_right_token() {
        let refusal = gate(
            &Method::GET,
            Some("same-origin"),
            Some(token().as_str()),
            &token(),
        )
        .expect("refused");
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    }
}
