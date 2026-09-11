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

use std::path::PathBuf;

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
        std::fs::write(&path, &self.0).ok()?;
        restrict(&path);
        Some(path)
    }
}

/// Where the token file goes, resolved at runtime rather than compiled in.
///
/// The runtime directory is preferred on Unix because it is cleared on logout, which is
/// the right lifetime for a token belonging to a running process. A config directory
/// would keep a dead token around indefinitely.
fn token_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("ssh-browser").join("token"))
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) {
    // On Windows a file created under the user's own LOCALAPPDATA inherits an ACL that
    // already excludes other users, and there is no mode to set.
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
}

/// Check the two things that must hold before any control route runs, returning the
/// refusal if there is one.
///
/// Separated from routing so that a caller cannot reach a route without going through it:
/// there is no path to the annotation handlers that does not pass this function first.
pub fn gate(
    method: &Method,
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

pub fn hello(aliases: &[String], suffix: &str) -> Response<Full<Bytes>> {
    json(&Hello {
        daemon: env!("CARGO_PKG_VERSION"),
        protocol: Protocol {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        },
        aliases,
        suffix,
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
        assert!(gate(&Method::GET, Some(token().as_str()), &token()).is_none());
    }

    #[test]
    fn a_missing_or_wrong_token_is_refused_identically() {
        for presented in [None, Some(""), Some("wrong"), Some(&token().as_str()[..10])] {
            let refusal = gate(&Method::GET, presented, &token()).expect("refused");
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        }
    }

    /// The boundary. If a preflight ever passes, an untrusted page can start negotiating
    /// with the control API instead of being stopped before the request is even made.
    #[test]
    fn a_preflight_is_refused_even_with_a_valid_token() {
        let refusal = gate(&Method::OPTIONS, Some(token().as_str()), &token()).expect("refused");
        assert_eq!(refusal.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Nothing here may emit CORS headers: that is what stops a page reading a response
    /// even if it somehow manages to send the request.
    #[test]
    fn no_response_carries_cors_headers() {
        let mut responses = vec![hello(&["docs".to_string()], "ssh-browser")];
        responses.extend(gate(&Method::OPTIONS, None, &token()));
        responses.extend(gate(&Method::GET, None, &token()));
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
        })
        .expect("serialises");
        assert!(body.contains("\"min\":1"));
        assert!(body.contains("\"max\":1"));
        assert!(body.contains("\"aliases\":[\"docs\"]"));
        assert!(body.contains("\"daemon\":\""));
    }

    #[test]
    fn routes_are_named_after_the_prefix() {
        assert_eq!(route_of("/_control/hello"), "hello");
        assert_eq!(route_of("/_control/annotations"), "annotations");
        assert_eq!(route_of("/not-control"), "");
    }
}
