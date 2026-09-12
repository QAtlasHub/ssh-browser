//! Request guards: two separate checks for two separate attacks.
//!
//! The Host check stops a DNS-rebinding site from reading the remote through the
//! loopback listener. Binding to 127.0.0.1 does nothing about that on its own,
//! and leaving it out is the hole rclone's `serve http` has.
//!
//! The path check keeps a request inside its alias base.

use anyhow::{Context, Result, bail, ensure};

/// Which shape of request arrived.
#[derive(Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// Proxied: the browser asked for `http://<alias>.<suffix>/<path>`.
    Alias { alias: &'a str, path: &'a str },
    /// Direct: something reached the loopback listener by address.
    Direct { path: &'a str },
}

/// Decide what a request is, or refuse it.
pub fn classify<'a>(host: &'a str, path: &'a str, suffix: &str, port: u16) -> Result<Target<'a>> {
    let (name, given_port) = split_host(host);

    if let Some(alias) = name
        .strip_suffix(suffix)
        .and_then(|head| head.strip_suffix('.'))
    {
        ensure!(
            is_label(alias),
            "alias {alias:?} is not a bare hostname label"
        );
        // A proxied request carries the site's own port, normally none or 80.
        // Anything else is not something we handed out.
        ensure!(
            matches!(given_port, None | Some(80) | Some(443)),
            "refusing {host:?}: unexpected port for an alias"
        );
        return Ok(Target::Alias { alias, path });
    }

    if matches!(name, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        // The port must be ours. A rebinding site resolved to loopback would
        // still arrive carrying its own Host, which the check above already
        // rejected, but pinning the port keeps the direct path honest too.
        ensure!(
            given_port == Some(port),
            "refusing {host:?}: not this listener's port {port}"
        );
        return Ok(Target::Direct { path });
    }

    bail!("refusing Host {host:?}: neither <alias>.{suffix} nor this loopback listener")
}

fn split_host(host: &str) -> (&str, Option<u16>) {
    // Bracketed IPv6 literal: the colons inside the brackets are not a port.
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.split_once("]:") {
            Some((addr, port)) => (&host[..addr.len() + 2], port.parse().ok()),
            None => (host, None),
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) => (name, port.parse().ok()),
        None => (host, None),
    }
}

/// The shape a hostname label has to have, and the rule every request is held to.
///
/// Crate-visible so that `Alias::new` checks exactly this rather than a second copy of
/// it. The copies had already drifted: `-docs` passed the constructor and was then
/// refused by `classify` on every request, so the daemon paid for the ssh connection,
/// printed the route and listed it as a link that could not work.
pub(crate) fn is_label(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Resolve a request path against an alias base, refusing anything that escapes.
///
/// Deliberately string-only. Asking the remote to REALPATH every request would
/// add a round trip per request and break invariant 1. The cost is real and worth
/// stating plainly: a symlink inside the base that points outside it is not
/// caught here. That check needs the listing cache and arrives with it.
pub fn resolve(base: &str, path: &str) -> Result<String> {
    let decoded = percent_decode(path)?;
    ensure!(!decoded.contains('\0'), "path contains NUL");

    let mut out: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    bail!("path escapes the alias base");
                }
            }
            s => out.push(s),
        }
    }

    let base = base.trim_end_matches('/');
    if out.is_empty() {
        return Ok(base.to_string());
    }
    Ok(format!("{base}/{}", out.join("/")))
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = *b.get(i + 1).context("truncated percent escape")?;
            let lo = *b.get(i + 2).context("truncated percent escape")?;
            out.push((hex(hi)? << 4) | hex(lo)?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context("path is not valid UTF-8 once decoded")
}

fn hex(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("bad hex digit in percent escape"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alias_host_is_recognised() {
        assert_eq!(
            classify("docs.ssh-browser", "/docs/", "ssh-browser", 7391).unwrap(),
            Target::Alias {
                alias: "docs",
                path: "/docs/"
            }
        );
    }

    #[test]
    fn the_loopback_listener_is_recognised_on_its_own_port() {
        assert_eq!(
            classify("127.0.0.1:7391", "/proxy.pac", "ssh-browser", 7391).unwrap(),
            Target::Direct { path: "/proxy.pac" }
        );
    }

    /// The whole point of the Host check: binding to loopback does not stop a
    /// rebinding site, only refusing its Host does.
    #[test]
    fn a_rebinding_host_is_refused() {
        assert!(classify("evil.example", "/", "ssh-browser", 7391).is_err());
        assert!(classify("127.0.0.1:9999", "/", "ssh-browser", 7391).is_err());
        assert!(classify("docs.ssh-browser.evil.example", "/", "ssh-browser", 7391).is_err());
    }

    #[test]
    fn an_alias_must_be_a_bare_label() {
        assert!(classify("a.b.ssh-browser", "/", "ssh-browser", 7391).is_err());
        assert!(classify("-bad.ssh-browser", "/", "ssh-browser", 7391).is_err());
        assert!(classify(".ssh-browser", "/", "ssh-browser", 7391).is_err());
    }

    #[test]
    fn paths_resolve_under_the_base() {
        assert_eq!(
            resolve("/srv/docs", "/a/b.html").unwrap(),
            "/srv/docs/a/b.html"
        );
        assert_eq!(resolve("/srv/docs/", "/").unwrap(), "/srv/docs");
        assert_eq!(resolve("/srv/docs", "/a/./b").unwrap(), "/srv/docs/a/b");
        assert_eq!(resolve("/srv/docs", "/a/../b").unwrap(), "/srv/docs/b");
    }

    #[test]
    fn traversal_is_refused_however_it_is_spelled() {
        assert!(resolve("/srv/docs", "/../etc/passwd").is_err());
        assert!(resolve("/srv/docs", "/a/../../etc/passwd").is_err());
        // Percent-encoded dot-dot must be decoded before normalising, or it walks
        // straight through.
        assert!(resolve("/srv/docs", "/%2e%2e/etc/passwd").is_err());
        assert!(resolve("/srv/docs", "/%2E%2E%2Fetc/passwd").is_err());
    }

    #[test]
    fn a_nul_byte_is_refused() {
        assert!(resolve("/srv/docs", "/a%00b").is_err());
    }
}
