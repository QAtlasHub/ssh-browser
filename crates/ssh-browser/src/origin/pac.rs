//! The PAC script that makes `http://<alias>.<suffix>/` reach this daemon.
//!
//! A PAC routes by hostname and never resolves it, so the suffix does not have to
//! be a real TLD and no DNS server or hosts-file entry is needed. That is why
//! this works where mkcert-style setups reach for dnsmasq. It also leaves the
//! address bar alone, unlike a declarativeNetRequest redirect, which rewrites the
//! URL to 127.0.0.1 and loses the origin the user asked for.

use anyhow::{Result, ensure};

/// Build the script. The suffix is validated rather than escaped: it lands inside
/// a JavaScript string literal, and a label is the only shape that cannot break
/// out of one.
pub fn script(suffix: &str, port: u16) -> Result<String> {
    ensure!(
        is_suffix(suffix),
        "suffix {suffix:?} must be lowercase letters, digits, hyphens and dots"
    );
    Ok(format!(
        "function FindProxyForURL(url, host) {{\n  \
         if (dnsDomainIs(host, \".{suffix}\") || host === \"{suffix}\") {{\n    \
         return \"PROXY 127.0.0.1:{port}\";\n  \
         }}\n  \
         return \"DIRECT\";\n\
         }}\n"
    ))
}

fn is_suffix(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['-', '.'])
        && !s.ends_with(['-', '.'])
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_the_suffix_and_nothing_else() {
        let s = script("ssh-browser", 7391).unwrap();
        assert!(s.contains("dnsDomainIs(host, \".ssh-browser\")"));
        assert!(s.contains("PROXY 127.0.0.1:7391"));
        assert!(s.contains("return \"DIRECT\""));
    }

    /// The suffix is configurable, so it is attacker-adjacent input as far as the
    /// generated script is concerned.
    #[test]
    fn a_suffix_that_could_break_out_of_the_string_is_refused() {
        assert!(script("a\" + evil + \"b", 7391).is_err());
        assert!(script("a\nb", 7391).is_err());
        assert!(script("", 7391).is_err());
        assert!(script("UPPER", 7391).is_err());
    }

    #[test]
    fn a_custom_suffix_works() {
        let s = script("internal.example", 9000).unwrap();
        assert!(s.contains("dnsDomainIs(host, \".internal.example\")"));
        assert!(s.contains("PROXY 127.0.0.1:9000"));
    }
}
